"""The three v0.1 heuristics."""

from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Pattern, Tuple

from ..models import Alert, ProcessEvent, basename, normalise_binary
from .engine import Rule

# --------------------------------------------------------------------------
# Rule A - a service or interpreter spawning an interactive shell
# --------------------------------------------------------------------------

SHELLS = frozenset(
    {"sh", "bash", "zsh", "dash", "ash", "ksh", "fish", "csh", "tcsh", "busybox"}
)

# Parents with no legitimate reason to drop to a shell. sshd, su, sudo, login
# and terminal emulators are deliberately absent: for them it is normal.
SERVICE_PARENTS = frozenset(
    {
        "nginx",
        "apache",
        "apache2",
        "httpd",
        "lighttpd",
        "caddy",
        "haproxy",
        "node",
        "nodejs",
        "deno",
        "bun",
        "python",
        "php",
        "php-fpm",
        "php-cgi",
        "ruby",
        "perl",
        "java",
        "tomcat",
        "catalina",
        "uwsgi",
        "gunicorn",
        "puma",
        "unicorn",
        "redis-server",
        "memcached",
        "mongod",
        "mysqld",
        "postgres",
        "postmaster",
        "vsftpd",
        "proftpd",
        "smbd",
        "exim",
        "postfix",
    }
)

# An -i anywhere in the flags, including bundles such as -li.
_INTERACTIVE_FLAG = re.compile(r"(?:^|\s)-[a-zA-Z]*i[a-zA-Z]*(?:$|\s)")


class ShellSpawnRule(Rule):
    """Rule A: web server / daemon / interpreter spawns an interactive shell."""

    rule_id = "EDR-001-SUSPICIOUS-SHELL-SPAWN"
    severity = "HIGH"
    name = "Interactive shell spawned by unusual parent"

    def evaluate(self, event: ProcessEvent) -> Optional[Alert]:
        child = normalise_binary(event.exe_path) or normalise_binary(event.comm)
        if child not in SHELLS:
            return None

        parent = normalise_binary(event.parent_exe_path)
        if parent not in SERVICE_PARENTS:
            return None

        # A shell carrying -i is a live session rather than the one-shot
        # "sh -c ..." a service might legitimately run.
        interactive = bool(_INTERACTIVE_FLAG.search(event.cmdline))
        severity = "CRITICAL" if interactive else "HIGH"
        detail = "parent=%s child=%s%s" % (
            basename(event.parent_exe_path) or parent,
            basename(event.exe_path) or child,
            " (interactive flag)" if interactive else "",
        )
        return self._alert(
            event,
            "Interactive shell spawned by unusual parent",
            detail=detail,
            severity=severity,
        )


# --------------------------------------------------------------------------
# Rule B - dangerous one-liners
# --------------------------------------------------------------------------

_SHELL_ALT = r"(?:ba|z|da|a|k)?sh"

ONELINER_PATTERNS: Tuple[Tuple[str, Pattern[str], str], ...] = (
    (
        "download-pipe-shell",
        re.compile(
            r"\b(?:curl|wget|fetch)\b[^|]*\|\s*(?:sudo\s+)?"
            r"(?:" + _SHELL_ALT + r"|python[0-9.]*|perl|ruby)\b",
            re.IGNORECASE,
        ),
        "Remote content piped directly into an interpreter",
    ),
    (
        "base64-decode-pipe",
        re.compile(
            r"\bbase64\b[^|]*(?:-d|-D|--decode)[^|]*\|\s*"
            r"(?:" + _SHELL_ALT + r"|python[0-9.]*|perl)\b",
            re.IGNORECASE,
        ),
        "Base64-decoded payload piped into an interpreter",
    ),
    (
        "echo-base64-decode",
        re.compile(
            r"\becho\b\s+[\"']?[A-Za-z0-9+/=]{24,}[\"']?\s*\|\s*base64\b",
            re.IGNORECASE,
        ),
        "Inline base64 blob decoded at runtime",
    ),
    (
        "devtcp-reverse-shell",
        re.compile(r"/dev/(?:tcp|udp)/[^\s/]+/\d+", re.IGNORECASE),
        "Bash /dev/tcp network redirection (reverse shell)",
    ),
    (
        "netcat-exec",
        re.compile(r"\bn(?:c|cat|etcat)(?:\.\w+)?\b[^|;]*\s-\w*e\w*\s", re.IGNORECASE),
        "Netcat invoked with command execution",
    ),
    (
        "interpreter-inline-decode",
        re.compile(
            r"\bpython[0-9.]*\b[^|]*-c\b[^|]*"
            r"(?:b64decode|exec\s*\(|eval\s*\()",
            re.IGNORECASE,
        ),
        "Python one-liner decoding or evaluating a payload",
    ),
)


class SuspiciousOneLinerRule(Rule):
    """Rule B: dangerous shell chaining / staged payload execution."""

    rule_id = "EDR-002-SUSPICIOUS-ONELINER"
    severity = "HIGH"
    name = "Suspicious one-liner execution"

    def evaluate(self, event: ProcessEvent) -> Optional[Alert]:
        cmdline = event.cmdline
        if not cmdline:
            return None

        for key, pattern, description in ONELINER_PATTERNS:
            match = pattern.search(cmdline)
            if match is None:
                continue
            snippet = match.group(0)
            if len(snippet) > 160:
                snippet = snippet[:157] + "..."
            severity = "CRITICAL" if key == "devtcp-reverse-shell" else self.severity
            return self._alert(
                event,
                description,
                detail="pattern=%s match=%r" % (key, snippet),
                severity=severity,
            )
        return None


# --------------------------------------------------------------------------
# Rule C - reconnaissance chains
# --------------------------------------------------------------------------

RECON_BINARIES = frozenset(
    {
        "whoami",
        "id",
        "groups",
        "uname",
        "hostname",
        "hostnamectl",
        "arch",
        "uptime",
        "lscpu",
        "lsb_release",
        "netstat",
        "ss",
        "ifconfig",
        "route",
        "arp",
        "w",
        "who",
        "last",
        "lastlog",
        "env",
        "printenv",
        "crontab",
        "dmidecode",
    }
)

# These only count as recon with enumeration flags; bare "ps" and "ip" run
# constantly during normal operation.
_CONDITIONAL_RECON: Dict[str, Pattern[str]] = {
    "ip": re.compile(r"\b(?:a|addr|address|link|route|neigh)\b"),
    "ps": re.compile(r"-\w*(?:e|a)\w*"),
    "sudo": re.compile(r"(?:^|\s)-l(?:\s|$)"),
    "find": re.compile(r"-perm\b.*(?:4000|u\+s|-2000)"),
}


class ReconChainRule(Rule):
    """Rule C: several distinct enumeration binaries from one parent, fast."""

    rule_id = "EDR-003-RECON-CHAIN"
    severity = "MEDIUM"
    name = "Reconnaissance command chain"

    def __init__(
        self,
        window_seconds: float = 10.0,
        threshold: int = 3,
        cooldown_seconds: float = 30.0,
    ) -> None:
        self.window = window_seconds
        self.threshold = threshold
        self.cooldown = cooldown_seconds
        self._history: Dict[int, Deque[Tuple[float, str]]] = defaultdict(deque)
        self._last_alert: Dict[int, float] = {}

    @staticmethod
    def _recon_name(event: ProcessEvent) -> Optional[str]:
        name = normalise_binary(event.exe_path) or normalise_binary(event.comm)
        if not name:
            return None
        if name in RECON_BINARIES:
            return name
        conditional = _CONDITIONAL_RECON.get(name)
        if conditional is not None and conditional.search(event.cmdline):
            return name
        return None

    def evaluate(self, event: ProcessEvent) -> Optional[Alert]:
        name = self._recon_name(event)
        if name is None:
            return None
        if event.ppid <= 0:
            return None

        now = event.monotonic
        history = self._history[event.ppid]
        history.append((now, name))

        cutoff = now - self.window
        while history and history[0][0] < cutoff:
            history.popleft()

        distinct = {entry[1] for entry in history}
        if len(distinct) < self.threshold:
            return None

        last = self._last_alert.get(event.ppid)
        if last is not None and (now - last) < self.cooldown:
            return None
        self._last_alert[event.ppid] = now
        self._prune(now)

        ordered: List[str] = []
        for _ts, seen in history:
            if seen not in ordered:
                ordered.append(seen)

        return self._alert(
            event,
            "Reconnaissance command chain from a single parent",
            detail="%d distinct recon binaries within %.0fs from ppid %d: %s"
            % (len(distinct), self.window, event.ppid, ", ".join(ordered)),
        )

    def _prune(self, now: float) -> None:
        """Drop parents that have gone quiet so state cannot grow unbounded."""
        stale = now - max(self.window, self.cooldown) * 2
        dead = [p for p, h in self._history.items() if not h or h[-1][0] < stale]
        for ppid in dead:
            self._history.pop(ppid, None)
            self._last_alert.pop(ppid, None)


def default_rules() -> List[Rule]:
    return [ShellSpawnRule(), SuspiciousOneLinerRule(), ReconChainRule()]

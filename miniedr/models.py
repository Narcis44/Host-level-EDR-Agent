"""Core data types shared by every component."""

from __future__ import annotations

import datetime
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# Matches a trailing interpreter version so "python3.12" and "php8.1" normalise
# to "python" and "php" for rule matching.
_VERSION_SUFFIX = re.compile(r"[0-9]+(\.[0-9]+)*$")


def utc_now_iso() -> str:
    """UTC ISO-8601 with millisecond precision, e.g. 2026-08-26T14:30:00.123Z."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (now.microsecond // 1000)


def basename(path: str) -> str:
    """Basename of an exe path, tolerating the kernel's ' (deleted)' suffix."""
    if not path:
        return ""
    return os.path.basename(path.removesuffix(" (deleted)"))


def normalise_binary(path: str) -> str:
    """Basename with any trailing version stripped: /usr/bin/python3.12 -> python."""
    name = basename(path)
    stripped = _VERSION_SUFFIX.sub("", name)
    # Only accept the strip if something is left ("7z" must not become "").
    return stripped.rstrip(".-_") or name


@dataclass
class ProcessEvent:
    """One enriched process-execution event."""

    timestamp: str
    pid: int
    ppid: int
    exe_path: str
    cmdline: str
    uid: int
    username: str
    parent_exe_path: str
    parent_cmdline: str
    comm: str = ""
    source: str = "procfs"
    # Monotonic clock reading, used by time-window rules. Never serialised.
    monotonic: float = 0.0

    @property
    def exe_name(self) -> str:
        return basename(self.exe_path)

    @property
    def parent_exe_name(self) -> str:
        return basename(self.parent_exe_path)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "pid": self.pid,
            "ppid": self.ppid,
            "exe_path": self.exe_path,
            "cmdline": self.cmdline,
            "uid": self.uid,
            "username": self.username,
            "parent_exe_path": self.parent_exe_path,
            "source": self.source,
        }


@dataclass
class Alert:
    """A rule match, serialised to the v0.1 alert schema."""

    rule_id: str
    severity: str
    alert: str
    event: ProcessEvent
    detail: str = ""
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self, hostname: str = "") -> Dict[str, Any]:
        doc: Dict[str, Any] = {
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "alert": self.alert,
            "process": {
                "pid": self.event.pid,
                "ppid": self.event.ppid,
                "exe": self.event.exe_path,
                "cmdline": self.event.cmdline,
                "uid": self.event.uid,
                "username": self.event.username,
            },
            "parent": {
                "pid": self.event.ppid,
                "exe": self.event.parent_exe_path,
                "cmdline": self.event.parent_cmdline,
            },
        }
        if self.detail:
            doc["detail"] = self.detail
        if hostname:
            doc["host"] = hostname
        return doc


SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

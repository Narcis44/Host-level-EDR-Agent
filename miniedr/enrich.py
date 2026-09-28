"""Component 2: telemetry enricher.

Turns a bare PID into a fully populated ProcessEvent by reading procfs.

Everything here races the scheduler: by the time we read /proc/<pid>/, the
process may already be gone. Every read therefore degrades to a placeholder
rather than raising, and a small LRU of previously seen processes lets us still
describe a parent that exited before we got to it.
"""

from __future__ import annotations

import os
import pwd
import time
from collections import OrderedDict
from typing import Dict, Optional, Tuple

from .models import ProcessEvent, utc_now_iso

PROC = "/proc"

# A process is visible with a resolvable exe link a moment before the kernel
# has finished populating its argv, and PROC_EVENT_EXEC lands inside exactly
# that window. Without a short retry the agent records an empty cmdline for a
# fraction of all execs - which would blind every cmdline-based rule. Budget:
# 0.5 + 1 + 2 = 3.5ms worst case, only ever paid when argv reads back empty.
CMDLINE_RETRIES = 3
CMDLINE_RETRY_BASE = 0.0005


class _ProcessCache:
    """Bounded LRU of pid -> (exe_path, cmdline), for enriching dead parents."""

    def __init__(self, max_entries: int = 4096) -> None:
        self._max = max_entries
        self._data: "OrderedDict[int, Tuple[str, str]]" = OrderedDict()

    def put(self, pid: int, exe_path: str, cmdline: str) -> None:
        self._data[pid] = (exe_path, cmdline)
        self._data.move_to_end(pid)
        while len(self._data) > self._max:
            self._data.popitem(last=False)

    def get(self, pid: int) -> Optional[Tuple[str, str]]:
        entry = self._data.get(pid)
        if entry is not None:
            self._data.move_to_end(pid)
        return entry


def _read_exe(pid: int) -> str:
    """Absolute path of the running binary via /proc/<pid>/exe."""
    try:
        return os.readlink("%s/%d/exe" % (PROC, pid))
    except (OSError, ValueError):
        # Kernel threads have no exe link; neither do processes we may not
        # inspect, nor ones that exited underneath us.
        return ""


def _read_cmdline(pid: int, retries: int = 0) -> str:
    """Full argv from /proc/<pid>/cmdline (NUL-separated on disk).

    With retries > 0, an empty result is re-read with a short backoff to ride
    out the post-exec window where argv is not yet published.
    """
    for attempt in range(retries + 1):
        try:
            with open("%s/%d/cmdline" % (PROC, pid), "rb") as handle:
                raw = handle.read()
        except (OSError, ValueError):
            # Gone, or not ours to read. Retrying cannot help.
            return ""

        parts = [p.decode("utf-8", "replace") for p in raw.split(b"\x00") if p]
        if parts:
            return " ".join(parts)

        if attempt < retries:
            time.sleep(CMDLINE_RETRY_BASE * (2 ** attempt))

    return ""


def _read_status(pid: int) -> Dict[str, str]:
    """Selected fields from /proc/<pid>/status."""
    wanted = ("Name", "State", "PPid", "Uid")
    found: Dict[str, str] = {}
    try:
        with open("%s/%d/status" % (PROC, pid), "r") as handle:
            for line in handle:
                key, _, value = line.partition(":")
                if key in wanted:
                    found[key] = value.strip()
                    if len(found) == len(wanted):
                        break
    except (OSError, ValueError):
        pass
    return found


def _username(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


class Enricher:
    """Builds ProcessEvents from PIDs."""

    def __init__(self) -> None:
        self._cache = _ProcessCache()

    def enrich(self, pid: int, source: str = "procfs") -> Optional[ProcessEvent]:
        """Return an enriched event, or None if the PID vanished entirely."""
        status = _read_status(pid)
        exe_path = _read_exe(pid)

        # Zombies have reached exit and will never publish an argv, so spending
        # the retry budget on them is pure latency. Everything else gets it.
        state = status.get("State", "")
        is_zombie = state.startswith("Z")
        retries = 0 if (is_zombie or not status) else CMDLINE_RETRIES
        cmdline = _read_cmdline(pid, retries=retries)

        if not status and not exe_path and not cmdline:
            # Process is fully gone and we cached nothing about it.
            return None

        comm = status.get("Name", "")
        try:
            ppid = int(status.get("PPid", "0"))
        except ValueError:
            ppid = 0

        # "Uid:" is "real effective saved fs" - the real UID is what we want.
        uid = 0
        uid_field = status.get("Uid", "")
        if uid_field:
            try:
                uid = int(uid_field.split()[0])
            except (ValueError, IndexError):
                uid = 0

        if not cmdline and comm:
            # Kernel threads and zombies expose no argv; keep the kernel's own
            # convention of bracketing the comm so it reads unambiguously.
            cmdline = "[%s]" % comm

        parent_exe, parent_cmdline = self._describe_parent(ppid)

        if exe_path and not cmdline.startswith("["):
            # Only cache fully resolved processes, so a parent lookup never
            # replays a degraded placeholder.
            self._cache.put(pid, exe_path, cmdline)

        return ProcessEvent(
            timestamp=utc_now_iso(),
            pid=pid,
            ppid=ppid,
            exe_path=exe_path,
            cmdline=cmdline,
            uid=uid,
            username=_username(uid),
            parent_exe_path=parent_exe,
            parent_cmdline=parent_cmdline,
            comm=comm,
            source=source,
            monotonic=time.monotonic(),
        )

    def _describe_parent(self, ppid: int) -> Tuple[str, str]:
        """Resolve the parent, preferring live procfs and falling back to cache."""
        if ppid <= 0:
            return "", ""

        exe_path = _read_exe(ppid)
        if exe_path:
            cmdline = _read_cmdline(ppid)
            if cmdline:
                self._cache.put(ppid, exe_path, cmdline)
                return exe_path, cmdline
            cached = self._cache.get(ppid)
            if cached is not None:
                return cached
            return exe_path, ""

        cached = self._cache.get(ppid)
        if cached is not None:
            return cached

        # Parent is gone, or unreadable, and was never seen. Take what we can.
        return "", _read_cmdline(ppid)

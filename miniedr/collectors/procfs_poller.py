"""Portable collector: poll /proc for PIDs we have not seen before.

Needs no privileges, but it samples rather than observes: a process that
starts and exits inside one poll interval is never seen. Prefer the netlink
collector where CAP_NET_ADMIN is available.
"""

from __future__ import annotations

import os
import time
from typing import Iterator, Set

PROC = "/proc"


def _current_pids() -> Set[int]:
    pids: Set[int] = set()
    try:
        entries = os.listdir(PROC)
    except OSError:
        return pids
    for entry in entries:
        if entry.isdigit():
            pids.add(int(entry))
    return pids


class ProcfsPoller:
    name = "procfs"

    def __init__(self, interval: float = 0.075) -> None:
        self.interval = interval
        self._seen: Set[int] = set()
        self._running = False

    def stop(self) -> None:
        self._running = False

    def events(self) -> Iterator[int]:
        """Yield PIDs of newly observed processes, forever."""
        self._running = True
        # Prime with everything already running so startup is not one huge burst.
        self._seen = _current_pids()

        while self._running:
            time.sleep(self.interval)
            current = _current_pids()
            for pid in current - self._seen:
                yield pid
            # Rebind rather than update so exited PIDs drop out and a recycled
            # PID number is reported as new.
            self._seen = current

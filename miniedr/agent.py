"""Wires the four components into a running agent."""

from __future__ import annotations

import os
import sys
from typing import Iterator, Optional

from .alerting import AlertLogger
from .collectors import NetlinkProcCollector, NetlinkUnavailable, ProcfsPoller
from .enrich import Enricher
from .rules import RuleEngine, default_rules


class Agent:
    def __init__(
        self,
        logger: AlertLogger,
        collector_mode: str = "auto",
        poll_interval: float = 0.075,
        print_events: bool = False,
        exclude_self: bool = True,
        allow_foreign_pidns: bool = False,
    ) -> None:
        self.logger = logger
        self.collector_mode = collector_mode
        self.poll_interval = poll_interval
        self.print_events = print_events
        self.exclude_self = exclude_self
        self.allow_foreign_pidns = allow_foreign_pidns

        self.enricher = Enricher()
        self.engine = RuleEngine(default_rules())
        self.collector = None
        self._running = False

        self.events_seen = 0
        self.alerts_raised = 0

    # -- collector selection ------------------------------------------------

    def _build_collector(self):
        mode = self.collector_mode

        if mode in ("auto", "netlink"):
            collector = NetlinkProcCollector(
                allow_foreign_pidns=self.allow_foreign_pidns
            )
            try:
                collector.open()
                return collector
            except NetlinkUnavailable as exc:
                if mode == "netlink":
                    raise
                self.logger.agent(
                    "netlink collector unavailable, falling back to procfs polling",
                    reason=str(exc),
                )

        return ProcfsPoller(interval=self.poll_interval)

    # -- main loop ----------------------------------------------------------

    def stop(self) -> None:
        self._running = False
        if self.collector is not None:
            self.collector.stop()

    def run(self) -> int:
        self.collector = self._build_collector()
        self._running = True
        self_pid = os.getpid()

        self.logger.agent(
            "miniedr started",
            collector=self.collector.name,
            pid=self_pid,
            rules=[rule.rule_id for rule in self.engine.rules],
        )

        try:
            for pid in self.collector.events():
                if not self._running:
                    break
                if self.exclude_self and pid == self_pid:
                    continue

                event = self.enricher.enrich(pid, source=self.collector.name)
                if event is None:
                    # Process exited before we could read /proc; nothing to do.
                    continue

                self.events_seen += 1
                if self.print_events:
                    self.logger.telemetry(event)

                for alert in self.engine.evaluate(event):
                    self.alerts_raised += 1
                    self.logger.alert(alert)
        except KeyboardInterrupt:
            pass
        finally:
            close = getattr(self.collector, "close", None)
            if callable(close):
                close()
            self.logger.agent(
                "miniedr stopped",
                events_seen=self.events_seen,
                alerts_raised=self.alerts_raised,
            )

        return 0

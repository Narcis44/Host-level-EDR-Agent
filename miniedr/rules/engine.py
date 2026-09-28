"""Component 3: the detection rule engine."""

from __future__ import annotations

from typing import Iterable, List, Optional

from ..models import Alert, ProcessEvent


class Rule:
    """Base class. A rule inspects one event and optionally returns an Alert."""

    rule_id = "EDR-000-UNSPECIFIED"
    severity = "LOW"
    name = "unnamed rule"

    def evaluate(self, event: ProcessEvent) -> Optional[Alert]:
        raise NotImplementedError

    def _alert(
        self,
        event: ProcessEvent,
        message: str,
        detail: str = "",
        severity: Optional[str] = None,
    ) -> Alert:
        return Alert(
            rule_id=self.rule_id,
            severity=severity or self.severity,
            alert=message,
            event=event,
            detail=detail,
            timestamp=event.timestamp,
        )


class RuleEngine:
    """Runs every rule against every event, in registration order."""

    def __init__(self, rules: Optional[Iterable[Rule]] = None) -> None:
        self.rules: List[Rule] = list(rules or [])

    def add(self, rule: Rule) -> None:
        self.rules.append(rule)

    def evaluate(self, event: ProcessEvent) -> List[Alert]:
        alerts: List[Alert] = []
        for rule in self.rules:
            try:
                alert = rule.evaluate(event)
            except Exception as exc:  # a broken rule must not kill the agent
                alerts.append(
                    Alert(
                        rule_id="EDR-000-RULE-ERROR",
                        severity="LOW",
                        alert="Rule %s raised %s" % (rule.rule_id, type(exc).__name__),
                        event=event,
                        detail=str(exc),
                    )
                )
                continue
            if alert is not None:
                alerts.append(alert)
        return alerts

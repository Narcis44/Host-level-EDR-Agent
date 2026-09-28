"""Component 4: structured alert logger.

Emits one JSON document per line (JSONL) so the stream can be tailed, piped
into jq, or shipped to a SIEM without further parsing.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from typing import Any, Dict, Optional, TextIO

from .models import Alert, ProcessEvent

DEFAULT_LOG_PATH = "/var/log/miniedr.log"


class AlertLogger:
    def __init__(
        self,
        log_path: Optional[str] = None,
        stdout: bool = True,
        pretty: bool = False,
        include_host: bool = True,
    ) -> None:
        self.pretty = pretty
        self.hostname = socket.gethostname() if include_host else ""
        self._stdout: Optional[TextIO] = sys.stdout if stdout else None
        self._file: Optional[TextIO] = None
        self.log_path = log_path

        if log_path:
            directory = os.path.dirname(os.path.abspath(log_path))
            if directory and not os.path.isdir(directory):
                os.makedirs(directory, exist_ok=True)
            # Line buffered so a tail -f sees alerts as they happen.
            self._file = open(log_path, "a", buffering=1, encoding="utf-8")

    def _write(self, doc: Dict[str, Any]) -> None:
        if self.pretty:
            line = json.dumps(doc, indent=2, sort_keys=False)
        else:
            line = json.dumps(doc, separators=(",", ":"), sort_keys=False)

        for stream in (self._stdout, self._file):
            if stream is None:
                continue
            try:
                stream.write(line + "\n")
                stream.flush()
            except (BrokenPipeError, ValueError):
                pass

    def alert(self, alert: Alert) -> None:
        self._write(alert.to_dict(hostname=self.hostname))

    def telemetry(self, event: ProcessEvent) -> None:
        """Raw (non-alerting) process telemetry, for debugging and tuning."""
        doc: Dict[str, Any] = {"type": "process", **event.to_dict()}
        if self.hostname:
            doc["host"] = self.hostname
        self._write(doc)

    def agent(self, message: str, **fields: Any) -> None:
        """Agent lifecycle messages, kept in the same structured stream."""
        doc: Dict[str, Any] = {"type": "agent", "message": message}
        doc.update(fields)
        if self.hostname:
            doc["host"] = self.hostname
        self._write(doc)

    def close(self) -> None:
        if self._file is not None:
            try:
                self._file.close()
            finally:
                self._file = None

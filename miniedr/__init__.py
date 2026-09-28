"""miniedr - a minimal host-level EDR agent for Linux (v0.1).

Four components:
  1. Process event collector  -> miniedr.collectors
  2. Telemetry enricher       -> miniedr.enrich
  3. Detection rule engine    -> miniedr.rules
  4. Structured alert logger  -> miniedr.alerting
"""

__version__ = "0.1.0"

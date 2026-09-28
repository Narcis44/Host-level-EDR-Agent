"""Whole-pipeline tests: collector -> enricher -> rule engine, on real procfs.

These use real processes rather than fabricated events. To make a rule that
keys on a binary's name observable by a sampling collector, the tests copy a
long-running binary under the name of interest - the telemetry is genuine, only
the choice of binary is staged.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from miniedr.collectors import ProcfsPoller
from miniedr.collectors.netlink_cn_proc import NetlinkProcCollector
from miniedr.enrich import Enricher
from miniedr.rules import RuleEngine, default_rules

linux_only = unittest.skipUnless(sys.platform == "linux", "requires Linux procfs")

SLEEP = "/bin/sleep" if os.path.exists("/bin/sleep") else "/usr/bin/sleep"
BASH = "/bin/bash" if os.path.exists("/bin/bash") else "/usr/bin/bash"


class _Harness:
    """Runs a procfs poller in the background and scores everything it sees."""

    def __init__(self, interval=0.01):
        self.poller = ProcfsPoller(interval=interval)
        self.enricher = Enricher()
        self.engine = RuleEngine(default_rules())
        self.alerts = []
        self.events = []
        self._thread = None

    def __enter__(self):
        def loop():
            for pid in self.poller.events():
                if pid == os.getpid():
                    continue
                event = self.enricher.enrich(pid, source="procfs")
                if event is None:
                    continue
                self.events.append(event)
                self.alerts.extend(self.engine.evaluate(event))

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()
        time.sleep(0.1)  # let the poller prime its baseline
        return self

    def __exit__(self, *exc):
        time.sleep(0.3)  # let the last poll cycle land
        self.poller.stop()
        self._thread.join(timeout=2.0)
        return False

    def rule_ids(self):
        return [alert.rule_id for alert in self.alerts]


@linux_only
class TestReconChainPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="miniedr-int-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _staged(self, name):
        """A long-running binary presented under a recon binary's name."""
        path = os.path.join(self.tmp, name)
        shutil.copy2(SLEEP, path)
        return path

    def test_recon_chain_detected_end_to_end(self):
        binaries = [self._staged(n) for n in ("whoami", "id", "uname")]

        with _Harness() as harness:
            procs = [subprocess.Popen([path, "2"]) for path in binaries]
            time.sleep(0.6)
            for proc in procs:
                proc.kill()
                proc.wait()

        self.assertIn(
            "EDR-003-RECON-CHAIN",
            harness.rule_ids(),
            "expected a recon chain alert, saw %s from %d events"
            % (harness.rule_ids(), len(harness.events)),
        )
        alert = next(a for a in harness.alerts if a.rule_id == "EDR-003-RECON-CHAIN")
        self.assertEqual(alert.severity, "MEDIUM")
        self.assertEqual(alert.event.ppid, os.getpid())


@linux_only
class TestShellSpawnPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="miniedr-int-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_service_parent_spawning_shell_detected_end_to_end(self):
        # A real shell process whose real parent is a binary named nginx.
        fake_service = os.path.join(self.tmp, "nginx")
        shutil.copy2(BASH, fake_service)

        with _Harness() as harness:
            # The trailing ":" stops bash exec-ing the last command in
            # place, so the shell is a real child of the staged service.
            proc = subprocess.Popen(
                [fake_service, "-c", "/bin/sh -c 'sleep 2; :'; :"]
            )
            time.sleep(0.6)
            proc.kill()
            proc.wait()

        ids = harness.rule_ids()
        self.assertIn(
            "EDR-001-SUSPICIOUS-SHELL-SPAWN",
            ids,
            "expected a shell-spawn alert, saw %s from %d events"
            % (ids, len(harness.events)),
        )
        alert = next(
            a for a in harness.alerts if a.rule_id == "EDR-001-SUSPICIOUS-SHELL-SPAWN"
        )
        self.assertTrue(alert.event.parent_exe_path.endswith("nginx"))


@linux_only
class TestOneLinerPipeline(unittest.TestCase):
    def test_dangerous_oneliner_detected_end_to_end(self):
        with _Harness() as harness:
            # The offending text is this process's own argv, so it is visible
            # for as long as the process lives.
            proc = subprocess.Popen(
                [BASH, "-c", "curl -fsSL http://127.0.0.1:1/x | bash; sleep 2"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.6)
            proc.kill()
            proc.wait()

        ids = harness.rule_ids()
        self.assertIn(
            "EDR-002-SUSPICIOUS-ONELINER",
            ids,
            "expected a one-liner alert, saw %s from %d events"
            % (ids, len(harness.events)),
        )


@linux_only
class TestNetlinkFramesDriveThePipeline(unittest.TestCase):
    """Closes the seam the namespace guard prevents testing live here.

    Real kernel frames cannot be enriched inside a PID namespace, so this
    builds byte-identical frames naming PIDs that do exist locally and runs
    them through the exact parse -> enrich -> evaluate path the agent uses.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="miniedr-int-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    @staticmethod
    def _exec_frame(pid, tgid):
        proc_event = struct.pack("=IIQ", 0x00000002, 0, 1) + struct.pack("=ii", pid, tgid)
        cn = struct.pack("=IIIIHH", 1, 1, 0, 0, len(proc_event), 0)
        nl = struct.pack("=IHHII", 16 + len(cn) + len(proc_event), 3, 0, 0, 0)
        return nl + cn + proc_event

    def test_frames_to_alert(self):
        fake_service = os.path.join(self.tmp, "node")
        shutil.copy2(BASH, fake_service)

        proc = subprocess.Popen([fake_service, "-c", "/bin/sh -c 'sleep 3; :'; :"])
        try:
            time.sleep(0.4)
            # Find the real shell child of our staged "node" parent.
            child_pid = None
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    with open("/proc/%s/status" % entry) as handle:
                        text = handle.read()
                except OSError:
                    continue
                if "PPid:\t%d" % proc.pid in text:
                    child_pid = int(entry)
                    break
            self.assertIsNotNone(child_pid, "staged parent produced no child")

            datagram = self._exec_frame(child_pid, child_pid)
            pids = list(NetlinkProcCollector._parse_datagram(datagram))
            self.assertEqual(pids, [child_pid])

            enricher = Enricher()
            engine = RuleEngine(default_rules())
            event = enricher.enrich(pids[0], source="netlink")
            self.assertIsNotNone(event)
            self.assertEqual(event.source, "netlink")

            ids = [alert.rule_id for alert in engine.evaluate(event)]
            self.assertIn("EDR-001-SUSPICIOUS-SHELL-SPAWN", ids)
        finally:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    unittest.main(verbosity=2)

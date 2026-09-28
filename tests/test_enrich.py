"""Enricher tests. Linux-only: they read real procfs."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from miniedr.enrich import Enricher, _read_cmdline

linux_only = unittest.skipUnless(sys.platform == "linux", "requires Linux procfs")


def find_kernel_thread():
    """A PID with no exe link and no argv at all, or None if none is visible."""
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            if os.path.exists("/proc/%d/exe" % pid) and os.readlink("/proc/%d/exe" % pid):
                continue
        except OSError:
            # Unreadable link: could be a kernel thread or just not ours.
            pass
        try:
            with open("/proc/%d/cmdline" % pid, "rb") as handle:
                if handle.read().strip(b"\x00") == b"":
                    return pid
        except OSError:
            continue
    return None


@linux_only
class TestEnricher(unittest.TestCase):
    def setUp(self):
        self.enricher = Enricher()

    def test_enriches_own_process(self):
        event = self.enricher.enrich(os.getpid())
        self.assertIsNotNone(event)
        self.assertEqual(event.pid, os.getpid())
        self.assertEqual(event.ppid, os.getppid())
        self.assertEqual(event.uid, os.getuid())
        self.assertIn("python", event.exe_path)
        self.assertIn("python", event.cmdline)
        self.assertTrue(event.username)
        self.assertTrue(event.timestamp.endswith("Z"))

    def test_resolves_parent_exe(self):
        event = self.enricher.enrich(os.getpid())
        self.assertTrue(event.parent_exe_path, "parent exe should resolve")
        self.assertTrue(os.path.isabs(event.parent_exe_path))

    def test_enriches_a_real_child(self):
        proc = subprocess.Popen(["/bin/sleep", "5"])
        try:
            event = self.enricher.enrich(proc.pid)
            self.assertIsNotNone(event)
            self.assertEqual(event.pid, proc.pid)
            self.assertEqual(event.ppid, os.getpid())
            self.assertEqual(event.exe_path, os.path.realpath("/bin/sleep"))
            self.assertEqual(event.cmdline, "/bin/sleep 5")
            self.assertIn("python", event.parent_exe_path)
        finally:
            proc.kill()
            proc.wait()

    def test_cmdline_survives_the_post_exec_race(self):
        """Regression: argv is published a moment after the exe link resolves.

        Reading once, with no retry, loses argv for a sizeable fraction of
        freshly exec'd processes - which would blind every cmdline-based rule.
        """
        naive_misses = 0
        children = []
        try:
            for _ in range(25):
                proc = subprocess.Popen(["/bin/sleep", "5"])
                children.append(proc)
                if not _read_cmdline(proc.pid, retries=0):
                    naive_misses += 1
                event = self.enricher.enrich(proc.pid)
                self.assertIsNotNone(event)
                self.assertEqual(
                    event.cmdline,
                    "/bin/sleep 5",
                    "enricher must resolve argv despite the post-exec window",
                )
        finally:
            for proc in children:
                proc.kill()
                proc.wait()
        # Not asserted (the race is timing dependent and may not fire on a
        # fast or idle machine), but recorded so the reason for the retry
        # logic is visible when running verbosely.
        sys.stderr.write(
            "\n    [post-exec race hit %d/25 naive reads]\n" % naive_misses
        )

    def test_missing_pid_returns_none(self):
        # PID 0 never exists as a /proc entry.
        self.assertIsNone(self.enricher.enrich(0))

    def test_dead_parent_falls_back_to_cache(self):
        # Prime the cache with a live process, then look it up as a parent
        # after it is gone.
        proc = subprocess.Popen(["/bin/sleep", "5"])
        self.enricher.enrich(proc.pid)
        proc.kill()
        proc.wait()
        exe, cmdline = self.enricher._describe_parent(proc.pid)
        self.assertEqual(exe, os.path.realpath("/bin/sleep"))
        self.assertEqual(cmdline, "/bin/sleep 5")

    def test_kernel_thread_is_tolerated(self):
        pid = find_kernel_thread()
        if pid is None:
            self.skipTest("no kernel thread visible on this host")
        event = self.enricher.enrich(pid)
        if event is not None:
            self.assertEqual(event.exe_path, "")
            self.assertTrue(event.cmdline.startswith("["))

    def test_unreadable_process_does_not_raise(self):
        # PID 1 is not ours to inspect unless we are root; either way this
        # must produce an event rather than an exception.
        event = self.enricher.enrich(1)
        self.assertIsNotNone(event)
        self.assertEqual(event.pid, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

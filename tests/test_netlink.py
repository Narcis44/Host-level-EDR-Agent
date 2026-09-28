"""Netlink CN_PROC wire-format tests.

Builds synthetic kernel datagrams so the struct offsets are verified without
needing CAP_NET_ADMIN or a live kernel feed.
"""

from __future__ import annotations

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from miniedr.collectors.netlink_cn_proc import (
    CN_IDX_PROC,
    CN_VAL_PROC,
    NLMSG_DONE,
    NLMSG_ERROR,
    PROC_EVENT_EXEC,
    PROC_EVENT_EXIT,
    PROC_EVENT_FORK,
    NetlinkProcCollector,
    _build_subscribe,
    _nlmsg_align,
)


def build_proc_event(what: int, payload: bytes) -> bytes:
    """One nlmsghdr + cn_msg + proc_event, exactly as the kernel emits it."""
    proc_event = struct.pack("=IIQ", what, 0, 1234567890) + payload
    cn = struct.pack(
        "=IIIIHH", CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(proc_event), 0
    )
    total = 16 + len(cn) + len(proc_event)
    nl = struct.pack("=IHHII", total, NLMSG_DONE, 0, 0, 0)
    return nl + cn + proc_event


def exec_event(pid: int, tgid: int) -> bytes:
    return build_proc_event(PROC_EVENT_EXEC, struct.pack("=ii", pid, tgid))


def fork_event(ppid: int, ptgid: int, cpid: int, ctgid: int) -> bytes:
    return build_proc_event(
        PROC_EVENT_FORK, struct.pack("=iiii", ppid, ptgid, cpid, ctgid)
    )


class TestSubscribeMessage(unittest.TestCase):
    def test_listen_message_layout(self):
        msg = _build_subscribe(1)
        self.assertEqual(len(msg), 40)

        nl_len, nl_type, _flags, _seq, nl_pid = struct.unpack_from("=IHHII", msg, 0)
        self.assertEqual(nl_len, 40)
        self.assertEqual(nl_type, NLMSG_DONE)
        self.assertEqual(nl_pid, os.getpid())

        idx, val, _s, _a, data_len, _f = struct.unpack_from("=IIIIHH", msg, 16)
        self.assertEqual(idx, CN_IDX_PROC)
        self.assertEqual(val, CN_VAL_PROC)
        self.assertEqual(data_len, 4)

        (op,) = struct.unpack_from("=I", msg, 36)
        self.assertEqual(op, 1)


class TestAlignment(unittest.TestCase):
    def test_nlmsg_align_rounds_to_four(self):
        self.assertEqual(_nlmsg_align(0), 0)
        self.assertEqual(_nlmsg_align(1), 4)
        self.assertEqual(_nlmsg_align(4), 4)
        self.assertEqual(_nlmsg_align(60), 60)
        self.assertEqual(_nlmsg_align(61), 64)


class TestDatagramParsing(unittest.TestCase):
    def parse(self, buf):
        return list(NetlinkProcCollector._parse_datagram(buf))

    def test_single_exec_yields_tgid(self):
        self.assertEqual(self.parse(exec_event(4242, 4200)), [4200])

    def test_fork_and_exit_are_ignored(self):
        self.assertEqual(self.parse(fork_event(1, 1, 2, 2)), [])
        self.assertEqual(
            self.parse(build_proc_event(PROC_EVENT_EXIT, struct.pack("=iiii", 1, 1, 0, 0))),
            [],
        )

    def test_multiple_messages_in_one_datagram(self):
        buf = exec_event(10, 10) + fork_event(1, 1, 2, 2) + exec_event(20, 20)
        self.assertEqual(self.parse(buf), [10, 20])

    def test_truncated_datagram_does_not_raise(self):
        self.assertEqual(self.parse(exec_event(10, 10)[:40]), [])
        self.assertEqual(self.parse(b""), [])
        self.assertEqual(self.parse(b"\x00" * 8), [])

    def test_error_message_stops_parsing(self):
        good = exec_event(10, 10)
        err = struct.pack("=IHHII", 20, NLMSG_ERROR, 0, 0, 0) + b"\x00" * 4
        self.assertEqual(self.parse(err + good), [])
        self.assertEqual(self.parse(good + err), [10])

    def test_bogus_length_does_not_loop_forever(self):
        bogus = struct.pack("=IHHII", 2, NLMSG_DONE, 0, 0, 0) + b"\x00" * 40
        self.assertEqual(self.parse(bogus), [])



class TestPidNamespaceGuard(unittest.TestCase):
    """The connector reports initial-namespace PIDs, so a namespaced agent
    would enrich every event to nothing. open() must refuse instead."""

    def test_root_namespace_is_accepted(self):
        from miniedr.collectors import netlink_cn_proc as mod

        original = mod.current_pid_namespace
        mod.current_pid_namespace = lambda: mod.ROOT_PID_NAMESPACE
        try:
            self.assertTrue(mod.in_root_pid_namespace())
        finally:
            mod.current_pid_namespace = original

    def test_foreign_namespace_is_rejected(self):
        from miniedr.collectors import netlink_cn_proc as mod

        original = mod.current_pid_namespace
        mod.current_pid_namespace = lambda: "pid:[4026532222]"
        try:
            self.assertFalse(mod.in_root_pid_namespace())
            collector = mod.NetlinkProcCollector()
            with self.assertRaises(mod.NetlinkUnavailable) as ctx:
                collector.open()
            self.assertIn("4026532222", str(ctx.exception))
            self.assertIsNone(collector._sock)
        finally:
            mod.current_pid_namespace = original

    def test_unknown_namespace_is_permissive(self):
        from miniedr.collectors import netlink_cn_proc as mod

        original = mod.current_pid_namespace
        mod.current_pid_namespace = lambda: ""
        try:
            self.assertTrue(mod.in_root_pid_namespace())
        finally:
            mod.current_pid_namespace = original

    def test_override_bypasses_the_guard(self):
        """--allow-foreign-pidns must get past the check (and then fail, if at
        all, on the socket itself rather than on the namespace)."""
        from miniedr.collectors import netlink_cn_proc as mod

        original = mod.current_pid_namespace
        mod.current_pid_namespace = lambda: "pid:[4026532222]"
        try:
            collector = mod.NetlinkProcCollector(allow_foreign_pidns=True)
            try:
                collector.open()
            except mod.NetlinkUnavailable as exc:
                self.assertNotIn("PID namespace", str(exc))
            else:
                collector.close()
        finally:
            mod.current_pid_namespace = original

if __name__ == "__main__":
    unittest.main(verbosity=2)

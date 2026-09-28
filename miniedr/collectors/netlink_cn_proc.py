"""Systems-native collector: kernel PROC_EVENT_EXEC broadcasts.

Opens an AF_NETLINK/NETLINK_CONNECTOR socket, subscribes to the CN_IDX_PROC
multicast group, and reads the process-event stream the kernel emits. Unlike
polling this cannot miss a short-lived process.

Binding to the CN_IDX_PROC group requires CAP_NET_ADMIN (in practice: root).

The connector is NOT PID-namespace aware: it always reports task->pid from the
initial namespace. Inside a container or WSL2 those numbers refer to processes
that do not exist in the local /proc, so every event would enrich to nothing.
open() refuses to run there rather than emitting silent garbage - see
in_root_pid_namespace().

Wire format of one message, all little-endian on x86:

    offset  size  field
    0       16    struct nlmsghdr  {len u32, type u16, flags u16, seq u32, pid u32}
    16      20    struct cn_msg    {idx u32, val u32, seq u32, ack u32, len u16, flags u16}
    36      16    struct proc_event header {what u32, cpu u32, timestamp_ns u64}
    52      ..    event_data union, per `what`
"""

from __future__ import annotations

import os
import socket
import struct
from typing import Iterator, Optional

NETLINK_CONNECTOR = 11

CN_IDX_PROC = 1
CN_VAL_PROC = 1

PROC_CN_MCAST_LISTEN = 1
PROC_CN_MCAST_IGNORE = 2

NLMSG_ERROR = 2
NLMSG_DONE = 3

PROC_EVENT_NONE = 0x00000000
PROC_EVENT_FORK = 0x00000001
PROC_EVENT_EXEC = 0x00000002
PROC_EVENT_UID = 0x00000004
PROC_EVENT_EXIT = 0x80000000

_NLMSGHDR = struct.Struct("=IHHII")      # 16 bytes
_CNMSG = struct.Struct("=IIIIHH")        # 20 bytes
_PROC_EVENT_HDR = struct.Struct("=IIQ")  # 16 bytes
_EXEC_DATA = struct.Struct("=ii")        # process_pid, process_tgid

_HDR_LEN = _NLMSGHDR.size + _CNMSG.size            # 36
_EVENT_OFF = _HDR_LEN + _PROC_EVENT_HDR.size       # 52

RECV_BUFFER = 8192

# The initial PID namespace is always this inode (kernel PROC_PID_INIT_INO,
# 0xEFFFFFFC). Anything else means we are namespaced and the connector's PIDs
# refer to a namespace we cannot see into.
ROOT_PID_NAMESPACE = "pid:[4026531836]"


class NetlinkUnavailable(RuntimeError):
    """Raised when the connector socket cannot be opened or subscribed."""


def current_pid_namespace() -> str:
    """This process's PID namespace, e.g. 'pid:[4026531836]'; '' if unknown."""
    try:
        return os.readlink("/proc/self/ns/pid")
    except OSError:
        return ""


def in_root_pid_namespace() -> bool:
    """True when connector PIDs will resolve against the local /proc.

    An unreadable namespace link is treated as the root namespace: that is the
    permissive answer, and it keeps the collector working on kernels built
    without CONFIG_PID_NS.
    """
    namespace = current_pid_namespace()
    return namespace in ("", ROOT_PID_NAMESPACE)


def _nlmsg_align(length: int) -> int:
    return (length + 3) & ~3


def _build_subscribe(op: int) -> bytes:
    """A single netlink datagram carrying a proc_cn_mcast_op."""
    payload = struct.pack("=I", op)
    cn = _CNMSG.pack(CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(payload), 0)
    total = _NLMSGHDR.size + len(cn) + len(payload)
    nl = _NLMSGHDR.pack(total, NLMSG_DONE, 0, 0, os.getpid())
    return nl + cn + payload


class NetlinkProcCollector:
    name = "netlink"

    def __init__(
        self, timeout: float = 1.0, allow_foreign_pidns: bool = False
    ) -> None:
        self.timeout = timeout
        self.allow_foreign_pidns = allow_foreign_pidns
        self._sock: Optional[socket.socket] = None
        self._running = False

    def open(self) -> None:
        if not self.allow_foreign_pidns and not in_root_pid_namespace():
            raise NetlinkUnavailable(
                "this process runs in PID namespace %s, but the kernel "
                "connector reports PIDs from the initial namespace - they "
                "cannot be resolved against this /proc. Use --collector "
                "procfs, run in the host PID namespace (docker run "
                "--pid=host), or override with --allow-foreign-pidns."
                % (current_pid_namespace() or "unknown")
            )

        try:
            sock = socket.socket(
                socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR
            )
        except (AttributeError, OSError) as exc:
            raise NetlinkUnavailable(
                "cannot create NETLINK_CONNECTOR socket: %s" % exc
            ) from exc

        try:
            # groups=CN_IDX_PROC is the part that needs CAP_NET_ADMIN.
            sock.bind((os.getpid(), CN_IDX_PROC))
        except PermissionError as exc:
            sock.close()
            raise NetlinkUnavailable(
                "binding the CN_IDX_PROC multicast group needs CAP_NET_ADMIN - "
                "run as root, or use --collector procfs"
            ) from exc
        except OSError as exc:
            sock.close()
            raise NetlinkUnavailable("netlink bind failed: %s" % exc) from exc

        try:
            sock.send(_build_subscribe(PROC_CN_MCAST_LISTEN))
        except OSError as exc:
            sock.close()
            raise NetlinkUnavailable("PROC_CN_MCAST_LISTEN failed: %s" % exc) from exc

        sock.settimeout(self.timeout)
        self._sock = sock

    def close(self) -> None:
        self._running = False
        if self._sock is None:
            return
        try:
            self._sock.send(_build_subscribe(PROC_CN_MCAST_IGNORE))
        except OSError:
            pass
        try:
            self._sock.close()
        finally:
            self._sock = None

    def stop(self) -> None:
        self._running = False

    def events(self) -> Iterator[int]:
        """Yield the TGID of every process that calls execve()."""
        if self._sock is None:
            self.open()
        assert self._sock is not None

        self._running = True
        while self._running:
            try:
                buf = self._sock.recv(RECV_BUFFER)
            except socket.timeout:
                # Expected: gives the caller a chance to observe shutdown.
                continue
            except InterruptedError:
                continue
            except OSError:
                if not self._running:
                    break
                raise

            for tgid in self._parse_datagram(buf):
                yield tgid

    @staticmethod
    def _parse_datagram(buf: bytes) -> Iterator[int]:
        """A datagram may pack several netlink messages back to back."""
        offset = 0
        total = len(buf)

        while offset + _NLMSGHDR.size <= total:
            nl_len, nl_type, _flags, _seq, _pid = _NLMSGHDR.unpack_from(buf, offset)
            if nl_len < _NLMSGHDR.size or offset + nl_len > total:
                break
            if nl_type == NLMSG_ERROR:
                break

            if offset + _EVENT_OFF <= total:
                what, _cpu, _ts = _PROC_EVENT_HDR.unpack_from(buf, offset + _HDR_LEN)
                if what == PROC_EVENT_EXEC:
                    data_at = offset + _EVENT_OFF
                    if data_at + _EXEC_DATA.size <= total:
                        _pid_, tgid = _EXEC_DATA.unpack_from(buf, data_at)
                        # The thread group leader is the process we report on.
                        yield tgid

            offset += _nlmsg_align(nl_len)

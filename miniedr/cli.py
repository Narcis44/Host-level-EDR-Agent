"""Command-line entry point."""

from __future__ import annotations

import argparse
import os
import signal
import sys
from typing import List, Optional

from . import __version__
from .agent import Agent
from .alerting import DEFAULT_LOG_PATH, AlertLogger
from .collectors import NetlinkUnavailable


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="miniedr",
        description="Minimal host-level EDR agent: real-time process execution "
        "monitoring with heuristic rule alerting (v%s)." % __version__,
    )
    parser.add_argument(
        "--collector",
        choices=("auto", "netlink", "procfs"),
        default="auto",
        help="event source. 'netlink' uses kernel CN_PROC broadcasts and needs "
        "CAP_NET_ADMIN; 'procfs' polls /proc and needs no privileges; "
        "'auto' (default) tries netlink and falls back to procfs.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=75.0,
        metavar="MS",
        help="procfs poll interval in milliseconds (default: 75)",
    )
    parser.add_argument(
        "--log-file",
        nargs="?",
        const=DEFAULT_LOG_PATH,
        default=None,
        metavar="PATH",
        help="also append JSONL to PATH (default when the flag is given "
        "without a value: %s)" % DEFAULT_LOG_PATH,
    )
    parser.add_argument(
        "--no-stdout",
        action="store_true",
        help="suppress stdout output (use with --log-file)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="pretty-print JSON instead of one compact object per line",
    )
    parser.add_argument(
        "--print-events",
        action="store_true",
        help="also emit every enriched process event, not just alerts",
    )
    parser.add_argument(
        "--allow-foreign-pidns",
        action="store_true",
        help="use the netlink collector even when this process is not in the "
        "initial PID namespace (its PIDs will most likely not resolve)",
    )
    parser.add_argument(
        "--include-self",
        action="store_true",
        help="do not exclude the agent's own PID from monitoring",
    )
    parser.add_argument("--version", action="version", version="miniedr " + __version__)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if sys.platform != "linux":
        sys.stderr.write(
            "miniedr targets Linux; /proc and NETLINK_CONNECTOR are unavailable "
            "on %s\n" % sys.platform
        )
        return 2

    if args.no_stdout and not args.log_file:
        sys.stderr.write("--no-stdout requires --log-file\n")
        return 2

    try:
        logger = AlertLogger(
            log_path=args.log_file,
            stdout=not args.no_stdout,
            pretty=args.pretty,
        )
    except OSError as exc:
        sys.stderr.write("cannot open log file: %s\n" % exc)
        return 1

    agent = Agent(
        logger=logger,
        collector_mode=args.collector,
        poll_interval=args.poll_interval / 1000.0,
        print_events=args.print_events,
        exclude_self=not args.include_self,
        allow_foreign_pidns=args.allow_foreign_pidns,
    )

    def handle_signal(signum, _frame):
        agent.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, handle_signal)

    try:
        return agent.run()
    except NetlinkUnavailable as exc:
        sys.stderr.write("netlink collector unavailable: %s\n" % exc)
        return 1
    finally:
        logger.close()


if __name__ == "__main__":
    raise SystemExit(main())

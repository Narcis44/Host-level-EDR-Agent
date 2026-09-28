# miniedr - Host-Level EDR Agent (v0.1)

Real-time process-execution monitoring with heuristic rule alerting for Linux.

Python 3.9+, **standard library only** - no third-party packages, no build step.

---

## Scope of v0.1

One capability, done properly: watch every process that starts, enrich it with
context, score it against a small set of threat heuristics, and emit structured
JSON alerts.

```
┌──────────────────┐   pid    ┌──────────────────┐  event   ┌──────────────┐  alert  ┌──────────────┐
│ 1. Collector     │ ───────► │ 2. Enricher      │ ───────► │ 3. Rules     │ ──────► │ 4. Logger    │
│ netlink / procfs │          │ /proc/<pid>/...  │          │ A · B · C    │         │ JSONL        │
└──────────────────┘          └──────────────────┘          └──────────────┘         └──────────────┘
```

| # | Component | Module |
|---|-----------|--------|
| 1 | Process event collector | [`miniedr/collectors/`](miniedr/collectors/) |
| 2 | Telemetry enricher | [`miniedr/enrich.py`](miniedr/enrich.py) |
| 3 | Detection rule engine | [`miniedr/rules/`](miniedr/rules/) |
| 4 | Structured alert logger | [`miniedr/alerting.py`](miniedr/alerting.py) |

Wiring lives in [`miniedr/agent.py`](miniedr/agent.py); the CLI is
[`miniedr/cli.py`](miniedr/cli.py).

---

## Quick start

```bash
python3 -m miniedr
```

Netlink needs `CAP_NET_ADMIN`, so for the kernel-driven collector:

```bash
sudo python3 -m miniedr --collector netlink --log-file /var/log/miniedr.log
```

Without privileges it falls back to polling automatically:

```bash
python3 -m miniedr --collector procfs --poll-interval 50
```

### Options

| Flag | Default | Meaning |
|------|---------|---------|
| `--collector {auto,netlink,procfs}` | `auto` | Event source. `auto` tries netlink, falls back to procfs. |
| `--poll-interval MS` | `75` | Poll interval for the procfs collector. |
| `--log-file [PATH]` | off | Append JSONL to PATH (bare flag ⇒ `/var/log/miniedr.log`). |
| `--no-stdout` | off | Suppress stdout (requires `--log-file`). |
| `--pretty` | off | Indent JSON instead of one object per line. |
| `--print-events` | off | Emit every enriched process event, not just alerts. |
| `--include-self` | off | Do not exclude the agent's own PID. |
| `--allow-foreign-pidns` | off | Force netlink outside the initial PID namespace (see below). |

---

## 1. Process event collector

Two interchangeable implementations behind the same `events()` iterator.

### Netlink connector (preferred)

`AF_NETLINK` / `NETLINK_CONNECTOR` socket bound to the `CN_IDX_PROC` multicast
group, subscribed with `PROC_CN_MCAST_LISTEN`. The kernel pushes every
`PROC_EVENT_EXEC`; nothing is missed, however short-lived the process.

Wire format parsed in [`netlink_cn_proc.py`](miniedr/collectors/netlink_cn_proc.py):

```
offset  size  field
0       16    struct nlmsghdr   {len u32, type u16, flags u16, seq u32, pid u32}
16      20    struct cn_msg     {idx u32, val u32, seq u32, ack u32, len u16, flags u16}
36      16    struct proc_event {what u32, cpu u32, timestamp_ns u64}
52      ..    event_data union, per `what`
```

A single datagram may pack several messages, so parsing walks them with
`NLMSG_ALIGN`.

### Procfs poller (fallback)

Scans `/proc` for numeric entries every N ms and diffs against the previous
set. No privileges required.

### Choosing between them

| | netlink | procfs poll |
|---|---|---|
| Privileges | `CAP_NET_ADMIN` | none |
| Misses short-lived processes | no | **yes** |
| Sees `execve()` in place (same PID) | **yes** | no |
| Works in a PID namespace | **no** | yes |
| CPU at idle | ~0 | proportional to `1/interval` |

---

## 2. Telemetry enricher

Per event: `timestamp` (UTC ISO-8601, ms precision), `pid`, `ppid`, `exe_path`,
`cmdline`, `uid`, `username`, `parent_exe_path`, `parent_cmdline`.

Two details that matter more than they look:

- **The post-exec argv window.** A process is visible with a resolvable
  `/proc/<pid>/exe` a moment *before* the kernel publishes its `cmdline`, and
  `PROC_EVENT_EXEC` lands inside exactly that window. Reading once loses argv
  for a sizeable fraction of freshly exec'd processes — which would blind every
  cmdline-based rule. The enricher retries briefly (3.5 ms worst case, and only
  when argv reads back empty), skipping the retry for zombies that will never
  publish one. Regression test:
  `test_enrich.py::test_cmdline_survives_the_post_exec_race`.
- **Dead parents.** A bounded LRU of previously seen processes means a parent
  that exited before we looked can still be described. Only fully resolved
  processes are cached, so a placeholder never replays as parent context.

Every read degrades to a placeholder rather than raising: enrichment races the
scheduler by definition.

---

## 3. Detection rules

| Rule ID | Severity | Triggers on |
|---------|----------|-------------|
| `EDR-001-SUSPICIOUS-SHELL-SPAWN` | HIGH / **CRITICAL** if interactive | A service or interpreter (`nginx`, `apache2`, `node`, `python`, `php-fpm`, `java`, …) spawning a shell (`sh`, `bash`, `zsh`, `dash`, …) |
| `EDR-002-SUSPICIOUS-ONELINER` | HIGH / **CRITICAL** for reverse shells | `curl\|wget → shell`, `base64 -d → shell`, inline base64 blobs, `/dev/tcp` redirection, `nc -e`, `python -c` with `exec`/`b64decode` |
| `EDR-003-RECON-CHAIN` | MEDIUM | ≥3 *distinct* enumeration binaries (`whoami`, `id`, `uname`, `netstat`, `ss`, …) from one parent within 10 s |

Deliberate false-positive controls:

- `sshd`, `su`, `sudo` and terminal emulators are **not** service parents —
  spawning a shell is their job.
- Interpreter versions normalise, so `python3.12` and `php8.1` match as
  `python` and `php`.
- Bare `ps` and `ip` are ignored; they only count as recon with enumeration
  flags (`ps -ef`, `ip addr`).
- Rule C requires *distinct* binaries, and has a 30 s per-parent cooldown so
  one busy shell cannot flood the stream.

A rule that raises is caught and reported as `EDR-000-RULE-ERROR` rather than
taking the agent down.

Add a rule by subclassing `Rule` in
[`miniedr/rules/engine.py`](miniedr/rules/engine.py) and registering it in
`default_rules()`.

---

## 4. Structured alert logger

One JSON document per line (JSONL) to stdout and/or a file, flushed
immediately so `tail -f` and SIEM shippers see alerts as they happen.

```json
{
  "timestamp": "2026-08-26T14:04:38.278Z",
  "rule_id": "EDR-001-SUSPICIOUS-SHELL-SPAWN",
  "severity": "HIGH",
  "alert": "Interactive shell spawned by unusual parent",
  "process": {
    "pid": 454,
    "ppid": 453,
    "exe": "/usr/bin/dash",
    "cmdline": "/bin/sh -c sleep 0.2",
    "uid": 1000,
    "username": "narcis"
  },
  "parent": {
    "pid": 453,
    "exe": "/usr/bin/python3.12",
    "cmdline": "python3 /tmp/miniedr-sim.vZ9Zql/server2.py"
  },
  "detail": "parent=python3.12 child=dash",
  "host": "Narcis"
}
```

`detail` and `host` are additive; the `process` / `parent` shape is the v0.1
contract and is asserted in `test_rules.py::TestAlertSchema`.

---

## Known limitations

These are real and worth knowing before you deploy.

1. **Netlink is not PID-namespace aware.** `cn_proc` always reports
   `task->pid` from the *initial* namespace. Inside a container or WSL2 those
   numbers name processes that do not exist in the local `/proc`, so every
   event would enrich to nothing and the agent would sit there silently
   detecting zero threats. `open()` therefore **refuses to start** there with
   an actionable message, and `--collector auto` falls back to polling.
   Override with `--allow-foreign-pidns` if you know better. To get kernel
   events in a container, share the host PID namespace
   (`docker run --pid=host`).
2. **The procfs poller misses short-lived processes.** Anything that starts
   and exits inside one interval is never sampled. Recon binaries like
   `whoami` are exactly this shape — expect Rule C to under-fire on the
   poller. Use netlink where you can.
3. **The poller cannot see `execve()` in place.** When a process replaces
   itself (a web server exec'ing a shell without forking), the PID is
   unchanged, so a PID-diffing collector sees nothing. Netlink catches it.
4. **Rules are per-event and mostly stateless.** Only Rule C correlates across
   events, and only by parent PID. No process-tree ancestry, no cross-host
   correlation.
5. **Detection only.** No prevention, no quarantine, no tamper resistance —
   and an attacker with root can stop the agent.
6. **Non-root runs see less.** `/proc/<pid>/exe` is unreadable for other
   users' processes, which weakens rules that key on the parent binary.

---

## Testing

```bash
python3 -m unittest discover -s tests -v
```

53 tests: rule logic, netlink wire-format parsing against synthetic kernel
frames, the PID-namespace guard, enrichment against real procfs, and
whole-pipeline integration tests that drive real processes through
collector → enricher → engine.

Verified on Linux 6.18 (WSL2 Ubuntu), Python 3.12 — all four components
end-to-end on the procfs collector, and the netlink collector confirmed
receiving and correctly decoding live kernel `EXEC`/`FORK`/`EXIT` frames. The
netlink-to-enrichment seam could not be exercised live there because WSL2 runs
the distro in a PID namespace (limitation 1); it is covered instead by
`test_integration.py::TestNetlinkFramesDriveThePipeline`, which feeds
byte-identical frames naming local PIDs through the real code path.

### Attack simulation

```bash
./simulate_attack.sh          # all three scenarios
./simulate_attack.sh b        # just Rule B
```

Benign by construction: payloads are local files, and the reverse-shell line
points at a closed local port. Run it against a live agent on a machine you
own to see alerts appear.

---

## Roadmap beyond v0.1

- eBPF collector (`sched_process_exec`) — namespace-aware, richer context
- Process ancestry tracking, so rules can reason about full trees
- File and network telemetry alongside process events
- Rules as data (YAML/Sigma) rather than Python classes
- Alert deduplication and rate limiting
- Shipping to syslog / a SIEM endpoint

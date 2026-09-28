#!/usr/bin/env bash
# Benign simulation of the three behaviours miniedr v0.1 detects.
#
# Nothing here touches the network or writes outside a temp directory: the
# "payloads" are local files and the reverse-shell line points at a port that
# is never opened. The point is to produce the process tree an attacker would,
# so the rules can be exercised on a machine you own.
#
#   ./simulate_attack.sh            all three scenarios
#   ./simulate_attack.sh a|b|c      just one

set -u

SCENARIO="${1:-all}"
PAUSE="${MINIEDR_SIM_PAUSE:-0.4}"
WORKDIR="$(mktemp -d /tmp/miniedr-sim.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

say() { printf '\n=== %s ===\n' "$1"; }

# --- Rule A: a "web service" drops to an interactive shell -----------------
# A python HTTP server is a stand-in for any compromised daemon. It execs a
# shell, which is what a web shell looks like from the process tree.
scenario_a() {
  say "Rule A - service spawning an interactive shell"
  cat >"$WORKDIR/server.py" <<'PYEOF'
import os
# Stand-in for a compromised request handler dropping to a shell.
os.execv("/bin/bash", ["/bin/bash", "-i", "-c", "sleep 0.2"])
PYEOF
  python3 "$WORKDIR/server.py"
  sleep "$PAUSE"

  # And the non-interactive variant, which should alert at HIGH not CRITICAL.
  cat >"$WORKDIR/server2.py" <<'PYEOF'
import subprocess
subprocess.run(["/bin/sh", "-c", "sleep 0.2"])
PYEOF
  python3 "$WORKDIR/server2.py"
  sleep "$PAUSE"
}

# --- Rule B: dangerous one-liners ------------------------------------------
scenario_b() {
  say "Rule B - suspicious one-liner execution"

  # A local file stands in for the remote payload; no network involved.
  printf 'echo "simulated payload ran"\n' >"$WORKDIR/payload.sh"

  # curl | bash, against a file:// URL so nothing leaves the host.
  bash -c "curl -fsSL file://$WORKDIR/payload.sh | bash" || true
  sleep "$PAUSE"

  # base64 -d | sh
  PAYLOAD="$(printf 'echo "simulated staged payload"\n' | base64 -w0)"
  bash -c "echo $PAYLOAD | base64 -d | sh" || true
  sleep "$PAUSE"

  # /dev/tcp reverse shell shape, pointed at a closed local port.
  bash -c 'timeout 1 bash -i >& /dev/tcp/127.0.0.1/9 0>&1' || true
  sleep "$PAUSE"

  # Python inline decode.
  bash -c 'python3 -c "import base64;exec(base64.b64decode(\"cHJpbnQoMSk=\"))"' || true
  sleep "$PAUSE"
}

# --- Rule C: reconnaissance chain ------------------------------------------
# Distinct enumeration binaries in quick succession from one parent shell.
scenario_c() {
  say "Rule C - reconnaissance chain"
  bash -c 'whoami; id; uname -a; hostname; netstat -tlpn 2>/dev/null || ss -tlpn'
  sleep "$PAUSE"
}

case "$SCENARIO" in
  a|A) scenario_a ;;
  b|B) scenario_b ;;
  c|C) scenario_c ;;
  all) scenario_a; scenario_b; scenario_c ;;
  *) echo "usage: $0 [a|b|c|all]" >&2; exit 2 ;;
esac

printf '\nsimulation complete\n'

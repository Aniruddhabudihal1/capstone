#!/usr/bin/env bash
# test_axios_tcp.sh — end-to-end test: run monitor, install axios, verify TCP events
#
# axios is a good test package because:
#   1. It makes HTTPS connections to registry.npmjs.org (port 443)
#   2. The download triggers multiple TCP state transitions
#   3. We can verify SYN_SENT → ESTABLISHED → CLOSE/CLOSE_WAIT transitions
set -euo pipefail

BINARY="$(cd "$(dirname "$0")" && pwd)/npm-ebpf-monitor"
OUT="/tmp/monitor_tcp_out.txt"
TEST_DIR="/tmp/npm-tcp-test"
DURATION="120s"

# ── 0. Must be run as a normal user (we'll sudo internally) ─────────────────
if [[ $EUID -eq 0 ]]; then
  echo "ERROR: Run this script as your normal user, not as root." >&2
  exit 1
fi

if [[ ! -x "$BINARY" ]]; then
  echo "ERROR: Binary not found at $BINARY — run 'make build' first." >&2
  exit 1
fi

# ── 1. Cache sudo credentials NOW (interactive, foreground) ─────────────────
echo "==> Caching sudo credentials (you will be prompted once)..."
sudo -v
echo "==> Credentials cached."

# ── 2. Prepare clean npm test directory ─────────────────────────────────────
echo "==> Preparing test folder: $TEST_DIR"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"
npm init -y > /dev/null 2>&1

# ── 3. Start monitor in background (no TTY prompt — credentials are cached) ─
rm -f "$OUT"
echo "==> Starting monitor ($DURATION window)..."
sudo "$BINARY" -duration "$DURATION" > "$OUT" 2>&1 &
MONITOR_PID=$!
echo "    Monitor PID: $MONITOR_PID (sudo wrapper)"

# Wait until the monitor prints its "Tracing" line (signals BPF is attached)
echo -n "    Waiting for BPF attach"
for i in $(seq 1 30); do
  if grep -q "Tracing" "$OUT" 2>/dev/null; then
    echo " ✓"
    break
  fi
  echo -n "."
  sleep 1
done
if ! grep -q "Tracing" "$OUT" 2>/dev/null; then
  echo ""
  echo "ERROR: Monitor did not start within 30s. Output so far:" >&2
  cat "$OUT" >&2
  exit 1
fi

# ── 4. Run npm install axios ────────────────────────────────────────────────
echo "==> Running: npm install axios (in $TEST_DIR)"
echo "    This will download from registry.npmjs.org (443/HTTPS)"
npm install axios 2>&1 | sed 's/^/    [npm] /'
echo "==> npm install complete."

# ── 5. Wait for monitor to finish ───────────────────────────────────────────
echo "==> Waiting for monitor to finish (up to $DURATION)..."
wait $MONITOR_PID 2>/dev/null || true   # sudo exits after the binary does

# ── 6. Print full monitor output ────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════"
echo "  MONITOR OUTPUT"
echo "══════════════════════════════════════════════════"
cat "$OUT"
echo "══════════════════════════════════════════════════"

# ── 7. Verify TCP events were captured ──────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════"
echo "  TCP EVENT ANALYSIS"
echo "═══════════════════════════════════════════════════"

# Extract TCP event count
TCP_TOTAL=$(grep -c "\[TCP\]" "$OUT" || echo "0")
echo "Total TCP events captured: $TCP_TOTAL"

# Count transitions to/from key states
SYN_SENT=$(grep -c "SYN_SENT" "$OUT" || echo "0")
ESTABLISHED=$(grep -c "ESTABLISHED" "$OUT" || echo "0")
CLOSE_WAIT=$(grep -c "CLOSE_WAIT" "$OUT" || echo "0")
FIN_WAIT=$(grep -cE "FIN_WAIT1|FIN_WAIT2" "$OUT" || echo "0")

echo "  SYN_SENT transitions:   $SYN_SENT"
echo "  ESTABLISHED transitions: $ESTABLISHED"
echo "  CLOSE_WAIT transitions:  $CLOSE_WAIT"
echo "  FIN_WAIT transitions:    $FIN_WAIT"

# Check for port 443 (HTTPS to npm registry)
PORT_443=$(grep "\[TCP\]" "$OUT" | grep -c ":443 " || echo "0")
echo "  Connections to port 443: $PORT_443"

# Extract a sample TCP event for verification
echo ""
echo "Sample TCP events:"
grep "\[TCP\]" "$OUT" | head -5 || echo "  (none)"

# ── 8. Verify test conditions ───────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════"
echo "  TEST RESULTS"
echo "═══════════════════════════════════════════════════"

PASS=0
FAIL=0

# Condition 1: At least 1 TCP event captured
if [[ $TCP_TOTAL -ge 1 ]]; then
  echo "✅  PASS — TCP events captured ($TCP_TOTAL)"
  PASS=$((PASS + 1))
else
  echo "❌  FAIL — No TCP events captured"
  FAIL=$((FAIL + 1))
fi

# Condition 2: SYN_SENT → ESTABLISHED transition observed
if [[ $SYN_SENT -ge 1 && $ESTABLISHED -ge 1 ]]; then
  echo "✅  PASS — Connection establishment captured (SYN_SENT: $SYN_SENT, ESTABLISHED: $ESTABLISHED)"
  PASS=$((PASS + 1))
else
  echo "❌  FAIL — Connection establishment not fully captured (SYN_SENT: $SYN_SENT, ESTABLISHED: $ESTABLISHED)"
  FAIL=$((FAIL + 1))
fi

# Condition 3: Port 443 connections observed (npm registry uses HTTPS)
if [[ $PORT_443 -ge 1 ]]; then
  echo "✅  PASS — Port 443 (HTTPS) connections observed ($PORT_443)"
  PASS=$((PASS + 1))
else
  echo "⚠️   WARN — No port 443 connections (expected for npm registry)"
  # Not a hard failure — npm might use mirrors or cached packages
fi

# Condition 4: Connection teardown captured (CLOSE_WAIT or FIN_WAIT)
if [[ $CLOSE_WAIT -ge 1 || $FIN_WAIT -ge 1 ]]; then
  echo "✅  PASS — Connection teardown captured (CLOSE_WAIT: $CLOSE_WAIT, FIN_WAIT: $FIN_WAIT)"
  PASS=$((PASS + 1))
else
  echo "⚠️   WARN — Connection teardown not captured"
  # Not a hard failure — connections might still be open when monitor stops
fi

echo ""
echo "═══════════════════════════════════════════════════"
if [[ $FAIL -eq 0 && $PASS -ge 2 ]]; then
  echo "✅  OVERALL: PASS — TCP monitoring working ($PASS checks passed)"
  exit 0
else
  echo "❌  OVERALL: FAIL — TCP monitoring incomplete ($PASS passed, $FAIL failed)"
  exit 1
fi

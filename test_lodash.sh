#!/usr/bin/env bash
# test_lodash.sh — end-to-end test: run monitor, install lodash, verify >1000 syscalls
set -euo pipefail

BINARY="$(cd "$(dirname "$0")" && pwd)/npm-ebpf-monitor"
OUT="/tmp/monitor_out.txt"
TEST_DIR="/tmp/npm-test"
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

# ── 4. Run npm install lodash ───────────────────────────────────────────────
echo "==> Running: npm install lodash (in $TEST_DIR)"
npm install lodash 2>&1 | sed 's/^/    [npm] /'
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

# ── 7. Verify >1000 syscall events ──────────────────────────────────────────
echo ""
TOTAL=$(grep -oP '(?<=captured )\d+(?= total syscall)' "$OUT" || echo "0")
NPM_EVENTS=$(grep -oP '(?<=captured )\d+(?= total syscall)' "$OUT" | head -1 || echo "0")

if grep -q "✅ PASS" "$OUT"; then
  echo "✅  TEST PASSED — $TOTAL syscall events captured (≥1000 threshold met)"
  exit 0
else
  echo "❌  TEST FAILED — only $TOTAL syscall events captured (want ≥1000)"
  exit 1
fi

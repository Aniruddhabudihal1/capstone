#!/usr/bin/env bash
# test_tcp_simple.sh — minimal TCP test: monitor + simple Node.js HTTP request
set -euo pipefail

BINARY="$(cd "$(dirname "$0")" && pwd)/npm-ebpf-monitor"
OUT="/tmp/monitor_tcp_simple.txt"
DURATION="20s"

if [[ $EUID -eq 0 ]]; then
  echo "ERROR: Run this script as your normal user, not as root." >&2
  exit 1
fi

if [[ ! -x "$BINARY" ]]; then
  echo "ERROR: Binary not found at $BINARY — run 'make build' first." >&2
  exit 1
fi

# Create a simple Node.js script that makes HTTP requests
cat > /tmp/tcp_test.js <<'EOJS'
const http = require('http');
const https = require('https');

console.log('[TEST] Making HTTP request to example.com...');
http.get('http://example.com/', (res) => {
  console.log(`[TEST] HTTP response: ${res.statusCode}`);
  res.on('data', () => {});
  res.on('end', () => {
    console.log('[TEST] HTTP request complete');

    console.log('[TEST] Making HTTPS request to www.google.com...');
    https.get('https://www.google.com/', (res2) => {
      console.log(`[TEST] HTTPS response: ${res2.statusCode}`);
      res2.on('data', () => {});
      res2.on('end', () => {
        console.log('[TEST] HTTPS request complete');
        console.log('[TEST] All requests done');
        process.exit(0);
      });
    }).on('error', (e) => {
      console.error(`[TEST] HTTPS error: ${e.message}`);
      process.exit(1);
    });
  });
}).on('error', (e) => {
  console.error(`[TEST] HTTP error: ${e.message}`);
  process.exit(1);
});

// Timeout after 10 seconds
setTimeout(() => {
  console.log('[TEST] Timeout - exiting');
  process.exit(0);
}, 10000);
EOJS

echo "==> Caching sudo credentials..."
sudo -v

rm -f "$OUT"
echo "==> Starting monitor ($DURATION window)..."
sudo "$BINARY" -duration "$DURATION" > "$OUT" 2>&1 &
MONITOR_PID=$!

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
  echo "ERROR: Monitor did not start within 30s." >&2
  cat "$OUT" >&2
  exit 1
fi

# Give BPF programs a moment to fully attach
sleep 2

echo "==> Running Node.js TCP test..."
node /tmp/tcp_test.js 2>&1 | sed 's/^/    /'

echo "==> Waiting for monitor to finish..."
wait $MONITOR_PID 2>/dev/null || true

echo ""
echo "══════════════════════════════════════════════════"
echo "  TCP EVENTS CAPTURED"
echo "══════════════════════════════════════════════════"
grep "\[TCP\]" "$OUT" || echo "(no TCP events)"

echo ""
echo "══════════════════════════════════════════════════"
echo "  SUMMARY"
echo "══════════════════════════════════════════════════"

TCP_COUNT=$(grep -c "\[TCP\]" "$OUT" || echo "0")
SYN_SENT=$(grep "\[TCP\]" "$OUT" | grep -c "SYN_SENT" || echo "0")
ESTABLISHED=$(grep "\[TCP\]" "$OUT" | grep -c "ESTABLISHED" || echo "0")

echo "Total TCP events: $TCP_COUNT"
echo "SYN_SENT:         $SYN_SENT"
echo "ESTABLISHED:      $ESTABLISHED"

if [[ $TCP_COUNT -ge 1 ]]; then
  echo ""
  echo "✅ PASS — TCP monitoring is working ($TCP_COUNT events captured)"
  exit 0
else
  echo ""
  echo "❌ FAIL — No TCP events captured"
  echo ""
  echo "Full monitor output:"
  cat "$OUT"
  exit 1
fi

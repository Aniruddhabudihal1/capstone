#!/usr/bin/env bash
# test_lodash_tcp_aggregator.sh — Day 14 E2E:
# run monitor, npm install lodash, and verify Go TCPAggregator summary reports
# at least one public RemoteIP and RemotePort 443.
set -euo pipefail

BINARY="$(cd "$(dirname "$0")" && pwd)/npm-ebpf-monitor"
OUT="/tmp/day14_monitor_out.txt"
TEST_DIR="/tmp/day14-npm-test"
DURATION="120s"

if [[ $EUID -eq 0 ]]; then
  echo "ERROR: Run this script as your normal user, not as root." >&2
  exit 1
fi

if [[ ! -x "$BINARY" ]]; then
  echo "ERROR: Binary not found at $BINARY — run 'make build' first." >&2
  exit 1
fi

echo "==> Caching sudo credentials (you will be prompted once)..."
sudo -v
echo "==> Credentials cached."

echo "==> Preparing test folder: $TEST_DIR"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"
npm init -y >/dev/null 2>&1

rm -f "$OUT"
echo "==> Starting monitor ($DURATION window)..."
sudo "$BINARY" -duration "$DURATION" > "$OUT" 2>&1 &
MONITOR_PID=$!
echo "    Monitor PID: $MONITOR_PID (sudo wrapper)"

echo -n "    Waiting for monitor attach"
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

echo "==> Running: npm install lodash"
npm install lodash 2>&1 | sed 's/^/    [npm] /'
echo "==> npm install complete."

echo "==> Waiting for monitor to finish..."
wait $MONITOR_PID 2>/dev/null || true

echo ""
echo "══════════════════════════════════════════════════"
echo "  MONITOR OUTPUT"
echo "══════════════════════════════════════════════════"
cat "$OUT"
echo "══════════════════════════════════════════════════"

echo ""
echo "══════════════════════════════════════════════════"
echo "  AGGREGATOR VALIDATION"
echo "══════════════════════════════════════════════════"

python3 - <<'PY'
import ipaddress
import re
from pathlib import Path

out = Path('/tmp/day14_monitor_out.txt').read_text(errors='ignore')
summary = None
for line in out.splitlines():
    if 'AGGREGATOR SUMMARY:' in line:
        summary = line

if summary is None:
    print('❌ FAIL — AGGREGATOR SUMMARY line not found')
    raise SystemExit(1)

print('Summary line:')
print(summary)

m_ips = re.search(r'RemoteIPs=\[([^\]]*)\]', summary)
m_ports = re.search(r'RemotePorts=\[([^\]]*)\]', summary)

remote_ips = []
if m_ips:
    raw = m_ips.group(1).strip()
    if raw:
        remote_ips = raw.split()

remote_ports = set()
if m_ports:
    raw = m_ports.group(1).strip()
    if raw:
        for tok in raw.split():
            try:
                remote_ports.add(int(tok))
            except ValueError:
                pass

public_remote_ips = []
for ip in remote_ips:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        continue
    if addr.is_global:
        public_remote_ips.append(ip)

ok_public = len(public_remote_ips) >= 1
ok_443 = 443 in remote_ports

print('RemoteIPs:', remote_ips)
print('Public RemoteIPs:', public_remote_ips)
print('RemotePorts:', sorted(remote_ports))

if ok_public:
    print('✅ PASS — RemoteIPs contains at least one public IP')
else:
    print('❌ FAIL — RemoteIPs has no public IP')

if ok_443:
    print('✅ PASS — RemotePorts contains 443')
else:
    print('❌ FAIL — RemotePorts does not contain 443')

if not (ok_public and ok_443):
    raise SystemExit(1)

print('✅ OVERALL PASS — Day 14 TCP aggregator validation succeeded')
PY

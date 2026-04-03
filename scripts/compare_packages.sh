#!/usr/bin/env bash
# compare_packages.sh — installs benign-test and suspicious-test via the eBPF
# monitor, then prints a QUT-DV25-feature comparison table.
#
# Usage (from project root):
#   bash scripts/compare_packages.sh
#
# Exit code 0  → suspicious > benign for ≥3 of 4 features
# Exit code 1  → test failed or comparison did not pass threshold
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_ROOT/npm-ebpf-monitor"
SESSIONS_DIR="$PROJECT_ROOT/sessions"
PKG_BENIGN="$PROJECT_ROOT/tests/packages/benign-test"
PKG_SUSPICIOUS="$PROJECT_ROOT/tests/packages/suspicious-test"
MONITOR_LOG="/tmp/monitor_compare.log"
# How long to wait after each npm install before stopping the session
NPM_SETTLE_SECS=20
# Seconds to poll for the JSON output file
JSON_WAIT_SECS=30

# ── 0. Pre-flight checks ────────────────────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
  echo "ERROR: Run this script as your normal user, not root." >&2
  exit 1
fi
if [[ ! -x "$BINARY" ]]; then
  echo "ERROR: Binary not found: $BINARY — run 'make build' first." >&2
  exit 1
fi
if [[ ! -d "$PKG_BENIGN" ]]; then
  echo "ERROR: Missing test package: $PKG_BENIGN" >&2
  exit 1
fi
if [[ ! -d "$PKG_SUSPICIOUS" ]]; then
  echo "ERROR: Missing test package: $PKG_SUSPICIOUS" >&2
  exit 1
fi
if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required but not installed. Install it with: sudo apt install jq" >&2
  exit 1
fi

echo "==> Caching sudo credentials..."
sudo -v
echo "==> Credentials cached."

# ── 1. Clean sessions directory ─────────────────────────────────────────────
echo ""
echo "==> Cleaning $SESSIONS_DIR ..."
rm -f "$SESSIONS_DIR"/*.json 2>/dev/null || true
mkdir -p "$SESSIONS_DIR"

# ── helper: wait_for_json <package-name> <timeout-secs> ─────────────────────
# Returns the path of the first matching JSON file, or exits on timeout.
wait_for_json() {
  local pkg="$1"
  local timeout="$2"
  local elapsed=0
  while [[ $elapsed -lt $timeout ]]; do
    # The writer names files: <sessionID>_<packageName>.json
    local match
    match=$(ls "$SESSIONS_DIR"/*_"${pkg}".json 2>/dev/null | head -1 || true)
    if [[ -n "$match" ]]; then
      echo "$match"
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "ERROR: Timed out waiting for JSON file for package '$pkg' after ${timeout}s." >&2
  return 1
}

# ── 2. Start monitor in background ──────────────────────────────────────────
echo ""
echo "==> Starting eBPF monitor in background..."
rm -f "$MONITOR_LOG"
sudo "$BINARY" -output-dir "$SESSIONS_DIR" >"$MONITOR_LOG" 2>&1 &
MONITOR_PID=$!
echo "    Monitor PID: $MONITOR_PID"

# Wait for BPF probes to attach
echo -n "    Waiting for BPF attach"
for i in $(seq 1 30); do
  if grep -qE "Tracing|active\." "$MONITOR_LOG" 2>/dev/null; then
    echo " ✓"
    break
  fi
  echo -n "."
  sleep 1
done
if ! grep -qE "Tracing|active\." "$MONITOR_LOG" 2>/dev/null; then
  echo ""
  echo "ERROR: Monitor did not start within 30s. Log:" >&2
  cat "$MONITOR_LOG" >&2
  sudo kill "$MONITOR_PID" 2>/dev/null || true
  exit 1
fi

# ── 3. Pack + install benign-test ───────────────────────────────────────────
# We use `npm pack` + `npm install <tarball>` instead of `npm install <path>`.
# When a local path is passed the monitor's parseInstallTarget records the full
# path (e.g. /home/.../benign-test) which contains slashes and breaks the JSON
# filename written by json_writer.go.  A tarball name has no slashes.
echo ""
echo "==> Packing benign-test..."
BENIGN_PACK_DIR=$(mktemp -d /tmp/benign-pack-XXXXXX)
cd "$BENIGN_PACK_DIR"
BENIGN_TGZ=$(npm pack "$PKG_BENIGN" --quiet 2>/dev/null)
echo "    tarball: $BENIGN_TGZ"

BENIGN_INSTALL_DIR=$(mktemp -d /tmp/benign-install-XXXXXX)
cd "$BENIGN_INSTALL_DIR"
npm init -y >/dev/null 2>&1
# Copy the tarball in so we can reference it by bare filename (no slashes).
# parseInstallTarget in detector.go takes the raw argument verbatim, so an
# absolute path like /tmp/benign-pack-.../benign-test-1.0.0.tgz would be stored
# as the package name, containing '/' which makes json_writer fail.
cp "$BENIGN_PACK_DIR/$BENIGN_TGZ" "$BENIGN_TGZ"
echo "==> Installing benign-test (via tarball)..."
npm install "$BENIGN_TGZ" 2>&1 | sed 's/^/    [npm] /'
echo "    npm install (benign-test) done. Waiting ${NPM_SETTLE_SECS}s for events to flush..."
sleep "$NPM_SETTLE_SECS"

# The monitor stores PackageName = tarball basename, e.g. "benign-test-1.0.0.tgz"
# Match on the package name prefix embedded in the session filename.
echo -n "    Waiting for benign-test JSON"
BENIGN_JSON=""
for i in $(seq 1 "$JSON_WAIT_SECS"); do
  BENIGN_JSON=$(ls "$SESSIONS_DIR"/*_benign-test*.json 2>/dev/null | head -1 || true)
  if [[ -n "$BENIGN_JSON" ]]; then
    echo " ✓  ($BENIGN_JSON)"
    break
  fi
  echo -n "."
  sleep 1
done
if [[ -z "$BENIGN_JSON" ]]; then
  echo ""
  echo "ERROR: No JSON output for benign-test after ${JSON_WAIT_SECS}s." >&2
  sudo kill "$MONITOR_PID" 2>/dev/null || true
  exit 1
fi

# ── 4. Pack + install suspicious-test ───────────────────────────────────────
echo ""
echo "==> Packing suspicious-test..."
SUSPICIOUS_PACK_DIR=$(mktemp -d /tmp/suspicious-pack-XXXXXX)
cd "$SUSPICIOUS_PACK_DIR"
SUSPICIOUS_TGZ=$(npm pack "$PKG_SUSPICIOUS" --quiet 2>/dev/null)
echo "    tarball: $SUSPICIOUS_TGZ"

SUSPICIOUS_INSTALL_DIR=$(mktemp -d /tmp/suspicious-install-XXXXXX)
cd "$SUSPICIOUS_INSTALL_DIR"
npm init -y >/dev/null 2>&1
# Same bare-filename trick for suspicious-test.
cp "$SUSPICIOUS_PACK_DIR/$SUSPICIOUS_TGZ" "$SUSPICIOUS_TGZ"
echo "==> Installing suspicious-test (via tarball)..."
npm install "$SUSPICIOUS_TGZ" 2>&1 | sed 's/^/    [npm] /'
echo "    npm install (suspicious-test) done. Waiting ${NPM_SETTLE_SECS}s for events to flush..."
sleep "$NPM_SETTLE_SECS"

echo -n "    Waiting for suspicious-test JSON"
SUSPICIOUS_JSON=""
for i in $(seq 1 "$JSON_WAIT_SECS"); do
  SUSPICIOUS_JSON=$(ls "$SESSIONS_DIR"/*_suspicious-test*.json 2>/dev/null | head -1 || true)
  if [[ -n "$SUSPICIOUS_JSON" ]]; then
    echo " ✓  ($SUSPICIOUS_JSON)"
    break
  fi
  echo -n "."
  sleep 1
done
if [[ -z "$SUSPICIOUS_JSON" ]]; then
  echo ""
  echo "ERROR: No JSON output for suspicious-test after ${JSON_WAIT_SECS}s." >&2
  sudo kill "$MONITOR_PID" 2>/dev/null || true
  exit 1
fi

# ── 5. Stop the monitor ──────────────────────────────────────────────────────
echo ""
echo "==> Stopping monitor..."
sudo kill -SIGTERM "$MONITOR_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true
echo "    Monitor stopped."

# ── 6. Extract QUT-DV25 features from both JSON files ───────────────────────
# JSON structure (flattened paths):
#   opensnoop.etc_dir_access   → /etc reads
#   opensnoop.other_dir_access → other reads (includes .ssh, .aws)
#   tcp.remote_ports           → unique remote port count
#   syscalls.network_ops       → network syscall count

extract() {
  local file="$1" path="$2" default="${3:-0}"
  jq -r "${path} // ${default}" "$file" 2>/dev/null || echo "$default"
}

B_ETC=$(extract    "$BENIGN_JSON"    '.opensnoop.etc_dir_access')
B_OTHER=$(extract  "$BENIGN_JSON"    '.opensnoop.other_dir_access')
B_RPORTS=$(extract "$BENIGN_JSON"   '.tcp.remote_ports')
B_NETOPS=$(extract "$BENIGN_JSON"   '.syscalls.network_ops')

S_ETC=$(extract    "$SUSPICIOUS_JSON" '.opensnoop.etc_dir_access')
S_OTHER=$(extract  "$SUSPICIOUS_JSON" '.opensnoop.other_dir_access')
S_RPORTS=$(extract "$SUSPICIOUS_JSON" '.tcp.remote_ports')
S_NETOPS=$(extract "$SUSPICIOUS_JSON" '.syscalls.network_ops')

# Compute ratio strings (avoid division by zero)
ratio() {
  local b="$1" s="$2"
  if [[ "$b" -eq 0 ]]; then
    if [[ "$s" -gt 0 ]]; then
      echo "∞"
    else
      echo "1.0x"
    fi
  else
    # Use awk for floating-point
    awk -v b="$b" -v s="$s" 'BEGIN { printf "%.1fx", s/b }'
  fi
}

R_ETC=$(ratio    "$B_ETC"    "$S_ETC")
R_OTHER=$(ratio  "$B_OTHER"  "$S_OTHER")
R_RPORTS=$(ratio "$B_RPORTS" "$S_RPORTS")
R_NETOPS=$(ratio "$B_NETOPS" "$S_NETOPS")

# ── 7. Print comparison table ────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  QUT-DV25 Feature Comparison: benign-test vs suspicious-test"
echo "════════════════════════════════════════════════════════════════"
printf "%-24s | %-11s | %-15s | %s\n" "Feature" "benign-test" "suspicious-test" "Ratio"
printf "%-24s-+-%-11s-+-%-15s-+-%s\n" "------------------------" "-----------" "---------------" "-------"
printf "%-24s | %11s | %15s | %s\n" "etc_dir_access"   "$B_ETC"    "$S_ETC"    "$R_ETC"
printf "%-24s | %11s | %15s | %s\n" "other_dir_access" "$B_OTHER"  "$S_OTHER"  "$R_OTHER"
printf "%-24s | %11s | %15s | %s\n" "remote_ports"     "$B_RPORTS" "$S_RPORTS" "$R_RPORTS"
printf "%-24s | %11s | %15s | %s\n" "network_ops"      "$B_NETOPS" "$S_NETOPS" "$R_NETOPS"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  benign-test JSON:     $BENIGN_JSON"
echo "  suspicious-test JSON: $SUSPICIOUS_JSON"
echo ""

# ── 8. Evaluate: suspicious > benign for ≥3 of 4 features ───────────────────
WINS=0
check_feature() {
  local name="$1" b="$2" s="$3"
  if [[ "$s" -gt "$b" ]]; then
    echo "  ✅  $name: suspicious ($s) > benign ($b)"
    WINS=$((WINS + 1))
  else
    echo "  ❌  $name: suspicious ($s) NOT > benign ($b)"
  fi
}

check_feature "etc_dir_access"   "$B_ETC"    "$S_ETC"
check_feature "other_dir_access" "$B_OTHER"  "$S_OTHER"
check_feature "remote_ports"     "$B_RPORTS" "$S_RPORTS"
check_feature "network_ops"      "$B_NETOPS" "$S_NETOPS"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ $WINS -ge 3 ]]; then
  echo "✅  PASS — suspicious > benign for $WINS/4 features (need ≥3)"
  exit 0
else
  echo "❌  FAIL — suspicious > benign for only $WINS/4 features (need ≥3)"
  exit 1
fi

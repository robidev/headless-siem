#!/usr/bin/env bash
# ── siemctl digest integration test ────────────────────────────────────────
# Runs a synthetic multi-source fixture through the real pipeline
# (normalized --config config/normalized.toml → indexd) and asserts on
# `siemctl digest --format json` output. Unit tests in src/siemctl/src/
# digest.rs/digest_query.rs/digest_config.rs already cover the section logic
# exhaustively against synthetic SQLite fixtures; this test exists to catch
# wiring bugs those can't: does the real syslog → normalized → indexd chain
# actually populate the fields digest.rs queries by name (event_type,
# src_ip, unit, admin_user, target_user, command, ...), and does the whole
# command run end-to-end without error.
#
# Fixture design: two adjacent hours, 2026-07-01 13:00-14:00 (baseline) and
# 14:00-15:00 (window), using RFC5424 lines with explicit UTC offsets so
# every event lands in an exact, deterministic raw_file bucket (RFC3164
# lines have no year and are bucketed relative to wall-clock "now", which
# would make this test flaky).
#
# Usage: ./tests/integration/test-siemctl-digest.sh   (run from anywhere)
# Per CLAUDE.md, integration tests use the DEBUG binaries — build them first:
#   (cd src/normalized && cargo build) && (cd src/indexd && cargo build) \
#     && (cd src/siemctl && cargo build)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

NORMALIZED="$PROJECT_ROOT/target/debug/normalized"
INDEXD="$PROJECT_ROOT/target/debug/indexd"
SIEMCTL="$PROJECT_ROOT/target/debug/siemctl"
NORM_CONFIG="$PROJECT_ROOT/config/normalized.toml"

PASS=0; FAIL=0
pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1: $2"; FAIL=$((FAIL + 1)); }

# assert_jq DESC JQ_FILTER EXPECTED  — evaluate a jq filter over $DIGEST_JSON
# and compare its (trimmed) output to an expected string.
assert_jq() {
    local desc="$1" filter="$2" expected="$3"
    local actual
    actual="$(jq -r "$filter" <<<"$DIGEST_JSON" 2>&1)" || true
    if [ "$actual" = "$expected" ]; then
        pass "$desc"
    else
        fail "$desc" "expected '$expected', got '$actual'"
    fi
}

for bin in "$NORMALIZED" "$INDEXD" "$SIEMCTL"; do
    [ -x "$bin" ] || { echo "missing debug binary: $bin (run 'cargo build' in its crate)"; exit 1; }
done
command -v jq >/dev/null 2>&1 || { echo "jq is required for this test"; exit 1; }

TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT

echo "=== siemctl digest Integration Test ==="
echo ""

# ── Fixture ─────────────────────────────────────────────────────────────
# Baseline (13:00-14:00): cron (goes silent in the window), one filterlog
# BLOCK and one outbound ALLOW (so the window's spike/new-destination
# checks have something real to compare against, not just zero).
# Window (14:00-15:00): sshd auth failures, sudo privilege escalation, a
# systemd unit restart cycle, a pfsense config change, a filterlog BLOCK
# spike, an inbound ALLOW, the same outbound destination as baseline (must
# NOT show up as "new"), a genuinely new outbound destination, and an
# openvpn event (a source that only exists in the window).
FIXTURE="$TEST_DIR/fixture.log"
cat > "$FIXTURE" <<'EOF'
<142>1 2026-07-01T13:10:00+00:00 myhost cron 1 - - (root) CMD (/usr/bin/backup.sh)
<134>1 2026-07-01T13:20:00+00:00 pfsense filterlog 1 - - 1,,,5,re1,match,block,in,4,0x0,0x0,64,5,0,DF,6,tcp,60,203.0.113.99,192.168.178.1,54322,23,0
<134>1 2026-07-01T13:25:00+00:00 pfsense filterlog 1 - - 1,,,3,lan,match,pass,out,4,0x0,0x0,64,3,0,DF,6,tcp,60,192.168.178.12,172.66.152.176,55556,80,0
<86>1 2026-07-01T14:05:00+00:00 myhost sshd 1234 - - Failed password for root from 203.0.113.5 port 22 ssh2
<86>1 2026-07-01T14:05:30+00:00 myhost sshd 1234 - - Failed password for root from 203.0.113.5 port 22 ssh2
<86>1 2026-07-01T14:10:00+00:00 myhost sudo 999 - - robin : TTY=pts/0 ; PWD=/home/robin ; USER=root ; COMMAND=/bin/nano /etc/x
<86>1 2026-07-01T14:15:00+00:00 myhost systemd 1 - - Stopped sshguard.service
<86>1 2026-07-01T14:15:30+00:00 myhost systemd 1 - - Started sshguard.service
<134>1 2026-07-01T14:20:00+00:00 pfsense php-fpm 1 - - /firewall_rules.php: Configuration Change: admin@192.168.178.75 (Local Database): updated rule
<134>1 2026-07-01T14:25:00+00:00 pfsense filterlog 1 - - 1,,,10,re1,match,block,in,4,0x0,0x0,64,10,0,DF,6,tcp,60,198.51.100.9,192.168.178.1,54321,22,0
<134>1 2026-07-01T14:25:10+00:00 pfsense filterlog 1 - - 1,,,11,re1,match,block,in,4,0x0,0x0,64,11,0,DF,6,tcp,60,198.51.100.9,192.168.178.1,54321,22,0
<134>1 2026-07-01T14:25:20+00:00 pfsense filterlog 1 - - 1,,,12,re1,match,block,in,4,0x0,0x0,64,12,0,DF,6,tcp,60,198.51.100.9,192.168.178.1,54321,22,0
<134>1 2026-07-01T14:25:30+00:00 pfsense filterlog 1 - - 1,,,13,re1,match,block,in,4,0x0,0x0,64,13,0,DF,6,tcp,60,198.51.100.9,192.168.178.1,54321,22,0
<134>1 2026-07-01T14:25:40+00:00 pfsense filterlog 1 - - 1,,,14,re1,match,block,in,4,0x0,0x0,64,14,0,DF,6,tcp,60,198.51.100.9,192.168.178.1,54321,22,0
<134>1 2026-07-01T14:30:00+00:00 pfsense filterlog 1 - - 1,,,15,re1,match,pass,in,4,0x0,0x0,64,15,0,DF,6,tcp,60,217.103.119.242,192.168.178.12,55555,8006,0
<134>1 2026-07-01T14:35:00+00:00 pfsense filterlog 1 - - 1,,,16,lan,match,pass,out,4,0x0,0x0,64,16,0,DF,6,tcp,60,192.168.178.12,172.66.152.176,55556,80,0
<134>1 2026-07-01T14:40:00+00:00 pfsense filterlog 1 - - 1,,,17,lan,match,pass,out,4,0x0,0x0,64,17,0,DF,6,tcp,60,192.168.178.12,172.66.200.1,55557,443,0
<86>1 2026-07-01T14:45:00+00:00 myhost openvpn 1 - - UDPv4 link remote: [AF_INET]203.0.113.9:1194
EOF

echo "[setup] normalizing $FIXTURE → $TEST_DIR/raw, then indexing"
cat "$FIXTURE" | "$NORMALIZED" --stdin --data-dir "$TEST_DIR" --config "$NORM_CONFIG" >/dev/null 2>&1

"$INDEXD" --data-dir "$TEST_DIR" > "$TEST_DIR/indexd.log" 2>&1 &
INDEXD_PID=$!
for _ in $(seq 1 10); do
    grep -q "watching" "$TEST_DIR/indexd.log" 2>/dev/null && break
    sleep 1
done
kill -9 "$INDEXD_PID" 2>/dev/null || true
wait "$INDEXD_PID" 2>/dev/null || true

BUCKETS=$(find "$TEST_DIR/index" -name '*.db' | wc -l)
echo "  built $BUCKETS index bucket(s)"
[ "$BUCKETS" -ge 2 ] && pass "setup: ≥2 hourly buckets (baseline + window)" \
                      || fail "setup" "expected ≥2 buckets, got $BUCKETS"

# ── Alerts fixture (bypasses ruled — build_alerts reads data/alerts/ directly) ──
mkdir -p "$TEST_DIR/alerts/2026/07/01/13" "$TEST_DIR/alerts/2026/07/01/14"
PRE_WINDOW_TS=$(date -u -d '2026-07-01T13:30:00Z' +%s)
cat > "$TEST_DIR/alerts/2026/07/01/13/alerts.jsonl" <<EOF
{"_ruled":true,"rule_id":"known-rule","rule_title":"Known Rule","level":"low","event":{},"timestamp":$PRE_WINDOW_TS}
EOF
{
    echo '{"_ruled":true,"rule_id":"sudo-execution","rule_title":"Sudo Execution","level":"low","event":{},"timestamp":'"$(date -u -d '2026-07-01T14:10:01Z' +%s)"'}'
    for i in $(seq 1 9); do
        echo '{"_ruled":true,"rule_id":"new-rule","rule_title":"New Rule","level":"medium","event":{},"timestamp":'"$(date -u -d "2026-07-01T14:12:0${i}Z" +%s)"'}'
    done
} > "$TEST_DIR/alerts/2026/07/01/14/alerts.jsonl"
echo ""

# ── Run the digest over the fixture's exact window ─────────────────────────
echo "[digest] siemctl digest --window 2026-07-01T14..2026-07-01T15 --format json"
DIGEST_JSON="$("$SIEMCTL" digest --data-dir "$TEST_DIR" \
    --window "2026-07-01T14..2026-07-01T15" --interval 10m --format json 2>&1)" || true
echo "$DIGEST_JSON" | jq -C . 2>&1 | sed 's/^/      /' | head -60
echo ""

# ── Coverage ────────────────────────────────────────────────────────────
echo "[1] coverage"
assert_jq "6 sources reporting in the window" '.coverage.sources_reporting' "6"
assert_jq "cron went silent" '.coverage.gone_silent | sort | join(",")' "cron"
assert_jq "openvpn is a new source" '.coverage.new_sources | index("openvpn") != null' "true"
echo ""

# ── Volume ──────────────────────────────────────────────────────────────
echo "[2] volume"
assert_jq "filterlog flagged as a spike (8 vs. baseline 2)" \
    '(.volume[] | select(.source=="filterlog") | .flag)' "spike"
assert_jq "openvpn flagged as new" '(.volume[] | select(.source=="openvpn") | .flag)' "new"
echo ""

# ── Network ─────────────────────────────────────────────────────────────
echo "[3] network"
assert_jq "top blocked src_ip is the scanner" '.network.top_blocked[0].src_ip' "198.51.100.9"
assert_jq "top blocked count is 5" '.network.top_blocked[0].count' "5"
assert_jq "block_trend sums to 5" '([.network.block_trend[]] | add)' "5"
assert_jq "inbound allowed from 217.103.119.242 to :8006" \
    '(.network.inbound[] | select(.src_ip=="217.103.119.242") | .dst_port)' "8006"
assert_jq "172.66.152.176 is NOT a new destination (seen in baseline)" \
    '(.network.new_destinations | map(.dst_ip) | index("172.66.152.176")) // "absent"' "absent"
assert_jq "172.66.200.1 IS a new destination" \
    '(.network.new_destinations[] | select(.dst_ip=="172.66.200.1") | .dst_port)' "443"
echo ""

# ── Auth ────────────────────────────────────────────────────────────────
echo "[4] auth"
assert_jq "203.0.113.5 has 2 unified auth failures" \
    '(.auth.failures[] | select(.src_ip=="203.0.113.5") | .count)' "2"
assert_jq "sudo event captured with its command" '.auth.sudo[0].command' "/bin/nano /etc/x"
assert_jq "sudo event's target user is root" '.auth.sudo[0].target_user' "root"
echo ""

# ── Notable ─────────────────────────────────────────────────────────────
echo "[5] notable"
assert_jq "pfsense config change captured" '.notable.config_changes[0].admin_user' "admin"
assert_jq "sshguard.service restart counted twice (stop+start)" \
    '(.notable.service_restarts[] | select(.unit=="sshguard.service") | .count)' "2"
echo ""

# ── Alerts ──────────────────────────────────────────────────────────────
echo "[6] alerts"
assert_jq "10 alerts total in the window (pre-window alert excluded)" '.alerts.total' "10"
assert_jq "new-rule is a first-time rule" '.alerts.first_time_rules | index("new-rule") != null' "true"
assert_jq "known-rule (fired before the window) is NOT first-time" \
    '.alerts.first_time_rules | index("known-rule") != null' "false"
assert_jq "concentration warning names new-rule" \
    '(.alerts.concentration_warning // "" | contains("new-rule"))' "true"
echo ""

# ── Text format also runs without error ────────────────────────────────
echo "[7] --format text runs cleanly"
TEXT_OUT="$("$SIEMCTL" digest --data-dir "$TEST_DIR" \
    --window "2026-07-01T14..2026-07-01T15" --format text 2>&1)" || true
if grep -q "=== COVERAGE" <<<"$TEXT_OUT" && grep -q "=== NOTABLE EVENTS" <<<"$TEXT_OUT"; then
    pass "text output contains all section headers"
else
    fail "text output" "missing expected section headers"
fi
echo ""

echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -gt 0 ] && exit 1; exit 0

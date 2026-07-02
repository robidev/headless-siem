#!/usr/bin/env bash
# ── siemctl alerts integration test ────────────────────────────────────────
# Alerts are flat JSONL, not indexed — `siemctl alerts` reads
# data/alerts/**/*.jsonl and data/alerts/correlated/**/*.jsonl directly, so
# this test writes a synthetic fixture straight into that layout (no
# normalized/indexd/ruled pipeline needed) and asserts on `siemctl alerts`
# CLI behavior: default whole-record output, --query filtering/SELECT/GROUP
# BY against both alert shapes, --after/--before bucket pruning, --correlated,
# and error paths. Unit tests in src/siemctl/src/alerts.rs and query.rs's
# eval_json tests already cover the resolution/evaluation logic exhaustively
# against in-memory records; this test exists to catch CLI-wiring bugs those
# can't (arg parsing, exit codes, --correlated, real file I/O).
#
# Usage: ./tests/integration/test-siemctl-alerts.sh   (run from anywhere)
# Per CLAUDE.md, integration tests use the DEBUG binary — build it first:
#   (cd src/siemctl && cargo build)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

SIEMCTL="$PROJECT_ROOT/target/debug/siemctl"

PASS=0; FAIL=0
pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1: $2"; FAIL=$((FAIL + 1)); }

# demo_contains DESC NEEDLE CMD...  — run CMD, assert its output contains NEEDLE.
demo_contains() {
    local desc="$1" needle="$2"; shift 2
    local out; out="$("$@" 2>&1)" || true
    echo "  \$ ${*##*/siemctl}"
    echo "$out" | sed 's/^/      /'
    if grep -qF -- "$needle" <<<"$out"; then pass "$desc"; else fail "$desc" "missing '$needle'"; fi
}

# demo_not_contains DESC NEEDLE CMD...  — assert the output does NOT contain NEEDLE.
demo_not_contains() {
    local desc="$1" needle="$2"; shift 2
    local out; out="$("$@" 2>&1)" || true
    echo "  \$ ${*##*/siemctl}"
    echo "$out" | sed 's/^/      /'
    if grep -qF -- "$needle" <<<"$out"; then fail "$desc" "unexpectedly contains '$needle'"; else pass "$desc"; fi
}

demo_rejects() {
    local desc="$1" needle="$2"; shift 2
    local out rc
    out="$("$@" 2>&1)" && rc=0 || rc=$?
    echo "  \$ ${*##*/siemctl}"
    echo "$out" | sed 's/^/      /'
    if [ "$rc" -ne 0 ] && grep -qF -- "$needle" <<<"$out"; then
        pass "$desc"
    else
        fail "$desc" "expected non-zero exit mentioning '$needle' (rc=$rc)"
    fi
}

[ -x "$SIEMCTL" ] || { echo "missing debug binary: $SIEMCTL (run 'cargo build' in src/siemctl)"; exit 1; }

TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT

echo "=== siemctl alerts Integration Test ==="
echo ""

# ── Fixture: written directly into data/alerts/ — no pipeline needed ───────
mkdir -p "$TEST_DIR/alerts/2026/07/01/08"
mkdir -p "$TEST_DIR/alerts/2026/07/01/14"
mkdir -p "$TEST_DIR/alerts/correlated/2026/07/01/14"

# Before the window: excluded by --after below.
cat > "$TEST_DIR/alerts/2026/07/01/08/alerts.jsonl" <<'EOF'
{"_ruled":true,"rule_id":"known-rule","rule_title":"Known Rule","level":"low","event":{"src_ip":"10.0.0.1"},"timestamp":1782806400}
EOF

# In the window: two ssh-brute-force hits from the same src_ip, one
# high-severity suspicious-ssh hit from a different src_ip.
cat > "$TEST_DIR/alerts/2026/07/01/14/alerts.jsonl" <<'EOF'
{"_ruled":true,"rule_id":"1001-ssh-brute-force","rule_title":"SSH Brute Force Detection","level":"medium","event":{"src_ip":"10.10.50.11","event_type":"ssh_auth_failure"},"timestamp":1782831600}
{"_ruled":true,"rule_id":"1001-ssh-brute-force","rule_title":"SSH Brute Force Detection","level":"medium","event":{"src_ip":"10.10.50.11","event_type":"ssh_auth_failure"},"timestamp":1782831610}
{"_ruled":true,"rule_id":"1004-suspicious-ssh","rule_title":"Suspicious Internal SSH from External IP","level":"high","event":{"src_ip":"10.10.50.12","event_type":"ssh_auth_failure"},"timestamp":1782831620}
EOF

# A correlated alert in the same window hour, same src_ip as the brute-force hits.
cat > "$TEST_DIR/alerts/correlated/2026/07/01/14/correlated.jsonl" <<'EOF'
{"_correlated":true,"correlation_id":"cred-guess","correlation_title":"Credential Guessing","join_field":"src_ip","join_value":"10.10.50.11","chain_start":1782831600,"chain_end":1782831610,"step_counts":[2,1],"sample_events":[{"src_ip":"10.10.50.11"}]}
EOF
echo "[setup] fixture written to $TEST_DIR/alerts/"
echo ""

# ── 1. Default output: whole records, both shapes, unbounded time range ───
echo "[1] default output (no --query, no time range)"
demo_contains "includes a ruled alert" '"rule_id":"1001-ssh-brute-force"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR"
demo_contains "includes a correlated alert" '"correlation_id":"cred-guess"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR"
demo_contains "ruled alerts tagged type=ruled" '"type":"ruled"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR"
demo_contains "correlated alerts tagged type=correlated" '"type":"correlated"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR"
echo ""

# ── 2. --after/--before bucket pruning ─────────────────────────────────────
echo "[2] --after/--before excludes the pre-window alert"
demo_not_contains "known-rule excluded by --after" '"rule_id":"known-rule"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --after "2026-07-01T10" --before "2026-07-01T20"
demo_contains "in-window alert still present" '"rule_id":"1001-ssh-brute-force"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --after "2026-07-01T10" --before "2026-07-01T20"
echo ""

# ── 3. GROUP BY counts per rule ─────────────────────────────────────────────
echo "[3] GROUP BY rule_id"
demo_contains "ssh-brute-force counted twice" '{"rule_id":"1001-ssh-brute-force","count":2}' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --query "GROUP BY rule_id"
echo ""

# ── 4. SELECT resolves fields nested inside the embedded event ────────────
echo "[4] SELECT projects a field nested under event.*"
demo_contains "src_ip resolved from the embedded event" \
    '{"rule_id":"1001-ssh-brute-force","src_ip":"10.10.50.11"}' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --query "SELECT rule_id,src_ip WHERE src_ip == 10.10.50.11"
echo ""

# ── 5. level filter — correlated alerts (no level field) never match ──────
echo "[5] level == high matches only the high-severity ruled alert"
demo_contains "suspicious-ssh (high) matches" '"rule_id":"1004-suspicious-ssh"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --query "level == high"
demo_not_contains "ssh-brute-force (medium) excluded" '"rule_id":"1001-ssh-brute-force"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --query "level == high"
demo_not_contains "correlated alert excluded (no level field)" '"correlation_id"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --query "level == high"
echo ""

# ── 6. --correlated flag and its type == correlated DSL equivalent ────────
echo "[6] --correlated restricts to correlated alerts only"
demo_contains "correlated alert present" '"correlation_id":"cred-guess"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --correlated
demo_not_contains "ruled alerts excluded" '"rule_id"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --correlated
echo ""
echo "[7] type == correlated in --query has the same effect as --correlated"
demo_contains "correlated alert present via DSL" '"correlation_id":"cred-guess"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --query "type == correlated"
echo ""

# ── 8. --format tsv ─────────────────────────────────────────────────────────
echo "[8] GROUP BY rule_id --format tsv"
demo_contains "tsv header is 'rule_id<TAB>count'" "$(printf 'rule_id\tcount')" \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --query "GROUP BY rule_id" --format tsv
echo ""

# ── 9. Error paths ───────────────────────────────────────────────────────────
echo "[9] error paths"
demo_rejects "rejects an unsafe field name (SQL-injection guard)" "invalid field name" \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --query "GROUP BY src_ip-drop"
demo_rejects "missing data dir" "data directory not found" \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR/does-not-exist"
demo_rejects "no matches found" "no matches found" \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --query "rule_id == nonexistent"
echo ""

# ── 10. ack hides matching alerts by default; --all still shows them ──────
echo "[10] siemctl alerts ack <rule_id> hides that rule's existing alerts"
demo_contains "ssh-brute-force visible before ack" '"rule_id":"1001-ssh-brute-force"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR"
"$SIEMCTL" alerts ack "1001-ssh-brute-force" --data-dir "$TEST_DIR" --note "known pattern, reviewed" \
    | sed 's/^/      /'
demo_not_contains "ssh-brute-force hidden after ack (default view)" '"rule_id":"1001-ssh-brute-force"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR"
demo_contains "suspicious-ssh (never acked) still shown by default" '"rule_id":"1004-suspicious-ssh"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR"
demo_contains "--all bypasses the ack filter" '"rule_id":"1001-ssh-brute-force"' \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR" --all
echo ""

echo "[11] a NEW alert for the same rule, fired after the ack, still shows up"
FUTURE_TS=$(( $(date +%s) + 3600 ))
cat >> "$TEST_DIR/alerts/2026/07/01/14/alerts.jsonl" <<EOF
{"_ruled":true,"rule_id":"1001-ssh-brute-force","rule_title":"SSH Brute Force Detection","level":"medium","event":{"src_ip":"10.10.50.11","event_type":"ssh_auth_failure"},"timestamp":$FUTURE_TS}
EOF
demo_contains "post-ack occurrence of the same rule is not hidden" \
    "\"rule_id\":\"1001-ssh-brute-force\",\"rule_title\":\"SSH Brute Force Detection\",\"timestamp\":$FUTURE_TS" \
    "$SIEMCTL" alerts --data-dir "$TEST_DIR"
echo ""

# ── 12. siemctl retention compacts stale ack.jsonl lines ───────────────────
echo "[12] siemctl retention ages out stale ack.jsonl lines"
OLD_TS=$(( $(date +%s) - 400 * 86400 ))  # ~400 days ago
printf '{"rule_id":"stale-rule","timestamp":%d}\n' "$OLD_TS" >> "$TEST_DIR/alerts/ack.jsonl"
demo_contains "dry-run reports the stale ack line" "would drop 1 stale ack line(s)" \
    "$SIEMCTL" retention --data-dir "$TEST_DIR" --days 365 --dry-run
BEFORE_COUNT=$(wc -l < "$TEST_DIR/alerts/ack.jsonl")
"$SIEMCTL" retention --data-dir "$TEST_DIR" --days 365 --yes | sed 's/^/      /'
AFTER_COUNT=$(wc -l < "$TEST_DIR/alerts/ack.jsonl")
if [ "$AFTER_COUNT" -eq $((BEFORE_COUNT - 1)) ]; then
    pass "retention dropped exactly the one stale ack line"
else
    fail "retention dropped exactly the one stale ack line" "before=$BEFORE_COUNT after=$AFTER_COUNT"
fi
grep -q "stale-rule" "$TEST_DIR/alerts/ack.jsonl" \
    && fail "stale ack line actually removed" "still present" \
    || pass "stale ack line actually removed"
grep -q "1001-ssh-brute-force" "$TEST_DIR/alerts/ack.jsonl" \
    && pass "fresh ack line (from step 10) survives retention" \
    || fail "fresh ack line survives retention" "missing after retention run"
echo ""

echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -gt 0 ] && exit 1; exit 0

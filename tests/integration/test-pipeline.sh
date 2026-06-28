#!/usr/bin/env bash
# ── Headless SIEM End-to-End Pipeline Integration Test ────────────────
# Tests the full pipeline: normalized → indexd → ruled → correlated → siemctl
#
# Usage: ./tests/integration/test-pipeline.sh
# Must be run from the project root directory.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

TEST_DIR="/tmp/siem-pipeline-test"
PASS=0
FAIL=0

# ── Binaries ──────────────────────────────────────────────────────────
NORMALIZED="$PROJECT_ROOT/src/normalized/target/debug/normalized"
INDEXD="$PROJECT_ROOT/src/indexd/target/debug/indexd"
RULED="$PROJECT_ROOT/src/ruled/target/debug/ruled"
CORRELATED="$PROJECT_ROOT/src/correlated/target/debug/correlated"
SIEMCTL="$PROJECT_ROOT/src/siemctl/target/debug/siemctl"
FIXTURE="$PROJECT_ROOT/tests/fixtures/mixed.log"
RULES_DIR="$PROJECT_ROOT/config/rules"

# ── Helpers ───────────────────────────────────────────────────────────
green()  { echo -e "\033[32m[PASS]\033[0m $*"; }
red()    { echo -e "\033[31m[FAIL]\033[0m $*"; }
info()   { echo -e "\033[36m[INFO]\033[0m $*"; }

check() {
    local desc="$1"; shift
    if "$@"; then
        green "$desc"
        PASS=$((PASS + 1))
    else
        red "$desc"
        FAIL=$((FAIL + 1))
    fi
}

cleanup() {
    info "Cleaning up test directory: $TEST_DIR"
    rm -rf "$TEST_DIR"
}

# ── Step 0: Setup ─────────────────────────────────────────────────────
info "=== Step 0: Setup ==="
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"/{raw,normalized,index,alerts,correlated}

# Verify binaries exist
for bin in "$NORMALIZED" "$INDEXD" "$RULED" "$CORRELATED" "$SIEMCTL"; do
    if [[ ! -x "$bin" ]]; then
        red "Binary not found or not executable: $bin"
        cleanup
        exit 1
    fi
done
green "All binaries found and executable"

# Verify fixture exists
check "Fixture file exists" test -f "$FIXTURE"

# ── Step 1: Normalization ─────────────────────────────────────────────
info "=== Step 1: Normalization (normalized) ==="

# Run normalized: pipe mixed.log through, write to filesystem, capture stdout
NORM_STDOUT="$TEST_DIR/normalized-output.jsonl"
cat "$FIXTURE" | "$NORMALIZED" --stdin --data-dir "$TEST_DIR" > "$NORM_STDOUT" 2>/dev/null

check "Normalized stdout is non-empty" test -s "$NORM_STDOUT"

# Count lines
NORM_LINES=$(wc -l < "$NORM_STDOUT")
info "Normalized produced $NORM_LINES lines"
check "Normalized produced at least 20 lines" test "$NORM_LINES" -ge 20

# Verify _normalized:true appears in output
NORM_TRUE_COUNT=$(grep -c '"_normalized":true' "$NORM_STDOUT" || true)
info "Lines with _normalized:true: $NORM_TRUE_COUNT"
check "At least 15 lines are fully normalized" test "$NORM_TRUE_COUNT" -ge 15

# ── Step 2: Verify raw filesystem output ──────────────────────────────
info "=== Step 2: Verify raw filesystem output ==="

RAW_DIR="$TEST_DIR/raw"
check "raw/ directory exists" test -d "$RAW_DIR"

# Count .jsonl files under raw/
JSONL_COUNT=$(find "$RAW_DIR" -type f -name '*.jsonl' | wc -l)
info "JSONL files created: $JSONL_COUNT"
check "At least 3 .jsonl files created" test "$JSONL_COUNT" -ge 3

# Verify time-bucketed path structure: raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl
# Check that at least one file has the correct depth
DEEPEST=$(find "$RAW_DIR" -type f -name '*.jsonl' | head -1)
DEPTH=$(echo "$DEEPEST" | tr '/' '\n' | wc -l)
# Path should be like: /tmp/siem-pipeline-test/raw/2026/06/22/08/55/03/sshd.jsonl
# That's 10 components from /tmp
check "Files are in time-bucketed hierarchy (depth >= 8)" test "$DEPTH" -ge 8

# Verify source-specific files exist
check "sshd .jsonl files exist" test "$(find "$RAW_DIR" -name 'sshd.jsonl' | wc -l)" -ge 1
check "iptables .jsonl files exist" test "$(find "$RAW_DIR" -name 'iptables.jsonl' | wc -l)" -ge 1
check "sudo .jsonl files exist" test "$(find "$RAW_DIR" -name 'sudo.jsonl' | wc -l)" -ge 1
check "systemd .jsonl files exist" test "$(find "$RAW_DIR" -name 'systemd.jsonl' | wc -l)" -ge 1

# ── Step 3: Verify TSV sidecars ───────────────────────────────────────
info "=== Step 3: Verify TSV sidecars ==="

TSV_COUNT=$(find "$RAW_DIR" -type f -name '*.tsv' | wc -l)
info "TSV sidecar files: $TSV_COUNT"
check "TSV sidecars exist (at least 3)" test "$TSV_COUNT" -ge 3

# Verify TSV has header row
FIRST_TSV=$(find "$RAW_DIR" -type f -name '*.tsv' | head -1)
TSV_HEADER=$(head -1 "$FIRST_TSV")
check "TSV has correct header" test "$TSV_HEADER" = "timestamp	src_ip	dst_ip	event_type	severity	source"

# Verify TSV has at least one data row
TSV_LINES=$(wc -l < "$FIRST_TSV")
check "TSV has header + data rows" test "$TSV_LINES" -ge 2

# ── Step 4: Indexing (indexd) ─────────────────────────────────────────
info "=== Step 4: Indexing (indexd) ==="

# Start indexd in background. It scans existing files on startup,
# then enters the inotify watch loop (which blocks on read_events).
# We wait for the scan to complete, then force-kill it.
INDEXD_LOG="$TEST_DIR/indexd.log"
"$INDEXD" --data-dir "$TEST_DIR" > "$INDEXD_LOG" 2>&1 &
INDEXD_PID=$!
info "indexd started with PID $INDEXD_PID"

# Wait for the "watching" message which indicates the initial scan is done
for i in $(seq 1 10); do
    if grep -q "watching" "$INDEXD_LOG" 2>/dev/null; then
        info "indexd initial scan complete (after ${i}s)"
        break
    fi
    sleep 1
done

# Force-kill indexd (SIGTERM doesn't interrupt blocking inotify read)
kill -9 "$INDEXD_PID" 2>/dev/null || true
wait "$INDEXD_PID" 2>/dev/null || true
info "indexd stopped"

# Verify SQLite databases created
INDEX_DIR="$TEST_DIR/index"
check "index/ directory exists" test -d "$INDEX_DIR"

DB_COUNT=$(find "$INDEX_DIR" -type f -name '*.db' | wc -l)
info "SQLite index databases: $DB_COUNT"
check "At least 1 index database created" test "$DB_COUNT" -ge 1

# Verify at least one .db file has the events table with data
FIRST_DB=$(find "$INDEX_DIR" -type f -name '*.db' | head -1)
EVENT_COUNT=$(sqlite3 "$FIRST_DB" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo "0")
info "Events indexed in first DB: $EVENT_COUNT"
check "At least 5 events indexed" test "$EVENT_COUNT" -ge 5

# ── Step 5: Rule evaluation (ruled) ───────────────────────────────────
info "=== Step 5: Rule evaluation (ruled) ==="

# Pipe normalized output through ruled
RULED_STDOUT="$TEST_DIR/ruled-output.jsonl"
cat "$NORM_STDOUT" | "$RULED" --rules "$RULES_DIR" --output "$TEST_DIR/alerts" > "$RULED_STDOUT" 2>/dev/null

check "ruled stdout is non-empty" test -s "$RULED_STDOUT"

ALERT_COUNT=$(wc -l < "$RULED_STDOUT")
info "Alerts generated: $ALERT_COUNT"
check "At least 3 alerts generated" test "$ALERT_COUNT" -ge 3

# Verify alert structure
check "Alerts contain _ruled:true" grep -q '"_ruled":true' "$RULED_STDOUT"
check "Alerts contain rule_id" grep -q '"rule_id"' "$RULED_STDOUT"
check "Alerts contain rule_title" grep -q '"rule_title"' "$RULED_STDOUT"

# Verify specific rules triggered
check "SSH brute force rule triggered" grep -q '1001-ssh-brute-force' "$RULED_STDOUT"
check "IPTables deny rule triggered" grep -q '1003-iptables-deny' "$RULED_STDOUT"
check "Sudo execution rule triggered" grep -q '1002-sudo-execution' "$RULED_STDOUT"

# Verify filesystem alerts
ALERTS_DIR="$TEST_DIR/alerts"
check "alerts/ directory exists" test -d "$ALERTS_DIR"
FS_ALERT_COUNT=$(find "$ALERTS_DIR" -type f -name 'alerts.jsonl' | wc -l)
check "Filesystem alerts written" test "$FS_ALERT_COUNT" -ge 1

# ── Step 6: Correlation (correlated) ──────────────────────────────────
info "=== Step 6: Correlation (correlated) ==="

# Write a test-specific correlations.toml: single-step rule that fires when
# the same src_ip triggers the brute-force rule just once (min_count=1 so
# even a single dedup'd alert is enough to generate a correlation alert).
CORR_CONFIG="$TEST_DIR/correlations.toml"
cat > "$CORR_CONFIG" << 'EOF'
[[rule]]
id           = "test-brute-force"
title        = "Test SSH Brute Force"
join_field   = "src_ip"
window_seconds = 300
ordered      = false

  [[rule.step]]
  rule_id   = "1001-ssh-brute-force"
  min_count = 1
EOF

CORR_STDOUT="$TEST_DIR/correlated-output.jsonl"
cat "$RULED_STDOUT" | "$CORRELATED" --config "$CORR_CONFIG" --output "$TEST_DIR/correlated" > "$CORR_STDOUT" 2>/dev/null

check "correlated stdout is non-empty" test -s "$CORR_STDOUT"

# Count correlation alerts (lines with _correlated:true)
CORR_COUNT=$(grep -c '"_correlated":true' "$CORR_STDOUT" || true)
info "Correlation alerts: $CORR_COUNT"
check "At least 1 correlation alert generated" test "$CORR_COUNT" -ge 1

# Verify new correlation alert structure
check "Correlation alerts contain _correlated:true" grep -q '"_correlated":true' "$CORR_STDOUT"
check "Correlation alerts contain correlation_id" grep -q '"correlation_id"' "$CORR_STDOUT"
check "Correlation alerts contain step_counts" grep -q '"step_counts"' "$CORR_STDOUT"
check "Correlation alerts contain sample_events" grep -q '"sample_events"' "$CORR_STDOUT"

# Verify filesystem correlation output
CORR_FS_DIR="$TEST_DIR/correlated"
check "correlated/ directory exists" test -d "$CORR_FS_DIR"
FS_CORR_COUNT=$(find "$CORR_FS_DIR" -type f -name 'correlated.jsonl' | wc -l)
check "Filesystem correlation alerts written" test "$FS_CORR_COUNT" -ge 1

# ── Step 7: siemctl status ────────────────────────────────────────────
info "=== Step 7: siemctl status ==="

STATUS_OUT=$("$SIEMCTL" status --data-dir "$TEST_DIR" 2>&1) || true
check "siemctl status runs without crash" test -n "$STATUS_OUT"

# Verify status output contains expected sections
check "Status shows total size" grep -q "Total size:" <<< "$STATUS_OUT"
check "Status shows source file counts" grep -q "Source file counts:" <<< "$STATUS_OUT"
check "Status shows sshd source" grep -q "sshd" <<< "$STATUS_OUT"
check "Status shows indexed buckets" grep -q "Indexed buckets" <<< "$STATUS_OUT"

# ── Step 8: siemctl search ────────────────────────────────────────────
info "=== Step 8: siemctl search ==="

# Search by field (index-assisted)
SEARCH_FIELD_OUT=$("$SIEMCTL" search --data-dir "$TEST_DIR" --field src_ip --value "10.0.0.5" 2>&1) || true
check "siemctl search --field src_ip returns results" test -n "$SEARCH_FIELD_OUT"

# Search by query (grep on normalized JSONL — use a value that appears in the JSON)
SEARCH_QUERY_OUT=$("$SIEMCTL" search --data-dir "$TEST_DIR" --query "10.0.0.5" 2>&1) || true
check "siemctl search --query returns results" test -n "$SEARCH_QUERY_OUT"

# Search by source + time range
SEARCH_SOURCE_OUT=$("$SIEMCTL" search --data-dir "$TEST_DIR" --source sshd --after "2026-06-22T08:00" --before "2026-06-22T09:00" 2>&1) || true
check "siemctl search --source with time range returns results" test -n "$SEARCH_SOURCE_OUT"

# ── Step 9: Cleanup ──────────────────────────────────────────────────
info "=== Step 9: Cleanup ==="
cleanup
green "Test directory cleaned up"

# ── Summary ────────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  Integration Test Results"
echo "========================================"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "========================================"

if [[ "$FAIL" -gt 0 ]]; then
    echo ""
    red "INTEGRATION TEST FAILED ($FAIL failures)"
    exit 1
else
    echo ""
    green "INTEGRATION TEST PASSED (all $PASS checks)"
    exit 0
fi

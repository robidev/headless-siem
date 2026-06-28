#!/usr/bin/env bash
# Integration tests for the normalized binary.
# Validates end-to-end pipeline behavior with real fixtures.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$PROJECT_ROOT/src/normalized/target/release/normalized"
FIXTURES="$PROJECT_ROOT/tests/fixtures"

# Build if needed
if [ ! -x "$BINARY" ]; then
    echo "Building normalized..."
    cd "$PROJECT_ROOT/src/normalized"
    source "$HOME/.cargo/env" 2>/dev/null || true
    cargo build --release
fi

PASS=0
FAIL=0

pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1: $2"; FAIL=$((FAIL + 1)); }

echo "=== Integration Tests ==="
echo ""

# ── Test 1: sshd fixture produces valid JSON ────────────────────────
echo "[1] sshd.log → all lines are valid JSON"
COUNT=$(cat "$FIXTURES/sshd.log" | "$BINARY" --stdin --dry-run --source sshd | wc -l)
if [ "$COUNT" -ge 30 ]; then
    pass "sshd.log: $COUNT output lines (expected ≥30)"
else
    fail "sshd.log" "got $COUNT lines, expected ≥30"
fi

# ── Test 2: every output line is valid JSON ─────────────────────────
echo "[2] sshd.log → every line is valid JSON"
INVALID=$(cat "$FIXTURES/sshd.log" | "$BINARY" --stdin --dry-run --source sshd | while read -r line; do echo "$line" | jq empty 2>&1 || echo "INVALID"; done | grep -c "INVALID" || true)
if [ "${INVALID:-0}" -eq 0 ]; then
    pass "all output lines are valid JSON"
else
    fail "valid JSON" "$INVALID invalid lines"
fi

# ── Test 3: structured lines have _normalized: true ─────────────────
echo "[3] sshd.log → structured lines have _normalized: true"
NORMALIZED=$(cat "$FIXTURES/sshd.log" | "$BINARY" --stdin --dry-run --source sshd | jq -r '._normalized' | grep -c "true" || true)
if [ "${NORMALIZED:-0}" -ge 20 ]; then
    pass "structured: $NORMALIZED lines with _normalized=true (expected ≥20)"
else
    fail "structured" "only $NORMALIZED lines normalized"
fi

# ── Test 4: iptables fixture → all lines processed ──────────────────
echo "[4] iptables.log → all lines processed"
COUNT=$(cat "$FIXTURES/iptables.log" | "$BINARY" --stdin --dry-run --source iptables | wc -l)
if [ "$COUNT" -ge 12 ]; then
    pass "iptables.log: $COUNT output lines (expected ≥12)"
else
    fail "iptables.log" "got $COUNT lines, expected ≥12"
fi

# ── Test 5: mixed.log → source types preserved ──────────────────────
echo "[5] mixed.log → source types preserved"
SOURCES=$(cat "$FIXTURES/mixed.log" | "$BINARY" --stdin --dry-run | jq -r '._source_type' | sort -u | tr '\n' ' ')
if echo "$SOURCES" | grep -q "sshd" && echo "$SOURCES" | grep -q "iptables" && echo "$SOURCES" | grep -q "sudo" && echo "$SOURCES" | grep -q "systemd"; then
    pass "mixed.log: all 4 source types present ($SOURCES)"
else
    fail "mixed.log" "missing source types, got: $SOURCES"
fi

# ── Test 6: malformed.log → no crashes, all lines produce output ────
echo "[6] malformed.log → no crashes, all non-empty lines produce output"
COUNT=$(cat "$FIXTURES/malformed.log" | "$BINARY" --stdin --dry-run | wc -l)
# malformed.log has 25 non-empty lines (1 blank line, 1 non-JSON, 1 missing _raw)
if [ "$COUNT" -ge 24 ]; then
    pass "malformed.log: $COUNT output lines (expected ≥24)"
else
    fail "malformed.log" "got $COUNT lines, expected ≥24"
fi

# ── Test 7: --source flag overrides ─────────────────────────────────
echo "[7] --source flag overrides _source"
OVERRIDE=$(echo '{"_raw":"test line","_source":"sshd"}' | "$BINARY" --stdin --dry-run --source forced | jq -r '._source_type')
if [ "$OVERRIDE" = "forced" ]; then
    pass "--source forced: _source_type=$OVERRIDE"
else
    fail "--source forced" "got _source_type=$OVERRIDE, expected forced"
fi

# ── Test 8: --help prints usage ─────────────────────────────────────
echo "[8] --help prints usage"
if "$BINARY" --help 2>&1 | grep -q "USAGE"; then
    pass "--help: usage printed"
else
    fail "--help" "no USAGE found in output"
fi

# ── Test 9: unknown flag exits non-zero ─────────────────────────────
echo "[9] unknown flag exits non-zero"
if ! "$BINARY" --nonexistent 2>/dev/null; then
    pass "unknown flag: exit code non-zero"
else
    fail "unknown flag" "expected non-zero exit"
fi

# ── Test 10: --dry-run does not create files ────────────────────────
echo "[10] --dry-run does not create filesystem output"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT
cat "$FIXTURES/sshd.log" | "$BINARY" --stdin --dry-run --data-dir "$TMPDIR" > /dev/null
if [ -z "$(ls -A "$TMPDIR" 2>/dev/null)" ]; then
    pass "--dry-run: no files created in data dir"
else
    fail "--dry-run" "files were created: $(find "$TMPDIR" -type f)"
fi

# ── Test 11: normal mode creates files ──────────────────────────────
echo "[11] normal mode creates filesystem output"
TMPDIR2=$(mktemp -d)
trap "rm -rf $TMPDIR2 $TMPDIR" EXIT
echo '{"_raw":"Jun 22 08:55:03 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2","_source":"sshd"}' | "$BINARY" --stdin --data-dir "$TMPDIR2" > /dev/null
FILES=$(find "$TMPDIR2" -type f -name "*.jsonl" | wc -l)
if [ "$FILES" -ge 1 ]; then
    pass "normal mode: $FILES jsonl file(s) created"
else
    fail "normal mode" "no jsonl files created"
fi

# ── Test 12: TSV sidecar created ────────────────────────────────────
echo "[12] TSV sidecar created alongside JSONL"
TSV_FILES=$(find "$TMPDIR2" -type f -name "*.tsv" | wc -l)
if [ "$TSV_FILES" -ge 1 ]; then
    pass "TSV sidecar: $TSV_FILES tsv file(s) created"
else
    fail "TSV sidecar" "no tsv files created"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi

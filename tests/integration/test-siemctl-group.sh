#!/usr/bin/env bash
# ── siemctl search GROUP BY integration test ──────────────────────────────
# Demonstrates `siemctl search --query "GROUP BY f1,f2"`: it counts unique
# combinations of indexed fields, merging counts across the per-hour SQLite
# buckets, and emits the result through the shared render layer (so --format /
# --limit apply). Also exercises the new "filter then group" capability.
#
# The demonstration data is tests/fixtures/mixed.log run through the real
# pipeline (normalized → indexd). In that fixture only the `source` column is
# populated, and the sshd events straddle two hourly buckets (9 in one, 1 in
# the next) — which is exactly what makes it a good cross-bucket-merge demo:
# `--group source` must report sshd=10.
#
# Usage: ./tests/integration/test-siemctl-group.sh   (run from anywhere)
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
FIXTURE="$PROJECT_ROOT/tests/fixtures/mixed.log"

PASS=0; FAIL=0
pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1: $2"; FAIL=$((FAIL + 1)); }

# Show a command and its output, then assert the output contains a substring.
demo_contains() {
    local desc="$1" needle="$2"; shift 2
    local out; out="$("$@" 2>&1)" || true
    echo "  \$ ${*##*/siemctl} "         # print the (trimmed) command
    echo "$out" | sed 's/^/      /'        # indent the output
    if grep -qF -- "$needle" <<< "$out"; then pass "$desc"; else fail "$desc" "missing '$needle'"; fi
}

# Assert a command exits non-zero (error path) and its stderr mentions a phrase.
demo_rejects() {
    local desc="$1" needle="$2"; shift 2
    local out rc
    out="$("$@" 2>&1)" && rc=0 || rc=$?
    echo "  \$ ${*##*/siemctl}"
    echo "$out" | sed 's/^/      /'
    if [ "$rc" -ne 0 ] && grep -qF -- "$needle" <<< "$out"; then
        pass "$desc"
    else
        fail "$desc" "expected non-zero exit mentioning '$needle' (rc=$rc)"
    fi
}

for bin in "$NORMALIZED" "$INDEXD" "$SIEMCTL"; do
    [ -x "$bin" ] || { echo "missing debug binary: $bin (run 'cargo build' in its crate)"; exit 1; }
done

TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT

echo "=== siemctl GROUP BY Integration Test ==="
echo ""

# ── Build the index from the fixture (normalized → indexd) ────────────────
echo "[setup] normalizing $FIXTURE → $TEST_DIR/raw, then indexing"
cat "$FIXTURE" | "$NORMALIZED" --stdin --data-dir "$TEST_DIR" >/dev/null 2>&1

"$INDEXD" --data-dir "$TEST_DIR" > "$TEST_DIR/indexd.log" 2>&1 &
INDEXD_PID=$!
for _ in $(seq 1 10); do
    grep -q "watching" "$TEST_DIR/indexd.log" 2>/dev/null && break
    sleep 1
done
kill -9 "$INDEXD_PID" 2>/dev/null || true
wait "$INDEXD_PID" 2>/dev/null || true

BUCKETS=$(find "$TEST_DIR/index" -name '*.db' | wc -l)
echo "  built $BUCKETS index bucket(s):"
find "$TEST_DIR/index" -name '*.db' -printf '      %f\n' | sort
[ "$BUCKETS" -ge 2 ] && pass "setup: ≥2 hourly buckets (cross-bucket merge is exercised)" \
                      || fail "setup" "expected ≥2 buckets, got $BUCKETS"
echo ""

# ── 1. Single-field grouping, counts merged across buckets ────────────────
echo "[1] GROUP BY source  (sshd spans 2 buckets → must report 10)"
demo_contains "sshd count merged across buckets = 10" '{"source":"sshd","count":10}' \
    "$SIEMCTL" search --data-dir "$TEST_DIR" --query "GROUP BY source"
echo ""

echo "[2] other source counts are present"
GROUP_OUT="$("$SIEMCTL" search --data-dir "$TEST_DIR" --query "GROUP BY source" 2>&1)" || true
for kv in '"source":"iptables","count":6' '"source":"systemd","count":5' '"source":"sudo","count":4'; do
    grep -qF -- "$kv" <<< "$GROUP_OUT" && pass "contains $kv" || fail "count" "missing $kv"
done
echo ""

# ── 3. Sorted by count descending (sshd=10 is the first line) ─────────────
echo "[3] output is sorted by count descending"
FIRST_LINE="$(head -1 <<< "$GROUP_OUT")"
echo "      first line: $FIRST_LINE"
[ "$FIRST_LINE" = '{"source":"sshd","count":10}' ] \
    && pass "highest count (sshd=10) sorts first" \
    || fail "sort" "first line was: $FIRST_LINE"
echo ""

# ── 4. TSV format: header + a count column ────────────────────────────────
echo '[4] GROUP BY source --format tsv'
demo_contains "tsv header is 'source<TAB>count'" "$(printf 'source\tcount')" \
    "$SIEMCTL" search --data-dir "$TEST_DIR" --query "GROUP BY source" --format tsv
echo ""

# ── 5. LIMIT caps the number of group rows emitted ────────────────────────
echo '[5] GROUP BY source LIMIT 2  (top 2 only)'
LIMIT_OUT="$("$SIEMCTL" search --data-dir "$TEST_DIR" --query "GROUP BY source LIMIT 2" 2>&1)" || true
echo "$LIMIT_OUT" | sed 's/^/      /'
LIMIT_LINES=$(grep -c '"count"' <<< "$LIMIT_OUT")
[ "$LIMIT_LINES" -eq 2 ] && pass "LIMIT 2 emits exactly 2 rows" \
                         || fail "LIMIT" "expected 2 rows, got $LIMIT_LINES"
echo ""

# ── 6. Filter then group (new capability: predicate + GROUP BY) ───────────
echo '[6] source == sshd GROUP BY source  (filter then group)'
FILTERED_OUT="$("$SIEMCTL" search --data-dir "$TEST_DIR" --query "source == sshd GROUP BY source" 2>&1)" || true
echo "$FILTERED_OUT" | sed 's/^/      /'
# Only the sshd combo survives the predicate, still counting 10 across buckets.
{ [ "$(grep -c '"count"' <<< "$FILTERED_OUT")" -eq 1 ] \
    && grep -qF -- '{"source":"sshd","count":10}' <<< "$FILTERED_OUT"; } \
    && pass "predicate restricts grouping to sshd=10 only" \
    || fail "filter-then-group" "unexpected output: $FILTERED_OUT"
echo ""

# ── 7. Two-field grouping works; total across combos = 25 events ──────────
echo '[7] GROUP BY source, event_type  (multi-field SQL + merge)'
TWO_OUT="$("$SIEMCTL" search --data-dir "$TEST_DIR" --query "GROUP BY source, event_type" 2>&1)" || true
echo "$TWO_OUT" | sed 's/^/      /'
TWO_TOTAL=$(grep -oE '"count":[0-9]+' <<< "$TWO_OUT" | grep -oE '[0-9]+' | awk '{s+=$1} END {print s+0}')
[ "${TWO_TOTAL:-0}" -eq 25 ] && pass "combo counts sum to all 25 indexed events" \
                             || fail "two-field" "counts summed to ${TWO_TOTAL:-0}, expected 25"
echo ""

# ── 8. Error paths: DSL parse/validation rejects bad input ────────────────
echo "[8] error paths"
demo_rejects "rejects an unknown function" "unknown function" \
    "$SIEMCTL" search --data-dir "$TEST_DIR" --query "frobnicate(source,'x')"
demo_rejects "rejects an unknown field" "unknown field" \
    "$SIEMCTL" search --data-dir "$TEST_DIR" --query "GROUP BY not_a_field"
demo_rejects "rejects an unsafe field name (SQL-injection guard)" "invalid field name" \
    "$SIEMCTL" search --data-dir "$TEST_DIR" --query "GROUP BY src_ip-drop"
echo ""

echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -gt 0 ] && exit 1; exit 0

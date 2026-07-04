#!/usr/bin/env bash
# ── siemctl stats integration test ──────────────────────────────────────────
# Runs a synthetic multi-hour fixture through the real pipeline (normalized
# → indexd) and asserts on `siemctl stats` CLI behavior: the aggregate
# --after/--before path (including a regression check for a real bug found
# while building --interval: bucket-filename parsing used the CLI-argument
# parser, which requires a "T" separator and silently never matched
# dash-separated ".db" filenames, so --after/--before did not filter at
# all), and the --interval/--last volume-trend table (roadmap item 5).
#
# Fixture design: four adjacent hours, 2026-07-01 12:00 through 16:00, using
# RFC5424 lines with explicit UTC offsets so every event lands in an exact,
# deterministic bucket (RFC3164 lines have no year and bucket relative to
# wall-clock "now", which would make this test flaky).
#
# Usage: ./tests/integration/test-siemctl-stats.sh   (run from anywhere)
# Per CLAUDE.md, integration tests use the DEBUG binaries — build them first.

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

for bin in "$NORMALIZED" "$INDEXD" "$SIEMCTL"; do
    [ -x "$bin" ] || { echo "missing debug binary: $bin (run 'cargo build' in its crate)"; exit 1; }
done

TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT

echo "=== siemctl stats Integration Test ==="
echo ""

# ── Fixture ─────────────────────────────────────────────────────────────
# Hour 12: 2 cron. Hour 13: 3 cron, 1 systemd. Hour 14: 1 cron, 2 sshd
# (sshd only exists in this hour — a "new source" for this window). Hour
# 15: 4 cron (a mini spike, to make the trend table's column-to-column
# variance visible). No events land in hour 16 at all, to exercise a
# zero-count column.
FIXTURE="$TEST_DIR/fixture.log"
cat > "$FIXTURE" <<'EOF'
<142>1 2026-07-01T12:10:00+00:00 myhost cron 1 - - (root) CMD (job-a)
<142>1 2026-07-01T12:40:00+00:00 myhost cron 1 - - (root) CMD (job-b)
<142>1 2026-07-01T13:05:00+00:00 myhost cron 1 - - (root) CMD (job-a)
<142>1 2026-07-01T13:20:00+00:00 myhost cron 1 - - (root) CMD (job-b)
<142>1 2026-07-01T13:35:00+00:00 myhost cron 1 - - (root) CMD (job-c)
<86>1 2026-07-01T13:50:00+00:00 myhost systemd 1 - - Started sshguard.service
<142>1 2026-07-01T14:05:00+00:00 myhost cron 1 - - (root) CMD (job-a)
<86>1 2026-07-01T14:10:00+00:00 myhost sshd 1234 - - Failed password for root from 203.0.113.5 port 22 ssh2
<86>1 2026-07-01T14:10:30+00:00 myhost sshd 1234 - - Failed password for root from 203.0.113.5 port 22 ssh2
<142>1 2026-07-01T15:05:00+00:00 myhost cron 1 - - (root) CMD (job-a)
<142>1 2026-07-01T15:15:00+00:00 myhost cron 1 - - (root) CMD (job-b)
<142>1 2026-07-01T15:25:00+00:00 myhost cron 1 - - (root) CMD (job-c)
<142>1 2026-07-01T15:35:00+00:00 myhost cron 1 - - (root) CMD (job-d)
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
[ "$BUCKETS" -ge 4 ] && pass "setup: 4 hourly buckets" \
                     || fail "setup" "expected 4 buckets, got $BUCKETS"

echo ""
echo "[1] aggregate --after/--before actually filters (regression: bucket-filename parsing bug)"
OUT="$("$SIEMCTL" stats --data-dir "$TEST_DIR" --after 2026-07-01T14 --before 2026-07-01T14 2>&1)" || true
echo "$OUT" | sed 's/^/      /'
if echo "$OUT" | grep -qE 'cron\s+1\b'; then
    pass "hour-14-only window shows cron=1 (not the 10-event grand total)"
else
    fail "aggregate --after/--before filtering" "$OUT"
fi
if echo "$OUT" | grep -q "sshd"; then
    pass "sshd (only present in hour 14) shows up when scoped to hour 14"
else
    fail "sshd visible in scoped window" "$OUT"
fi

echo ""
echo "[2] a window excluding all fixture data returns no data"
OUT="$("$SIEMCTL" stats --data-dir "$TEST_DIR" --after 2026-07-01T20 --before 2026-07-01T21 2>&1)" || true
if echo "$OUT" | grep -q "(no data)"; then
    pass "out-of-range window correctly shows no data"
else
    fail "out-of-range window" "$OUT"
fi

echo ""
echo "[3] --interval trend table: one column per hour, correct per-hour counts"
OUT="$("$SIEMCTL" stats --data-dir "$TEST_DIR" --interval 1h --after 2026-07-01T12 --before 2026-07-01T16 2>&1)" || true
echo "$OUT" | sed 's/^/      /'
HEADER="$(echo "$OUT" | head -1)"
for col in "12:00" "13:00" "14:00" "15:00" "16:00"; do
    if echo "$HEADER" | grep -q "$col"; then
        pass "trend header includes the $col column"
    else
        fail "trend header column $col" "$HEADER"
    fi
done
CRON_ROW="$(echo "$OUT" | grep '^cron')"
# cron counts per hour: 12=2, 13=3, 14=1, 15=4, 16=0
if echo "$CRON_ROW" | awk '{ exit !($2==2 && $3==3 && $4==1 && $5==4 && $6==0) }'; then
    pass "cron row shows 2,3,1,4,0 across the five hourly columns"
else
    fail "cron row per-hour counts" "$CRON_ROW"
fi
if echo "$OUT" | grep -q "^sshd"; then
    pass "sshd row present (only nonzero in the 14:00 column)"
else
    fail "sshd row present" "$OUT"
fi

echo ""
echo "[4] --interval groups multiple hours per column"
OUT="$("$SIEMCTL" stats --data-dir "$TEST_DIR" --interval 2h --after 2026-07-01T12 --before 2026-07-01T16 2>&1)" || true
echo "$OUT" | sed 's/^/      /'
CRON_ROW="$(echo "$OUT" | grep '^cron')"
# [12,13] -> 2+3=5, [14,15] -> 1+4=5, [16,17] -> 0
if echo "$CRON_ROW" | awk '{ exit !($2==5 && $3==5 && $4==0) }'; then
    pass "2h grouping sums adjacent hours correctly (5, 5, 0)"
else
    fail "2h grouping" "$CRON_ROW"
fi

echo ""
echo "[5] --source narrows the trend table to that source's event types"
OUT="$("$SIEMCTL" stats --data-dir "$TEST_DIR" --source cron --interval 1h --after 2026-07-01T12 --before 2026-07-01T13 2>&1)" || true
echo "$OUT" | sed 's/^/      /'
if echo "$OUT" | head -1 | grep -q "event_type"; then
    pass "trend header switches to 'event_type' with --source"
else
    fail "event_type header" "$OUT"
fi

echo ""
echo "[6] error paths"
# Captured via command substitution, not a live pipe into `grep -q`: with
# pipefail active, `grep -q` exiting early on its first match can SIGPIPE
# the still-writing upstream process, and pipefail then reports the whole
# pipeline as failed regardless of grep's own match — capture-then-grep
# sidesteps that race entirely (same reason the rest of this file does it).
OUT="$("$SIEMCTL" stats --data-dir "$TEST_DIR" --interval 1h 2>&1)" || true
if echo "$OUT" | grep -q "requires --last or --after/--before"; then
    pass "--interval without a range is a clear error"
else
    fail "--interval without range" "$OUT"
fi

OUT="$("$SIEMCTL" stats --data-dir "$TEST_DIR" --interval 30m --last 4h 2>&1)" || true
if echo "$OUT" | grep -q "whole number of hours"; then
    pass "sub-hour --interval is rejected"
else
    fail "sub-hour --interval rejected" "$OUT"
fi

OUT="$("$SIEMCTL" stats --data-dir "$TEST_DIR" --interval 1h --last 4h --after 2026-07-01T12 2>&1)" || true
if echo "$OUT" | grep -q "cannot be combined"; then
    pass "--last + --after together is a clear error"
else
    fail "--last/--after conflict" "$OUT"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -gt 0 ] && exit 1
exit 0

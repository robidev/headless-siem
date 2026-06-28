#!/usr/bin/env bash
# Integration tests for the indexd binary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$PROJECT_ROOT/src/indexd/target/release/indexd"

if [ ! -x "$BINARY" ]; then
    echo "Building indexd..."
    cd "$PROJECT_ROOT/src/indexd"
    source "$HOME/.cargo/env" 2>/dev/null || true
    cargo build --release
fi

PASS=0; FAIL=0
pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1: $2"; FAIL=$((FAIL + 1)); }

echo "=== indexd Integration Tests ==="
echo ""

echo "[1] --help prints usage"
"$BINARY" --help 2>&1 | grep -q "USAGE" && pass "--help" || fail "--help" "no USAGE"

echo "[2] unknown flag exits non-zero"
! "$BINARY" --nonexistent 2>/dev/null && pass "unknown flag" || fail "unknown flag" "exit 0"

echo "[3] process starts and responds to SIGTERM"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT
mkdir -p "$TMPDIR/data/raw"
"$BINARY" --data-dir "$TMPDIR/data" &
PID=$!
sleep 1
kill -0 $PID 2>/dev/null && pass "startup" || fail "startup" "died"
kill $PID 2>/dev/null; wait $PID 2>/dev/null || true

echo "[4] handles missing raw/ gracefully"
RMDIR=$(mktemp -d)
trap "rm -rf $TMPDIR $RMDIR" EXIT
"$BINARY" --data-dir "$RMDIR" &
PID=$!
sleep 1
kill -0 $PID 2>/dev/null && pass "missing raw/" || fail "missing raw/" "died"
kill $PID 2>/dev/null; wait $PID 2>/dev/null || true

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -gt 0 ] && exit 1; exit 0

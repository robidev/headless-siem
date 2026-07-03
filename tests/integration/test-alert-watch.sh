#!/usr/bin/env bash
# ── alert-watch.sh integration test ─────────────────────────────────────────
# Exercises the real script end-to-end against a temp data dir and a stub
# soc-notify (the real one is an llm-based-soc deployment artifact, not part
# of this repo — see llm-based-soc/documentation/escalation.md): starts the
# watcher, appends alert lines of each level, asserts which ones triggered a
# notify call and with what arguments, restarts it to check no history
# replay, and asserts a clean shutdown (no orphaned inotifywait process) —
# the exact failure mode that would otherwise double-notify every alert
# after a `systemctl restart`.
#
# Usage: ./tests/integration/test-alert-watch.sh   (run from anywhere)
# Requires: inotify-tools, jq.

set -uo pipefail
# Deliberately not `set -e`: individual assertions must not abort the whole
# suite on a failure.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WATCHER="$PROJECT_ROOT/config/notify/alert-watch.sh"

PASS=0; FAIL=0
pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1: $2"; FAIL=$((FAIL + 1)); }

command -v inotifywait >/dev/null 2>&1 || { echo "inotifywait (inotify-tools) is required"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 1; }
[ -x "$WATCHER" ] || { echo "missing or non-executable: $WATCHER"; exit 1; }

TEST_DIR="$(mktemp -d)"
WATCHER_PID=""
cleanup() {
    # Group-kill (see [4] below for why plain single-PID kill isn't
    # reliable) so a test that fails/exits early doesn't leak inotifywait.
    if [ -n "$WATCHER_PID" ]; then
        WATCHER_PGID="$(ps -o pgid= -p "$WATCHER_PID" 2>/dev/null | tr -d ' ')"
        kill -TERM -- "-${WATCHER_PGID:-$WATCHER_PID}" 2>/dev/null
    fi
    sleep 0.3
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

DATA_DIR="$TEST_DIR/data"
STATE_DIR="$TEST_DIR/state"
NOTIFY_LOG="$TEST_DIR/notify.log"
NOTIFY_SCRIPT="$TEST_DIR/soc-notify-stub.sh"

mkdir -p "$DATA_DIR/alerts" "$STATE_DIR"

cat > "$NOTIFY_SCRIPT" <<EOF
#!/usr/bin/env bash
echo "\$1|\$2|\$(cat "\$3" | tr '\\n' ' ')" >> "$NOTIFY_LOG"
exit 0
EOF
chmod +x "$NOTIFY_SCRIPT"

start_watcher() {
    # setsid: gives the watcher its own session/process group, isolated
    # from this test script's — without it, a non-interactive script's
    # background jobs share its own process group (no job control), so a
    # group-kill aimed at "stop just the watcher" would also kill the test
    # script running it. systemd isolates each unit into its own
    # session/cgroup the same way; this makes the test's kill target match
    # what a real `systemctl stop` actually signals.
    SIEM_DATA_DIR="$DATA_DIR" \
    ALERT_WATCH_STATE_DIR="$STATE_DIR" \
    SOC_NOTIFY_SCRIPT="$NOTIFY_SCRIPT" \
    ALERT_WATCH_LEVEL="high" \
    setsid "$WATCHER" > "$TEST_DIR/watch.log" 2>&1 &
    WATCHER_PID=$!
    # Wait for the baseline-established log line rather than a fixed sleep —
    # bounded poll, not an indefinite one.
    for _ in $(seq 1 50); do
        grep -q "watching" "$TEST_DIR/watch.log" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

notify_count() {
    [ -f "$NOTIFY_LOG" ] && wc -l < "$NOTIFY_LOG" || echo 0
}

wait_for_notify_count() {
    local expected="$1" waited=0
    while [ "$waited" -lt 30 ]; do
        [ "$(notify_count)" -ge "$expected" ] && return 0
        sleep 0.1
        waited=$((waited + 1))
    done
    return 1
}

echo "=== alert-watch.sh Integration Test ==="
echo ""

echo "[1] watcher starts and establishes baseline"
if start_watcher; then
    pass "watcher started (pid=$WATCHER_PID)"
else
    fail "watcher started" "did not log 'watching' within 5s — see $TEST_DIR/watch.log"
    cat "$TEST_DIR/watch.log" 2>/dev/null
fi

echo ""
echo "[2] level filtering: medium is suppressed, high and critical notify"
BUCKET="$DATA_DIR/alerts/2026/07/03/23"
mkdir -p "$BUCKET"
echo '{"_ruled":true,"rule_id":"low-rule","level":"low"}' >> "$BUCKET/alerts.jsonl"
echo '{"_ruled":true,"rule_id":"medium-rule","level":"medium"}' >> "$BUCKET/alerts.jsonl"
echo '{"_ruled":true,"rule_id":"high-rule","level":"high"}' >> "$BUCKET/alerts.jsonl"
echo '{"_ruled":true,"rule_id":"critical-rule","level":"critical"}' >> "$BUCKET/alerts.jsonl"

if wait_for_notify_count 2; then
    pass "exactly the high+critical alerts triggered a notify (2 calls)"
else
    fail "notify count" "expected 2 calls within 3s, got $(notify_count)"
fi

if grep -q "^high|\[high\] high-rule|" "$NOTIFY_LOG"; then
    pass "high-rule notified with priority=high and the right subject"
else
    fail "high-rule notify content" "$(cat "$NOTIFY_LOG")"
fi

if grep -q "^critical|\[critical\] critical-rule|" "$NOTIFY_LOG"; then
    pass "critical-rule notified with priority=critical"
else
    fail "critical-rule notify content" "$(cat "$NOTIFY_LOG")"
fi

if grep -q "low-rule\|medium-rule" "$NOTIFY_LOG"; then
    fail "low/medium suppressed" "found a notify call for a below-threshold alert"
else
    pass "low-rule and medium-rule correctly did not notify"
fi

echo ""
echo "[3] correlated alerts always notify (no level field to filter on)"
CORR_BUCKET="$DATA_DIR/alerts/correlated/2026/07/03/23"
mkdir -p "$CORR_BUCKET"
echo '{"_correlated":true,"correlation_id":"port-scan","correlation_title":"Port Scan"}' >> "$CORR_BUCKET/correlated.jsonl"

if wait_for_notify_count 3; then
    pass "correlated alert triggered a notify"
else
    fail "correlated notify" "expected 3rd call within 3s"
fi
if grep -q "port-scan" "$NOTIFY_LOG"; then
    pass "correlated alert's correlation_id used as the subject's rule identifier"
else
    fail "correlated notify content" "$(cat "$NOTIFY_LOG")"
fi

echo ""
echo "[4] clean shutdown: no orphaned inotifywait after stop"
INOTIFY_PID="$(pgrep -P "$WATCHER_PID" -f inotifywait | head -1 || true)"
if [ -z "$INOTIFY_PID" ]; then
    fail "inotifywait running before stop" "could not find its pid — can't test cleanup"
else
    # Signal the watcher's whole process group, not just its own PID —
    # this is what `KillMode=control-group` (the systemd unit's actual stop
    # mechanism; see config/systemd/headless-siem-alert-watch.service) does
    # in production, and is what the script's own internal
    # `trap ... kill -- -$$` relies on when NOT run under systemd. A plain
    # single-PID kill can leave a pipeline's other members (inotifywait)
    # orphaned if the shell backgrounding it didn't allocate a fresh
    # process group for the job — group-kill is correct either way.
    WATCHER_PGID="$(ps -o pgid= -p "$WATCHER_PID" 2>/dev/null | tr -d ' ')"
    kill -TERM -- "-${WATCHER_PGID:-$WATCHER_PID}"
    ok=0
    for _ in $(seq 1 30); do
        if ! kill -0 "$INOTIFY_PID" 2>/dev/null; then
            ok=1
            break
        fi
        sleep 0.1
    done
    if [ "$ok" -eq 1 ]; then
        pass "inotifywait (pid=$INOTIFY_PID) exited within 3s of stop"
    else
        fail "inotifywait cleanup" "still running 3s after stopping the watcher — this is the orphan bug that causes duplicate notifications on restart"
        kill -9 "$INOTIFY_PID" 2>/dev/null
    fi
    if grep -q "shutting down" "$TEST_DIR/watch.log"; then
        pass "watcher logged a shutdown message exactly once"
        SHUTDOWN_COUNT="$(grep -c "shutting down" "$TEST_DIR/watch.log")"
        [ "$SHUTDOWN_COUNT" -eq 1 ] || fail "shutdown message count" "logged $SHUTDOWN_COUNT times (trap re-entrancy bug)"
    else
        fail "shutdown log" "no 'shutting down' message found"
    fi
fi
WATCHER_PID=""  # already handled above; don't double-signal in the trap

echo ""
echo "[5] restart does not replay history (no duplicate notify on old alerts)"
rm -f "$NOTIFY_LOG"
if start_watcher; then
    pass "watcher restarted"
    sleep 1
    n="$(notify_count)"
    if [ "$n" -eq 0 ]; then
        pass "no notify calls on restart (existing alerts correctly not replayed)"
    else
        fail "no replay on restart" "expected 0 calls, got $n"
    fi
else
    fail "watcher restarted" "did not come back up"
fi

echo ""
echo "[6] a genuinely new alert after restart still notifies"
echo '{"_ruled":true,"rule_id":"post-restart","level":"critical"}' >> "$BUCKET/alerts.jsonl"
if wait_for_notify_count 1; then
    pass "post-restart critical alert notified"
else
    fail "post-restart notify" "expected 1 call within 3s"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -gt 0 ] && exit 1
exit 0

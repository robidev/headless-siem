#!/usr/bin/env bash
# Integration tests for ruled's --suppress flag (alert suppression rules).
# Unit tests in src/ruled/src/suppress.rs already cover the condition
# parser/evaluator exhaustively; this test exists to prove the end-to-end
# wiring: a matching suppression rule actually prevents an alert from being
# written by the real binary, a non-matching event is unaffected, an expired
# rule still suppresses (just with a warning), and the shutdown summary
# reports how many alerts were dropped.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RULED="$PROJECT_ROOT/target/debug/ruled"
RULES_DIR="$PROJECT_ROOT/config/rules"

if [ ! -x "$RULED" ]; then
    echo "Building ruled..."
    cd "$PROJECT_ROOT/src/ruled"
    source "$HOME/.cargo/env" 2>/dev/null || true
    cargo build
fi

PASS=0 FAIL=0
pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1: $2"; FAIL=$((FAIL + 1)); }

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "=== ruled --suppress Integration Tests ==="
echo ""

cat > "$TMP_DIR/suppress.toml" <<'EOF'
[[suppress]]
rule_id = "1001-ssh-brute-force"
condition = 'cidr_match(src_ip, "10.0.0.0/24")'
note = "internal scanner, known benign"
EOF

echo "[1] matching suppression rule drops the alert"
OUT=$(echo '{"_source_type":"sshd","event_type":"ssh_auth_failure","src_ip":"10.0.0.5"}' \
    | "$RULED" --rules "$RULES_DIR" --suppress "$TMP_DIR/suppress.toml" --dedup-window 0 2>/dev/null)
if [ -z "$OUT" ]; then
    pass "suppressed event produces no alert on stdout"
else
    fail "suppressed event produces no alert on stdout" "got: $OUT"
fi

echo "[2] non-matching event (different rule_id / src_ip) is unaffected"
OUT=$(echo '{"_source_type":"sshd","event_type":"ssh_auth_failure","src_ip":"203.0.113.5"}' \
    | "$RULED" --rules "$RULES_DIR" --suppress "$TMP_DIR/suppress.toml" --dedup-window 0 2>/dev/null)
echo "$OUT" | grep -q "1004-suspicious-ssh" \
    && pass "unrelated rule still fires for a non-matching src_ip" \
    || fail "unrelated rule still fires" "got: $OUT"

echo "[3] suppress.toml in config/rules/ is not picked up as a Sigma rule"
LOG=$(echo "" | "$RULED" --rules "$RULES_DIR" 2>&1 >/dev/null)
echo "$LOG" | grep -qE "loaded [0-9]+ rules" && pass "rule count unaffected by suppress.toml sitting in config/rules/" \
    || fail "rule count" "got: $LOG"

echo "[4] loading suppression rules is logged"
LOG=$(echo "" | "$RULED" --rules "$RULES_DIR" --suppress "$TMP_DIR/suppress.toml" 2>&1 >/dev/null)
echo "$LOG" | grep -q "loaded 1 suppression rule(s)" \
    && pass "suppression rule count logged at startup" \
    || fail "suppression rule count logged" "got: $LOG"

echo "[5] shutdown summary reports how many alerts were suppressed"
LOG=$(echo '{"_source_type":"sshd","event_type":"ssh_auth_failure","src_ip":"10.0.0.5"}' \
    | "$RULED" --rules "$RULES_DIR" --suppress "$TMP_DIR/suppress.toml" --dedup-window 0 2>&1 >/dev/null)
echo "$LOG" | grep -q "shutdown complete (1 alert(s) suppressed)" \
    && pass "shutdown summary reports 1 suppressed alert" \
    || fail "shutdown summary" "got: $LOG"

echo "[6] expired suppression rule still suppresses, but warns"
cat > "$TMP_DIR/expired.toml" <<'EOF'
[[suppress]]
rule_id = "1001-ssh-brute-force"
condition = 'cidr_match(src_ip, "10.0.0.0/24")'
expires = "2000-01-01"
EOF
STDOUT_OUT=$(echo '{"_source_type":"sshd","event_type":"ssh_auth_failure","src_ip":"10.0.0.5"}' \
    | "$RULED" --rules "$RULES_DIR" --suppress "$TMP_DIR/expired.toml" --dedup-window 0 2>"$TMP_DIR/stderr.log")
if [ -z "$STDOUT_OUT" ]; then
    pass "expired rule still suppresses the alert"
else
    fail "expired rule still suppresses" "got: $STDOUT_OUT"
fi
grep -q "expired on 2000-01-01" "$TMP_DIR/stderr.log" \
    && pass "expiry warning logged to stderr" \
    || fail "expiry warning logged" "stderr was: $(cat "$TMP_DIR/stderr.log")"

echo "[7] malformed suppression condition is skipped, not fatal"
cat > "$TMP_DIR/bad-condition.toml" <<'EOF'
[[suppress]]
rule_id = "1001-ssh-brute-force"
condition = "src_ip =="
EOF
STDOUT_OUT=$(echo '{"_source_type":"sshd","event_type":"ssh_auth_failure","src_ip":"10.0.0.5"}' \
    | "$RULED" --rules "$RULES_DIR" --suppress "$TMP_DIR/bad-condition.toml" --dedup-window 0 2>"$TMP_DIR/stderr2.log")
echo "$STDOUT_OUT" | grep -q "1001-ssh-brute-force" \
    && pass "alert still fires when its only suppression rule is malformed" \
    || fail "alert still fires despite bad suppression rule" "got: $STDOUT_OUT"
grep -q "invalid condition" "$TMP_DIR/stderr2.log" \
    && pass "malformed condition warning logged to stderr" \
    || fail "malformed condition warning logged" "stderr was: $(cat "$TMP_DIR/stderr2.log")"

echo "[8] malformed suppress.toml (bad TOML syntax) is fatal at startup"
echo "not valid toml [[[" > "$TMP_DIR/malformed.toml"
if echo "" | "$RULED" --rules "$RULES_DIR" --suppress "$TMP_DIR/malformed.toml" >/dev/null 2>"$TMP_DIR/stderr3.log"; then
    fail "malformed suppress.toml is fatal" "expected non-zero exit"
else
    pass "malformed suppress.toml is fatal"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -gt 0 ] && exit 1; exit 0

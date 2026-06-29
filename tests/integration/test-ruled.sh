#!/usr/bin/env bash
# Integration tests for the ruled binary.
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

echo "=== ruled Integration Tests ==="
echo ""

echo "[1] --help prints usage"
"$RULED" --help 2>&1 | grep -q "USAGE" && pass "--help" || fail "--help" "no USAGE"

echo "[2] unknown flag exits non-zero"
! "$RULED" --nonexistent 2>/dev/null && pass "unknown flag" || fail "unknown flag" "exit 0"

echo "[3] --rules required"
! "$RULED" 2>/dev/null && pass "--rules required" || fail "--rules required" "exit 0"

echo "[4] loads sample rules"
OUT=$("$RULED" --rules "$RULES_DIR" 2>&1 <<< "" || true)
echo "$OUT" | grep -q "loaded 5 rules" && pass "loads 5 rules" || fail "loads 5 rules" "got: $OUT"

echo "[5] matches SSH failed event"
RESULT=$(echo '{"_source_type":"sshd","event_type":"ssh_auth_failure","src_ip":"10.0.0.5"}' | "$RULED" --rules "$RULES_DIR" 2>/dev/null)
echo "$RESULT" | grep -q "1001-ssh-brute-force" && pass "SSH brute force match" || fail "SSH brute force" "no match"
echo "$RESULT" | grep -q "1004-suspicious-ssh" && fail "suspicious SSH" "should not match internal IP" || pass "suspicious SSH: internal IP filtered"

echo "[6] matches external SSH failed event"
RESULT=$(echo '{"_source_type":"sshd","event_type":"ssh_auth_failure","src_ip":"203.0.113.5"}' | "$RULED" --rules "$RULES_DIR" 2>/dev/null)
echo "$RESULT" | grep -q "1004-suspicious-ssh" && pass "suspicious SSH: external IP matched" || fail "suspicious SSH" "no match for external IP"

echo "[7] matches sudo command"
RESULT=$(echo '{"_source_type":"sudo","event_type":"sudo_command","username":"root"}' | "$RULED" --rules "$RULES_DIR" 2>/dev/null)
echo "$RESULT" | grep -q "1002-sudo-execution" && pass "sudo execution match" || fail "sudo execution" "no match"

echo "[8] matches iptables deny"
RESULT=$(echo '{"_source_type":"iptables","event_type":"firewall_block","src_ip":"10.0.0.5"}' | "$RULED" --rules "$RULES_DIR" 2>/dev/null)
echo "$RESULT" | grep -q "1003-iptables-deny" && pass "iptables deny match" || fail "iptables deny" "no match"

echo "[9] non-matching event produces no output"
RESULT=$(echo '{"_source_type":"systemd","event_type":"unit_started"}' | "$RULED" --rules "$RULES_DIR" 2>/dev/null)
[ -z "$RESULT" ] && pass "non-matching: no output" || fail "non-matching" "got output: $RESULT"

echo "[10] deduplication suppresses duplicates"
# Send the same event twice — second should be suppressed
RESULT=$(printf '%s\n%s\n' '{"_source_type":"sshd","event_type":"ssh_auth_failure","src_ip":"10.0.0.5"}' '{"_source_type":"sshd","event_type":"ssh_auth_failure","src_ip":"10.0.0.5"}' | "$RULED" --rules "$RULES_DIR" 2>/dev/null)
COUNT=$(echo "$RESULT" | grep -c "1001-ssh-brute-force" || true)
[ "$COUNT" -eq 1 ] && pass "dedup: 1 alert (not 2)" || fail "dedup" "got $COUNT alerts"

echo "[11] --output writes to filesystem"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT
echo '{"_source_type":"sshd","event_type":"ssh_auth_failure","src_ip":"10.0.0.5"}' | "$RULED" --rules "$RULES_DIR" --output "$TMPDIR" 2>/dev/null
# Find alerts.jsonl somewhere under TMPDIR
FOUND=$(find "$TMPDIR" -name "alerts.jsonl" 2>/dev/null | head -1)
[ -n "$FOUND" ] && pass "--output: alerts.jsonl created" || fail "--output" "no alerts.jsonl"
[ -n "$FOUND" ] && grep -q "1001-ssh-brute-force" "$FOUND" && pass "--output: correct content" || fail "--output" "wrong content"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -gt 0 ] && exit 1

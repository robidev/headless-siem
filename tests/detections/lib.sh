# shellcheck shell=bash
# Shared helpers for detection trigger tests.
#
# Each test injects crafted syslog lines into a *running* dev pipeline over UDP
# (the same path real logs take) and asserts that the expected alert or
# correlation alert appears under data/alerts/ or data/alerts/correlated/.
#
# Prereqs:
#   ./dev.sh start            (pipeline up, listening on $SIEM_PORT)
#   Count-based correlation tests additionally need dedup disabled:
#   SIEM_DEDUP_WINDOW=0 ./dev.sh restart
#
# Env overrides: SIEM_PORT (default 5514), SIEM_DATA_DIR (default ./data).

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${SIEM_PORT:-5514}"
DATA_DIR="${SIEM_DATA_DIR:-$REPO_ROOT/data}"
SETTLE="${SIEM_TEST_SETTLE:-10}"   # max seconds to wait for an alert to appear
SIEMCTL="$REPO_ROOT/target/debug/siemctl"

# Colors (disabled if not a tty)
if [ -t 1 ]; then
  C_GREEN=$'\e[32m'; C_RED=$'\e[31m'; C_YEL=$'\e[33m'; C_DIM=$'\e[2m'; C_OFF=$'\e[0m'
else
  C_GREEN=""; C_RED=""; C_YEL=""; C_DIM=""; C_OFF=""
fi

_TEST_NAME=""

detection_test() { _TEST_NAME="$1"; echo "── ${C_DIM}test:${C_OFF} $1"; }

now() { date +%s; }

# inject "<raw syslog line>" — send one UDP datagram to normalized.
inject() {
  if ! printf '%s\n' "$1" > "/dev/udp/127.0.0.1/$PORT" 2>/dev/null; then
    echo "${C_RED}ERROR:${C_OFF} cannot send to udp/127.0.0.1/$PORT — is the pipeline running?" >&2
    return 1
  fi
}

# Is the pipeline up? (normalized listening)
pipeline_up() {
  command -v ss >/dev/null 2>&1 || return 0
  ss -uln 2>/dev/null | grep -q ":$PORT\b"
}

# Current ruled dedup window (seconds), or empty if unknown.
# /proc/<pid>/cmdline is NUL-separated, so split on NUL (not space).
ruled_dedup_window() {
  local pidf="/tmp/headless-siem-dev/pids/ruled.pid"
  [ -f "$pidf" ] || return 0
  tr '\0' '\n' < "/proc/$(cat "$pidf")/cmdline" 2>/dev/null \
    | grep -A1 -x -- '--dedup-window' | tail -1
}

# Total alerts emitted for a rule_id (across all buckets).
count_rule() {
  find "$DATA_DIR/alerts" -name '*.jsonl' -exec cat {} \; 2>/dev/null \
    | jq -r --arg r "$1" 'select(.rule_id == $r) | .rule_id' 2>/dev/null | wc -l
}

# Total correlation alerts emitted for a correlation_id.
# Reads data/alerts/correlated/ — the same tree `siemctl alerts --correlated`
# queries. (Previously this read data/correlated/, which matched dev.sh's
# old --output path but not siemctl's read path — correlations "fired" but
# were invisible to any siemctl query. See implementation-plan.md 1.5.)
count_corr() {
  find "$DATA_DIR/alerts/correlated" -name '*.jsonl' -exec cat {} \; 2>/dev/null \
    | jq -r --arg c "$1" 'select(.correlation_id == $c) | .correlation_id' 2>/dev/null | wc -l
}

# Tests use a baseline-delta model (timestamp-independent): capture a baseline
# count, inject, then assert how many NEW alerts appeared. This is immune to the
# whole-second granularity of alert timestamps and to alerts from earlier tests.

# expect_new_rule RULE BASELINE [MIN=1] — poll until (count - baseline) >= MIN.
expect_new_rule() {
  local rule_id="$1" base="$2" min="${3:-1}" waited=0 n=0 d=0
  while [ "$waited" -lt "$SETTLE" ]; do
    n=$(count_rule "$rule_id"); d=$((n - base))
    [ "$d" -ge "$min" ] && { echo "  ${C_GREEN}PASS${C_OFF} $rule_id fired ($d new alert(s))"; return 0; }
    sleep 1; waited=$((waited + 1))
  done
  echo "  ${C_RED}FAIL${C_OFF} $rule_id did not fire (got $d new, need $min within ${SETTLE}s)"
  return 1
}

# expect_no_new_rule RULE BASELINE — negative control; assert no new alerts.
expect_no_new_rule() {
  local rule_id="$1" base="$2" n d
  sleep 4
  n=$(count_rule "$rule_id"); d=$((n - base))
  if [ "$d" -eq 0 ]; then echo "  ${C_GREEN}PASS${C_OFF} $rule_id correctly did not fire on benign input"; return 0; fi
  echo "  ${C_RED}FAIL${C_OFF} $rule_id fired $d time(s) on benign input (false positive)"
  return 1
}

# expect_new_corr CORR BASELINE — poll for a new correlation alert.
#
# Also asserts the alert is visible through `siemctl alerts --correlated` —
# the actual query interface an agent uses — not just present as a raw file
# on disk. This is the launcher-parity check the plan calls for: it fails
# if dev.sh's correlated --output path and siemctl's read path ever
# disagree again (this is exactly how the alerts-invisible-to-queries bug
# in implementation-plan.md 1.5 shipped undetected).
expect_new_corr() {
  local corr_id="$1" base="$2" waited=0 n=0 d=0
  while [ "$waited" -lt "$SETTLE" ]; do
    n=$(count_corr "$corr_id"); d=$((n - base))
    [ "$d" -ge 1 ] && break
    sleep 1; waited=$((waited + 1))
  done
  if [ "$d" -lt 1 ]; then
    echo "  ${C_RED}FAIL${C_OFF} correlation $corr_id did not fire within ${SETTLE}s"
    return 1
  fi
  echo "  ${C_GREEN}PASS${C_OFF} correlation $corr_id fired ($d new)"
  if [ -x "$SIEMCTL" ]; then
    if "$SIEMCTL" alerts --data-dir "$DATA_DIR" --correlated 2>/dev/null \
        | jq -e --arg c "$corr_id" 'select(.correlation_id == $c)' >/dev/null 2>&1; then
      echo "  ${C_GREEN}PASS${C_OFF} correlation $corr_id visible via 'siemctl alerts --correlated'"
    else
      echo "  ${C_RED}FAIL${C_OFF} correlation $corr_id fired but NOT visible via 'siemctl alerts --correlated' (writer/reader path mismatch)"
      return 1
    fi
  else
    echo "  ${C_YEL}SKIP${C_OFF} siemctl binary not built at $SIEMCTL — skipping query-interface check"
  fi
  return 0
}

# require_dedup_off — skip a count-based test unless ruled runs with --dedup-window 0.
require_dedup_off() {
  local w; w="$(ruled_dedup_window)"
  if [ "$w" != "0" ]; then
    echo "  ${C_YEL}SKIP${C_OFF} needs 'SIEM_DEDUP_WINDOW=0 ./dev.sh restart' (current dedup-window='${w:-unknown}')"
    return 1
  fi
  return 0
}

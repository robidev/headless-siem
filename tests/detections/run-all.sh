#!/usr/bin/env bash
# Run every detection trigger test against a running dev pipeline.
#
#   ./dev.sh start                          # or: SIEM_DEDUP_WINDOW=0 ./dev.sh restart
#   bash tests/detections/run-all.sh
#
# Per-event Sigma rule tests work with any dedup setting. The count-based
# correlation tests (sustained-brute-force, cred-brute-force-success, port-scan)
# self-SKIP unless ruled runs with --dedup-window 0, since dedup collapses the
# bursts they rely on. Exit code is non-zero if any test FAILs (SKIP is ok).

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/lib.sh"

if ! pipeline_up; then
  echo "${C_RED}Pipeline not listening on udp/$PORT.${C_OFF} Start it first: ./dev.sh start" >&2
  exit 2
fi

echo "Running detection tests (port=$PORT, data=$DATA_DIR, ruled dedup-window='$(ruled_dedup_window)')"
echo

pass=0; fail=0; skip=0; failed_names=()
for t in "$DIR"/test-*.sh; do
  out="$(bash "$t" 2>&1)"; rc=$?
  echo "$out"
  if   echo "$out" | grep -q "SKIP"  && [ $rc -eq 0 ] && ! echo "$out" | grep -q "PASS"; then
    skip=$((skip + 1))
  elif [ $rc -eq 0 ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1)); failed_names+=("$(basename "$t")")
  fi
  echo
done

echo "──────────────────────────────────────────────"
echo "${C_GREEN}PASS:$pass${C_OFF}  ${C_RED}FAIL:$fail${C_OFF}  ${C_YEL}SKIP:$skip${C_OFF}"
if [ $fail -gt 0 ]; then
  printf '  failed: %s\n' "${failed_names[@]}"
  exit 1
fi
exit 0

#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "correlation cred-brute-force-success — failures then a login"
require_dedup_off || exit 0
src="203.0.113.88"
base=$(count_corr "cred-brute-force-success")
for p in 1 2 3 4; do
  inject "<38>1 2026-07-01T00:00:00+00:00 victim sshd-session 1 - -  Failed password for user from ${src} port $((50000 + p)) ssh2"
done
sleep 1
inject "<38>1 2026-07-01T00:00:00+00:00 victim sshd-session 1 - -  Accepted password for user from ${src} port 50099 ssh2"
expect_new_corr "cred-brute-force-success" "$base"

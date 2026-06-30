#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "correlation sustained-brute-force — 10+ failures from one IP"
require_dedup_off || exit 0
src="203.0.113.77"
base=$(count_corr "sustained-brute-force")
for p in $(seq 1 11); do
  inject "<38>1 2026-07-01T00:00:00+00:00 victim sshd-session 1 - -  Failed password for user from ${src} port $((40000 + p)) ssh2"
done
expect_new_corr "sustained-brute-force" "$base"

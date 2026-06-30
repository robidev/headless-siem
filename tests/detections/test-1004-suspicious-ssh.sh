#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "1004-suspicious-ssh — failed SSH from external IP"
rc=0
base=$(count_rule "1004-suspicious-ssh")
inject '<38>1 2026-07-01T00:00:00+00:00 victim sshd-session 1 - -  Failed password for root from 198.51.100.23 port 3333 ssh2'
expect_new_rule "1004-suspicious-ssh" "$base" || rc=1
# Negative control: a failure from a 10.0.* address is excluded by the rule filter.
base=$(count_rule "1004-suspicious-ssh")
inject '<38>1 2026-07-01T00:00:00+00:00 victim sshd-session 1 - -  Failed password for root from 10.0.0.5 port 3333 ssh2'
expect_no_new_rule "1004-suspicious-ssh" "$base" || rc=1
exit $rc

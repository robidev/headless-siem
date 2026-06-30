#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "1008-sudo-privilege-escalation — sudo to a root shell"
rc=0
base=$(count_rule "1008-sudo-privilege-escalation")
inject '<85>Jul  1 00:00:00 victim sudo[1]: mallory : TTY=pts/0 ; PWD=/home/mallory ; USER=root ; COMMAND=/usr/bin/bash'
expect_new_rule "1008-sudo-privilege-escalation" "$base" || rc=1
base=$(count_rule "1008-sudo-privilege-escalation")
inject '<85>Jul  1 00:00:00 victim sudo[1]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update'
expect_no_new_rule "1008-sudo-privilege-escalation" "$base" || rc=1
exit $rc

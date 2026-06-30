#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "1002-sudo-execution — any sudo command"
base=$(count_rule "1002-sudo-execution")
inject '<85>Jul  1 00:00:00 victim sudo[1]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id'
expect_new_rule "1002-sudo-execution" "$base"

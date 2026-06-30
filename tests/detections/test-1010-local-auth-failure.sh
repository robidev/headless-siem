#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "1010-local-auth-failure — unix_chkpwd failed check"
base=$(count_rule "1010-local-auth-failure")
inject '<85>1 2026-07-01T00:00:00+00:00 victim unix_chkpwd 1 - -  password check failed for user (admin)'
expect_new_rule "1010-local-auth-failure" "$base"

#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "1005-ssh-login-success — accepted SSH auth"
base=$(count_rule "1005-ssh-login-success")
inject '<38>1 2026-07-01T00:00:00+00:00 victim sshd-session 1 - -  Accepted password for user from 10.10.50.11 port 22 ssh2'
expect_new_rule "1005-ssh-login-success" "$base"

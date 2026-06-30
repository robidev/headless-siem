#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "1001-ssh-brute-force — failed SSH password"
base=$(count_rule "1001-ssh-brute-force")
inject '<38>1 2026-07-01T00:00:00+00:00 victim sshd-session 1 - -  Failed password for user from 203.0.113.5 port 2222 ssh2'
expect_new_rule "1001-ssh-brute-force" "$base"

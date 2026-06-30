#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "1003-iptables-deny — UFW block (kernel->iptables)"
base=$(count_rule "1003-iptables-deny")
inject '<4>Jul  1 00:00:00 victim kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=00:11 SRC=203.0.113.9 DST=10.0.0.1 LEN=40 PROTO=TCP SPT=4444 DPT=22 TTL=54'
expect_new_rule "1003-iptables-deny" "$base"

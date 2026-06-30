#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "1009-firewall-port-scan — single filterlog block (per-event)"
base=$(count_rule "1009-firewall-port-scan")
inject '<134>1 2026-07-01T00:00:00+00:00 FW1.homelab.lan filterlog 1 - - 80,,,1,re2.500,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,203.0.113.50,10.10.60.10,40000,9999,0,S,1,,64240,,mss'
expect_new_rule "1009-firewall-port-scan" "$base"

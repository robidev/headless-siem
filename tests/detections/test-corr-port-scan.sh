#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "correlation port-scan — 15+ firewall blocks from one IP"
require_dedup_off || exit 0
src="203.0.113.99"
base=$(count_corr "port-scan")
for dport in $(seq 1 16); do
  inject "<134>1 2026-07-01T00:00:00+00:00 FW1.homelab.lan filterlog 1 - - 80,,,1,re2.500,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,${src},10.10.60.10,40000,$((1000 + dport)),0,S,1,,64240,,mss"
done
expect_new_corr "port-scan" "$base"

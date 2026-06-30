#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "1007-haproxy-tls-probe — rejected TLS handshake"
base=$(count_rule "1007-haproxy-tls-probe")
inject '<134>Jul  1 00:00:00 haproxy haproxy[1]: 203.0.113.7:50001 [01/Jul/2026:00:00:00.000] proxmox_reverse_proxy/192.168.178.12:8006: SSL handshake failure (error:0A0000C7:SSL routines::peer did not return a certificate)'
expect_new_rule "1007-haproxy-tls-probe" "$base"

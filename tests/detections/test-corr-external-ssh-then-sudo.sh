#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; source "$DIR/lib.sh"
detection_test "correlation external-ssh-then-sudo"
# KNOWN LIMITATION: this correlation joins on src_ip, but sudo events are local
# and carry no src_ip, so the suspicious-ssh (remote IP) and sudo-execution
# (no IP) alerts never share a join value and the chain cannot complete with the
# current field mapping. Documented in docs/detections/external-ssh-then-sudo.md.
echo "  ${C_YEL}SKIP${C_OFF} not triggerable: sudo events lack src_ip to join on (see doc)"
exit 0

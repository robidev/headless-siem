# 1003 — IPTables / UFW Firewall Deny

| | |
|---|---|
| Rule ID | `1003-iptables-deny` |
| File | `config/rules/iptables-deny.yml` |
| Severity | low |
| Source | `iptables` (host UFW/iptables via kernel log) |
| ATT&CK | [T1046](https://attack.mitre.org/techniques/T1046/) |
| Status | stable |

## Rule
Fires on `event_type: firewall_block` from `_source_type: iptables` — a host
iptables/UFW deny. This is the host-firewall analogue of the pfSense
[1009](1009-firewall-port-scan.md) rule.

## Risk
Host-level firewall denies show traffic that reached a host but was refused —
useful for spotting lateral movement attempts and local scanning that never
crosses the perimeter firewall.

## Implementation
- **Parsing:** kernel UFW lines (`[UFW BLOCK] … SRC=… DST=… DPT=…`) are relabeled
  to source `iptables` by an override rule, and the `kernel` extract block
  captures `src_ip`/`dst_ip`/`dst_port`/`protocol` and sets `firewall_block`.
- **Detection:** single-event selection on `_source_type: iptables` +
  `event_type: firewall_block`.

## False positives
- Routine blocked broadcast/multicast and internet background noise.
- A misconfigured local client repeatedly hitting a closed port.

## Playbook
1. Pivot on `src_ip`: many denies to many `dst_port` from one source = scan.
2. Distinguish internal vs external source (network-topology). An internal host
   scanning peers is a strong compromise signal — isolate and investigate.

## Test
`bash tests/detections/test-1003-iptables-deny.sh`.

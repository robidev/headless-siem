# port-scan — Port Scan / Network Reconnaissance

| | |
|---|---|
| Correlation ID | `port-scan` |
| File | `config/correlations.toml` |
| Window | 120s |
| Join | `src_ip` |
| ATT&CK | [T1046](https://attack.mitre.org/techniques/T1046/) |

## Rule
A single source IP triggers rule [1009](1009-firewall-port-scan.md)
(pfSense `firewall_block`) **15+ times within 2 minutes**. One unordered step,
`min_count = 15`, joined on `src_ip`.

## Risk
Many firewall blocks from one source in a short window — typically across many
destination ports/hosts — is a port scan, the reconnaissance that precedes
exploitation and lateral movement.

## Implementation
- Step: `rule_id = 1009-firewall-port-scan`, `min_count = 15`.
- **Requires `ruled --dedup-window 0`.** A scan produces many
  `firewall_block` events that share `src_ip|event_type`; the default dedup would
  collapse them. Run `SIEM_DEDUP_WINDOW=0 ./dev.sh restart`.

## False positives
- A busy legitimate host (P2P, many short-lived connections) tripping default
  blocks. Distinguish by whether many *distinct* ports/hosts are involved and
  whether the source has a reason to reach those services.
- External internet background scanning hitting the WAN — common, lower priority
  than an **internal** source scanning internal subnets.

## Playbook
1. Note `join_value` (scanner IP). Enumerate what it hit:
   `siemctl search --query "src_ip == <ip> AND event_type == firewall_block"`.
2. Internal source → likely compromised host pivoting; isolate and investigate.
   External source → block at pfSense and monitor for follow-on exploitation of
   any port that was *allowed*.
3. Confirm nothing the scanner probed is unintentionally exposed.

## Test
`bash tests/detections/test-corr-port-scan.sh` (self-skips unless dedup is off).

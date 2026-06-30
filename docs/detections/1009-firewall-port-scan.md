# 1009 — Firewall Block (filterlog)

| | |
|---|---|
| Rule ID | `1009-firewall-port-scan` |
| File | `config/rules/firewall-port-scan.yml` |
| Severity | low (per-event); escalates via the `port-scan` correlation |
| Source | `filterlog` (pfSense) |
| ATT&CK | [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/) |
| Status | stable |

## Rule
Fires on every pfSense `filterlog` block (`_source_type: filterlog`,
`event_type: firewall_block`). A single block is low-signal and informational;
the security value comes from volume, handled by the
[`port-scan`](port-scan.md) correlation.

## Risk
One source IP blocked across many destination ports/hosts in a short window is a
port scan — reconnaissance that usually precedes exploitation. Tracking blocks
per source turns routine firewall noise into a scan signal.

## Implementation
- **Parsing:** the `filterlog` override triggers `parsers/filterlog.rs`, which
  decodes the pfSense CSV and sets `action = BLOCK` / `event_type =
  firewall_block` plus `src_ip`, `dst_ip`, `dst_port`, `protocol`, `interface`.
- **Detection:** single-event selection. The [`port-scan`](port-scan.md)
  correlation counts these per `src_ip`.

## False positives
- Background multicast/broadcast noise (IGMP/mDNS/SSDP) blocked by default rules.
  These have no `dst_port` and rarely accumulate per a single unicast `src_ip`.
- Misconfigured internal clients retrying a blocked port — bursts from one
  internal IP to *one* port (not a scan; the correlation needs many ports).
- P2P / connection-heavy apps from a known host.

## Playbook
1. This per-event rule alone is informational — don't alert on it directly; use
   the `port-scan` correlation for actioning. To investigate a source:
   `siemctl search --query "src_ip == <ip> AND event_type == firewall_block"`.
2. Determine whether the source is internal or external (see network-topology).
   External scans hitting the WAN are common background noise; internal sources
   scanning internal subnets are far more concerning (possible compromised host).
3. For a confirmed internal scanner, isolate and investigate the host.

## Test
`bash tests/detections/test-1009-firewall-port-scan.sh` (per-event) and
`bash tests/detections/test-corr-port-scan.sh` (the scan correlation).

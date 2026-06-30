# 1004 — Suspicious SSH from External IP

| | |
|---|---|
| Rule ID | `1004-suspicious-ssh` |
| File | `config/rules/suspicious-ssh.yml` |
| Severity | high |
| Source | `sshd` |
| ATT&CK | [T1110](https://attack.mitre.org/techniques/T1110/) / [T1133](https://attack.mitre.org/techniques/T1133/) |
| Status | experimental |

## Rule
Fires on `event_type: ssh_auth_failure` **unless** `src_ip` starts with `10.0.`.
Condition: `selection and not filter`. Intended to surface failed SSH from
outside the internal network.

## Risk
A failed SSH login from a non-internal address is higher-signal than an internal
typo: it suggests external brute force or that an exposed host is being probed.

## Implementation
- **Parsing:** same `ssh_auth_failure` path as [1001](1001-ssh-brute-force.md).
- **Detection:** `selection` (ssh_auth_failure) `and not filter`
  (`src_ip|startswith "10.0."`).

## False positives / known issues
- **Internal-range mismatch:** the filter excludes `10.0.*`, but this
  environment's internal subnets are `10.10.50.0/24` and `10.10.60.0/24`
  (see the network-topology note). Failed logins from those *internal* hosts are
  **not** excluded and will fire this "external" rule. Update the filter to match
  the real internal ranges (e.g. `src_ip|startswith: "10.10."`) to reduce noise.
- Legitimate remote admins on dynamic IPs fat-fingering a password.

## Playbook
1. Confirm `src_ip` is genuinely external (cross-check network-topology).
2. Check for a paired success (1005 / cred-brute-force-success) from the same IP
   → escalate to suspected compromise.
3. Block hostile external sources at pfSense; enforce key-only auth on exposed
   hosts. Fix the internal-range filter if internal IPs are triggering this.

## Test
`bash tests/detections/test-1004-suspicious-ssh.sh` — external IP fires; a
`10.0.*` address is the negative control (does not fire).

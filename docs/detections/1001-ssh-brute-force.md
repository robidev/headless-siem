# 1001 — SSH Brute Force (failed authentication)

| | |
|---|---|
| Rule ID | `1001-ssh-brute-force` |
| File | `config/rules/ssh-brute-force.yml` |
| Severity | medium |
| Source | `sshd` |
| ATT&CK | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) |
| Status | stable |

## Rule
Fires on every `event_type: ssh_auth_failure` from `sshd` (a failed SSH
password/publickey attempt). This is the per-event building block; the
*sustained* and *guessing-then-success* patterns are correlations
([sustained-brute-force](sustained-brute-force.md),
[cred-brute-force-success](cred-brute-force-success.md)).

## Risk
Repeated failed SSH authentications are the classic signature of password
guessing against an exposed or internal SSH service (T1110).

## Implementation
- **Parsing:** the `sshd` extract block matches `Failed password|publickey for …
  from <ip> port <port>` and sets `event_type = ssh_auth_failure`, `src_ip`,
  `username`. OpenSSH 9.8+ logs under `sshd-session`; `normalized` canonicalizes
  that to `sshd`.
- **Detection:** single-event selection. Note `ruled` deduplicates identical
  `(src_ip|event_type)` alerts within `--dedup-window` (default 5s); set it to 0
  when feeding count-based correlations.

## False positives
- A user with a stale key/agent or wrong saved password retrying — low volume
  from a known internal host.
- Automation/monitoring with outdated credentials.
- Connection scanners that never complete auth (also surface as `ssh_scanner`).

## Playbook
1. Group by `src_ip` and `username`. Internal source → likely misconfig; external
   source with many attempts → brute force.
2. Check whether any attempt *succeeded* (1005 / cred-brute-force-success) from
   the same `src_ip` — if so, treat as a likely credential compromise.
3. Block the source at pfSense if external and hostile; ensure key-only auth and
   fail2ban-style throttling on exposed hosts.

## Test
`bash tests/detections/test-1001-ssh-brute-force.sh`.

# sustained-brute-force — Sustained SSH Brute Force from Single IP

| | |
|---|---|
| Correlation ID | `sustained-brute-force` |
| File | `config/correlations.toml` |
| Window | 600s |
| Join | `src_ip` |
| ATT&CK | [T1110](https://attack.mitre.org/techniques/T1110/) |

## Rule
A single source IP triggers rule [1001](1001-ssh-brute-force.md)
(`ssh_auth_failure`) **10+ times within 10 minutes**. One unordered step,
`min_count = 10`, joined on `src_ip`.

## Risk
Sustained failures from one source — even without an observed success — is an
active brute-force campaign. This is the catch-all that replaced the old
`--threshold` flag.

## Implementation
- Step: `rule_id = 1001-ssh-brute-force`, `min_count = 10`.
- **Requires `ruled --dedup-window 0`.** The default 5s dedup keys on
  `src_ip|event_type`, so a rapid burst of identical failures collapses into one
  alert and never reaches 10. Run `SIEM_DEDUP_WINDOW=0 ./dev.sh restart`.

## False positives
- A misconfigured legitimate client (stale key/agent) retrying fast can exceed 10
  in 10 minutes from a known internal IP. Triage by whether the source is known.
- Security scanners / pentest tooling run with authorization.

## Playbook
1. Identify `join_value` (the source IP) and review `sample_events` for targeted
   usernames and host.
2. Check for any success from the same IP (→ escalate to
   [cred-brute-force-success](cred-brute-force-success.md) severity).
3. Block the source at pfSense if external; for internal sources investigate the
   originating host for compromise. Enforce key-only auth and rate limiting.

## Test
`bash tests/detections/test-corr-sustained-brute-force.sh` (self-skips unless
dedup is off).

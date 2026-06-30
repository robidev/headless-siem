# cred-brute-force-success — Credential Guessing Followed by Login Success

| | |
|---|---|
| Correlation ID | `cred-brute-force-success` |
| File | `config/correlations.toml` |
| Window | 300s |
| Join | `src_ip` |
| Ordered | yes |
| ATT&CK | [T1110](https://attack.mitre.org/techniques/T1110/) / [T1078](https://attack.mitre.org/techniques/T1078/) |

## Rule
From the same `src_ip` within 5 minutes, **ordered**: 3+ failures
([1001](1001-ssh-brute-force.md)) **then** a success
([1005](1005-ssh-login-success.md)).

## Risk
Failures immediately followed by a success from the same source is the
highest-confidence signal of a **guessed/cracked credential** — the attacker now
has valid access (T1078). This is one of the most actionable detections here.

## Implementation
- Step 1: `1001-ssh-brute-force`, `min_count = 3`; Step 2: `1005-ssh-login-success`,
  `min_count = 1`; `ordered = true`, join `src_ip`.
- **Requires `ruled --dedup-window 0`** so the 3 failures are counted (see
  [sustained-brute-force](sustained-brute-force.md)).

## False positives
- A real user who mistyped their password a few times and then logged in
  successfully — same shape as an attacker. Triage by source IP reputation, the
  username, and whether the timing/location is expected for that user.

## Playbook
1. **Treat the account as potentially compromised.** Note `join_value` (source
   IP) and the `username` from `sample_events`.
2. Review what the session did after login: sudo (1008), new sessions
   (`systemd-logind`), file/credential access.
3. Lock/reset the affected account, rotate keys/secrets it can reach, and block
   the source. Hunt for persistence created during the session.

## Test
`bash tests/detections/test-corr-cred-brute-force-success.sh` (self-skips unless
dedup is off).

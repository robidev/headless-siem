# 1005 — SSH Login Success

| | |
|---|---|
| Rule ID | `1005-ssh-login-success` |
| File | `config/rules/ssh-login-success.yml` |
| Severity | info |
| Source | `sshd` |
| ATT&CK | [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| Status | stable |

## Rule
Fires on `event_type: ssh_auth_success` — a successful SSH authentication
(password or publickey).

## Risk
On its own a successful login is benign/informational, but it is essential
context: a success **following** failures from the same source is the signature
of a guessed credential (see [cred-brute-force-success](cred-brute-force-success.md)).

## Implementation
- **Parsing:** the `sshd` extract block matches `Accepted password|publickey for
  <user> from <ip> …` → `event_type = ssh_auth_success`, `username`, `src_ip`,
  and `key_type`/`key_fingerprint` for publickey.
- **Detection:** single-event selection; primarily consumed by the
  cred-brute-force-success correlation as step 2.

## False positives
- Effectively all events are "true" successful logins; this is a visibility feed,
  not an alert. Route to logging/search.

## Playbook
1. Use as enrichment: when triaging a brute-force source, check for a 1005 from
   the same `src_ip`/`username`.
2. For unexpected successful logins (off-hours, unusual source, service account
   logging in interactively), verify with the account owner and review the
   session's subsequent activity (sudo, new sessions).

## Test
`bash tests/detections/test-1005-ssh-login-success.sh`.

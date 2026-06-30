# 1010 — Local Authentication Failure

| | |
|---|---|
| Rule ID | `1010-local-auth-failure` |
| File | `config/rules/local-auth-failure.yml` |
| Severity | medium |
| Source | `unix_chkpwd` |
| ATT&CK | [T1110](https://attack.mitre.org/techniques/T1110/) / [T1078](https://attack.mitre.org/techniques/T1078/) |
| Status | stable |

## Rule
Fires on `event_type: local_auth_failure` — the `unix_chkpwd` PAM helper
reporting a failed password check.

## Risk
`unix_chkpwd` verifies passwords for PAM consumers that are not SSH: `su`,
`login` (console/serial), screen-lock, `sudo` fallback, etc. Repeated failures
for a user indicate local password guessing — typically an attacker who already
has a foothold (a shell as a low-privileged user) trying to `su` to another
account, or console brute force. It complements the SSH-side rules (1001/1004),
which never see these local attempts.

## Implementation
- **Parsing:** `[[extract.rule]] app_name = "unix_chkpwd"` matches
  `password check failed for user (<user>)`, capturing `username` and setting
  `event_type = local_auth_failure`.
- **Detection:** single-event selection on `_source_type: unix_chkpwd` +
  `event_type: local_auth_failure`.

## False positives
- A user fat-fingering their password at a `su`/login/lock prompt. Single,
  isolated failures are usually benign; severity comes from repetition.
- Scripts or automation with a stale cached password hammering `su`.
- Screen-lock unlock typos after returning to a workstation.

## Playbook
1. Group failures by `username` + `hostname` over a short window. A few →
   probably a typo; many in seconds/minutes → guessing.
2. Identify the session generating them: check `systemd-logind` (`session_new`)
   and `sshd` (`ssh_auth_success`) around the same time to see who is on the host
   and from where.
3. If guessing is confirmed: determine the source session/user (possible prior
   compromise), lock the targeted account, and investigate how the attacker
   reached a local prompt in the first place.
4. Consider a correlation that escalates N local failures per host/user, and
   ensure SSH and local auth are reviewed together.

## Test
`bash tests/detections/test-1010-local-auth-failure.sh` — injects a
`unix_chkpwd … password check failed for user (admin)` line.

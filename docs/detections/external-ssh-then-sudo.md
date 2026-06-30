# external-ssh-then-sudo — External SSH Probe Followed by Sudo

| | |
|---|---|
| Correlation ID | `external-ssh-then-sudo` |
| File | `config/correlations.toml` |
| Window | 600s |
| Join | `src_ip` |
| Ordered | no |
| ATT&CK | [T1078](https://attack.mitre.org/techniques/T1078/) / [T1548](https://attack.mitre.org/techniques/T1548/) |

## Rule
Within 10 minutes, the same `src_ip` triggers both
[1004](1004-suspicious-ssh.md) (suspicious external SSH) **and**
[1002](1002-sudo-execution.md) (a sudo execution) — intended to flag lateral
movement / privilege escalation after external access.

## Risk
An external actor who gets in via SSH and then escalates with sudo is a classic
intrusion chain. Correlating the two on a shared identifier would catch it.

## ⚠️ Known limitation (currently not triggerable)
The correlation joins on `src_ip`, but **`sudo` events have no `src_ip`** — sudo
is local and its logs carry the host/user, not the remote address that opened the
SSH session. So the 1004 alert (which has the remote `src_ip`) and the 1002 alert
(which has none) never share a `join_value`, and the chain cannot complete. This
is noted inline in `config/correlations.toml`.

To make it work, one of:
- **Add a join bridge:** enrich sudo events with the originating remote IP (e.g.
  map the local TTY/session to the `sshd` `ssh_auth_success` `src_ip` via
  `systemd-logind` session correlation), then join on that.
- **Re-join on `username`/`hostname`:** correlate the SSH-authenticated user with
  their sudo activity instead of by IP (different, weaker, semantics).

Until then, the trigger test for this rule reports **SKIP** with this reason.

## Playbook
1. Treat as a design backlog item (see options above) rather than a live alert.
2. In the interim, manually pivot: for a suspicious external SSH source (1004),
   identify the authenticated `username` (1005 / `systemd-logind`) and review
   that user's sudo activity (1002/1008) on the target host.

## Test
`bash tests/detections/test-corr-external-ssh-then-sudo.sh` — intentionally
SKIPs, documenting the join limitation above.

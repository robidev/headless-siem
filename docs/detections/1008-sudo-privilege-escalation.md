# 1008 — Sudo Root Shell or Sensitive Binary

| | |
|---|---|
| Rule ID | `1008-sudo-privilege-escalation` |
| File | `config/rules/sudo-privilege-escalation.yml` |
| Severity | high |
| Source | `sudo` |
| ATT&CK | [T1548.003 Abuse Elevation Control: Sudo](https://attack.mitre.org/techniques/T1548/003/) |
| Status | experimental |

## Rule
Fires when a `sudo` command (`event_type: sudo_command`) targets `root`
(`target_user: root`) and the executed `command` is an interactive shell or a
sensitive account/credential binary: `/bash`, `/sh` (endswith), `/dash`, `/zsh`,
`/su`, `/passwd`, `visudo`, `useradd`. Condition: `selection and 1 of p_*`.

## Risk
Spawning a root shell via `sudo` (e.g. `sudo bash`, `sudo su -`) drops the
per-command auditing that makes sudo useful and gives the user an unlogged root
session. The same pattern covers direct account manipulation (`useradd`,
`passwd`, `visudo`). This is narrower and higher-signal than rule 1002, which
records every sudo command.

## Implementation
- **Parsing:** the `sudo` extract block sets `event_type = sudo_command` and
  captures `username` (invoker), `target_user`, `tty`, `pwd`, `command`.
- **Detection:** selection pins `target_user: root` + `event_type: sudo_command`;
  eight `command|contains`/`endswith` selections OR'd via `1 of p_*`.

## False positives
- Administrators legitimately opening a root shell for maintenance. This is
  expected and the rule is meant to make it *visible*, not to imply malice —
  triage by whether the `username` and timing are expected.
- Config-management/automation that runs `sudo bash -c '…'`. Allow-list the
  automation account if it is noisy.
- `useradd`/`passwd` during legitimate provisioning.

## False negatives / notes
- An interactive shell reached another way (e.g. `sudo vim` then `:!sh`) is not
  caught here — that is GTFOBins-style abuse; consider command allow-listing for
  high-value hosts.

## Playbook
1. Identify `username` (who), `hostname` (where), `tty`, `pwd`, and the exact
   `command`. Cross-check with 1005/1010 to see how that user authenticated.
2. Confirm the user is authorized for root on that host and that the action was
   expected (change ticket, maintenance window).
3. If unexpected: treat as potential privilege escalation. Review shell history
   for that root session, check for new users/keys/cron entries, and correlate
   with prior SSH/auth anomalies from the same actor.
4. Rotate credentials and review sudoers if the grant itself was unexpected.

## Test
`bash tests/detections/test-1008-sudo-privilege-escalation.sh` — injects a
`sudo … COMMAND=/usr/bin/bash` (fires) and a `sudo … apt update` (must not fire).

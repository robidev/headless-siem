# 1002 — Sudo Execution Monitoring

| | |
|---|---|
| Rule ID | `1002-sudo-execution` |
| File | `config/rules/sudo-execution.yml` |
| Severity | low |
| Source | `sudo` |
| ATT&CK | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) |
| Status | stable |

## Rule
Fires on every `event_type: sudo_command` — i.e. each command run through sudo.
This is an audit/visibility rule; the higher-signal subset (root shells and
sensitive binaries) is [1008](1008-sudo-privilege-escalation.md).

## Risk
Sudo is the primary sanctioned privilege-escalation path. A complete record of
sudo command executions supports auditing, incident reconstruction, and
detection of abuse.

## Implementation
- **Parsing:** the `sudo` extract block parses
  `<user> : TTY=… ; PWD=… ; USER=<target> ; COMMAND=<cmd>` into `username`,
  `target_user`, `tty`, `pwd`, `command` and sets `event_type = sudo_command`.
- **Detection:** single-event selection on `event_type: sudo_command`.

## False positives
- By design this fires on all sudo use, so on an admin host it is high-volume and
  mostly benign. It is intended as a low-severity audit feed, not a page. Route
  it to logging/search rather than alerting, and rely on 1008 for alerts.

## Playbook
1. Use as context, not a standalone alert: when investigating a host or user,
   `siemctl search --query "event_type == sudo_command AND username == <u>"`.
2. Look for unexpected `target_user`, off-hours activity, or commands that touch
   credentials, persistence locations, or security tooling.

## Test
`bash tests/detections/test-1002-sudo-execution.sh`.

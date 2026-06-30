# 1006 — Suspicious Cron Command

| | |
|---|---|
| Rule ID | `1006-cron-suspicious-command` |
| File | `config/rules/cron-suspicious-command.yml` |
| Severity | high |
| Source | `cron` |
| ATT&CK | [T1053.003 Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/) |
| Status | experimental |

## Rule
Fires when a cron job (`event_type: cron_exec`) runs a command whose text
contains a download-and-execute, reverse-shell, interpreter-pipe or
base64-decode pattern: `wget `, `curl `, `bash -i`, `/dev/tcp/`, `nc -`,
`| sh`, `| bash`, `python -c`, `base64 -d`. Condition: `selection and 1 of s_*`.

## Risk
Cron is a top Linux persistence and execution mechanism. An attacker who can
write a crontab (or drop a file in `/etc/cron.*`) commonly schedules a job that
pulls a payload and pipes it to a shell, or opens a reverse shell on a timer.
Legitimate system cron jobs almost never download and execute remote code.

## Implementation
- **Parsing:** `[[extract.rule]] app_name = "cron"` in `config/normalized.toml`
  extracts `cron_user` and `command` from `(<user>) CMD (<command>)` and sets
  `event_type = cron_exec`. Debian logs cron as `CRON`; `normalized`
  canonicalizes that to lowercase `cron` (`canonical_app_name`).
- **Detection:** nine `command|contains` selections OR'd via `1 of s_*`.

## False positives
- Admin maintenance jobs that legitimately use `curl`/`wget` (e.g. a backup that
  POSTs to a healthcheck URL, a job that fetches a feed). Tune by allow-listing
  known job signatures or the specific `cron_user`/host.
- Package/monitoring agents that pipe to `sh`. Review and suppress per command.

## Playbook
1. Pull the full event: `siemctl search --query "event_type == cron_exec AND ..."`
   note `cron_user`, `command`, host (`hostname`).
2. Decide if the command is expected for that host/user. Check the crontab
   source: `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/crontabs/<user>`.
3. If unexpected: capture the payload URL/host, treat as compromise. Isolate the
   host, snapshot the crontab and any downloaded artifacts, rotate credentials
   reachable from that user.
4. Remove the malicious entry, hunt for the initial access that planted it, and
   add the payload indicators to blocklists.

## Test
`bash tests/detections/test-1006-cron-suspicious-command.sh` — injects a
`curl … | bash` cron line (fires) and a benign `run-parts` line (must not fire).

# Detection Catalog

Documentation for every detection in this SIEM. Each file covers the rule, the
risk it addresses, how it is implemented, known false positives, and a response
playbook.

Per-event rules are Sigma YAML under `config/rules/`; multi-event rules are
correlation chains under `config/correlations.toml` (evaluated by `correlated`).

Trigger tests live in `tests/detections/` — run them against a live pipeline:

```bash
SIEM_DEDUP_WINDOW=0 ./dev.sh restart     # dedup off so count-based rules fire
bash tests/detections/run-all.sh
```

## Per-event rules (Sigma)

| ID | Title | Severity | Source | ATT&CK |
|----|-------|----------|--------|--------|
| [1001](1001-ssh-brute-force.md) | SSH Brute Force (failed auth) | medium | sshd | T1110 |
| [1002](1002-sudo-execution.md) | Sudo Execution Monitoring | low | sudo | T1548.003 |
| [1003](1003-iptables-deny.md) | IPTables/UFW Firewall Deny | low | iptables | T1046 |
| [1004](1004-suspicious-ssh.md) | Suspicious SSH from External IP | high | sshd | T1110/T1133 |
| [1005](1005-ssh-login-success.md) | SSH Login Success | info | sshd | T1078 |
| [1006](1006-cron-suspicious-command.md) | Suspicious Cron Command | high | cron | T1053.003 |
| [1007](1007-haproxy-tls-probe.md) | Unauthorized TLS Probe of Reverse Proxy | medium | haproxy | T1190/T1133 |
| [1008](1008-sudo-privilege-escalation.md) | Sudo Root Shell or Sensitive Binary | high | sudo | T1548.003 |
| [1009](1009-firewall-port-scan.md) | Firewall Block (filterlog) | low | filterlog | T1046 |
| [1010](1010-local-auth-failure.md) | Local Authentication Failure | medium | unix_chkpwd | T1110/T1078 |

## Correlation rules (multi-event)

| ID | Title | Window | ATT&CK |
|----|-------|--------|--------|
| [sustained-brute-force](sustained-brute-force.md) | Sustained SSH Brute Force from Single IP | 600s | T1110 |
| [cred-brute-force-success](cred-brute-force-success.md) | Credential Guessing Followed by Login Success | 300s | T1110/T1078 |
| [port-scan](port-scan.md) | Port Scan / Network Reconnaissance | 120s | T1046 |
| [external-ssh-then-sudo](external-ssh-then-sudo.md) | External SSH Probe Followed by Sudo | 600s | T1078/T1548 |

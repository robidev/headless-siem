# Forwarding syslog / journal to `normalized`

Short examples to forward system logs into the `normalized` binary.

Note: `normalized` accepts plain syslog lines and RFC 5424 envelopes directly, and also accepts JSONL objects with `{_raw: ..., _source: ...}`.

## rsyslog — modern (recommended)

Create `/etc/rsyslog.d/30-normalized.conf` with:

```
module(load="omprog")

# Send all messages to normalized (adjust filtering as needed)
action(type="omprog"
       binary="/usr/local/bin/normalized"
       template="RSYSLOG_TraditionalFileFormat")
```

To send RFC 5424 formatted messages (if your rsyslog is configured that way), use a syslog protocol template:

```
action(type="omprog" binary="/usr/local/bin/normalized" template="RSYSLOG_SyslogProtocol23Format")
```

## rsyslog — legacy pipe example

Add a line such as the following to forward a specific program (e.g. `sshd`):

```
:programname, isequal, "sshd" |/usr/local/bin/normalized --source sshd
```

This pipes the raw syslog message text to `normalized` and forces the source to `sshd`.

## journald / journalctl

`journalctl` can emit JSON and be pre-processed into the JSONL shape `normalized` accepts:

```bash
journalctl -f -o json | \
  jq -c '{_raw: .MESSAGE, _source: (. _SYSTEMD_UNIT // "default")}' | \
  /usr/local/bin/normalized --data-dir /var/log/siem
```

- This extracts `MESSAGE` into `_raw` and uses `_SYSTEMD_UNIT` as the source when present.
- When `_source` is missing, `normalized` will run its classifier/heuristics and fall back to `default`.

## Quick test (one-liners)

Plain syslog line:

```bash
printf 'Jun 22 08:55:03 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2\n' | \
  /usr/local/bin/normalized --dry-run
```

RFC 5424:

```bash
printf '<34>1 2024-06-26T12:00:00Z host sshd 1234 - - Failed password for root from 10.0.0.5 port 22 ssh2\n' | \
  /usr/local/bin/normalized --dry-run
```

## Notes

- Tune your rsyslog template to control whether you forward the entire RFC 5424 envelope or only the message text.
- If you prefer structured handling, push journald JSON through `jq` (or systemd `ForwardToSyslog=`) and feed JSONL `{_raw, _source}` to `normalized`.
- Running `normalized` as a service: create a systemd unit that runs the binary and configure rsyslog `omprog`/pipe to point to it.

---

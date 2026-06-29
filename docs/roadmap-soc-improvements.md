# SOC Usability Improvements — Roadmap

Gaps identified during live monitoring of a homelab network (2026-06-29).
Ordered by operational impact.

---

## 1. `siemctl alerts` — Alert query interface

**The problem:** Alerts from `ruled` land in `data/alerts/YYYY/MM/DD/HH/alerts.jsonl`
and correlated alerts in `data/alerts/correlated/YYYY/MM/DD/correlated.jsonl`. There is
no siemctl interface for either. Finding and filtering alerts currently requires manual
`find | xargs cat | jq` pipelines.

**What to build:**
- `siemctl alerts` command mirroring `siemctl search` in interface
- Supports `--after`, `--before`, `--query` DSL filtering on alert fields:
  `rule_id`, `level`, `rule_title`, and any field on the embedded event
  (e.g. `src_ip`, `_source_type`)
- Covers both `ruled` alerts and `correlated` alerts in one command
  (use `--correlated` flag or `type == correlated` in query to distinguish)
- Default output: one alert per line, `rule_title`, `level`, `timestamp`,
  key event fields. `SELECT _raw` gives the full embedded event JSON.

**Example usage once built:**
```bash
# All high/critical alerts in the last hour
siemctl alerts --after 2026-06-29T19 --query "level == high OR level == critical"

# All alerts for a specific source IP
siemctl alerts --query "SELECT rule_title,timestamp WHERE src_ip == 10.10.50.11"

# Alert volume by rule
siemctl alerts --query "GROUP BY rule_id,rule_title LIMIT 20"
```

---

## 2. Alert state management

**The problem:** Alerts are append-only JSONL. There is no way to mark an alert
as acknowledged, closed, or a false positive. Every monitoring session starts
with an undifferentiated pile of everything that ever fired.

**Proposed design (lightweight, no new daemon):**
- A sidecar file per alerts bucket: `data/alerts/YYYY/MM/DD/HH/alerts.ack`
  containing one JSON line per state change: `{"rule_id","timestamp","state","analyst","note"}`
- `siemctl alerts ack <rule_id> [--note "text"]` appends to the sidecar
- `siemctl alerts` filters out ACK'd alerts by default; `--all` shows everything
- States: `ack` (seen, no action), `closed` (investigated), `fp` (false positive)

**Why not a database:** Keeps the flat-file architecture consistent. Sidecars
are human-readable, survive crashes, and can be committed to git for audit trail.

---

## 3. Notification dispatch

**The problem:** Alerts sit in files. A SOC analyst cannot watch a directory tree
in real time. There is no active signal when something important fires.

**Proposed design:**
- Optional `[notify]` block in `config/ruled.toml` (new file, or extend
  normalized.toml conventions):
  ```toml
  [[notify]]
  level = "high"          # minimum level to trigger
  exec = "/usr/local/bin/notify-alert.sh"   # called with alert JSON on stdin
  ```
- `ruled` calls the exec hook synchronously after writing an alert that meets
  the level threshold
- The hook script is user-supplied: can POST to a webhook, send email via
  `sendmail`, push to ntfy.sh, etc.
- Keep it simple: no built-in integrations, just a stdin exec hook

**Alternative:** An inotify watcher script on `data/alerts/` outside the SIEM
binary is simpler to implement and doesn't require changes to `ruled`.

---

## 4. Alert suppression rules

**The problem:** False positives (e.g. Suricata TCP stream reassembly rules
2210020/2210029/2210045 firing on all Cloudflare connections) pollute the alert
output. The only current remedy is modifying the upstream tool's configuration.
A SIEM-level suppression layer lets you tune without touching Suricata/rsyslog.

**Proposed design:** `[[suppress]]` blocks in `config/rules/suppress.toml`:
```toml
# Suppress Suricata TCP stream noise on CDN connections
[[suppress]]
rule_id = "suricata-2210020"
condition = 'cidr_match(src_ip, "172.64.0.0/13")'
expires = "2026-12-31"   # optional — forces periodic review
note = "Cloudflare CDN TCP teardown false positives"

[[suppress]]
rule_id = "suricata-2210029"
condition = 'cidr_match(src_ip, "172.64.0.0/13")'
```

`ruled` loads suppression rules at startup and skips alert emission when a
suppression condition matches. `expires` causes `ruled` to log a warning after
the date so suppressions are reviewed rather than forgotten.

---

## 5. Time-trending / volume baselines

**The problem:** `siemctl stats` shows total event counts but no time distribution.
It is impossible to tell whether 500 sshd events in the current hour is normal
or an anomaly without manually running multiple time-bounded queries and
comparing results.

**Proposed design:** `siemctl stats --interval 1h --last 24h` that outputs a
table of event counts per source per time bucket:

```
source      18:00  19:00  20:00  21:00  ...
filterlog     312    296    803    241
openvpn        88     91    962     84
sshd           12      9     14     11
suricata        0      0   1651      0
```

A sudden spike (like the 962 openvpn events or the 1651 suricata events that
appeared in one hour) becomes immediately visible without constructing separate
queries per hour.

Implementation: `siemctl stats` already has `--after`/`--before`; the new flag
simply loops over N hourly buckets and tabulates the counts.

---

## 6. Filter expressions in `siemctl tail`

**The problem:** `siemctl tail` can filter by `--source` but not by field value.
During live monitoring you typically want to watch a specific event category,
not an entire source stream (e.g. watch only `action == BLOCK` events, or
`event_type == vpn_tls_error`).

**Proposed addition:** `--query` flag on `siemctl tail`, using the same DSL as
`siemctl search`. Events are matched against the query before being printed.

```bash
# Watch firewall blocks in real time
siemctl tail --query "action == BLOCK"

# Watch authentication failures across all sources
siemctl tail --query "event_type == ssh_failed OR event_type == vpn_tls_error"
```

Since `tail` reads raw JSONL (not the index), the DSL matcher would need to run
against the parsed JSONL fields directly rather than SQLite — a subset of the
existing DSL is sufficient (field equality, AND/OR/NOT, no GROUP BY).

---

## 7. Saved queries

**The problem:** Useful queries are ephemeral. Analysts who develop effective
"show current threat state" queries have no way to preserve or share them.
Every session starts from scratch.

**Proposed design:** `config/queries.toml`:
```toml
[query.top-blocked]
description = "Top blocked source IPs in the last hour"
command = "search"
query = "SELECT src_ip,count WHERE action == BLOCK GROUP BY src_ip LIMIT 20"
after_offset = "-1h"   # relative --after: current time minus 1 hour

[query.vpn-failures]
description = "VPN authentication failures"
command = "search"
query = "SELECT timestamp,src_ip,event_type WHERE _source_type == openvpn AND event_type == vpn_tls_error"
after_offset = "-4h"
```

`siemctl run top-blocked` expands and executes the named query. `siemctl run
--list` shows all available queries with descriptions.

This doubles as runbook documentation: the queries file is a machine-executable
record of what the SOC checks and why.

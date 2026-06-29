# Design Proposal: `siemctl digest`

A structured shift-briefing command that reduces a time window of SIEM data
into an anomaly-oriented summary. Intended as the primary entry point for
LLM-assisted triage and for human operators who want a quick situational
picture without running multiple queries.

---

## Motivation

`siemctl search` and `siemctl stats` require the operator to already know what
to look for. A digest inverts this: it runs a fixed set of opinionated analyses
and surfaces deviations from the norm, so the operator starts from a prioritised
picture rather than a blank slate.

For LLM use specifically, the digest must pre-compute anomalies. Showing raw
event counts and expecting the LLM to infer normality consumes context window
without adding value. Showing deltas and flagging deviations does the inference
up front where it is cheap.

---

## Command interface

```
siemctl digest [OPTIONS]

Options:
  --window  DURATION   Analysis period ending now (default: 6h)
                       Examples: 1h, 6h, 24h, 2026-06-29T18..2026-06-29T20
  --interval DURATION  Trending bucket size for time-series sections (default: 10m)
  --data-dir DIR       Data directory (default: ./data)
  --format FMT         text (default) | json
  --help
```

The comparison baseline is the same duration immediately preceding the window.
For a `--window 6h` run at 20:00, the window is 14:00–20:00 and the baseline
is 08:00–14:00.

---

## Output sections

### 1. Coverage / health

Answers: *can I trust what I'm about to read?*

Read this section first. If a source went silent or a parser is missing, every
other section must be interpreted with that caveat.

```
=== COVERAGE (14:00 – 20:00) ===

Sources reporting:     8
Sources gone silent:   — (none)
New sources:           suricata  (first seen this window)

Unparsed high-volume sources (>50 events, _normalized: false):
  gnome-shell     104 events
  rtkit-daemon     48 events

Index coverage:        current (latest raw: 20:07, latest bucket: 20:00)
```

**Fields:**
- Sources reporting vs. sources that reported in the baseline window
- Sources that appeared in baseline but not this window → "gone silent"
- Sources appearing for the first time ever → "new sources"
- App names with high event volume and elevated `_normalized: false` rate —
  these represent parser gaps
- Index lag: difference between the newest raw JSONL timestamp and the newest
  indexed bucket; anything >5 minutes warrants a note

---

### 2. Volume anomalies

Answers: *what is behaving differently from the previous period?*

Show all sources with their event count, baseline count, and delta. Flag rows
where the delta exceeds a threshold (suggested: >50% change or first appearance).

```
=== VOLUME (14:00 – 20:00 vs 08:00 – 14:00) ===

source        this window  baseline   delta
suricata            1,651         0   NEW ←
openvpn               874        88   +890% ←
haproxy               811       803   +1%
filterlog             796       812   -2%
php-fpm                60        57   +5%
sshguard               18        19   -5%
sudo                   20        18   +11%
```

Rows flagged with `←` are the only ones that need immediate attention. Normal
rows are shown for completeness but can be ignored.

---

### 3. Network (filterlog)

Answers: *what is flowing, what is being blocked, and is anything new?*

#### 3a. Trending — blocks per interval

ASCII sparkline of `filterlog` BLOCK events per `--interval` bucket across the
full `--window`. Each character represents one bucket; relative height shows
volume. A spike is immediately readable without parsing numbers.

```
=== FIREWALL TRENDS (BLOCK / 10min) ===

 8  9  7  8 10  9  8  7  9 11  8  9  8  9  7  8  9 10  8  9  7  9  8  9
14:00                                                               20:00
```

If no significant deviation exists, a single summary line suffices:
`BLOCK rate stable: avg 9/10min, max 11/10min`

#### 3b. Top blocked sources

```
=== TOP BLOCKED SOURCE IPs ===

src_ip              count  protocol  note
192.168.178.1         201  IGMP      router multicast (expected)
0.0.0.0               27   UDP/67    DHCP broadcast (expected)
fe80::...             14   ICMPv6    link-local (expected)
```

#### 3c. Inbound allowed (re1)

All `action == ALLOW` events on the WAN interface — these are connections
reaching in from outside the home network.

```
=== INBOUND ALLOWED (re1) ===

src_ip             dst                  count
217.103.119.242    192.168.178.12:8006    27   Proxmox via HAProxy
```

#### 3d. New outbound destinations

Destination IPs from this host that did not appear in the baseline window.
These are almost always worth reviewing.

```
=== NEW OUTBOUND DESTINATIONS (vs baseline) ===

dst_ip           dst_port  count  first seen
172.66.152.176       80      4    20:07:28
```

---

### 4. Authentication and access

Answers: *who is trying to get in, and who succeeded?*

Auth failures are unified across sources by `src_ip` — not listed per source
separately. This surfaces distributed attempts that might look innocuous in any
single source log.

```
=== AUTHENTICATION FAILURES (all sources) ===

src_ip              count  sources
192.168.178.10        268  openvpn (tls_error x123, auth_failure x145)

=== SUCCESSFUL LOGINS / ACCESS ===

  (none in window)

=== PRIVILEGE ESCALATION (sudo) ===

user → root  2 events
  17:27:03  nano /etc/rsyslog.d/50-default.conf
  17:27:39  systemctl restart rsyslog.service
```

Sudo events are always listed in full — they are low-volume by nature and high
value. Auth failures show a per-source breakdown only when multiple sources are
involved.

---

### 5. Alerts

Answers: *what did the detection rules catch, and is the alert distribution healthy?*

```
=== ALERTS ===

total alerts:   4 events, 2 rules

rule                      level   count
sudo-execution            low         2
pfsense-config-change     low         2

Rules firing for the first time this window:  —
High/critical alerts:                         none

Alert concentration: suricata rules account for 0% of alerts this window
  (note: suricata has 1,651 raw events — check suppression config)
```

Key signals beyond counts:
- **First-time rules**: a rule firing that has never fired before is almost
  always worth reading, regardless of level
- **Alert concentration**: if >80% of alert volume comes from one rule, this is
  a tuning signal rather than a real signal
- **Gap between event volume and alert volume**: 1,651 suricata events with
  zero alerts suggests either good suppression or a missed detection gap —
  worth a note either way

---

### 6. Notable events

Answers: *what low-volume, high-significance events happened regardless of volume?*

These categories are always shown in full because they are definitionally
low-frequency. Long lists here indicate a genuine problem.

```
=== NOTABLE EVENTS ===

Config changes (pfsense):
  17:31  admin @ 192.168.178.75  — Suricata configuration
  17:35  admin @ 192.168.178.75  — HAProxy restart

Service restarts (systemd/sshguard):
  17:27  rsyslog restarted (user via sudo)
  19:36  sshguard: 6x restart cycle

Severity critical/emergency:  none
```

---

## Implementation notes

### Data sources

All sections are computable from existing data with `siemctl search` queries:

| Section | Query approach |
|---|---|
| Coverage | `GROUP BY _source_type` for both windows; compare sets |
| Volume anomalies | `GROUP BY _source_type` for both windows; compute deltas |
| Firewall trends | `_source_type == filterlog AND action == BLOCK GROUP BY <bucket>` |
| Top blocked | `_source_type == filterlog AND action == BLOCK GROUP BY src_ip` |
| Inbound allowed | `_source_type == filterlog AND action == ALLOW AND interface == re1` |
| New destinations | `_source_type == filterlog AND src_ip == <this-host>` both windows; diff dst_ips |
| Auth failures | `event_type contains fail GROUP BY src_ip` across sources |
| Sudo | `_source_type == sudo SELECT timestamp,username,command` |
| Alerts | Read `data/alerts/` JSONL directly (index not required) |
| Notable events | `event_type == pfsense_config_change OR event_type == vpn_restart` etc. |

### Sparklines

The trending section uses a simple ASCII sparkline. Each bucket value is
normalized to a 1–9 scale relative to the window maximum, with `▁▂▃▄▅▆▇█`
or single digits. A flat line is a single summary sentence; a spike renders
as the full series.

### JSON output

`--format json` emits a single JSON object with one key per section. Each
section is structured data, not pre-formatted text. This is the intended input
format for LLM tool calls via an MCP server.

```json
{
  "window": {"start": "2026-06-29T14:00", "end": "2026-06-29T20:00"},
  "coverage": { "sources_reporting": 8, "gone_silent": [], "new_sources": ["suricata"], ... },
  "volume": [ {"source": "suricata", "count": 1651, "baseline": 0, "delta_pct": null, "flag": "new"}, ... ],
  "network": { "block_trend": [8,9,7,8,...], "top_blocked": [...], "inbound": [...], "new_destinations": [...] },
  "auth": { "failures": [...], "successes": [], "sudo": [...] },
  "alerts": { "total": 4, "by_rule": [...], "first_time_rules": [], "concentration_warning": null },
  "notable": { "config_changes": [...], "service_restarts": [...], "critical_events": [] }
}
```

### Baseline persistence

For the delta computation to work across sessions, the previous-window
counts need to be either recomputed on demand (cheap — just two GROUP BY
queries against the index) or cached. Recomputing on demand is simpler and
avoids stale cache problems. The index already covers historical data, so
both windows are always queryable.

### Thresholds and tuning

Anomaly thresholds (what counts as a spike, what minimum volume triggers an
unparsed-source warning) should be configurable in `config/digest.toml`.
Sensible defaults:

```toml
[volume]
spike_threshold_pct = 50      # flag if >50% increase over baseline
new_source_always_flag = true

[coverage]
unparsed_min_events = 50      # only flag unparsed sources with >50 events

[network]
new_destination_always_flag = true

[alerts]
concentration_threshold_pct = 80  # warn if one rule > 80% of alert volume
```

# normalized — Usage Guide

`normalized` is the log normalizer for Headless SIEM. It:

- **ingests** logs from **stdin**, **UDP/514**, and **TCP/514**;
- **parses** each line with a **deterministic, zero-config format chain**
  (RFC 5424 / RFC 3164 / JSON / CEF / LEEF / logfmt / CSV / XML / YAML / plain);
- **writes** flat, downstream-compatible JSON records into
  **time-bucketed filesystem storage** that the rest of the pipeline reads.

Its only external dependencies are `chrono` (timestamp parsing + bucket paths)
and `regex` (config-driven extraction rules); everything else is the Rust
standard library.

---

## Table of contents

1. [Quick start](#quick-start)
2. [Input modes](#input-modes)
3. [Command-line flags](#command-line-flags)
4. [Output schema](#output-schema)
5. [Storage layout](#storage-layout)
6. [Source derivation](#source-derivation)
7. [Time bucketing](#time-bucketing)
8. [The `_raw` envelope (rsyslog drop-in)](#the-_raw-envelope-rsyslog-drop-in)
9. [Configuration file](#configuration-file)
10. [Override rules](#override-rules)
11. [Second pass (nested payloads)](#second-pass-nested-payloads)
12. [Extraction rules](#extraction-rules)
13. [Feeding the rest of the pipeline](#feeding-the-rest-of-the-pipeline)

---

## Quick start

```bash
# Build
cargo build --release -p normalized
BIN=./target/release/normalized

# 1. Normalize a syslog file to stdout only (no files written)
cat /var/log/syslog | $BIN --stdin --dry-run | head

# 2. Normalize journald JSON into the bucket store under ./data
journalctl -o json --no-pager | $BIN --stdin --data-dir ./data

# 3. Run as a syslog receiver on UDP+TCP 514, storing under /var/log/siem
sudo $BIN --data-dir /var/log/siem
```

Every input line always produces exactly one output record — nothing is ever
dropped (see [Output schema](#output-schema)).

---

## Input modes

`normalized` runs in **one** of two modes:

| Mode | How to select | Source address | Typical use |
|------|---------------|----------------|-------------|
| **stdin** | `--stdin` | `"stdin"` | `cat`/`tail`/`journalctl` piping a file or stream |
| **listeners** | *(default — no `--stdin`)* | sender's IP | network syslog receiver (UDP + TCP) |

- **stdin** reads newline-delimited input, one log line per line. Use it for
  `/var/log/syslog`, `journalctl -o json`, replaying captured logs, or testing.
- **listeners** bind UDP and TCP on the ports from the [config file](#configuration-file)
  (default `0.0.0.0:514`, which needs root or `CAP_NET_BIND_SERVICE`). TCP input
  is line-framed and understands the RFC 6587 octet-count prefix (`123 <msg>`).

The two modes are mutually exclusive: `--stdin` disables the network listeners
so a simple `cat … | normalized --stdin` never tries to bind port 514.

---

## Command-line flags

```
normalized [FLAGS]

INPUT (choose one mode):
  --stdin               Read newline-delimited logs from stdin
  (default)             Listen on UDP+TCP per --config (default :514)

FLAGS:
  --data-dir <path>     Bucket root for raw storage (default: ./data)
  --dry-run             Write to stdout only; no filesystem storage
  --bucket-time <mode>  'event' (default) or 'receive' — clock used to choose
                        the YYYY/MM/DD/HH/MM/SS bucket
  --source <name>       Force the source label for every record
  --config <file>       Config file (listen ports, override rules, data_dir)
  --help                Print help
```

- Records are **always** written to stdout (so you can pipe into `ruled`).
  With a data dir (and without `--dry-run`) they are **also** written to buckets.
- `--data-dir` takes precedence over `storage.data_dir` in the config file,
  which takes precedence over the default `./data`.
- `--source NAME` overrides source derivation for *every* record — handy when a
  whole file is known to be one source: `cat audit.log | normalized --stdin --source auditd`.

---

## Output schema

Output is one JSON object per line (JSONL), with **flat top-level keys** and
**deterministically sorted** field order. This is the schema `indexd`, `ruled`,
and `siemctl` already consume.

Example (a `/var/log/syslog` sshd line):

```json
{
  "_format": "rfc3164",
  "_normalized": true,
  "_raw": "Jun 22 08:55:03 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2",
  "_received": "2026-06-27T12:06:03.315+00:00",
  "_source_type": "sshd",
  "app_name": "sshd",
  "hostname": "myhost",
  "message": "Failed password for root from 10.0.0.5 port 22 ssh2",
  "proc_id": "1234",
  "source_addr": "stdin",
  "timestamp": "Jun 22 08:55:03"
}
```

Always-present keys:

| Key | Meaning |
|-----|---------|
| `timestamp` | The event's own timestamp, **falling back to receive time** if the line carries none (so `indexd`, which requires it, never drops a line). |
| `_received` | Wall-clock time the line was ingested (RFC 3339). |
| `_source_type` | Derived source label (see [Source derivation](#source-derivation)). |
| `_format` | Which parser claimed the line (`rfc5424`, `json`, `cef`, `plain`, …). |
| `_normalized` | `true` for any structured parse; `false` only for the plain-text fallback. |
| `source_addr` | Sender IP, or `"stdin"`. |
| `_raw` | The original (inner) log line, verbatim — nothing is ever lost. |

### Syslog envelope fields

`source_addr`, `hostname`, and `app_name` come from the syslog transport layer
and are available on **every** event regardless of app or format. They are
**automatically indexed** in every `indexd` bucket — no `sources.toml` entry
needed.

| Field | Source | Notes |
|-------|--------|-------|
| `source_addr` | UDP source IP of the sending host | `"stdin"` when reading from a pipe or file. Use `source_addr == "10.0.0.5"` to find all logs from a specific forwarder. |
| `hostname` | Syslog header `HOSTNAME` field | The name the remote host put in its syslog header, which may differ from the IP in `source_addr` if NAT or a relay is involved. |
| `app_name` | Syslog header `APP-NAME` / tag field | The raw process name **before** any override rule rewrites `_source_type`. E.g. when kernel logs are relabelled to `iptables` by an override rule, `app_name` is still `kernel`. Useful for writing override rules and for querying sources that haven't been labelled yet. |

The following envelope fields are present **when the syslog header carries
them**, but are not automatically indexed (they're noisier and rarely useful
as search filters):

| Field | Meaning |
|-------|---------|
| `proc_id` | PID from the syslog header (changes each run). |
| `msg_id` | RFC 5424 MSGID (rarely populated in practice). |
| `facility` | Syslog facility number. |
| `message` | The human-readable message body (after structured parsing; the full payload for plain-text). |

Conditional structured-format keys: every field lifted to the top level by
JSON, CEF/LEEF, logfmt, CSV, or XML/YAML parsers, plus every named capture
from `[[extract.rule]]` patterns.

**Field canonicalization.** Common SIEM synonyms are renamed to canonical keys
so detection rules can rely on them: `src`→`src_ip`, `dst`→`dst_ip`,
`spt`→`src_port`, `dpt`→`dst_port`. An already-canonical key always wins over a
synonym. Envelope fields (e.g. an extracted `severity`) win over a same-named
structured field.

> **App-level extraction.** The chain normalizes by *format*, not by
> application — it gives you the syslog envelope (host, app, pid, timestamp) and
> any *structured* fields, but does not by itself crack open an sshd message to
> pull `src_ip`/`username` out of free text. Two mechanisms cover that:
> [extraction rules](#extraction-rules) (config-driven regex, no code) and the
> [second pass](#second-pass-nested-payloads) (for structured payloads wrapped
> in syslog).

---

## Storage layout

```
<data_dir>/raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl   # one JSON object per line
<data_dir>/raw/YYYY/MM/DD/HH/MM/SS/<source>.tsv     # 6-column grep sidecar
```

- The first write to a bucket file is **atomic** (temp file + rename);
  subsequent writes append (atomic for small lines on POSIX).
- The `.tsv` sidecar has a fixed 6-column header for zero-overhead grep:
  `timestamp  src_ip  dst_ip  event_type  severity  source`.

```bash
# fast IP search without a JSON parser
grep 10.0.0.5 data/raw/2026/06/22/08/55/03/sshd.tsv

# retention: delete buckets older than 30 days
find data/raw -type d -mtime +30 -delete
```

---

## Source derivation

`<source>` (the bucket filename and `_source_type`) is chosen by this
precedence, then sanitized for safe use as a path component
(`[A-Za-z0-9._-]`; anything else → `_`; empty/dot-only → `unknown`):

1. **`--source` CLI flag** — forces the label for every record.
2. **Override-rule `source`** — an explicit, ordered config rule (see below).
3. **`_source_type`/`_source` from the `_raw` envelope** — e.g. rsyslog's tag.
4. **Syslog `app_name`** — `sshd`, `sudo`, `kernel`, … from the parsed envelope.
5. **Detected `_format`** — `json`, `cef`, `plain`, … when nothing else applies.

This produces the familiar `sshd.jsonl` / `sudo.jsonl` per-source files from a
plain syslog stream without any classifier config. Reclassification, when you
need it, is explicit via override rules.

---

## Time bucketing

`--bucket-time` chooses which clock selects the `…/HH/MM/SS/` directory:

- `event` *(default)* — the event's own timestamp, parsed from RFC 3339,
  `YYYY-MM-DD[ T]HH:MM:SS`, or BSD-syslog `Mon DD HH:MM:SS` (current year
  assumed). If the timestamp can't be parsed, it falls back to receive time.
- `receive` — always the wall-clock ingestion time.

Either way the record carries **both** `timestamp` (event, or receive as
fallback) and `_received` (always receive), so you never lose the distinction.

```bash
cat old-incident.log | normalized --stdin --data-dir ./data --bucket-time event
syslog-stream            | normalized --data-dir /var/log/siem --bucket-time receive
```

---

## The `_raw` envelope (rsyslog drop-in)

The production feed (`config/rsyslog.d/50-headless-siem.conf`) ships each
message as a JSON object whose `_raw` field holds the real log line:

```json
{"_source_type":"sshd","_host":"h","_facility":"auth",
 "_severity":"info","_timestamp":"2026-…","_raw":"Failed password for root …"}
```

`normalized` detects this **deterministically** (a JSON object with a `_raw`
key), unwraps it, and runs the parser chain on the *inner* line. Envelope
metadata fills any field the inner parse didn't provide:

| Envelope key | Used as |
|--------------|---------|
| `_raw` | the line that is actually parsed |
| `_source_type` / `_source` | source label (precedence step 3 above) |
| `_timestamp` | `timestamp` if the inner line has none |
| `_host` | `hostname` if the inner line has none |
| `_severity` | `severity` if the inner line has none (word → level) |

Anything that is *not* such an envelope — plain syslog text, journald JSON
(no `_raw`), CEF, etc. — is parsed as-is. The legacy fixtures' older
`{"_source":"…","_raw":"…"}` form is recognized too.

---

## Configuration file

The config file is an optional, hand-parsed TOML subset (no TOML dependency).
Pass it with `--config`. With no config file, defaults apply (UDP+TCP `:514`,
buckets under `./data`).

```toml
[listen]
bind     = "0.0.0.0"
udp_port = 514
tcp_port = 514

[storage]
data_dir = "/var/log/siem"      # overridden by --data-dir

# Override rules — see the next section.
[[overrides.rule]]
source_ip = "192.168.10.1"
contains  = "filterlog"
source    = "pfsense"
format    = "csv"
remap     = { src = "src_ip", dst = "dst_ip" }
```

---

## Override rules

Override rules are the explicit, ordered replacement for a classifier.
They are checked **before** the auto-detection chain; **first match wins**; all
present conditions are **ANDed**. A matching rule may do any combination of:

| Field | Effect |
|-------|--------|
| `source_ip` | Match when the sender address starts with this prefix. |
| `starts_with` | Match when the (inner) raw line starts with this string. |
| `contains` | Match when the raw line contains this substring. |
| `format` | Force a specific parser instead of auto-detection (`rfc5424`, `rfc3164`, `json`, `json_array`, `cef`, `leef`, `logfmt`, `csv`, `xml`, `yaml`, `plain`). |
| `source` | Assign an explicit source label (bucket + `_source_type`). |
| `remap` | Rename parsed fields, `old = "new"`, after parsing. |
| `reparse` | `true` to run a [second pass](#second-pass-nested-payloads) on the message body. |
| `reparse_as` | Force the second pass to use this format (else auto-detect by prefix). |

Example — tag everything from the firewall host as `pfsense`, force the CSV
parser, and normalize its field names:

```toml
[[overrides.rule]]
source_ip = "192.168.10.1"
source    = "pfsense"
format    = "csv"
remap     = { field4 = "src_ip", field6 = "dst_ip" }
```

`remap` accepts either the inline form above or a block form:

```toml
[[overrides.rule]]
contains = "filterlog"
remap =
src = "src_ip"
dst = "dst_ip"
```

---

## Second pass (nested payloads)

A very common pattern is a structured payload wrapped in a syslog envelope:

```
<134>Nov 23 21:58:05 fw01 JATP: CEF:0|JATP|Cortex|3.6|http|TROJAN|8|src=10.0.0.1 dst=10.0.0.2
```

The chain parses the syslog envelope (host/app/time) and leaves the `CEF:…`
payload in `message`. The **second pass** re-parses that message body and merges
the result in.

- **Automatic** for unambiguous payloads: if a syslog message starts with
  `CEF:`, `LEEF:`, or `{` (JSON), it is re-parsed and merged with no config.
- **Config-driven** for anything else, via an override rule:

  ```toml
  [[overrides.rule]]
  source_ip  = "10.0.0.7"
  reparse    = true
  reparse_as = "logfmt"     # omit to auto-detect by prefix
  ```

Merge behavior: the payload is treated as the real event, so its structured
fields and `severity` win; the syslog envelope keeps `hostname`/`app_name`/
`timestamp` (filled from the payload only if absent). The record's `_format`
becomes the payload format (e.g. `cef`) and `_transport` records the envelope
(e.g. `rfc3164`):

```json
{ "_format": "cef", "_transport": "rfc3164", "hostname": "fw01",
  "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "cef.name": "TROJAN", … }
```

> The second pass goes one level deep (syslog → payload). It is not recursive.
> Multi-line payloads (a record split across physical lines) must be joined
> before ingestion, since input is line-oriented.

---

## Extraction rules

Extraction rules pull fields out of **free-text** messages that no parser
understands structurally — e.g. `sshd`'s `Failed password … from 10.0.0.5`.
They are config-driven regex with **named captures** applied to a chosen source
field. No code, no recompile.

```toml
[[extract.rule]]
# Conditions (all must match) — any parsed field, plus `source`/`_source_type`.
app_name = "sshd"
# Field to search: "message" (default), "_raw", or any parsed field.
from    = "message"
# One or more regexes; named captures (?P<name>…) become fields.
pattern = "from (?P<src_ip>[0-9.]+) port (?P<src_port>[0-9]+)"
pattern = "for (?P<username>[^ ]+) from"
# Static fields to add on match.
set     = { event_type = "ssh_auth" }
```

Given `Jun 22 08:55:03 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`,
this adds `src_ip=10.0.0.5`, `src_port=22`, `username=root`,
`event_type=ssh_auth`.

Semantics:

- Rules run **in declaration order**, after the parse/second pass and after the
  source is derived.
- **Conditions** are exact-match (`field = "value"`), ANDed. Matchable names
  include `app_name`, `hostname`, `source_addr`, `proc_id`, `msg_id`,
  `severity`, `timestamp`, `_format`, `source`/`_source_type`, and any
  structured field.
- **Captured fields fill only empty slots** — they never clobber a value the
  parser already set. **`set` values always overwrite.**
- Capture names follow the same canonicalization as everything else, so a
  capture named `src` becomes `src_ip`.
- **Fail-open:** an invalid regex is logged once at startup and skipped; the
  rest keep working.

> A `#` inside a pattern must be inside the quoted value (comment stripping is
> quote-aware); patterns are taken literally with no TOML escaping, so write
> `\d`, not `\\d`.

---

## Feeding the rest of the pipeline

`normalized` writes the same schema and layout the downstream tools expect, so
it slots straight in:

```bash
# Stream into the Sigma rule engine
cat /var/log/syslog | normalized --stdin --data-dir ./data \
  | ruled --rules config/rules/

# indexd watches the bucket store and builds SQLite indexes
indexd --data-dir ./data
```

Records carry top-level `timestamp` and `_source_type`, which is exactly what
`indexd` indexes (timestamp required, `_source_type` → `source`).

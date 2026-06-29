# Headless SIEM — User Guide & Operator Manual

## Table of Contents

1. [Installation](#installation)
2. [Quick Start: 5 Minutes to First Alert](#quick-start)
3. [Configuration](#configuration)
4. [Operations](#operations)
5. [Architecture Overview](#architecture-overview)
6. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- Linux (amd64 or arm64 — tested on Ubuntu 24.04 and Raspberry Pi OS)
- Rust toolchain (1.70+) — `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- C compiler — `sudo apt-get install build-essential` (needed to compile bundled SQLite)
- rsyslog (for production ingestion) — `sudo apt-get install rsyslog`

### Build from Source

```bash
git clone https://github.com/your-org/headless-siem.git
cd headless-siem
make all
```

This builds five Rust binaries:

| Binary | Path | Purpose |
|--------|------|---------|
| `normalized` | `target/release/normalized` | Log parsing & normalization |
| `indexd` | `target/release/indexd` | Filesystem watcher & SQLite indexer |
| `ruled` | `target/release/ruled` | Sigma rule engine |
| `correlated` | `target/release/correlated` | Sliding-window correlation |
| `siemctl` | `target/release/siemctl` | CLI for search, status, retention |

For development/debugging, debug binaries are at `src/<name>/target/debug/<name>`.

### Verify the Build

```bash
# Check each binary runs
target/debug/normalized --help
target/debug/indexd --help
target/debug/ruled --help
target/debug/correlated --help
target/debug/siemctl --help

# Run unit tests
make test
```

---

## Quick Start: 5 Minutes to First Alert

This section gets you from zero to seeing alerts in 5 minutes. All commands are copy-paste runnable.

### Step 1: Create the data directory

```bash
mkdir -p data/{raw,index,alerts,correlated}
```

### Step 2: Test normalization with a sample log

```bash
# Pipe a sample log through the normalizer
cat tests/fixtures/mixed.log | \
  target/debug/normalized --stdin --data-dir data/
```

You should see JSONL output on stdout and files created under `data/raw/`.

### Step 3: Verify the filesystem output

```bash
# See the time-bucketed directory structure
find data/raw/ -type f | head -10

# Grep for an IP address directly
grep -r "10.0.0.5" data/raw/

# Check the TSV sidecars
head -2 $(find data/raw/ -name '*.tsv' | head -1)
```

### Step 4: Start the indexer

```bash
# Start indexd in the background — it watches for new files
target/debug/indexd --data-dir data/ &
INDEXD_PID=$!
sleep 2  # let it scan existing files

# Verify indexes were created
find data/index/ -name '*.db'
sqlite3 $(find data/index/ -name '*.db' | head -1) \
  "SELECT COUNT(*) FROM events;"
```

### Step 5: Run the rule engine

```bash
# Pipe normalized output through the rule engine
cat tests/fixtures/mixed.log | \
  target/debug/normalized --stdin --data-dir data/ | \
  target/debug/ruled --rules config/rules/ --output data/alerts/
```

You should see alert JSONL on stdout. Each alert has `_ruled: true`, a `rule_id`, and the triggering event.

### Step 6: Run correlation

```bash
# Pipe alerts through the correlation engine
cat tests/fixtures/mixed.log | \
  target/debug/normalized --stdin --data-dir data/ | \
  target/debug/ruled --rules config/rules/ | \
  target/debug/correlated --config config/correlations.toml --output data/correlated/
```

### Step 7: Use siemctl

```bash
# Check system status
target/debug/siemctl status --data-dir data/

# Search for events by IP (uses SQLite index)
target/debug/siemctl search --data-dir data/ \
  --query "src_ip == 10.0.0.5"

# Search by time range
target/debug/siemctl search --data-dir data/ \
  --query "_source_type == sshd" --after "2026-06-22T08" --before "2026-06-22T09"

# Stream live events
target/debug/siemctl tail --data-dir data/

# Validate config and rules
target/debug/siemctl validate \
  --config config/sources.toml --rules config/rules/
```

### Step 8: Run the full integration test

```bash
bash tests/integration/test-pipeline.sh
```

### Clean up the quick-start data

```bash
kill $INDEXD_PID 2>/dev/null
rm -rf data/
```

---

## Configuration

### sources.toml

Located at `config/sources.toml`. Tells `indexd` which fields to extract per source into the SQLite index, and tells `siemctl` which fields are valid search targets.

```toml
[source.sshd]
index_fields = ["src_ip", "event_type", "username"]

[source.sudo]
index_fields = ["username", "event_type"]

[source.iptables]
index_fields = ["src_ip", "dst_ip", "dst_port", "event_type"]

[source.systemd]
index_fields = ["event_type", "unit"]

# Fallback for unknown sources
[source.default]
index_fields = ["src_ip", "dst_ip", "event_type"]
```

**Adding a new source:** add a `[source.<name>]` section with the fields you want indexed. Source names match the `_source_type` value in normalized output (derived from `app_name`, or set explicitly via override rules).

### normalized.toml

Located at `config/normalized.toml`. Configures extraction rules and override rules for `normalized`. Pass with `--config config/normalized.toml`.

**Override rules** relabel, force-parse, or remap fields before the format chain runs:

```toml
[[overrides.rule]]
source_ip = "192.168.10.1"    # match on sender address prefix
source    = "pfsense"          # assign source label
format    = "csv"              # force this parser
remap     = { field4 = "src_ip", field6 = "dst_ip" }

[[overrides.rule]]
contains = "[UFW "             # substring match on the raw line
source   = "iptables"
```

**Extraction rules** pull structured fields out of free-text messages using regex named captures. No code, no recompile:

```toml
[[extract.rule]]
app_name = "sshd"             # condition: match when app_name == "sshd"
from     = "message"          # field to search
# named captures (?P<name>…) become new fields
pattern  = "^(?P<auth_action>Failed|Accepted) \w+ for (?:invalid user )?(?P<username>\S+) from (?P<src_ip>[\d.]+) port (?P<src_port>\d+)"
pattern  = "session (?P<session_action>opened|closed) for user (?P<username>\S+)"
# static fields added when conditions match
set      = { }                # (set per-event-type in pass-2 rules)
```

See [normalized-usage.md](normalized-usage.md) for the full reference on conditions, `set`, multi-pass patterns, and the second-pass (CEF/JSON-inside-syslog) mechanism.

### Sigma Rule Writing

Rules live under `config/rules/` as YAML files. The engine supports a subset of the Sigma specification.

**Required fields:**
- `title` — human-readable rule name
- `id` — unique rule identifier
- `status` — `stable`, `experimental`, or `deprecated` (deprecated rules are skipped)
- `detection` — condition and selections

**Optional fields:**
- `description` — what the rule detects
- `level` — `low`, `medium`, `high`, `critical`
- `logsource` — filter by `product`, `service`, or `category`
- `tags` — list of string tags

**Example rule:**

```yaml
title: SSH Brute Force Detection
id: 1001-ssh-brute-force
status: stable
level: medium
description: Detects failed SSH password attempts
logsource:
  service: sshd
detection:
  selection:
    _source_type: sshd
    event_type: ssh_auth_failure
  condition: selection
```

**Field modifiers:**

| Modifier | Meaning | Example |
|----------|---------|---------|
| (none) | Exact match | `event_type: ssh_auth_failure` |
| `\|contains` | Case-insensitive substring | `message\|contains: "error"` |
| `\|startswith` | Prefix match | `src_ip\|startswith: "10.0."` |
| `\|endswith` | Suffix match | `user\|endswith: "admin"` |

**Condition expressions:**

| Expression | Meaning |
|------------|---------|
| `selection` | Named selection must match |
| `sel1 and sel2` | Both must match |
| `sel1 or sel2` | Either must match |
| `sel1 and not filter` | sel1 matches, filter does not |
| `not filter` | Filter must not match |
| `1 of them` | Any named selection matches |
| `1 of sel_*` | Any selection matching glob pattern |
| `(sel1 or sel2) and not filter` | Parenthesized expressions |

**Logsource filtering:**

```yaml
logsource:
  service: sshd     # only matches events with _source_type containing "sshd"
  product: linux    # further restricts to linux sources
```

If `logsource` is omitted, the rule matches all events regardless of source.

**Testing rules:**

```bash
# Dry-run: see which rules fire against sample data
cat tests/fixtures/mixed.log | \
  target/debug/normalized --stdin --dry-run | \
  target/debug/ruled --rules config/rules/

# Or use siemctl dry-run
target/debug/siemctl dry-run \
  --file tests/fixtures/mixed.log \
  --config config/normalized.toml \
  --rules config/rules/
```

---

## Operations

### Searching

`siemctl search` takes **one query expression** in a small SQL-ish DSL via
`--query`. Field filters, full-text, grouping and limits all compose in that one
string — and all run through the SQLite index. The whole predicate / `GROUP BY`
/ `LIMIT` is the `--query` value; the only other flags are `--after`/`--before`
(time-range bucket pruning), `--format`, `--data-dir`, and `--raw` (the raw-file
escape hatch).

**DSL grammar**

```
query   := [WHERE] [expr] [GROUP BY f1,f2,...] [LIMIT n]
expr    := AND / OR / NOT / ( ) over comparisons and functions
compare := field (== | = | != | <>) value
funcs   := startswith(f,'v')  endswith(f,'v')  contains(f,'v')
           any(f)  cidr_match(f,'a.b.c.d/n')  raw_contains('needle')
```

`AND` binds tighter than `OR`; use parentheses to override. Quotes are optional
everywhere (a slot's role is fixed by position) and keywords are
case-insensitive. A leading `WHERE` is accepted and ignored.

**1. Field predicates (index-backed):**

```bash
# Exact match
siemctl search --data-dir data/ --query "src_ip == 10.0.0.5"

# startswith / endswith / contains / any / cidr_match
siemctl search --data-dir data/ --query "startswith(event_type,'ssh')"
siemctl search --data-dir data/ --query "any(username)"
siemctl search --data-dir data/ --query "cidr_match(src_ip,'10.0.0.0/24')"

# Combine conditions and prune by time range
siemctl search --data-dir data/ \
  --query "src_ip == 10.0.0.5 AND _source_type == sshd" \
  --after "2026-06-22T08" --before "2026-06-22T12"
```

**2. Full-text (composes with everything):**

```bash
# Substring over each row's original raw line (via the raw_contains UDF)
siemctl search --data-dir data/ --query "raw_contains('Failed password')"

# Field filter + text — the field index narrows rows first, then the substring
# test runs only on survivors
siemctl search --data-dir data/ \
  --query "_source_type == sshd AND raw_contains('root')"
```

**3. Grouping (filter then group) and limits:**

```bash
# Count unique values, sorted by count desc (merged across hourly buckets)
siemctl search --data-dir data/ --query "GROUP BY src_ip"

# Filter, then group — a single composed query
siemctl search --data-dir data/ --query "_source_type == sshd GROUP BY src_ip,event_type"

# Cap the rows emitted
siemctl search --data-dir data/ --query "GROUP BY src_ip LIMIT 10"
```

**4. Time-range listing (empty predicate = match all):**

```bash
# Dump every indexed event in a time window
siemctl search --data-dir data/ \
  --after "2026-06-22T08" --before "2026-06-22T09"
```

**5. `--raw` — bypass the index:**

Text search now goes through the index, which is eventually consistent (inotify
driven), so the newest not-yet-indexed lines can be missed. `--raw` scans the
raw JSONL files directly — use it when the index is missing/stale or you need the
very latest events. Its argument is a **literal substring**, not DSL:

```bash
# Substring scan straight over raw files
siemctl search --data-dir data/ --raw "Failed password"

# With a time range; omit the substring to dump the range
siemctl search --data-dir data/ --raw --after "2026-06-22T08" --before "2026-06-22T09"
```

**Direct grep (no siemctl needed):**

```bash
# The filesystem is the database — use any tool
grep -r "10.0.0.5" data/raw/
rg "Failed password" data/raw/
jq '.src_ip' data/raw/2026/06/22/08/**/*.jsonl
```

### Live Tail

Stream events as they arrive:

```bash
# All sources
siemctl tail --data-dir data/

# Single source
siemctl tail --data-dir data/ --source sshd

# Read current files and exit (no follow)
siemctl tail --data-dir data/ --no-follow
```

### Monitoring

```bash
# System status overview
siemctl status --data-dir data/
```

Output includes:
- Total data directory size
- File counts per source (how many raw log files per source type)
- Last event timestamp per source
- Index coverage (which time buckets have SQLite databases)

**Manual monitoring:**

```bash
# Watch data directory growth
watch -n 60 'du -sh data/'

# Count events per source
find data/raw/ -name '*.jsonl' | sed 's|.*/||' | sort | uniq -c | sort -rn

# Check index health
find data/index/ -name '*.db' -exec sqlite3 {} "SELECT COUNT(*) FROM events;" \;
```

### Retention

```bash
# Preview what would be deleted (dry-run)
siemctl retention --data-dir data/ --days 30 --dry-run

# Delete data older than 30 days
siemctl retention --data-dir data/ --days 30
```

Retention deletes files by modification time and removes empty directories. You can also use standard tools:

```bash
# Manual retention with find
find data/ -type f -mtime +30 -delete
find data/ -type d -empty -delete
```

### Dry-Run Testing

Test parsers and rules without writing to the data directory:

```bash
# Test normalization only
siemctl dry-run --file tests/fixtures/sshd.log \
  --config config/normalized.toml

# Test full pipeline (normalization + rules)
siemctl dry-run --file tests/fixtures/mixed.log \
  --config config/normalized.toml \
  --rules config/rules/
```

Output shows:
- Lines processed / matched / unmatched
- Match rate percentage
- Alerts generated and rules triggered (if `--rules` specified)

### Validate

Check config and rule files for structural correctness:

```bash
siemctl validate --config config/sources.toml --rules config/rules/
```

Reports:
- Each source in `sources.toml` with its `index_fields`
- Each rule file — OK, ERROR (missing required fields), or SKIP (deprecated)
- Summary of error and warning counts

### Backups

Since all data is plain files:

```bash
# Backup with rsync
rsync -av data/ backup-server:/backups/siem/

# Backup with tar
tar -czf siem-backup-$(date +%Y%m%d).tar.gz data/
```

---

## Architecture Overview

Headless SIEM is a pipeline of five small, single-purpose binaries connected by stdin/stdout and the filesystem.

### Data Flow

```
[Log Sources]
     │
     ▼
  rsyslog ─── (disk-queued, tagged with source type)
     │
     ▼
  normalized ─── stdin: raw logs → stdout: normalized JSONL
     │
     ├──→ data/raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl
     │    data/raw/YYYY/MM/DD/HH/MM/SS/<source>.tsv
     │
     │    indexd (inotify watcher) ──→ data/index/YYYY-MM-DD-HH.db
     │
     └──→ ruled ──→ alerts to stdout
            │
            ├──→ data/alerts/YYYY/MM/DD/HH/alerts.jsonl
            │
            └──→ correlated ──→ compound alerts
                   │
                   └──→ data/correlated/YYYY/MM/DD/HH/correlated.jsonl
```

### Data Layout

```
data/
├── raw/                        # Normalized events (filesystem as database)
│   └── YYYY/MM/DD/HH/MM/SS/
│       ├── <source>.jsonl      # One JSON object per line
│       └── <source>.tsv       # Sidecar: timestamp, src_ip, dst_ip, event_type, severity, source
├── index/                      # SQLite indexes (one per clock-hour)
│   └── YYYY-MM-DD-HH.db        # Indexed fields from sources.toml
├── alerts/                     # Rule engine output
│   └── YYYY/MM/DD/HH/
│       └── alerts.jsonl
└── correlated/                 # Correlation engine output
    └── YYYY/MM/DD/HH/
        └── correlated.jsonl
```

### Key Design Decisions

1. **Filesystem as database** — `grep`, `jq`, `awk` work directly. Retention is `find -mtime +30 -delete`. Backups are `rsync`.

2. **rsyslog as durability layer** — disk-assisted queues ensure logs are durable *before* they reach our code. If any component crashes, rsyslog buffers and retries.

3. **Fail-open parsing** — every line is claimed by exactly one parser. If no format matches, the plain-text fallback captures it. Nothing is ever dropped.

4. **Format chain, then extraction rules** — the format chain (RFC 5424/3164, JSON, CEF, LEEF, logfmt, CSV, XML, YAML, plain) handles wire formats; config-driven regex extraction rules pull app-level fields (src_ip, username, event_type, …) out of free-text messages. No code, no recompile.

5. **SQLite per clock-hour** — indexes stay small, retention is trivial (delete old `.db` files), and SQLite is zero-configuration.

6. **Sigma rules** — open standard, human-readable YAML, thousands of community rules available.

7. **Separate correlation** — stateful correlation is fundamentally different from stateless rule matching. Keeps `ruled` simple and fast.

### Component Summary

| Component | Language | Input | Output | State |
|-----------|----------|-------|--------|-------|
| `normalized` | Rust | stdin or UDP/TCP 514 | stdout (normalized JSONL) + filesystem | Stateless |
| `indexd` | Rust | inotify on `data/raw/` | SQLite databases | Stateless (DB is state) |
| `ruled` | Rust | stdin (normalized JSONL) | stdout (alert JSONL) + filesystem | Dedup cache (5s window) |
| `correlated` | Rust | stdin (alert JSONL) | stdout (correlation JSONL) + filesystem | Sliding windows per rule_id |
| `siemctl` | Rust | CLI arguments | stdout (human-readable) | Stateless |

---

## Troubleshooting

### "ruled: no rules loaded"

The rules directory is empty or contains no valid YAML files. Check:
```bash
ls config/rules/
```
Rules must have `.yml` or `.yaml` extension and contain valid Sigma YAML with `id`, `title`, and `detection` fields. Run `siemctl validate` to see which files pass.

### "indexd: raw directory does not exist"

`indexd` was started before `normalized` created the `data/raw/` directory. Start `normalized` first, or create the directory manually:
```bash
mkdir -p data/raw
```

### "siemctl: data directory does not exist"

Pass `--data-dir` pointing to the correct location:
```bash
siemctl status --data-dir /path/to/your/data/
```

### indexd hangs / won't stop with SIGTERM

`indexd` uses blocking inotify reads. Use SIGKILL (`kill -9`) to force-stop it. In production, systemd handles this correctly with `TimeoutStopSec`.

### Alerts not firing

1. Check that rules are loaded: `ruled` prints "loaded N rules" on startup
2. Check that events have the expected `_source_type`: inspect normalized output
3. Check logsource filters: if a rule has `logsource: { service: sshd }`, it only matches events with `_source_type` containing "sshd"
4. Check that extraction rules ran: expected fields like `event_type` must be present
5. Use dry-run to debug: `siemctl dry-run --file test.log --config config/normalized.toml --rules config/rules/`

### Fields missing from search results

Field predicates in `--query` (e.g. `field == value`, `contains(field,…)`) only work for fields listed in `index_fields` in `sources.toml` — an unknown field is a clean parse error. To search an unindexed field, use `raw_contains('…')` (or `--raw 'substring'`) for a full-text match, or inspect the JSONL directly:

```bash
jq 'select(.src_ip == "10.0.0.5")' data/raw/**/**/**/**/**/**/*.jsonl
```

To index a new field, add it to `index_fields` in `sources.toml` and restart `indexd`.

### SQLite database locked / busy

Multiple processes accessing the same `.db` file. `indexd` uses WAL mode which allows concurrent readers. If you see lock errors:
```bash
# Check for stale locks
fuser data/index/*.db
```

### Disk space growing too fast

1. Check retention: `siemctl retention --data-dir data/ --days 7 --dry-run`
2. Apply retention: `siemctl retention --data-dir data/ --days 7`
3. Set up a cron job for automatic retention:
```bash
# Daily retention cron
0 3 * * * /path/to/siemctl retention --data-dir /var/lib/headless-siem/data --days 30
```

### Performance tuning

- **normalized**: extraction rule compilation happens once at startup (O(rules)). Conditions are cheap string comparisons; regex runs only on matching events.
- **indexd**: initial scan indexes all existing files. For large backlogs, let it run once, then it only handles new files.
- **ruled**: O(rules × events). With 100 rules and 1000 events/sec, this is ~100K evaluations/sec — well within Rust's capabilities.
- **correlated**: O(alerts) with bounded sliding windows. Memory usage is proportional to (distinct rule_ids × window size).

### Getting help

- Check component help: `<binary> --help`
- Validate config: `siemctl validate --config config/sources.toml --rules config/rules/`
- Run the integration test: `bash tests/integration/test-pipeline.sh`
- Inspect data directly: `find data/ -type f | head -20`
- Check raw output: `cat data/raw/2026/06/22/08/55/03/sshd.jsonl | jq .`

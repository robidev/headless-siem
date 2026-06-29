# How to Verify Indexing with indexd

A step-by-step guide to confirming that your new log source is being indexed correctly by `indexd`.

---

## Table of Contents

1. [How indexd Works](#how-indexd-works)
2. [Prerequisites](#prerequisites)
3. [Step 1: Declare index_fields in sources.toml](#step-1-declare-index_fields-in-sourcestoml)
4. [Step 2: Start indexd and Check Startup Output](#step-2-start-indexd-and-check-startup-output)
5. [Step 3: Feed Events Through the Pipeline](#step-3-feed-events-through-the-pipeline)
6. [Step 4: Verify the SQLite Schema](#step-4-verify-the-sqlite-schema)
7. [Step 5: Verify Data Is Being Inserted](#step-5-verify-data-is-being-inserted)
8. [Step 6: Verify Indexes Are Working](#step-6-verify-indexes-are-working)
9. [Step 7: Verify TSV Sidecar for grep](#step-7-verify-tsv-sidecar-for-grep)
10. [Troubleshooting](#troubleshooting)
11. [Quick Reference](#quick-reference)

---

## How indexd Works

`indexd` watches the `data/raw/` directory tree for new `.jsonl` files using `inotify`. When a file is closed after writing (or moved into the tree), `indexd`:

1. **Derives the time bucket** from the file path (`YYYY/MM/DD/HH`)
2. **Opens or creates** a per-bucket SQLite database at `data/index/YYYY-MM-DD-HH.db`
3. **Creates the schema dynamically** from the union of all `index_fields` in `config/sources.toml`
4. **Parses each JSONL line**, extracting only the declared fields
5. **Batch-inserts** events into SQLite (100 per batch)
6. **Creates a SQLite index** on every indexed column for fast queries

The schema is built from `sources.toml` at startup. Adding a field to `index_fields` and restarting `indexd` is all that's needed to index it.

### Architecture

```
data/raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl   ← written by normalized
    │
    │  inotify (CLOSE_WRITE / MOVED_TO)
    ▼
indexd
    │
    ├── parser.rs: parse_line() → HashMap<field, value>
    │
    └── db.rs: insert_event() → SQLite
         │
         ▼
data/index/YYYY-MM-DD-HH.db
    ├── events table (dynamic columns from sources.toml)
    └── idx_events_<field> (one index per column)
```

---

## Prerequisites

- `normalized` is running and writing `.jsonl` files to `data/raw/`
- `indexd` is built: `cargo build --release -p indexd`
- `config/sources.toml` has your source registered with `index_fields`

---

## Step 1: Declare index_fields in sources.toml

The `index_fields` array in `sources.toml` is the **single source of truth** for what gets indexed. `indexd` reads this file at startup and builds the SQLite schema from the union of all `index_fields` across every source.

### Example: Adding a new auditd source

```toml
# config/sources.toml

[source.auditd]
pattern = "linux/auditd"
index_fields = ["src_ip", "dst_ip", "event_type", "username", "command"]
```

**What this means:**
- `timestamp`, `source`, and `byte_offset` are **always indexed** (mandatory, added automatically)
- `src_ip`, `dst_ip`, `event_type`, `username`, and `command` are indexed for this source
- The union across all sources determines the full schema — if `sshd` declares `src_port` and `auditd` declares `command`, both columns exist in every bucket database

### Verify your sources.toml is valid

```bash
# Check TOML syntax
python3 -c "import tomllib; tomllib.load(open('config/sources.toml', 'rb'))" && echo "OK"

# List all declared index_fields
grep -A5 '\[source\.' config/sources.toml | grep index_fields
```

---

## Step 2: Start indexd and Check Startup Output

Start `indexd` pointing at the same data directory as `normalized`:

```bash
# From the project root
./target/release/indexd --data-dir ./data
```

**Expected startup output:**

```
indexd: loaded config with 9 index fields: ["byte_offset", "dst_ip", "dst_port", "event_type", "severity", "source", "src_ip", "timestamp", "username"]
indexd: scanning existing files in ./data/raw
indexd: watching ./data/raw for new .jsonl files
indexd: send SIGTERM or SIGINT to stop
```

**What to check:**
1. The field list includes your new fields (e.g. `username`, `command`)
2. No error about missing `sources.toml`
3. The `raw/` directory is being watched

### If the config can't be found

```bash
# Explicitly specify the config path
indexd --data-dir ./data --config ./config/sources.toml

# Or set the environment variable
HEADLESS_SIEM_ROOT=/path/to/project indexd --data-dir ./data
```

---

## Step 3: Feed Events Through the Pipeline

Send test events through `normalized` so `indexd` has something to index:

```bash
# Pipe a few test lines through normalized
echo '{"_raw":"Jun 22 08:55:03 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2","_source":"sshd"}' | \
  normalized --data-dir ./data

# Or feed a batch from a file
cat test_events.jsonl | normalized --data-dir ./data
```

**indexd should log:**

```
indexd: indexing: ./data/raw/2026/06/22/08/55/03/sshd.jsonl
indexd: indexed 1 events, skipped 0 lines
```

**What to check:**
- `indexed N events` — these were successfully inserted into SQLite
- `skipped N lines` — these were malformed JSON or missing `timestamp` (see [Troubleshooting](#troubleshooting))

### If indexd doesn't pick up the file

`indexd` uses `inotify` which triggers on `CLOSE_WRITE` and `MOVED_TO`. If you're writing to the file slowly (e.g. `tail -f`), the file may not be closed yet. Force a scan:

```bash
# Touch the file to trigger a re-scan, or restart indexd
# indexd scans existing files on startup
```

---

## Step 4: Verify the SQLite Schema

Check that the bucket database was created with the correct columns and indexes:

```bash
# Find the bucket database for your event's timestamp
ls -la data/index/

# Inspect the schema
sqlite3 data/index/2026-06-22-08.db ".schema events"
```

**Expected output (with auditd fields):**

```sql
CREATE TABLE events (
    byte_offset INTEGER NOT NULL DEFAULT 0,
    dst_ip TEXT NOT NULL DEFAULT '',
    dst_port TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    src_ip TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    command TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_events_dst_ip ON events(dst_ip);
CREATE INDEX idx_events_dst_port ON events(dst_port);
CREATE INDEX idx_events_event_type ON events(event_type);
CREATE INDEX idx_events_severity ON events(severity);
CREATE INDEX idx_events_source ON events(source);
CREATE INDEX idx_events_src_ip ON events(src_ip);
CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_username ON events(username);
CREATE INDEX idx_events_command ON events(command);
```

**What to check:**
1. Every field from `index_fields` (across all sources) has a column
2. `timestamp`, `source`, and `byte_offset` are always present
3. Every column (except `byte_offset`) has a corresponding `CREATE INDEX`
4. Column order is alphabetical (deterministic from `BTreeSet`)

### Verify column list programmatically

```bash
sqlite3 data/index/2026-06-22-08.db "PRAGMA table_info(events);"
```

### Verify indexes

```bash
sqlite3 data/index/2026-06-22-08.db \
  "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='events' ORDER BY name;"
```

---

## Step 5: Verify Data Is Being Inserted

Query the database to confirm events are stored with the correct field values:

### Count total events

```bash
sqlite3 data/index/2026-06-22-08.db "SELECT COUNT(*) FROM events;"
```

### Inspect recent events

```bash
sqlite3 data/index/2026-06-22-08.db \
  "SELECT timestamp, source, src_ip, event_type, severity FROM events ORDER BY rowid DESC LIMIT 10;"
```

### Check that your new fields have values

```bash
# If you added 'username' and 'command' to index_fields
sqlite3 data/index/2026-06-22-08.db \
  "SELECT timestamp, source, username, command FROM events WHERE username != '' LIMIT 10;"
```

### Check for empty fields

Fields that weren't present in the JSONL are stored as empty strings:

```bash
# Count events where username is populated vs empty
sqlite3 data/index/2026-06-22-08.db \
  "SELECT COUNT(*) as total, SUM(CASE WHEN username != '' THEN 1 ELSE 0 END) as with_username FROM events;"
```

### Verify byte_offset is tracked

```bash
sqlite3 data/index/2026-06-22-08.db \
  "SELECT timestamp, byte_offset FROM events ORDER BY rowid LIMIT 5;"
```

`byte_offset` is an approximate position in the `.jsonl` file, useful for seeking to the raw event later.

---

## Step 6: Verify Indexes Are Working

SQLite indexes make queries fast. Verify they're being used:

### Check that queries use the index

```bash
sqlite3 data/index/2026-06-22-08.db "EXPLAIN QUERY PLAN SELECT * FROM events WHERE src_ip = '10.0.0.5';"
```

**Expected output:**

```
SEARCH events USING INDEX idx_events_src_ip (src_ip=?)
```

If you see `SCAN events` instead of `SEARCH ... USING INDEX`, the index isn't being used — check that the column name matches exactly.

### Test query performance

```bash
# Count events by source
sqlite3 data/index/2026-06-22-08.db \
  "SELECT source, COUNT(*) as cnt FROM events GROUP BY source ORDER BY cnt DESC;"

# Find all events from a specific IP
sqlite3 data/index/2026-06-22-08.db \
  "SELECT timestamp, event_type, severity FROM events WHERE src_ip = '10.0.0.5';"

# Events in a time range
sqlite3 data/index/2026-06-22-08.db \
  "SELECT * FROM events WHERE timestamp BETWEEN 'Jun 22 08:00:00' AND 'Jun 22 08:30:00';"

# Cross-reference IPs
sqlite3 data/index/2026-06-22-08.db \
  "SELECT timestamp, source, src_ip, dst_ip FROM events WHERE src_ip = '10.0.0.5' OR dst_ip = '10.0.0.5';"
```

### Query across multiple buckets

```bash
# All events for a day
for db in data/index/2026-06-22-*.db; do
  echo "=== $(basename $db) ==="
  sqlite3 "$db" "SELECT timestamp, source, src_ip FROM events WHERE src_ip = '10.0.0.5';"
done
```

---

## Step 7: Verify TSV Sidecar for grep

The TSV sidecar (written by `normalized`, not `indexd`) provides zero-overhead grep access. Verify it exists and is grep-friendly:

### Check TSV exists alongside JSONL

```bash
ls -la data/raw/2026/06/22/08/55/03/
# Should show both sshd.jsonl and sshd.tsv
```

### Verify TSV header

```bash
head -1 data/raw/2026/06/22/08/55/03/sshd.tsv
```

**Expected:**

```
timestamp	src_ip	dst_ip	event_type	severity	source
```

### Grep for an IP in the TSV

```bash
grep "10.0.0.5" data/raw/2026/06/22/08/55/03/sshd.tsv
```

### Count events by severity from TSV

```bash
cut -f5 data/raw/2026/06/22/08/55/03/sshd.tsv | sort | uniq -c | sort -rn
```

**Note:** The TSV has fixed 6 columns (`timestamp`, `src_ip`, `dst_ip`, `event_type`, `severity`, `source`). It does **not** include custom fields like `username` or `command`. For those, query SQLite directly.

---

## Troubleshooting

### "indexd: loaded config with 0 index fields"

Your `sources.toml` is empty or has no `index_fields` arrays. Check:

```bash
grep -c 'index_fields' config/sources.toml
```

### "indexd: skipping event without timestamp"

The JSONL line is missing a `timestamp` field. `indexd` requires `timestamp` to index an event. Check the `normalized` output:

```bash
cat data/raw/2026/06/22/08/55/03/sshd.jsonl | jq 'select(.timestamp == null)'
```

Layer 3 passthrough events (`_normalized: false`) may not have a `timestamp` field. These are stored in the JSONL but skipped by `indexd`.

### "indexd: skipping malformed JSON"

The line isn't valid JSON. This shouldn't happen with `normalized` output, but can occur if you're piping raw text. Check:

```bash
cat data/raw/2026/06/22/08/55/03/sshd.jsonl | python3 -c "
import sys, json
for i, line in enumerate(sys.stdin, 1):
    try:
        json.loads(line)
    except json.JSONDecodeError as e:
        print(f'Line {i}: {e}')
"
```

### "indexd: could not derive bucket from path"

The `.jsonl` file isn't in the expected `YYYY/MM/DD/HH/MM/SS/<source>.jsonl` directory structure. `indexd` needs at least 7 path components to derive the hour bucket. Check:

```bash
# Should show something like: .../raw/2026/06/22/08/55/03/sshd.jsonl
find data/raw/ -name "*.jsonl" | head -5
```

### Events exist in JSONL but not in SQLite

1. Check that `timestamp` is present in the JSONL
2. Check that `indexd` actually processed the file (look for "indexing:" log lines)
3. Check that the bucket database exists: `ls data/index/`
4. Try restarting `indexd` — it scans existing files on startup

### Schema mismatch after changing index_fields

If you add a field to `index_fields` and restart `indexd`, **existing bucket databases won't get the new column automatically**. Options:

**Option A: Delete and re-scan (simplest)**

```bash
rm -rf data/index/
# Restart indexd — it will re-scan all existing .jsonl files
```

**Option B: Migrate existing databases**

```bash
for db in data/index/*.db; do
  sqlite3 "$db" "ALTER TABLE events ADD COLUMN username TEXT NOT NULL DEFAULT '';"
  sqlite3 "$db" "CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);"
done
```

---

## Quick Reference

### Startup

```bash
# Default (auto-detect config)
indexd --data-dir ./data

# Explicit config
indexd --data-dir ./data --config ./config/sources.toml

# With environment variable
HEADLESS_SIEM_ROOT=/path/to/project indexd --data-dir ./data
```

### Schema Inspection

```bash
# List all bucket databases
ls -la data/index/

# Show schema for a bucket
sqlite3 data/index/2026-06-22-08.db ".schema"

# List columns
sqlite3 data/index/2026-06-22-08.db "PRAGMA table_info(events);"

# List indexes
sqlite3 data/index/2026-06-22-08.db \
  "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='events';"
```

### Data Queries

```bash
# Count events
sqlite3 data/index/2026-06-22-08.db "SELECT COUNT(*) FROM events;"

# Events by source
sqlite3 data/index/2026-06-22-08.db \
  "SELECT source, COUNT(*) FROM events GROUP BY source;"

# Find by IP
sqlite3 data/index/2026-06-22-08.db \
  "SELECT * FROM events WHERE src_ip = '10.0.0.5';"

# Recent events
sqlite3 data/index/2026-06-22-08.db \
  "SELECT * FROM events ORDER BY rowid DESC LIMIT 10;"

# Verify index usage
sqlite3 data/index/2026-06-22-08.db \
  "EXPLAIN QUERY PLAN SELECT * FROM events WHERE src_ip = '10.0.0.5';"
```

### TSV Grep

```bash
# Find IP in TSV
grep "10.0.0.5" data/raw/2026/06/22/08/55/03/sshd.tsv

# Count by severity
cut -f5 data/raw/2026/06/22/08/55/03/sshd.tsv | sort | uniq -c

# Count by source
cut -f6 data/raw/2026/06/22/08/55/03/sshd.tsv | sort | uniq -c
```

### Verification Checklist

- [ ] `sources.toml` has `index_fields` for your source
- [ ] `indexd` startup shows the correct field list
- [ ] `indexd` logs "indexed N events" when files are written
- [ ] Bucket database exists at `data/index/YYYY-MM-DD-HH.db`
- [ ] Schema has all expected columns (`.schema events`)
- [ ] Every column has a corresponding index
- [ ] `SELECT COUNT(*)` returns expected event count
- [ ] Queries by `src_ip`, `event_type`, etc. return results
- [ ] `EXPLAIN QUERY PLAN` shows `SEARCH ... USING INDEX`
- [ ] TSV sidecar exists and is grep-friendly

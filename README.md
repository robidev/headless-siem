# Headless SIEM

A minimal, Unix-philosophy SIEM for home-lab environments. Filesystem is the database. Every component is a standalone binary that reads stdin and writes stdout. Nothing is opaque.

## Architecture

```
rsyslog ──omprog──→ normalized ──→ data/raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl
  (disk-queued)      (Rust)         data/raw/.../<source>.tsv (sidecar)
                       │
                  indexd (Rust) ──→ data/index/YYYY/MM/DD/HH/MM/SS.db
                       │              (timestamp, src_ip, dst_ip, event_type, severity, offset)
                       │
                  ruled (Rust)  ──→ data/alerts/YYYY/MM/DD/HH/alerts.jsonl
                  (stdin→stdout,
                   Sigma rules)
                       │
                  correlated (Rust) ──→ data/alerts/correlated/...
                  (stateful, reads
                   alert stream)
```

## Design Principles

- **Filesystem is the database.** Logs stored as `YYYY/MM/DD/HH/MM/SS/<source>.jsonl`. `grep`, `find`, `ripgrep` work directly. Retention is `find -mtime +N -delete`.
- **Fail-open, never-drop.** rsyslog disk queues guarantee durability before our code touches a line. A bad parser affects only its source. Unknown sources get heuristic extraction — never lost.
- **Isolated parsers.** Deterministic format chain + config-driven extraction. A bad extraction pattern is logged and skipped; the rest keep working.
- **Index is optional.** Search falls back to `grep`/`ripgrep` when no index exists. Indexes are tiny — only the 5-6 most-queried fields.
- **Sigma rules.** Community-standard detection format. Thousands of rules available. No custom DSL.

## Components

| Binary | Language | Role |
|--------|----------|------|
| `normalized` | Rust | Deterministic-chain log normalizer (stdin/UDP/TCP 514). Never drops. |
| `indexd` | Rust | inotify watcher. Builds SQLite indexes per time bucket. |
| `ruled` | Rust | Sigma rule engine. stdin→stdout. Stream or batch. |
| `correlated` | Rust | Stateful correlation. Reads alert stream, emits compound alerts. |
| `siemctl` | Rust | CLI: search, status, retention, dry-run parsing. |

## Quick Start

```bash
# Build all components
make

# Test a parser against sample logs
cat tests/fixtures/sshd.log | ./src/normalized/target/release/normalized --stdin --dry-run --source sshd

# Run the full pipeline
make run
```

## Data Layout

```
/var/log/siem/          (or ./data/ for dev)
├── raw/                # Time-bucketed normalized logs
│   └── 2026/06/22/08/55/03/
│       ├── router.jsonl
│       ├── router.tsv
│       ├── sshd.jsonl
│       └── sshd.tsv
├── index/              # Companion SQLite indexes
│   └── 2026/06/22/08/55/03.db
└── alerts/             # Rule engine output
    └── 2026/06/22/08/
        └── alerts.jsonl
```

## Status

### What Works

- **5 binaries** — `normalized`, `indexd`, `ruled`, `correlated`, and `siemctl` (all Rust) compile and run.
- **Log normalization** — Deterministic format chain (RFC 5424/3164, JSON, CEF, LEEF, logfmt, CSV, XML, YAML, plain) with config-driven second-pass and regex extraction. Outputs timestamped `.jsonl` + `.tsv` sidecar.
- **Indexing** — `indexd` watches the raw directory via inotify and builds per-bucket SQLite indexes on the most-queried fields.
- **Sigma rule engine** — `ruled` evaluates 5 Sigma rules (SSH brute-force, suspicious SSH, sudo execution, iptables deny, SSH login success) against the normalized stream and emits alerts. Alerts are deduplicated within a configurable window (`--dedup-window`, default 5s; `0` disables for batch replay / count-based correlation).
- **Correlation** — `correlated` reads the alert stream and produces compound alerts from related events.
- **CLI** — `siemctl` provides search, status, retention, and dry-run parsing.
- **Integration tests** — 4 test scripts in `tests/integration/` exercise the full pipeline end-to-end.
- **Documentation** — 5 guides in `docs/` covering parsers, detection rules, indexing verification, correlation testing, and a user guide.

### In Progress / Known Gaps

- **Rule coverage** — Only 5 Sigma rules shipped; needs expansion for broader threat detection.
- **Correlation engine** — Stateful correlation is functional but the rule set is minimal; more correlation scenarios needed.
- **Processing-time windows** — `ruled` dedup and `correlated` windows key off wall-clock
  processing time, not event time. This is correct for a live tail. For batch/historical replay,
  run `ruled --dedup-window 0` so repeats aren't collapsed; event-time windowing is a planned
  follow-up.
- **Performance tuning** — No benchmarking or throughput optimization yet.
- **Packaging** — No system packages (`.deb`/`.rpm`) or container images; build-from-source only.
- **Alerting** — No built-in notification channels (email, webhook, Slack); alerts are filesystem-only.
- **Dashboard** — No web UI or visualization layer; `siemctl` is CLI-only.

The project is functional and can ingest, normalize, index, detect, and correlate in a home-lab setting, but it is still evolving — expect rough edges and missing conveniences.

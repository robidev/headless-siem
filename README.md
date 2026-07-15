# Headless SIEM

![Alt text](headless-siem.png?raw=true "Moody cartoon picture about headless-siem")

A minimal, Unix-philosophy SIEM for home-lab environments. Filesystem is the database. Every component is a standalone binary that reads stdin and writes stdout. Nothing is opaque.

## Architecture

```
rsyslog ──omprog──→ normalized ──→ data/raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl
  (disk-queued)      (Rust)         data/raw/.../<source>.tsv (sidecar)
                       │
                  indexd (Rust) ──→ data/index/YYYY-MM-DD-HH.db
                       │              (timestamp, src_ip, dst_ip, event_type, severity, offset)
                       │
                  ruled (Rust)  ──→ data/alerts/YYYY/MM/DD/HH/alerts.jsonl
                  (stdin→stdout,        │
                   Sigma rules,     [[suppress]] rules (config/rules/suppress.toml, opt-in
                   optional         via --suppress) drop known-false-positive alerts
                   --suppress)      before they're written
                       │
                  correlated (Rust) ──→ data/alerts/correlated/YYYY/MM/DD/HH/correlated.jsonl
                  (stateful, reads
                   alert stream)

siemctl (Rust) — standalone CLI, reads the filesystem above directly:
  search   full DSL queries against the SQLite index (or raw files)
  digest   anomaly-oriented shift-briefing summary over a time window
  alerts   query + acknowledge ruled/correlated alerts (data/alerts/ack.jsonl)
  status / stats / tail / retention / dry-run / validate

alert-watch (bash) — inotify watcher on data/alerts/, independent of siemctl:
  dispatches alerts >= a configurable level to an external notify script
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
| `ruled` | Rust | Sigma rule engine. stdin→stdout. Stream or batch. Optional `--suppress` for known-FP rules. |
| `correlated` | Rust | Stateful correlation. Reads alert stream, emits compound alerts. |
| `siemctl` | Rust | CLI: search, digest, alerts (query/ack), status, stats, tail, retention, dry-run, validate. |

## Quick Start

```bash
# Build all components
make

# Test a parser against sample logs
cat tests/fixtures/sshd.log | ./target/release/normalized --stdin --dry-run --source sshd

# Run the full pipeline as background processes (UDP :5514, no systemd needed)
./dev.sh start
./dev.sh status

# Shift-briefing summary of the last 6 hours vs. the 6 hours before that
./target/release/siemctl digest --data-dir data/

# Query alerts, then acknowledge a known-benign one
./target/release/siemctl alerts --data-dir data/ --query "GROUP BY rule_id,rule_title"
./target/release/siemctl alerts ack 1007-haproxy-tls-probe --note "known CDN probe pattern"
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
├── index/              # Companion SQLite indexes (one per clock-hour)
│   └── 2026-06-22-08.db
└── alerts/             # Rule engine output
    ├── ack.jsonl       # siemctl alerts ack watermarks (one line per ack)
    ├── correlated/     # Stateful correlation output
    │   └── 2026/06/22/08/
    │       └── correlated.jsonl
    └── 2026/06/22/08/
        └── alerts.jsonl
```

## Status

### What Works

- **5 binaries** — `normalized`, `indexd`, `ruled`, `correlated`, and `siemctl` (all Rust) compile and run.
- **Log normalization** — Deterministic format chain (RFC 5424/3164, JSON, CEF, LEEF, logfmt, CSV, XML, YAML, plain) with config-driven second-pass and regex extraction. Outputs timestamped `.jsonl` + `.tsv` sidecar.
- **Indexing** — `indexd` watches the raw directory via inotify and builds per-bucket SQLite indexes on the most-queried fields.
- **Sigma rule engine** — `ruled` evaluates 10 Sigma rules (SSH brute-force, suspicious SSH, sudo execution, sudo privilege escalation, iptables deny, SSH login success, cron suspicious command, HAProxy TLS probe, firewall port scan, local auth failure) against the normalized stream and emits alerts. Alerts are deduplicated within a configurable window (`--dedup-window`, default 5s; `0` disables for batch replay / count-based correlation). Optional `--suppress config/rules/suppress.toml` drops known-false-positive alerts (e.g. CDN ranges tripping a network IDS rule) before they're written — inactive by default.
- **Correlation** — `correlated` reads the alert stream and produces compound alerts from related events (4 correlation rules, e.g. port-scan detection from repeated firewall blocks).
- **CLI** — `siemctl` provides:
  - `search` — full DSL (field predicates, full-text, `GROUP BY`, `LIMIT`) against the SQLite index or raw files
  - `digest` — anomaly-oriented shift-briefing: coverage/health, volume deltas vs. the preceding baseline, network trends, auth activity, alerts, and notable events, in text or JSON (the primary input for LLM-assisted triage)
  - `alerts` — query ruled + correlated alerts with the same DSL as `search`; `alerts ack <rule_id>` acknowledges a rule's alerts up to now (a watermark, not a global switch)
  - `status`, `stats`, `tail`, `retention` (also compacts stale ack state), `dry-run`, `validate`
- **Alert notification** — `config/notify/alert-watch.sh` (`headless-siem-alert-watch` service) watches `data/alerts/` via inotify (plus a periodic reconciliation sweep for the new-directory race) and dispatches any alert at/above a configurable level (default: `high`) to an external notify script — pluggable via `SOC_NOTIFY_SCRIPT`, called as `<script> <priority> <subject> <body-file>`. No opinion on the delivery channel; bring your own script.
- **Integration tests** — 10 test scripts in `tests/integration/` (plus 16 detection-trigger scripts in `tests/detections/`) exercise the full pipeline end-to-end. 430 tests across the workspace (`cargo test --workspace`).
- **Documentation** — Guides and design docs in `docs/` covering parsers, detection rules (with a per-rule catalog in `docs/detections/`), indexing verification, correlation testing, a user guide, the digest/alerts/suppression design docs, and the SOC improvement roadmap.

### In Progress / Known Gaps

- **Rule coverage** — 10 Sigma rules and 4 correlation rules shipped; still narrow relative to the Sigma ecosystem, and there's no automated FP-tuning loop yet beyond manually authored `--suppress` rules and `alerts ack`.
- **No built-in triage automation** — `digest`, `alerts` (query + ack), and `ruled --suppress` give a consumer everything it needs to poll this SIEM on a schedule and triage/acknowledge findings (see `docs/design/design-llm-soc-analyst.md` for the design rationale behind that split), but actually running such a loop — cron scheduling, escalation policy, ticketing — is outside this project's scope. `siemctl` and the pipeline stop at the query/ack interface.
- **Alert state** — `siemctl alerts ack <rule_id>` is a single watermark per rule (hide up to now); there's no per-alert investigation state (closed/false-positive/etc.) beyond that.
- **Processing-time windows** — `ruled` dedup and `correlated` windows key off wall-clock
  processing time, not event time. This is correct for a live tail. For batch/historical replay,
  run `ruled --dedup-window 0` so repeats aren't collapsed; event-time windowing is a planned
  follow-up.
- **Performance tuning** — No benchmarking or throughput optimization yet.
- **Packaging** — No system packages (`.deb`/`.rpm`) or container images; build-from-source only.
- **Alerting** — `alert-watch` dispatches to *a* notify script, but ships none itself — no built-in email/webhook/Slack backend; the operator has to provide `SOC_NOTIFY_SCRIPT`.
- **Dashboard** — No web UI or visualization layer; `siemctl` is CLI-only.

The project is functional and can ingest, normalize, index, detect, correlate, summarize, and triage-query in a home-lab setting, but it is still evolving — expect rough edges and missing conveniences.

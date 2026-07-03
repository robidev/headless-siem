# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

The five crates form a **Cargo workspace** (root `Cargo.toml`): one `Cargo.lock`, one shared `target/` directory. Run cargo from the repo root.

```bash
# Build all 5 binaries (release mode)
make           # or: just all  — both wrap `cargo build --release`

# Build a single crate
cargo build --release -p ruled

# Run all tests (cargo unit tests + integration tests)
make test      # or: just test — wraps `cargo test` + the integration scripts

# Run tests for a single crate
cargo test -p ruled

# Run a single integration test
bash tests/integration/test-pipeline.sh

# Install to /usr/local/bin + systemd units (requires root)
make install
```

> Integration tests use **debug** binaries from `target/debug/`, not release. Build with `cargo build` (no `--release`) before running them.

## Architecture

Five independent binaries connected by Unix pipes and the filesystem:

```
rsyslog ──omprog──→ normalized → data/raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl
                                                               <source>.tsv
                       │
                  indexd (inotify) → data/index/YYYY-MM-DD-HH.db
                       │
                  ruled (Sigma) → data/alerts/YYYY/MM/DD/HH/alerts.jsonl
                       │
                  correlated → data/alerts/correlated/YYYY/MM/DD/HH/correlated.jsonl
```

`siemctl` (Rust) is a standalone search/status CLI that reads from the filesystem.

### Key files per component

| Component | Key files |
|-----------|-----------|
| `normalized` | `src/normalized/src/main.rs` (Processor, handle()), `parsers/mod.rs` (chain + second pass), `event.rs` (Event, flatten), `config.rs` (overrides + extract rules), `extract.rs`, `envelope.rs`, `output.rs` |
| `indexd` | `src/indexd/src/main.rs` (inotify loop), `db.rs` (SQLite), `parser.rs` (JSONL→row), `config.rs` |
| `ruled` | `src/ruled/src/main.rs` (stdin loop), `rules.rs` (Sigma YAML parser + condition AST), `output.rs` (dedup, AlertRouter) |
| `correlated` | `src/correlated/src/main.rs`, `correlation.rs` (sliding-window state), `output.rs` |
| `siemctl` | `src/siemctl/src/main.rs` (dispatch + all commands), `db.rs` (SQLite), `sources.rs`, `time.rs` |

## Configuration

- **`config/normalized.toml`** — optional config for `normalized`: listen ports, storage path, `[[overrides.rule]]` (force parser, assign source, remap fields, second-pass), `[[extract.rule]]` (regex field extraction from free text). Pass with `--config`.
- **`config/sources.toml`** — index field definitions consumed by `indexd` (SQLite schema) and `siemctl` (searchable field list). Each `[source.*]` entry lists the `index_fields` to extract. No grok/classifier content — those are gone.
- **`config/rules/*.yml`** — Sigma YAML detection rules consumed by `ruled`.
- **`config/rsyslog.d/50-headless-siem.conf`** — rsyslog config that disk-queues logs and pipes them to `normalized` via `omprog`.

## Adding a New Log Parser

Most sources need no code — try these in order:

1. **Override rule** in `config/normalized.toml`: force an existing parser, assign a source label, rename fields. See `docs/normalized-usage.md#override-rules`.
2. **Extraction rule**: pull `src_ip`, `username`, etc. from free-text via regex named captures. See `docs/normalized-usage.md#extraction-rules`.
3. **New parser module** (code): only when the wire format itself is new. See `docs/normalized-writing-parsers.md`.

Test without writing files:
```bash
cat sample.log | ./target/release/normalized --stdin --dry-run --source name | jq .
```

## Data Invariants

- **Never drops.** Every input line exits one of two paths: any structured parse (`_normalized: true`, format-specific fields), or plain-text passthrough (`_normalized: false`, `_raw` only).
- **Atomic writes.** OutputRouter writes to `.tmp` then renames for the first event in a time bucket; subsequent events in the same second use `O_APPEND`.
- **BTreeMap fields.** Normalized output uses `BTreeMap` for deterministic sorted JSON keys.
- **Events bucketed by event timestamp**, not processing time. If a log line has a parseable timestamp, it goes into the corresponding `HH/MM/SS` directory.

## Sigma Rules

Rules live in `config/rules/*.yml`. `ruled` evaluates every rule against every event. Alerts are deduplicated within a 5-second window. To test a rule:

```bash
cat data/raw/**/*.jsonl | ./target/release/ruled --rules config/rules/ --dry-run
```

## Useful Dev Patterns

```bash
# Dry-run a parser against a fixture
cat tests/fixtures/sshd.log | ./target/release/normalized --stdin --dry-run --source sshd | jq .

# Count normalized vs unnormalized lines
cat tests/fixtures/mixed.log | \
  ./target/release/normalized --stdin --dry-run | \
  jq -r '._normalized' | sort | uniq -c

# Grep raw data without JSON parsing
grep "10.0.0.5" data/raw/2026/06/22/08/55/03/sshd.tsv

# Retention (delete logs older than 30 days)
find data/raw -type d -mtime +30 -delete
```

---
name: siemctl
description: Use when searching, tailing, validating, or dry-running headless-siem's data directory — status/stats/search/tail/retention/dry-run/validate commands.
---

# siemctl

## Purpose

`siemctl` is the read-side CLI for the headless-siem pipeline: a standalone Rust binary
that queries the filesystem (`data/raw/`) and SQLite index (`data/index/`) built by
`normalized`/`indexd`/`ruled`/`correlated`. It never writes to the pipeline; it only
reads, searches, validates config, and prunes old data.

Reach for it when a Claude session needs to: find specific events (`search`), check
whether the pipeline is healthy and what's indexed (`status`, `stats`), watch events as
they arrive (`tail`), sanity-check `sources.toml`/Sigma rules before deploying them
(`validate`), test a parser or rule change against a fixture without touching real data
(`dry-run`), or clean up old data (`retention`). For writing new parsers or rules, see
`docs/normalized-writing-parsers.md` and `docs/guide-detection-rules.md` instead — this
skill covers the query/ops surface only.

## Install / Build

This is a Cargo **workspace** — one shared `target/` at the repo root, not a
`target/` per crate.

```bash
cargo build --release -p siemctl   # → target/release/siemctl
cargo build -p siemctl             # → target/debug/siemctl (for dev/testing)
```

`make` / `just all` builds all 5 binaries at once. Run cargo from the repo root.

**Gotcha:** `siemctl dry-run` shells out to the `normalized` and `ruled` binaries.
It looks for them next to its own exe assuming a *per-crate* `src/<name>/target/<profile>/<name>`
layout, which doesn't exist in this workspace — that lookup always misses here, so it
silently falls back to bare binary names resolved via `PATH`. Put `target/debug` (or
`target/release`) on `PATH` before running `dry-run`, or it fails with
`failed to run 'normalized': No such file or directory`. See `references/flags.md` for
the exact fallback logic if you need to debug it further.

## Commands & Flags

Full flag reference (types, defaults, pulled from `src/siemctl/src/main.rs` arg
parsing): **[references/flags.md](references/flags.md)**

Quick index — `siemctl <command> --help` always works and is authoritative:

| Command | Purpose |
|---|---|
| `status` | Data dir size, per-source file counts, index coverage. `--verbose` adds config field inventory. |
| `stats` | Event counts per source (or event-type breakdown + field coverage % with `--source`). |
| `search` | Query the SQLite index via a small DSL (`--query`), or bypass it with `--raw`. |
| `tail` | Stream raw JSONL as it's written (follows by default). |
| `retention` | Delete files older than N days; `--days 0` wipes everything (confirmation required). |
| `dry-run` | Pipe a fixture file through `normalized` (+ `ruled` if `--rules` given), report match/alert rates. |
| `validate` | Structural check of `sources.toml` and `config/rules/*.yml`; optional cross-check against `normalized.toml`. |

## Parser Chain Behavior

`siemctl` itself doesn't parse logs — `normalized` does, and `siemctl dry-run` /
`stats` / `search` surface the results. Understanding the chain matters when
`dry-run` reports low match rates or `search` can't find an expected field.

Full detail: **[references/parser-chain.md](references/parser-chain.md)**

Summary: override rules (from `normalized.toml`) are checked first, in file order —
first match wins. If none match, a fixed-order auto-detection chain runs (prefix/shape
sniffing: `<N>` → syslog, `{`/`[` → JSON, `CEF:`/`LEEF:` → CEF/LEEF, then bare
RFC3164, then logfmt/CSV/XML/YAML heuristics). The **plain-text fallback always
succeeds** — no line is ever dropped (`_normalized: false`, `_raw` only). Ties don't
really occur: each detector either self-validates and returns `Some`, or the chain
falls through to the next by construction.

## Usage Examples

All verified by running the binaries in this repo (`target/debug/*`) against
`tests/fixtures/mixed.log` and `config/`.

### 1. Search failed SSH logins, TSV output

```bash
# setup: normalize + index the fixture with the app-level config so event_type/src_ip etc. populate
cat tests/fixtures/mixed.log | target/debug/normalized --stdin --data-dir data/ --config config/normalized.toml
target/debug/indexd --data-dir data/ --config config/sources.toml &  # let it scan, then stop it

target/debug/siemctl search --data-dir data/ \
  --query "_source_type == sshd AND event_type == ssh_auth_failure" --format tsv
```
```
_format _normalized     _raw    _received       _source_type    app_name        auth_action     auth_method     event_type      hostname        message proc_id source_addr     src_ip  src_port        timestamp       username
rfc3164 true    Jun 22 08:55:52 myhost sshd[1234]: Failed password for ubuntu from 10.0.0.5 port 22 ssh2 2026-07-02T20:11:11.313388676+00:00 sshd    sshd    Failed  password        ssh_auth_failure        myhost  Failed password for ubuntu from 10.0.0.5 port 22 ssh2 1234    stdin   10.0.0.5        22      Jun 22 08:55:52 ubuntu
... (6 rows total)
```

### 2. Group events by source (attack surface overview)

```bash
target/debug/siemctl search --data-dir data/ --query "GROUP BY _source_type"
```
```
{"_source_type":"sshd","count":10}
{"_source_type":"iptables","count":6}
{"_source_type":"systemd","count":5}
{"_source_type":"sudo","count":4}
```
Sorted by count descending, ties broken by group key ascending.

### 3. Dry-run a fixture through normalization + rules (needs `PATH` fix from Gotchas)

```bash
PATH="$PWD/target/debug:$PATH" target/debug/siemctl dry-run \
  --file tests/fixtures/mixed.log --config config/normalized.toml --rules config/rules/
```
```
=== Normalization ===
  Lines processed: 25
  Matched:         25  (100.0%)
  Unmatched:       0
[normalized] loaded config from config/normalized.toml

=== Rule Evaluation ===
  Alerts generated: 7
  Rules triggered:  4
    1003-iptables-deny
    1002-sudo-execution
    1005-ssh-login-success
    1001-ssh-brute-force
```

### 4. Validate config before deploying

```bash
target/debug/siemctl validate --config config/sources.toml --rules config/rules/
```
```
  OK   [haproxy] index_fields: [src_ip, src_port, frontend, backend, event_type, http_method, http_uri]
  ...
  Total: 15 source(s)

=== Sigma rules: config/rules/ ===
  OK   [cron-suspicious-command.yml]
  OK   [firewall-port-scan.yml]
  ...
Validation complete: 10 rule file(s), 0 error(s), 0 warning(s).
```

## Gotchas / Edge Cases

- **`dry-run` needs `normalized`/`ruled` on `PATH`** in this workspace layout (see
  Install section) — otherwise it fails with a clean "No such file or directory" error
  and produces no useful output at all.
- **`search` field predicates only work on indexed fields.** `sources.toml`'s
  `index_fields` (plus always-indexed `source_addr`, `hostname`, `app_name`,
  `timestamp`, `_source_type`, `severity`) is the full set of queryable columns. An
  unknown field is a **parse-time error** listing all known fields — it never silently
  matches nothing. To search unindexed fields (e.g. `message`), use
  `raw_contains('substring')` or `SELECT` it as an output projection (`SELECT` fields
  are *not* validated, so non-indexed keys like `message`/`_raw` can still be
  projected).
- **`--raw` and `--query` are mutually exclusive.** `--raw`'s argument, if given, is a
  literal substring — never DSL. Passing both is a clean error.
- **The index is eventually consistent** (inotify-driven `indexd`). Just-written events
  may not be indexed yet; `search --raw` bypasses the index and scans `data/raw/`
  directly for the freshest data (slower, no field filtering — substring-only).
- **`stats`/`search` fall back gracefully when there's no index yet** (`stats` counts
  raw JSONL lines instead; `search` returns an error suggesting `--raw` or running
  `indexd`) rather than crashing.
- **`retention --days 0` wipes everything** (raw logs + all index DBs). It requires an
  interactive `yes` confirmation, or `--yes`/`--force` for cron/non-interactive use —
  it refuses non-interactively without `--yes`.
- **`validate`'s cross-check (`--normalized-config`) is advisory only** — it never
  affects the exit code, because it can't see fields produced by structured-format
  parsers (CEF/LEEF/JSON) that don't go through the config-driven extraction path, so
  both directions of the comparison can have false positives.
- **DSL quoting is optional everywhere**; a token's role (field vs. value) is fixed by
  position, not by quoting. `src_ip == 10.0.0.5` and `'src_ip' == "10.0.0.5"` parse
  identically. `AND` binds tighter than `OR` — use parens to override.
- **`tail --follow` (default) never exits** — it polls every 200ms for new time-bucket
  directories. Use `--no-follow`/`-F` for a one-shot dump, or background/timeout it.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success. For `search`: at least one match was found/emitted. |
| `1` | Command-level failure or "no results": unknown command, unknown flag, missing required flag, config/data errors (`Err` from any `cmd_*` handler), `search` producing zero rows, `stats`/`tail`/`search --raw` finding no files. |
| (none run) | `--help`/`-h` at any level prints usage and exits `0`. |

`siemctl` never panics on user-facing errors — all `Result` errors are caught in `run()`
and printed as `siemctl: <message>` to stderr with exit code `1`. Per-bucket SQLite
errors during `search` (e.g. a bucket whose schema predates a new `index_fields` entry)
are treated as benign and skipped with a warning, not a hard failure — the query still
runs against every bucket whose schema does match.

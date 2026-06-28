# Implementation Plan — NOTES.md backlog

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done & committed.
Each task is a self-contained, independently committable + testable unit.
**Resume protocol:** read this file top-to-bottom, then `git log --oneline` to
see which tasks are committed. The first `[ ]`/`[~]` task is the resume point.
Never start a new task until the previous one is committed with green tests.

---

## Recommended order

Foundation-first so output-layer tasks don't get reworked:

| # | Task | Model | Effort | Depends on |
|---|------|-------|--------|-----------|
| T4 | indexd "does not exit" bug | **opus** | med | — |
| T3 | retention `--days 0` wipes everything | **sonnet** | low–med | — |
| T6 | normalized `--since/--until` time filter | **sonnet** | med | — |
| T8 | siemctl output/render layer (`--render`, `--format`) | **opus** | high | — (foundation) |
| T1 | siemctl: make full record the default (`--index-record`) | **sonnet** | low | T8 | ✓ |
| T5 | siemctl `--limit N` | **sonnet** | med | T8 | ✓ |
| T7 | siemctl `--group f1,f2` with counts | **opus** | high | T8 |
| T2 | merge sources.toml + normalized.toml (design doc) | **opus** | med | — |

T4, T3, T6, T2 are independent and can be done in any order. T1/T5/T7 all sit on
top of the T8 render layer, so T8 goes first among the siemctl-output tasks.

---

## T4 — indexd does not exit  (opus, med)  `[x]`
NOTES: "properly check whats going on with indexed, and why it does not exit"

**Diagnosis (reproduced against a scratch copy of data/raw, 7838 files / 26404 rows):**
The process was never actually stuck — two separate problems made it *look* stuck:
1. **Silent by default.** `EnvFilter::from_default_env()` with `RUST_LOG` unset
   suppressed all `info!` output, so a working `--no-watch` scan ran ~12s with
   zero feedback ("just kept open"). With `RUST_LOG=info` it worked but spewed
   15,679 lines (2 per file) — still no sense of overall progress.
2. **Uninterruptible initial scan.** The initial `scan_existing` runs before the
   watch loop and never checked `shutdown`, so a Ctrl-C during the ~12s scan
   wasn't honored until every file finished — "Ctrl-C doesn't work."

**Fix (src/indexd/src/main.rs):**
- Default the env filter to `info` when `RUST_LOG` is unset (still overridable;
  `RUST_LOG=debug` gives per-file detail, `RUST_LOG=warn` quiets it).
- Added `ScanProgress`: aggregate `progress:` line every 2s + a final
  `scan complete:` summary. Demoted per-file logs to `debug`.
- Threaded `&AtomicBool` shutdown into `scan_existing`; it checks before each
  dir and each file and returns early. Added a post-scan shutdown check so a
  signal during the initial scan exits instead of entering the watch loop.

**Verified:** `--no-watch` now prints progress every 2s + summary (no spam);
watch-mode SIGINT 3s in stopped the scan at 2.8s elapsed (2317/7838 files) and
exited cleanly (rc 0). All 42 `cargo test` pass.

**Perf follow-up (done):** wrapped each file's inserts in a single transaction
(`IndexDb::insert_batch`, replacing per-row `insert_event`), made `open_bucket`
a no-op when the bucket is already open (was re-running `CREATE TABLE` + 7×
`CREATE INDEX` for all 7838 files), and set `PRAGMA synchronous=NORMAL` under
WAL. Initial scan 11.6s → 3.8s (~3x); row counts identical (26404). 42 tests pass.

## T3 — retention `--days 0` removes everything  (sonnet, low–med)  `[x]`
NOTES: "ensure retention for 0 days works to remove everything(raw logs and indexes)"

**Done.** Removed the `days == 0` guard. `collect_old_files` already walks all of
`data_dir` including `index/`, so a 0-day cutoff (= now) catches raw logs, index
`.db`, and `.db-wal/.db-shm` sidecars; empty dirs are pruned afterward. Added a
`--yes`/`--force`/`-y` flag and a confirmation gate that only applies to
`--days 0`: interactive "yes" prompt when stdin is a TTY, refuse with a clear
error when non-interactive without `--yes`. Normal retention (≥1 day) behavior is
unchanged, so cron usage isn't affected. `--dry-run` previews raw+index. Help
text updated. New unit test `collect_old_files_zero_day_cutoff_catches_raw_and_index`;
all 21 siemctl tests pass. Verified manually: dry-run lists 3 files, non-TTY
refuses, `--yes` wipes all + prunes dirs, `--days 30` unchanged.

## T6 — normalized time-range filter  (sonnet, med)  `[x]`
NOTES: "normalized: allows a timerange ... so that only logs within a timerange are normalised"

**Done.** Added `--since <ts>` / `--until <ts>` (accept RFC3339, ISO without
zone, BSD syslog, and bare `YYYY-MM-DD` = midnight UTC) and `--drop-undated`.
`Processor::handle` filters on the event's **own** timestamp (computed before
`flatten`, so the receive-time fallback doesn't mask undated events) and skips
emit (stdout + storage) when outside `[since, until]`. Undated events pass by
default and are dropped only with `--drop-undated`, preserving the "never drops"
invariant unless opted in. `--since > --until` errors at startup.
Shared the timestamp parser: made `output::parse_event_timestamp` pub, added
`output::parse_time_bound` (CLI) and `output::event_time` (refactored the
bucketer's duplicated logic onto it).

**Verified:** 54 normalized unit tests (5 new: parse_time_bound, event_time,
in_time_range range/no-bounds/undated). test-normalized.sh 12/12. Manual e2e on
a multi-hour fixture: window keeps only in-range dated lines + undated
passthrough; `--drop-undated` keeps only in-range dated lines; bad range exits 1.

## T-HARNESS — pre-existing integration-test rot (newly found)  (sonnet, low)  `[x]`
Not part of the NOTES backlog; surfaced while verifying T6/T8. None are product
regressions — the binaries and unit suites are fine.
1. `test-pipeline.sh:22` — fixed siemctl path to `target/debug/siemctl`. ✓
2. `test-pipeline.sh:70` — added `--stdin` to normalized invocation. ✓
3. `test-pipeline.sh:241-244` — rewrote 4 broken `check ... echo ... | grep`
   calls (pipefail + wrong strings) to `check "..." grep -q "..." <<< "$STATUS_OUT"`.
   Updated strings to match actual siemctl output ("Total size:", "Source file
   counts:", "Indexed buckets"). ✓
4. `test-indexd.sh:50` — added `exit 0` so success doesn't return exit code 1. ✓

**Known remaining failures in test-pipeline.sh (pre-existing, not in scope):**
- Step 5: SSH brute-force alert not seen in ruled stdout (dedup window or rule
  condition issue in `ruled` binary — separate from siemctl).
- Step 6: correlated produces 0 alerts (depends on Step 5's missing brute-force
  alert). Both are pre-existing issues in ruled/correlated.

**Verified:** test-indexd.sh exits 0 (4/4 pass). test-pipeline.sh steps 1–4 and
7–8 all pass (36 passed, 7 failed — all 7 failures are in ruled/correlated steps).

## T8 — siemctl output/render layer  (opus, high)  `[x]`  ⭐ foundation
NOTES: "--render flag, to decide what fields to show ... and what format (json, tabs with headers on/off...), default is everything in json"

**Done.** New `src/siemctl/src/render.rs`: `Format` (Json / Tsv{header}),
typed `Val` (Str/Int/Real/Bool/Null so JSON re-serialization keeps types), and
`Renderer<W: Write>` with `emit_record` (structured rows) + `emit_raw_line`
(grep/dump/full lines). Flags `--render f1,f2,...` (ordered allowlist; default
all) and `--format json|tsv|tsv-noheader` (default json). All three search paths
now feed the Renderer; db.rs `query_bucket`/`print_rows`/`print_rows_cidr` are
generic over the writer and build a `Record` per row via `row_to_record`
(removed the old `row_to_json`/`json_escape`, moved escaping into render.rs).
Added `serde_json = "1"` (already used by indexd/ruled; locked 1.0.150) to parse
raw lines for render/tsv.

Key behaviors:
- **Default json unchanged**: index rows serialize in the same column order +
  escaping as before; grep/dump lines pass through **verbatim** (no parse) when
  json + no `--render` — zero regression on the default path.
- **`--render`/tsv on grep/dump** parses the JSON line; unparseable lines pass
  through (json) or are skipped (tsv).
- **`--full --render`** parses the resolved raw record, so you can select fields
  that aren't index columns (verified pulling `_source_type`).
- TSV header printed once; columns = `--render` fields, else first row's keys;
  tab/newline in values neutralized to spaces.

**Verified:** 32 siemctl unit tests (11 new render tests: format parse, json
all/selected, tsv header/noheader/all-fields/escaping, raw passthrough/parse,
unparseable handling). Manual e2e on a freshly-indexed scratch dataset across
index + grep + dump paths, `--full`, tsv/tsv-noheader, field subsets, and error
cases (`--format yaml` and empty `--render` both exit 1).

**Foundation for:** T1 (`--index-record` just flips the existing `full` default
— the raw-line path already routes through the Renderer), T5 (`--limit` — the
Renderer is the natural place to count + stop), T7 (`--group` — emit aggregate
rows as `Record`s through the same Renderer).

## T1 — make full record the default  (sonnet, low)  `[x]`
NOTES: "make --full the default ... returning just the index is a switch by adding --index-record"

**Done.** Flipped `full` default to `true` in `cmd_search`. Added `--index-record`
flag to opt out (sets full=false). `--full` kept as an accepted no-op alias.
Help and examples updated. 35 tests pass.

## T5 — siemctl `--limit N`  (sonnet, med)  `[x]`
NOTES: "siemctl allows to stop after a certain amount of hits with --limit"

**Done.** Added `--limit N` to `cmd_search`. Renderer owns `limit: Option<usize>`
+ `emitted: usize`; new `is_done()` method. `emit_record`/`emit_raw_line` are
no-ops once limit is reached (skipped TSV lines don't count against the limit).
`is_done()` checked after each emit in `print_rows`, `print_rows_cidr`, and the
file-scan loops in `search_by_grep` and `search_dump`; checked per-bucket in
`search_by_index` to stop scanning DBs early. 3 new render tests. 35 tests pass.

## T7 — siemctl `--group f1,f2`  (opus, high)  `[ ]`
NOTES: "--group src_ip ... unique src_ip per line + count ... also --group src_ip,dst_ip"

- Add `--group <comma-list>`; validate every field is a known **indexed** field
  (reuse `valid_fields`), else error (free-text grouping not supported).
- Buckets are separate SQLite DBs, so per-bucket `SELECT f1,f2,COUNT(*) GROUP BY
  f1,f2` then **merge counts in Rust** across buckets via a
  `BTreeMap<Vec<String>, u64>`.
- Output through the T8 Renderer: columns = group fields + `count`. Respect
  `--format`. Sort by count desc (or by key — pick desc, document it).
- Mutually exclusive with `--full`/`--index-record` (grouping returns
  aggregates, not records) — error if combined.

**Done when:** `--group src_ip` and `--group src_ip,dst_ip` produce unique
combos + counts merged across buckets; tests cover multi-bucket merge.

## T2 — merge sources.toml + normalized.toml (design)  (opus, med)  `[ ]`
NOTES: "discussion: consider merging sources.toml and normalized.toml"

This is **analysis + recommendation**, not necessarily code. Deliver
`docs/config-merge-proposal.md` covering:
- Consumers today: `normalized` reads normalized.toml (listen/storage/overrides/
  extract); `indexd` + `siemctl` read sources.toml (index_fields per source).
- Options: (a) single file with namespaced sections each tool ignores what it
  doesn't need; (b) keep split but share via `--config-dir` (already supported
  by normalized); (c) status quo.
- Trade-offs: coupling, blast radius, who must parse what, migration cost.
- Recommendation + migration steps if "merge" is chosen.

**Done when:** proposal doc committed; no behavior change unless we then act on it.

---

## Token-budget / mid-task resilience strategy

1. **One task = one commit.** Never leave the tree half-edited across tasks.
   Each task above compiles, passes `cargo test` for its crate, and passes the
   relevant integration test before commit.
2. **Update this file as you go.** Flip `[ ]`→`[~]`→`[x]` and commit it *with*
   the task. The checklist + `git log` is the single source of truth on resume.
3. **Checkpoint within long tasks (T7, T8).** Commit at natural sub-points
   (e.g. T8: land `render.rs` + tests first, then wire each search path in
   follow-up commits). Note the sub-step in the task's `[~]` line.
4. **Build debug, not release, for integration tests** (per CLAUDE.md): the
   integration scripts use debug binaries — run `cargo build` before
   `bash tests/integration/*.sh`.
5. **Leave a breadcrumb.** If stopping mid-task, append a short
   `RESUME:` note under that task describing the exact next edit and any
   half-done file, so the next session doesn't re-derive context.
6. **Don't batch unrelated tasks** into one session's working tree — keeps each
   resumable in isolation.

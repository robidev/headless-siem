# SOC Usability Improvements — Roadmap

Gaps identified during live monitoring of a homelab network (2026-06-29).
Ordered by operational impact.

---

## 1. `siemctl alerts` — Alert query interface

> **Status: implemented** (2026-07-02, Batches 1–2 in the Implementation
> Plan below). Two deviations from the sketch below, both explained where
> they're implemented: default output is the **whole alert record**, not a
> curated subset (`digest.rs`'s own reasoning: match `search`'s existing
> "whole record when no SELECT" convention rather than invent a second
> one) — so there's no special-cased `SELECT _raw`, since `_raw` already
> resolves normally to the embedded event's own `_raw` field. See
> [user-guide.md](user-guide.md#alerts) for usage.

**The problem:** Alerts from `ruled` land in `data/alerts/YYYY/MM/DD/HH/alerts.jsonl`
and correlated alerts in `data/alerts/correlated/YYYY/MM/DD/HH/correlated.jsonl`. There is
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

> **Status: implemented** (2026-07-03, llm-based-soc implementation plan
> Phase 1.3). Built the **alternative** design below (inotify watcher, no
> `ruled`/`correlated` changes): `config/notify/alert-watch.sh` +
> `config/systemd/headless-siem-alert-watch.service` +
> `tests/integration/test-alert-watch.sh`. Watches `data/alerts/`
> recursively; for `alerts.jsonl` (has `level`) forwards anything at or
> above a configurable threshold (`ALERT_WATCH_LEVEL`, default `high`); for
> `correlated.jsonl` (no `level` field — see this doc's own note further
> down and `llm-based-soc/soc-structure/overall.md`'s correlated-alert
> convention) always forwards, since a correlation is by definition a
> multi-step compound pattern, inherently rarer/higher-signal than a single
> rule firing. Calls the configured notify script
> (`SOC_NOTIFY_SCRIPT`, default `/usr/local/bin/soc-notify`) as
> `<script> <priority> <subject> <body-file>` — that script itself is an
> `llm-based-soc` deployment artifact (see
> `llm-based-soc/documentation/escalation.md`), not part of this repo;
> until it's deployed, the watcher logs an error per alert instead of
> silently doing nothing. Tracks a per-file byte offset (so a restart
> doesn't replay history) and is independent of the LLM analyst's 10-minute
> cron — the whole point is a signal path that still works if the agent
> loop is down. See the script's own header comment for the full design
> rationale, including a subtle bash pitfall it had to route around:
> `kill -- -$$` inside a signal trap re-triggers that same trap unless the
> trap is disabled first, and a plain single-PID `kill` doesn't reliably
> stop a `cmd1 | cmd2` pipeline's other member — the fix is a
> process-group kill (matching `KillMode=control-group`, systemd's own
> default stop behavior for this unit).
>
> **Update (2026-07-04):** running this live surfaced a real miss — a
> brand-new hour bucket's first alert was never notified on. Root cause is
> the same class of inotify recursive-watch race fixed for `indexd` in
> item 27/Phase 1.6 (a multi-level-deep directory chain can be created
> faster than the watcher installs a watch on the new intermediate
> levels, so the kernel never emits an event for it — nothing to catch up
> on later, because the event never existed). Fixed with the same
> pattern: a periodic mtime-based reconciliation sweep
> (`sweep_recent`/`sweep_loop` in the script, `ALERT_WATCH_SWEEP_INTERVAL`/
> `ALERT_WATCH_SWEEP_LOOKBACK_MINUTES` to tune) running alongside the
> reactive watch, both funneling through the same offset-tracked
> `process_file()` so there's no double-notify risk. Also switched the
> notify backend to a real, working `soc-notify` (ntfy.sh, public instance
> for now — see `llm-based-soc/decisions.md` § 0.5) and verified the full
> path end-to-end against the live dev pipeline: injected alert → `ruled`
> → watcher → `soc-notify` → push notification received.

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

> **Status: implemented** (2026-07-02, Batch 4 in the Implementation Plan
> below). Opt-in via a new `ruled --suppress <path>` flag (not automatic) —
> a ready-to-edit `config/rules/suppress.toml` exists with no active rules
> and the example below commented out; see `src/ruled/src/suppress.rs`'s
> module doc comment for the condition grammar actually implemented.

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

> **Status: implemented** (2026-07-04, llm-based-soc implementation plan
> Phase 1.4). `siemctl stats --interval Nh (--last Nh | --after ... --before
> ...) [--source SRC]` — matches the proposed design below closely (one
> column per interval-sized bucket, one row per source, or per event type
> with `--source`). `--interval` must be a whole number of hours (the index
> is bucketed per clock-hour; sub-hour trends are `siemctl digest`'s
> sparkline's job, not this command's). Column labels are always
> date-qualified (`MM-DD HH:00`) rather than the mockup's bare `HH:MM`,
> since this is a specialist's investigation tool read closely, not a
> Tier-1 agent's every-run summary — unambiguous beats compact here.
> Building this surfaced a real, previously untested bug in the existing
> aggregate `--after`/`--before` path: it parsed index bucket *filenames*
> ("2026-06-22-08.db") with the CLI-argument parser, which requires a "T"
> separator ("2026-06-22T08") and returns no match for the dash-only form —
> silently skipping the filter entirely, so `stats --after X --before Y`
> was returning the grand total across *all* buckets regardless of the
> requested range. Fixed at both call sites (the pre-existing aggregate
> path and the new trend path) to use the filename-specific parser;
> `tests/integration/test-siemctl-stats.sh` has a regression check for it.

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

---

## Implementation Plan (items 1, 2, 4 — the LLM-analyst prerequisites)

Scoped 2026-07-02 against the real code, for the three items that
`docs/design-llm-soc-analyst.md` names as blocking (see that doc's
"Prerequisites" section; the digest, item 3 there, is planned separately in
`docs/design-digest-command.md`). Items 3/5/6/7 are not scoped here — they
aren't on the analyst's critical path.

### Ground truth that shaped this plan

- `ruled` alerts (`data/alerts/YYYY/MM/DD/HH/alerts.jsonl`) and correlated
  alerts (`data/alerts/correlated/YYYY/MM/DD/HH/correlated.jsonl`, confirmed
  via `src/correlated/src/output.rs` — same `HH`-level bucketing as `ruled`,
  despite the coarser path shown in `CLAUDE.md`'s architecture diagram) have
  **genuinely different JSON shapes**, not just different field names:
  - `ruled` alert: `rule_id`, `rule_title`, `level`, `event` (single nested
    object), `timestamp` (epoch seconds).
  - correlated alert (`src/correlated/src/correlation.rs:189-200`):
    `correlation_id`, `correlation_title`, `join_field`, `join_value`,
    `chain_start`, `chain_end`, `step_counts` (array), `sample_events`
    (array of up to 5 embedded events) — **no `level` field at all**.
  - Decision: don't paper over this with field aliasing (e.g. mapping
    `correlation_id` to `rule_id`). Tag every loaded record with a synthetic
    `type` field (`"ruled"` or `"correlated"`) and let field lookups resolve
    against whichever shape is actually present. A query like
    `level == high` simply never matches correlated rows, which is correct
    today (they carry no severity) — a future correlated-severity feature is
    a separate, unscoped change.
  - Field resolution order for the query DSL, covering both shapes:
    top-level key → `event.<field>` → `sample_events[0].<field>`.
- `siemctl`'s DSL parser (`query.rs`) already supports this reuse for free:
  `Query::parse(dsl, &valid)` accepts *any* field name when `valid` is an
  empty `HashSet` (`query.rs:476`, `!valid.is_empty() && ...`) — this is the
  exact bypass needed for alert fields, which aren't a fixed indexed schema.
  Only `Query::to_sql()` is SQL-specific; a new JSON-evaluator sits alongside
  it and reuses the same `Expr`/`Condition` AST unchanged.
- `db::cidr_contains` (`src/siemctl/src/db.rs`) is already a plain Rust
  function (the SQLite UDF is a thin wrapper around it) — directly reusable
  by the new JSON evaluator with no duplication.
- Suppression conditions (`cidr_match(src_ip, "...")`, equality, AND/OR/NOT)
  need a small boolean-expression evaluator inside `ruled`, which doesn't
  depend on `siemctl` today. Decision: hand-roll a small (~100–150 line)
  parser/evaluator directly in `ruled`, rather than extracting a shared
  crate for two different-shaped grammars (siemctl's DSL also has
  SELECT/GROUP BY/LIMIT, which suppression doesn't need). This matches the
  codebase's existing convention of duplicating small parsers per-crate
  instead of centralizing (e.g. `sources.rs` vs. `normconfig.rs`).
- `ruled`'s Sigma loader already filters `config/rules/` by `.yml`/`.yaml`
  extension (`rules.rs:302-305`), so `config/rules/suppress.toml` sitting in
  the same directory (as the roadmap item proposes) is automatically ignored
  by rule loading — no conflict.
- `ruled` has no `toml` dependency yet; add `toml = "0.8"` + use its existing
  `serde` derive, matching `indexd`/`correlated`'s config-loading convention.
  Also add `chrono` (already a workspace dependency, used by `normalized`)
  for the `expires` date check — compared as a fixed-width ISO string, so a
  plain string comparison against `Utc::now()` suffices, no date-math needed.
- **Resolved 2026-07-02 (was an open question):** item 2's design is a
  single append-only `data/alerts/ack.jsonl`, not a `.ack` sidecar per hour
  bucket — one file, no fragmenting a single logical action ("ack this
  rule") across however many buckets it happens to span. Each line is
  `{"rule_id", "timestamp", "note"}` (`timestamp` = when the ack action was
  taken, epoch seconds — dropped the original sketch's `state`/`analyst`
  fields, see below).
  - **Ack semantics: a watermark, not a global switch.** `siemctl alerts
    ack <rule_id>` means "hide alerts for this rule_id up to now" — any
    alert with `timestamp <= ` the *latest* ack timestamp for that rule_id
    is hidden by default; a *new* alert for the same rule_id firing after
    the ack shows up normally next time. This is why `state`
    (ack/closed/fp) was dropped from the schema: those are richer,
    per-alert-instance investigation states that don't fit a "one
    watermark per rule" model — a future richer state-tracking feature
    would be a different, unscoped change, not a bigger version of this
    one.
  - **Retention gap this creates, and how it's closed:** `siemctl
    retention` already walks the whole `data_dir` tree by file mtime
    (`collect_old_files` in `main.rs`), so it already cleans bucketed
    `alerts.jsonl`/`correlated.jsonl` files fine — a bucket's mtime reflects
    its last write, so it ages out normally. `ack.jsonl` can't work that
    way: it's touched every time *any* rule anywhere gets acked, so its
    mtime is always recent regardless of how old individual lines inside
    it are — whole-file mtime deletion can never clean it. Batch 3 extends
    `siemctl retention` (same `--days`/`--dry-run`/`--yes` flags already
    there, not a new subcommand — "one thing to run periodically" per the
    user's own framing) to also compact `ack.jsonl`: drop lines whose own
    `timestamp` predates the retention cutoff, rewrite the file with the
    survivors.

### Batches

Strict dependency order: Batch 1 → Batch 2 → Batch 3. Batch 4 (suppression)
is independent of the other three (different crate, no shared code) and can
run whenever, but is listed last because it's lower operational urgency than
having query access to alerts at all.

**Batch 1 — Alert loading + JSON query engine** — *Sonnet 5, effort: high*
— ✅ **Done** (2026-07-02)
(New parsing/evaluation logic, not just plumbing — same risk profile as the
digest's Batch 1.)
- New `src/siemctl/src/alerts.rs`: bucket enumeration for
  `data/alerts/YYYY/MM/DD/HH/alerts.jsonl` and
  `data/alerts/correlated/YYYY/MM/DD/HH/correlated.jsonl` (generalize
  `time::HourBucket`'s directory-building rather than duplicating it
  wholesale — it currently only builds `raw/` paths).
- JSON query executor reusing `query::Query::parse` unchanged: add
  `Expr::eval_json`/`Condition::eval_json` operating on `serde_json::Value`
  (field resolution order as above; `MatchMode::Cidr` reuses
  `db::cidr_contains`). Row mode (filter + optional SELECT projection +
  LIMIT) and GROUP BY mode (filter + group + count), mirroring `run_query`'s
  two modes in shape.
- Unit tests: field resolution across both alert shapes, each `MatchMode`,
  GROUP BY counting, `type == correlated` filtering.

  Implementation notes for Batch 2 (the consumer of this code):
  - `time.rs`: `HourBucket::raw_dir` was replaced by a general
    `dir_under(base)` (builds `base/YYYY/MM/DD/HH` for any base, not just
    `data_dir/raw`); `hour_dirs_in_range` now delegates to a new
    `dirs_in_range_under(base, from, to)`. `raw_dir` itself was deleted
    rather than kept as a thin wrapper — nothing outside its own test used
    it once the refactor landed, and an unused convenience method is just
    noise.
  - `query.rs` gained the actual reusable pieces: `resolve_json_field`
    (`pub(crate)`, the top-level → `event.<field>` → `sample_events[0]
    .<field>` traversal, returning the *native* JSON value so callers pick
    their own coercion) and `json_scalar_to_string` (`pub(crate)`, used by
    both `eval_json`'s WHERE-matching and `alerts.rs`'s `GROUP BY` keying —
    one traversal implementation, not two that could drift apart).
    `Condition::eval_json`/`Expr::eval_json` are `pub(crate)` on the
    existing types, reusing `Query::parse` and the `Expr`/`Condition` AST
    completely unchanged — no new parser.
  - `render.rs`'s `json_to_val` (JSON → `Val`) and `main.rs`'s `walk_jsonl`
    (generic recursive `.jsonl` directory walk, previously used only by
    `collect_raw_files` for unbounded `--after`/`--before`) were both
    widened from private to `pub(crate)` so `alerts.rs` could reuse them
    instead of duplicating a JSON-to-`Val` mapping or a recursive walker.
  - `alerts.rs::run_query(records, query, renderer) -> Result<i32>` mirrors
    `query::run_query`'s exact external shape (same `Renderer` contract,
    same 0/1 exit-code convention) — Batch 2's CLI should be able to call
    it exactly like `cmd_search` calls `query::run_query`, with no
    additional adaptation layer.
  - One real design decision resolved during implementation, not just
    plumbing: `SELECT` projection uses `resolve_json_field` too (not
    `Renderer`'s own flat-object JSON parsing, which only ever sees a
    record's top-level keys). Without this, `WHERE src_ip == ...` would
    work on a `ruled` alert (via the fallback chain) while `SELECT src_ip`
    silently returned `null` (no fallback) — same field, inconsistent
    behavior depending on which clause referenced it. Both clauses now
    share one resolver.
  - Everything is `#[allow(dead_code)]` at the module level (matching
    Batches 1–2 of the digest plan) — nothing outside this file's and
    `query.rs`'s own tests calls any of it yet; strip the annotations as
    Batch 2 wires the CLI in.
  - `cargo build`/`cargo build --release`/`cargo test` (whole workspace)
    clean: 157 tests in `siemctl` (up from 133 after the digest command),
    0 warnings. All integration scripts still pass individually (same
    pre-existing unrelated `test-ruled.sh` failure as before).

**Batch 2 — CLI wiring** — *Sonnet 5, effort: medium*
— ✅ **Done** (2026-07-02) — closes out `siemctl alerts` (item 1);
only Batch 3 (state management, item 2, blocked on the open design question
above) and Batch 4 (suppression, item 4, independent) remain in this doc.
(Mechanical once Batch 1's engine exists.)
- `siemctl alerts [--query DSL] [--after ..] [--before ..] [--correlated]
  [--data-dir DIR] [--format json|tsv]` subcommand, wired into `main.rs`
  dispatch and `print_top_help`.
- Output: reuse `render::Renderer`/`Record`/`Val` for projected/grouped
  output; reuse the existing raw-line passthrough path for whole-alert
  output when no `SELECT` is given (matches how `search` already handles
  `_raw`/whole-row output — don't invent a second convention).
- Integration test following `tests/integration/test-siemctl-group.sh`'s
  pattern: real alerts.jsonl fixture, assert on a few `--query` DSL forms
  from the roadmap item's examples.

  Implementation notes:
  - `cmd_alerts` mirrors `cmd_search`'s arg-parsing shape exactly (same
    flag-loop style, same `--after`/`--before` → `HourBucket::parse`
    handling), and calls `alerts::load_alerts` + `alerts::run_query`
    exactly like `cmd_search` calls `query::run_query` — no adaptation
    layer needed, confirming Batch 1's "mirror `run_query`'s external
    shape" design paid off.
  - `--correlated` is implemented as a plain `Vec::retain` filter on the
    loaded records by their synthetic `type` field, run *before*
    `alerts::run_query` — not by constructing an `Expr::And` and splicing
    it into the parsed query. Simpler, and avoids exposing AST
    construction outside `query.rs` for a one-off CLI convenience flag.
  - Confirmed by testing against this repo's own real `data/alerts/`
    (10 rule types, hundreds of alerts): default dump, `GROUP BY
    rule_id,rule_title`, `SELECT ... WHERE level == high`, and
    `--format tsv` all behave correctly on real data, not just synthetic
    fixtures.
  - Docs added: an `### Alerts` section in `user-guide.md`'s Operations
    part (right after `### Digest`), and a `Status: implemented` banner
    on this doc's item 1 above documenting the two deviations from the
    original sketch (whole-record default output, no special-cased
    `SELECT _raw`).
  - `cargo build`/`cargo build --release`/`cargo test` (whole workspace)
    clean: 157 tests in `siemctl` (unchanged from Batch 1 — this batch
    added an integration test, not unit tests), 0 warnings. New
    `tests/integration/test-siemctl-alerts.sh`: 18/18 assertions pass.
    Same pre-existing unrelated `test-ruled.sh` failure as every prior
    batch.

**Batch 3 — Alert state management (item 2)** — *Sonnet 5, effort: medium*
— ✅ **Done** (2026-07-02) — this closes out every item in this roadmap
doc (Batch 4/item 4 was already done — see below).
Depends on Batch 1/2 (done). Design resolved above (2026-07-02) — ready to
implement, nothing left to decide.
- `siemctl alerts ack <rule_id> [--note "text"]`: append
  `{"rule_id","timestamp","note"}` (`timestamp` = now, epoch seconds) to
  `data/alerts/ack.jsonl`, creating the file if it doesn't exist yet.
- `siemctl alerts`'s default output filters out any alert whose `timestamp`
  is `<=` the *latest* ack timestamp for its `rule_id` (no matching ack
  entries → nothing filtered for that rule_id). `--all` disables the filter
  and shows everything, acked or not. Correlated alerts have no `rule_id`
  (they key on `correlation_id` instead — see Batch 1's ground-truth notes)
  so acking is a `ruled`-alert-only concept; a correlated alert is never
  filtered by this.
- Extend `siemctl retention` (not a new subcommand): after its existing
  mtime-based sweep, read `data/alerts/ack.jsonl` if present, drop lines
  whose `timestamp` predates the `--days` cutoff, rewrite the file with the
  survivors (or delete it if none survive). Respects `--dry-run` (report
  how many stale ack lines would be dropped, without rewriting) and the
  existing confirmation flow for `--days 0`.
- Unit tests: ack-then-filter round trip (alert before the watermark
  hidden, alert after it still shown), multiple acks for the same rule_id
  use the latest timestamp, `--all` bypasses filtering, retention's
  ack-compaction drops only stale lines and leaves fresh ones + other
  files untouched.
- Integration test extending `test-siemctl-alerts.sh`'s fixture (or a new
  script — whichever reads more naturally once written): `ack`, confirm
  the alert disappears from default output and reappears with `--all`,
  confirm a *new* alert for the same rule_id after the ack still shows up
  unfiltered.

  Implementation notes:
  - `siemctl alerts ack` is a positional subcommand of `alerts`
    (`cmd_alerts` checks `args.first() == Some("ack")` and dispatches to
    `cmd_alerts_ack` before doing any of its own flag parsing), not a
    separate top-level command — matches how the roadmap's own example
    usage (`siemctl alerts ack <rule_id>`) reads.
  - `alerts.rs` gained four functions: `ack` (append one watermark line),
    `load_ack_watermarks` (latest timestamp per `rule_id`, a `HashMap`),
    `filter_acked` (drops ruled alerts at-or-before their rule's
    watermark — records with no `rule_id`, no matching watermark, or no
    `timestamp` are always kept, i.e. it fails open rather than risk
    hiding something it can't confidently evaluate), and
    `compact_ack_log(path, cutoff_epoch, dry_run)` — one function handles
    both the dry-run count and the real rewrite, so there's exactly one
    place that decides which lines are stale.
  - `siemctl retention` required more surgery than a one-line hook: its
    original early-return ("no files older than N days found") had to
    become `old.is_empty() && stale_ack_lines == 0`, since there could be
    zero old *files* but stale ack *lines* still worth reporting/dropping
    — the original single-condition check would have silently skipped ack
    compaction whenever nothing else needed deleting, the most common case
    in practice.
  - `cargo build`/`cargo build --release`/`cargo test` (whole workspace)
    clean: 168 tests in `siemctl` (up from 157), 0 warnings.
    `test-siemctl-alerts.sh` extended in place (27/27, up from 18) rather
    than split into a separate script — acking and querying are the same
    feature area and share the same fixture. Same pre-existing unrelated
    `test-ruled.sh` failure as every batch before this one.

**Batch 4 — Alert suppression rules (item 4)** — *Sonnet 5, effort: high*
— ✅ **Done** (2026-07-02) — this closes out the alert-suppression item.
(At the time this batch was built, Batch 3 was still blocked on the open
design question above; that question was resolved and Batch 3 completed
afterward — see its own entry — so every batch in this doc is now done.)
(Independent of Batches 1–3; touches only `ruled`. High effort because it's
new grammar/parsing code where a subtle bug means real detections silently
disappear — the failure mode is invisible unless you go looking.)
- Add `toml`, `chrono` deps to `src/ruled/Cargo.toml`.
- New `src/ruled/src/suppress.rs`: `#[derive(Deserialize)]` structs for
  `config/rules/suppress.toml` (`rule_id`, `condition`, `expires`, `note`);
  a small recursive-descent parser/evaluator for `condition` supporting
  `==`/`!=` against a literal, `cidr_match(field, "cidr")`, `AND`/`OR`/`NOT`,
  parens — evaluated directly against the alert's embedded event
  (`serde_json::Value`), no SQL involved.
- `expires` check at load time: string-compare against `Utc::now()`
  (ISO date strings sort correctly as strings); log a one-time warning per
  expired rule at startup, per the roadmap item's spec — it still suppresses,
  it just nags.
- Wire into `src/ruled/src/main.rs`: new optional `--suppress <path>` flag,
  loaded once alongside `rule_set`; check suppression after
  `rule.matches(&event)` returns `true` and before `router.emit(...)`
  (`main.rs:159-169`). Log a suppressed-alert count at shutdown alongside
  the existing `"[ruled] shutdown complete"` line.
- Unit tests for the condition parser/evaluator (equality, cidr, AND/OR/NOT,
  malformed condition strings); an end-to-end test that a matching
  suppression rule prevents `router.emit` from being called, and an expired
  rule still suppresses but logs the warning.

  Implementation notes:
  - One deliberate change from the original sketch: a malformed
    `condition` string is a **warning, not fatal** — that one rule is
    skipped and the rest of the file still loads, matching
    `rules::load_rules`'s own "warn and skip one bad file" posture for
    Sigma YAML. A hard failure on one config typo would take down the
    entire `ruled` process (fail closed — no alerts at all), which is
    worse than the alternative (fail open — one intended suppression
    doesn't happen, but detection keeps working). Malformed *TOML syntax*
    in the file as a whole is still fatal at startup — that's a config the
    operator needs to fix before the process can know what it's supposed
    to load at all.
  - `cidr_contains`/`ipv4_to_u32` are duplicated from
    `siemctl/src/db.rs` rather than shared across the workspace — `ruled`
    has no dependency on `siemctl` today, and ~25 lines of IPv4 CIDR math
    isn't worth introducing a shared crate for two call sites.
  - `config/rules/suppress.toml` was added as a real, ready-to-edit file
    (`ruled`'s Sigma loader already only reads `.yml`/`.yaml` from that
    directory, confirmed by a dedicated integration test — a `.toml` file
    living alongside the detection rules doesn't interfere) with the
    roadmap's own example commented out, not deleted — no suppression is
    active by default. `config/systemd/headless-siem-ruled.service` got a
    commented-out `--suppress` line showing how to enable it (verified the
    unit file still parses with `systemd-analyze verify`).
  - New `tests/integration/test-ruled-suppress.sh` (kept separate from the
    existing `test-ruled.sh`, which has a pre-existing unrelated failure —
    didn't want to entangle a new feature's tests with an already-broken
    file): matching-rule suppression, non-matching passthrough, `.toml`
    ignored by the Sigma loader, startup/shutdown logging, expired-rule
    and malformed-condition behavior, fatal malformed TOML. 10/10 pass.
  - `cargo build`/`cargo build --release`/`cargo test` (whole workspace)
    clean: 58 tests in `ruled` (up from 47), 157 in `siemctl` (unchanged —
    this batch didn't touch siemctl), 0 warnings. Same pre-existing
    unrelated `test-ruled.sh` failure as every prior batch.

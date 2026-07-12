# Design Proposal: `siemctl digest`

> **Status: implemented** (2026-07-02, Batches 1–4 in the Implementation Plan
> below). This doc remains the design record; for usage see
> [user-guide.md](user-guide.md#digest) and `config/digest.toml`.

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
- "Gone silent" / "new sources": since 2026-07-12 these two are diffed over a
  **separate long lookback window** (`coverage_lookback_hours`, default 24h,
  ending at the digest window's end) against that lookback's own preceding
  baseline — not against the window's short adjacent baseline — so a
  sub-daily source (corosync, pmxcfs) doesn't flap between the two lists on
  a short `--window`. The lookback has its own independent cold-start gate
  (`coverage_cold_start` in JSON, alongside the short-window `cold_start`).
  Everything else in this section still describes the window itself.
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
coverage_lookback_hours = 24  # gone_silent/new_sources lookback, independent of --window (added 2026-07-12)

[network]
new_destination_always_flag = true

[alerts]
concentration_threshold_pct = 80  # warn if one rule > 80% of alert volume
```

---

## Implementation Plan

Scoped 2026-07-02 by reading the actual `siemctl`/`indexd` internals against this
spec. Key decisions made during scoping (so a fresh session doesn't re-derive
them):

- **No `indexd` schema changes.** The indexed `raw_file` column already encodes
  exact minute/second via its zero-padded path
  (`raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl`), which sorts lexicographically =
  chronologically. Sub-hour window/baseline boundaries and the 10-minute
  sparkline buckets are computed from `raw_file` string ranges in SQL — this
  avoids touching the mandatory-indexed-field list, which would orphan
  existing `.db` buckets built before the change.
- **"Unparsed high-volume sources"** (`_normalized: false`) isn't indexed and
  doesn't need to be — read the raw JSONL for just the window (small, hours of
  data), the same fallback pattern `stats_from_raw` in `main.rs` already uses.
- **"New outbound destinations"** — rather than hardcoding "this host's IP",
  use the already-indexed `filterlog` field `direction == "out"`.
- **"sshguard restart cycles"** — sshguard has no parser at all today. This
  refers to the *systemd unit* restarting (`app_name=systemd`, `event_type` ∈
  `unit_stopped`/`unit_started`/`unit_failed`, `unit` containing `sshguard`),
  not a new sshguard log parser.
- **WAN interface `re1`** (hardcoded in the mockup) becomes a
  `config/digest.toml` value instead.
- **Alerts "first-time-ever rule"** scans the full `data/alerts/` tree (not
  just the baseline window) — alert volume is small enough for this to be
  cheap.
- Relevant `event_type` vocabulary confirmed in `config/normalized.toml`:
  `pfsense_config_change` (fields `admin_user`, `src_ip`, `pfsense_page`),
  `sudo_command` (fields `username`, `target_user`, `command`, `tty`),
  systemd `unit_started`/`unit_stopped`/`unit_stopping`/`unit_failed`
  (field `unit`). Severity strings (`src/normalized/src/event.rs`):
  `emergency`, `alert`, `critical`, `error`, `warning`, `notice`,
  `informational`, `debug`.

### Batches

Strict dependency order — each batch needs the previous one merged before it
can build. Model/effort noted per batch so each can be run as one session.

**Batch 1 — Time/window math + query engine core** — *Sonnet 5, effort: high*
— ✅ **Done** (2026-07-02)
(Correctness bugs here silently corrupt every number downstream, so it
warrants the higher effort despite being a small diff.)
- `time.rs`: parse `--window`/`--interval` durations (`6h`, `10m`) and explicit
  ranges (`start..end`); compute window+baseline pairs; derive exact event
  time from `raw_file` path; lexicographic range-string helper for SQL;
  N-minute bucket-key math. Unit tests for month/year rollover.
- New `digest_query.rs`: bucket enumeration with partial first/last hour;
  `group_count_in_range()` (GROUP BY + raw_file-range WHERE, built on existing
  `db::open_bucket_conn`/`fold_group_sql`); minute-bucketed count helper for
  the sparkline. Tests reuse the existing temp-SQLite harness pattern from
  `db.rs`.

  Implementation notes for Batch 2 (the consumer of this code):
  - Added `chrono = "0.4"` to `src/siemctl/Cargo.toml` (precedented — same
    crate `normalized` uses for identical UTC calendar-math reasons).
    `HourBucket`'s existing hand-rolled calendar math was left untouched;
    the new `time::Window`/`parse_duration`/`parse_window`/`raw_file_range`/
    `parse_raw_file_time` live alongside it as a separate, chrono-backed
    section.
  - `query::is_benign` was widened from private to `pub(crate)` so
    `digest_query.rs` can reuse the same "skip bucket on schema mismatch"
    tolerance `query.rs`'s executor already has, instead of duplicating it.
  - Everything new is marked `#[allow(dead_code)]` for now — nothing calls
    it yet. Remove those annotations as Batch 2 wires each piece in; if
    anything is still unused after Batch 2 lands, that's a sign it wasn't
    actually needed.
  - `cargo build` and `cargo test` (whole workspace) are clean: 102 tests in
    `siemctl` (up from 55), 0 warnings.

**Batch 2 — Section builders (business logic)** — *Sonnet 5, effort: high*
— ✅ **Done** (2026-07-02)
All in a new `digest.rs`, each producing a plain struct (shared by both
renderers in Batch 3):
- Coverage/health (source set diff, unparsed-source raw scan, index lag)
- Volume anomalies (delta % + flag threshold)
- Network (BLOCK sparkline, top blocked IPs, inbound ALLOW on configurable WAN
  iface, new outbound dests via `direction=="out"`)
- Auth (cross-source failures unified by `src_ip`, successes, sudo list from
  `sudo_command`)
- Alerts (read `data/alerts/**/*.jsonl`, first-time-rule vs full history,
  concentration %)
- Notable events (`pfsense_config_change`, systemd unit transitions grouped by
  unit, severity ∈ {critical, emergency})

  Implementation notes for Batch 3 (the consumer of this code):
  - `DigestReport`/`WindowInfo`/`DigestConfig` + all six section structs live
    in `digest.rs`, all `#[derive(Serialize)]` (added `serde` with the
    `derive` feature, and `chrono`'s `serde` feature, to `siemctl`'s
    `Cargo.toml` — `DateTime<Utc>` fields serialize as RFC3339 directly).
    `build_report(data_dir, &window, &DigestConfig::default())` assembles
    everything; call `DigestConfig { .. }` with loaded `config/digest.toml`
    values once Batch 3's config loader exists — `Default` gives the spec's
    documented defaults in the meantime.
  - `digest_query.rs` gained five more primitives beyond Batch 1's:
    `select_rows_in_range` (unaggregated row projection — sudo list, config
    changes, critical events), `first_seen_in_range`/`last_seen_in_range`
    (MIN/MAX `raw_file` for an arbitrary predicate — new-destination
    "first seen", service-restart first/last), `raw_files_in_range` (real
    filesystem walk of `data/raw/`, for the one section that needs
    never-indexed `_normalized: false` events), and
    `latest_raw_event_time`/`newest_indexed_event_time` (the coverage
    section's index-lag check). `db::value_ref_to_string` was extracted from
    `fold_group_sql` so `select_rows_in_range` could reuse it instead of
    duplicating the SQLite-value-to-string match.
  - **`config/sources.toml`'s `[source.sudo]` now indexes `target_user`,
    `command`, `tty`** (previously only `username`/`event_type`) — needed
    for the privilege-escalation list. Existing un-reindexed hour buckets
    just lack the column and are skipped by the existing `is_benign`
    tolerance, not an error; no `indexd` code change needed, this is the
    normal per-source `index_fields` extension path.
  - Real scoping calls made and documented in `digest.rs`'s module doc
    comment (read it before touching this file): auth failures are unified
    by `src_ip` only for event types that actually carry one (excludes
    `sudo_auth_failure`/`local_auth_failure` — local-origin, no network
    component); the alerts section covers `ruled` alerts only, not
    `data/alerts/correlated/` (that's `siemctl alerts`'s job, a separate
    unbuilt roadmap item); top-blocked/inbound rows group by their full key
    tuple rather than picking a "dominant protocol" per IP; critical/
    emergency notable events list source/event_type/severity/timestamp only,
    not the resolved raw message text (would need `byte_offset` too, and
    those fields aren't indexed).
  - `build_network` picks a default sparkline interval (window/24) when
    called without one; `build_network_with_interval` takes an explicit
    `chrono::Duration` for Batch 3's `--interval` flag to call instead.
  - Everything is `#[allow(dead_code)]` at the module level for now (exactly
    like Batch 1) — nothing outside this file's own tests calls any of it
    yet. Remove the annotation as Batch 3 wires the CLI in.
  - `cargo build`/`cargo test` (whole workspace) are clean: 126 tests in
    `siemctl` (up from 102 after Batch 1), 0 warnings. One pre-existing
    failure in `tests/integration/test-ruled.sh` ("loads 5 rules" vs. the
    actual 10 rule files now in `config/rules/`) predates this batch —
    confirmed via `git stash` — and is unrelated to the digest work.

**Batch 3 — CLI, rendering, config** — *Sonnet 5, effort: medium*
— ✅ **Done** (2026-07-02)
(Mechanical — the doc's ASCII mockups are the spec, low ambiguity.)
- `config/digest.toml` loader using `serde::Deserialize` + the `toml` crate
  (add both as new `siemctl` deps) — this matches `indexd`/`correlated`'s own
  config loaders, not `normconfig.rs`'s hand-scan (that one is deliberately a
  best-effort *advisory* read of another crate's config file, not the right
  model for siemctl's own config)
- `siemctl digest` subcommand + arg parsing, wire into `main.rs` dispatch and
  `print_top_help`
- Text renderer matching the doc's exact tables/sparkline/`←` formatting
- JSON renderer via `serde_json` matching the doc's documented schema

  Implementation notes for whoever builds `siemctl alerts`/the analyst loop
  next (nothing left for a future digest batch — this closes the command):
  - New `digest_config.rs` (`find_digest_toml` + `load`/`load_or_default`,
    same discovery-path convention as `sources::find_sources_toml`/
    `normconfig::find_normalized_toml`) and a real `config/digest.toml`
    checked in with the spec's documented defaults, fully commented.
    Malformed config is a warning + fallback to defaults, not fatal.
  - Added two config fields the original spec's TOML implied but Batch 2
    hadn't wired up: `new_source_always_flag` (volume) and
    `new_destination_always_flag` (network) — both default `true`; setting
    either `false` suppresses that flag/list without changing anything else.
  - `build_report`/`build_network_with_interval` now take an explicit
    `interval: Duration` (the CLI's `--interval`) instead of the Batch 2
    placeholder `build_network` wrapper that guessed one — that wrapper and
    `default_sparkline_interval` were deleted rather than kept around
    unused; tests call `build_network_with_interval` directly.
  - `render_json` is a direct `serde_json::to_string_pretty(report)` — no
    hand-built JSON, since `DigestReport`'s `#[derive(Serialize)]` field
    names already match the doc's documented schema exactly (this is the
    payoff of that naming choice in Batch 2).
  - `render_text` is intentionally **not** byte-for-byte identical to the
    doc's mockups — three places where the mockup implies a correlation
    this command's data model doesn't attempt are documented in
    `digest_render.rs`'s module doc comment (read it before "fixing"
    formatting): config-change lines show the raw `pfsense_page` path, not
    a human label like "Suricata configuration"; service-restart lines
    never show `rsyslog restarted (user via sudo)`-style entries (that
    would mean correlating `sudo` command text against systemd events,
    which Batch 2 doesn't do); alert concentration never includes the
    "check suppression config" gap note (needs a rule_id → source mapping
    that lives in each Sigma rule's `logsource`, not in alert records).
  - Sparkline rendering reuses `spike_threshold_pct` (rather than a new
    magic number) to decide "flat summary line" vs. full block-character
    (`▁▂▃▄▅▆▇█`) sparkline: if the series' max exceeds its own average by
    more than that threshold, render the full line.
  - Manually smoke-tested against this repo's real `data/` (both a
    `--window 6h` default run and an explicit `2026-07-01T07..2026-07-01T20`
    range, both `--format text` and `--format json` piped through `jq`) —
    output is sensible against real multi-day homelab data, not just the
    synthetic test fixtures. `cargo build --release` (whole workspace) is
    clean too, not just debug.
  - `cargo build`/`cargo test` (whole workspace) are clean: 133 tests in
    `siemctl` (up from 126 after Batch 2), 0 warnings. Same pre-existing
    `test-ruled.sh` failure as Batches 1–2 (confirmed via `git stash`,
    unrelated to this work).

**Batch 4 — Integration test + docs** — *Sonnet 5, effort: medium*
— ✅ **Done** (2026-07-02) — this closes out the digest command; no batches remain.
- `tests/integration/test-siemctl-digest.sh` following
  `test-siemctl-group.sh`'s pattern (fixture → normalized → indexd →
  `siemctl digest --format json` → jq assertions)
- Document the command in `docs/user-guide.md` (or a new
  `docs/siemctl-usage.md`); this design doc stays as the design record

  Implementation notes:
  - The fixture uses **RFC5424 syslog lines with explicit UTC offsets**
    (`<134>1 2026-07-01T14:25:00+00:00 pfsense filterlog 1 - - <csv>`), not
    RFC3164 (`Jun 22 08:55:03`, no year) like the other integration tests'
    fixtures. RFC3164 lines get bucketed relative to wall-clock "now" at
    ingestion time (no year to anchor them), which would make a
    baseline/window-based test flaky by construction. RFC5424 pins every
    event to an exact, deterministic `raw_file` bucket. `normalized` needs
    `--config config/normalized.toml` for this to matter at all — without
    it, none of the `[[extract.rule]]`/`[[overrides.rule]]` entries run and
    every event comes through as bare envelope fields with no `event_type`.
  - 22 assertions across all six sections plus a "text format doesn't
    crash" check, run against the real `normalized → indexd → siemctl`
    chain — this is the layer the unit tests structurally can't cover
    (they build synthetic SQLite fixtures directly; this proves the real
    parsers actually populate the columns `digest.rs` queries by name).
    Every assertion passed on the first real run.
  - `config/rules/suppress.toml` doesn't exist yet, so alerts are written
    directly to `data/alerts/.../alerts.jsonl` in the test, bypassing
    `ruled` entirely (`build_alerts` only ever reads that directory, so
    there's nothing lost by not running the real rule engine here).
  - Docs added: a `### Digest` section in `user-guide.md`'s Operations
    part (right after `### Searching`, since digest is a natural next step
    from ad-hoc search) and a `### digest.toml` section in Configuration
    (mirroring `### sources.toml`/`### normalized.toml`'s style). This
    design doc got a `Status: implemented` banner at the top pointing at
    both.
  - **Known limitation, not fixed here (out of scope):** `make test`'s
    integration loop (`Makefile`) does `bash "$t" || exit 1` per script in
    glob order, so the pre-existing `test-ruled.sh` failure (stale
    "loads 5 rules" assertion — see Batches 1–3's notes) prevents
    `make test` from ever reaching `test-siemctl-digest.sh`, which sorts
    after it alphabetically. Confirmed the new test passes when run
    directly (`bash tests/integration/test-siemctl-digest.sh`, 22/22) and
    that every other integration script still passes individually.
  - `cargo build`/`cargo build --release`/`cargo test` (whole workspace)
    all clean: 133 tests in `siemctl`, 0 warnings.

### Relationship to `design-llm-soc-analyst.md`

This digest is **one of three prerequisites** that doc names for the automated
analyst loop, not the only one:

1. `siemctl alerts` — alert query interface (`docs/roadmap-soc-improvements.md`
   item 1). Not covered by this plan. The digest's own Alerts section reads
   `data/alerts/` directly and internally, but Tier 2/3 of the analyst design
   need a general-purpose query interface over alerts (`--query` DSL,
   `--correlated`, `SELECT _raw`) — that's separate, unbuilt work.
2. Alert suppression rules (`docs/roadmap-soc-improvements.md` item 4). Not
   covered by this plan. Without it, Tier 2 triage in the analyst design
   drowns in known false positives (e.g. Suricata TCP-stream noise on CDN
   ranges).
3. This digest — drives the Tier 1 trigger. Covered above.

Not blocking per that doc, but also needed before the analyst loop is
genuinely autonomous end-to-end: alert state management (roadmap item 2, so
Tier 2 verdicts persist and feed back into suppression) and the actual
orchestration layer (a scheduled Claude invocation with tiered model
selection reading the digest + network topology + runbooks + `siemctl` tool
access) — that orchestration is operational setup outside this codebase, not
a Rust feature to build.

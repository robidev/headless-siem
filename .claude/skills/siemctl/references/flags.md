# siemctl — Full Flag Reference

Pulled directly from the arg-parsing loops in `src/siemctl/src/main.rs` (not just the
docs), so it reflects the actual accepted flags even if `docs/user-guide.md` has
drifted. Every command also accepts `--help`/`-h`, which prints the same usage text
shown here and exits `0`.

Unknown flags anywhere print `siemctl: unknown flag: <flag>` to stderr and return exit
code `1` (not a hard crash).

## `siemctl status`

```
siemctl status [--verbose] [--data-dir DIR]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--data-dir`, `-d` | path | `./data` | Root data directory. |
| `--verbose`, `-v` | flag | off | Adds `sources.toml` field inventory, `normalized.toml` per-app_name fields (with a "not indexed" gap check), and the actual column set of the **latest** index bucket. |

Errors if `--data-dir` is not a directory (`data directory not found: <path>`).

## `siemctl stats`

```
siemctl stats [--source SRC] [--after YYYY-MM-DDTHH] [--before YYYY-MM-DDTHH] [--data-dir DIR]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--data-dir`, `-d` | path | `./data` | |
| `--source`, `-s` | string | none (all sources) | Restrict to one `_source_type`. Switches from per-source counts to per-event_type breakdown + field coverage scoped to that source. |
| `--after`, `-a` | `HourBucket` (`YYYY-MM-DDTHH`) | none | Inclusive lower bound on hour-bucket, parsed via `HourBucket::parse`. |
| `--before`, `-b` | `HourBucket` | none | Inclusive upper bound. |

If no index exists yet, falls back to counting lines in raw JSONL files (`stats_from_raw`)
and prints a warning that field coverage is unavailable without the index.

Exit code: `1` if there is no data / no matching source at all, else `0` — even when
`total_events == 0` but some source_counts exist, returns `0`.

## `siemctl search`

```
siemctl search [--query "<dsl>"] [--raw [SUBSTRING]] [--after H] [--before H]
               [--format json|tsv|tsv-noheader] [--no-limit] [--data-dir DIR]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--data-dir`, `-d` | path | `./data` | |
| `--query`, `-q` | DSL string | `""` (match-all) | See DSL grammar below. Mutually exclusive with `--raw`. |
| `--raw` | optional string | absent | Bypasses the index. With an argument, does a **literal substring** scan over raw JSONL (not DSL). Without one, dumps everything in the time range. The following token is only consumed as the substring if it doesn't start with `-`. |
| `--after`, `-a` | `HourBucket` | none | Bucket-pruning only (coarse — hour granularity), applies to both `--query` and `--raw` paths. |
| `--before`, `-b` | `HourBucket` | none | |
| `--format` | `json` \| `tsv` \| `tsv-noheader` | `json` | Any other value is a clean parse error listing the three valid options. |
| `--no-limit` | flag | off | Disables the default row cap below entirely. No effect if the DSL already has an explicit `LIMIT` (that always applies regardless). |

Passing both `--query` and `--raw` is a clean error: `--raw and --query are mutually
exclusive (--raw takes a literal substring, not a DSL expression)`.

**Default row cap:** if the DSL has no explicit `LIMIT` and `--no-limit` wasn't
passed, output is capped at `DEFAULT_ROW_CAP` = 150 rows (`src/siemctl/src/query.rs`)
— applies to both plain-row and `GROUP BY` mode. When the cap is reached, a notice
(`siemctl: showing first N matches (default row cap reached) — add an explicit LIMIT
to your --query or pass --no-limit to see more`) is printed to **stderr only**, so
piping stdout into `jq`/scripts is unaffected. An explicit `LIMIT n` in `--query`
always wins and is never overridden by the default. Added 2026-07-16 after repeated
`context_balloon` tickets from unbounded `search` queries; sized at 150 rows (~150KB
at worst-case ~1000 bytes/row) to stay comfortably under `context-balloon-scan`'s
200KB threshold. Note: `siemctl alerts` does **not** have this cap (not yet extended
there — see Gotchas).

### DSL grammar (recursive descent, `src/siemctl/src/query.rs`)

```
query      := [ "SELECT" identlist ] [ "WHERE" ] [ expr ] [ "GROUP" "BY" identlist ] [ "LIMIT" int ]
expr       := or_expr
or_expr    := and_expr { "OR" and_expr }
and_expr   := not_expr { "AND" not_expr }
not_expr   := [ "NOT" ] primary
primary    := "(" expr ")" | comparison | func_call
comparison := field ( "==" | "=" | "!=" | "<>" ) literal
func_call  := fname "(" [ arg { "," arg } ] ")"
identlist  := field { "," field }
```

- Keywords (`SELECT`, `WHERE`, `GROUP`, `BY`, `LIMIT`, `AND`, `OR`, `NOT`) are
  case-insensitive. Quotes (`'…'`/`"…"`) are optional everywhere and stripped — a
  slot's role (field vs. literal) is fixed by grammar position, not quoting.
- `AND` binds tighter than `OR`; use `()` to override.
- A leading `WHERE` is accepted and silently discarded — it's cosmetic.
- Empty query string, or a query with only `GROUP BY`/`LIMIT`, means match-all
  (`expr = None`).
- `SELECT` fields are **output projections only** — not validated against the
  indexed-field set, so `message`/`_raw`/any JSON key can be selected even though it's
  not searchable as a predicate. Missing fields render as `null` (JSON) / empty (TSV).
- `GROUP BY`/comparison/function field arguments **are** validated against the
  indexed-field set (when `sources.toml` is found) — an unknown field is a parse error:
  `unknown field '<name>'. Known fields: <sorted list>`.
- Field identifiers must match `is_sql_ident`: `[A-Za-z_][A-Za-z0-9_]*` — anything else
  (leading digit, dash, dot) is `invalid field name '<name>'`.

**Functions** (all validate field name; args beyond arity are a clean error):

| Function | Arity | Compiles to | Notes |
|---|---|---|---|
| `startswith(field, 'v')` | 2 | `field LIKE 'v%'` | |
| `endswith(field, 'v')` | 2 | `field LIKE '%v'` | |
| `contains(field, 'v')` | 2 | `field LIKE '%v%' COLLATE NOCASE` | Case-insensitive. |
| `any(field)` | 1 | `field != ''` | True if the field is non-empty. |
| `cidr_match(field, 'a.b.c.d/n')` | 2 | `cidr_match(field, ?)` (custom SQLite UDF) | CIDR literal is validated **at parse time** — a malformed range is a clean parse error, not a silent no-match at runtime. |
| `raw_contains('needle')` | 1 | `raw_contains(raw_file, byte_offset, ?)` (custom UDF) | Substring test over the row's original raw JSONL line. Composes with field filters — the index narrows rows first, then this runs only on survivors. |

**Comparisons**: `==` and `=` are both exact-match (`field = ?`); `!=` and `<>` are
both not-exact (`field != ?`). All values are always bound as SQL parameters, never
interpolated into the query string (verified by `values_are_always_bound_never_inline`
test) — safe against injection via `--query`.

**`GROUP BY`**: switches to aggregate mode — `SELECT <cols>, COUNT(*) FROM events
<where> GROUP BY <cols>`. Merges counts across every hour-bucket DB, sorted by count
descending, ties broken by group-key ascending. `LIMIT` in group mode is applied
**after** the cross-bucket merge (not per-bucket).

**Row mode `LIMIT`**: compiled directly into the per-bucket SQL (`... LIMIT n`), and
also enforced by the renderer across buckets via `Renderer::is_done()`, which callers
check to break out of the bucket-scan loop early.

## `siemctl alerts`

```
siemctl alerts [--query "<dsl>"] [--correlated] [--all]
               [--after H | --before H | --window W]
               [--format json|tsv|tsv-noheader] [--data-dir DIR]
siemctl alerts ack <rule_id> [--note "text"] [--data-dir DIR]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--data-dir`, `-d` | path | `./data` | |
| `--query`, `-q` | DSL string | `""` (match-all) | Same grammar as `search`, but compiled against an unrestricted field set — an empty `valid` set means **any** field name parses (no "unknown field" errors here). Resolved per-record at runtime: top-level alert keys, then the embedded event (`event` for a `ruled` alert, `sample_events[0]` for a `correlated` one). |
| `--correlated` | flag | off | Only correlated alerts. Equivalent to `type == correlated` in `--query`. |
| `--all` | flag | off | Include acked alerts (default view hides anything acked via `alerts ack` up to its watermark). |
| `--after`, `-a` / `--before`, `-b` | `HourBucket` | none | Same bucket-pruning as `search`. Mutually exclusive with `--window`. |
| `--window`, `-w` | duration | none | Relative (`10m`,`6h`,`24h`,`2d`) or explicit `start..end`, ending now. Mutually exclusive with `--after`/`--before` — combining them is an error. |
| `--format` | `json` \| `tsv` \| `tsv-noheader` | `json` | |

Reads both `data/alerts/YYYY/MM/DD/HH/alerts.jsonl` (from `ruled`) and
`data/alerts/correlated/YYYY/MM/DD/HH/correlated.jsonl` (from `correlated`) — flat
JSONL, not the SQLite index, evaluated directly per-record rather than compiled to SQL.
Every record carries a synthetic `type` field (`ruled` or `correlated`); correlated
alerts have no `level` field (no severity).

### `siemctl alerts ack <rule_id>`

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--note` | string | none | Free-text, stored alongside the ack watermark. |
| `--data-dir`, `-d` | path | `./data` | |

Marks alerts for `<rule_id>` up to *right now* as acknowledged — a watermark
(`data/alerts/ack.jsonl`), not a global switch or a delete. A new alert for the same
`rule_id` fired afterward still shows up normally. `alerts --all` bypasses the ack
filter entirely regardless of watermark.

## `siemctl digest`

```
siemctl digest [--window DURATION] [--interval DURATION] [--format text|json] [--data-dir DIR]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--data-dir`, `-d` | path | `./data` | |
| `--window` | duration | `6h` | Analysis period ending now. Relative (`1h`,`6h`,`24h`) or explicit `start..end`. |
| `--interval` | duration | `10m` | Trending bucket size within the window. |
| `--format` | `text` \| `json` | `text` | Any other value is a clean parse error. |

Anomaly-oriented shift-briefing: coverage/health, volume deltas vs. the
immediately-preceding baseline period, network trends, auth activity, alert summary,
and notable low-volume events. Spike-percentage/unparsed-event thresholds are read
from `config/digest.toml` if present, else built-in defaults — see that file for the
actual numbers. Always exits `0` once flags parse successfully (an invalid
`--window`/`--interval`/`--format` is the only way to get a non-zero exit).

**`now` is lagged 300s** (`digest::NOW_LAG_SECONDS`, `src/siemctl/src/digest.rs`):
`cmd_digest` derives both the window and its baseline from `Utc::now() - 300s`, not
raw wall-clock time, so a relative `--window` (e.g. `6h`) never lands its trailing
edge in the last few minutes `indexd` might still be catching up on for a very
recent hour bucket — a lagging index previously read back near-zero counts there,
producing a spurious `flag=new baseline=0` on the next run once real data caught up.
300s matches `indexd`'s own worst-case catch-up bound (`RECENT_FILE_SWEEP_INTERVAL`).
**Only affects a relative `--window`** — an explicit `start..end` range ignores `now`
entirely and is unaffected. Added 2026-07-16; see
`ticketing-system/tuner-dev/20260716T163247.000_digest-baseline-zero-index-lag-suspected.md`
(in `llm-based-soc/`) for the original incident.

## `siemctl tail`

```
siemctl tail [--data-dir DIR] [--source SRC] [--follow | --no-follow]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--data-dir`, `-d` | path | `./data` | |
| `--source`, `-s` | string | none (all sources) | Filters by file stem (e.g. `sshd`), matched via `path.file_stem()`. |
| `--follow`, `-f` | flag | **on** by default | Explicit flag is redundant unless overriding a prior `--no-follow` earlier in argv (last one wins, since flags are just booleans set in a loop). |
| `--no-follow`, `-F` | flag | off | Dumps current files once and exits `0`; errors if no JSONL files found (`1`). |

Follow mode polls every 200ms, re-scanning `collect_raw_files` for newly created
time-bucket files and tracking a byte offset per file so partial (in-progress) lines
aren't emitted until the writer completes them. Starts new files at the current EOF —
matches `tail -n 0 -F` semantics (only shows events written after `tail` starts). Never
exits on its own; must be killed/backgrounded/timed out.

## `siemctl retention`

```
siemctl retention --days N [--dry-run] [--yes|--force] [--data-dir DIR]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--days`, `-n` | `u32` | **required** — errors `--days N is required` if omitted | `0` deletes **everything** under `data_dir` (raw logs + index DBs, including WAL/SHM sidecars). |
| `--dry-run`, `-D` | flag | off | Prints what would be deleted (path + size) without deleting; returns `0`. |
| `--yes`, `--force`, `-y` | flag | off | Skips the confirmation prompt. **Required** for `--days 0` when stdin is not a TTY (non-interactive/cron use) — otherwise errors: `refusing to wipe all data non-interactively`. |
| `--data-dir`, `-d` | path | `./data` | |

Cutoff = `now - (days * 86400s)`, computed via `checked_sub`; underflow (e.g. absurdly
large `days`) saturates to `UNIX_EPOCH` (deletes everything with a valid mtime). Deletes
by file mtime, then removes now-empty directories in repeated passes until a pass
removes nothing.

## `siemctl dry-run`

```
siemctl dry-run --file FILE [--source SRC] [--config CFG] [--rules DIR]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--file`, `-f` | path | **required** — errors `--file FILE is required` | Input log file; must exist (`file not found: <path>` otherwise). |
| `--source`, `-s` | string | none | Passed through to `normalized --source`. |
| `--config`, `-c` | path | none | Passed through to `normalized --config`. |
| `--rules`, `-r` | path | none | If set, output is piped into `ruled --rules <dir>` for a second pass reporting alert counts and triggered rule IDs. Errors if the directory doesn't exist. |

Internally spawns `normalized --stdin --dry-run [--source ...] [--config ...] < FILE`
via `std::process::Command`, resolved through `find_binary("normalized")` (see the
workspace gotcha in SKILL.md — this needs `PATH` fallback in this repo's layout). If
`--rules` is given, `normalized` is **run a second time** (its stdout can't be
re-consumed) and piped into `ruled`.

Never returns non-zero on its own besides the file/dir existence checks — a 0% match
rate or 0 alerts is still exit code `0`.

## `siemctl validate`

```
siemctl validate --config sources.toml --rules DIR [--normalized-config normalized.toml]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--config`, `-c` | path | **required** | `sources.toml` path; errors `--config FILE is required` if omitted, `not found: <path>` if it doesn't exist. |
| `--rules`, `-r` | path | **required** | Directory of Sigma `.yml`/`.yaml` files. |
| `--normalized-config`, `-N` | path | none | Enables an advisory cross-check between fields `normalized.toml` extraction rules produce and fields `sources.toml` declares as indexed. **Never affects exit code** — see Gotchas in SKILL.md. |

`sources.toml` parsing here is a hand-rolled line scanner (not a real TOML parser) —
it looks for `[source.X]` headers and `index_fields = [...]` on a single line; it will
not follow multi-line arrays.

Each Sigma rule file is checked for: non-empty `id:`, non-empty `title:`, a
`detection:` block, and an indented `condition:` line inside it. A rule with
`status: ... deprecated` (substring match) prints `SKIP` and counts as a **warning**,
not an error, even if otherwise well-formed.

**Exit code**: `1` if `errors > 0` (missing required Sigma fields, no `[source.*]`
entries, unreadable rule file), else `0` — warnings (missing `index_fields`, deprecated
rules) do not affect exit code.

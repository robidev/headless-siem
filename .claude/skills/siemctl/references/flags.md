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
               [--format json|tsv|tsv-noheader] [--data-dir DIR]
```

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--data-dir`, `-d` | path | `./data` | |
| `--query`, `-q` | DSL string | `""` (match-all) | See DSL grammar below. Mutually exclusive with `--raw`. |
| `--raw` | optional string | absent | Bypasses the index. With an argument, does a **literal substring** scan over raw JSONL (not DSL). Without one, dumps everything in the time range. The following token is only consumed as the substring if it doesn't start with `-`. |
| `--after`, `-a` | `HourBucket` | none | Bucket-pruning only (coarse — hour granularity), applies to both `--query` and `--raw` paths. |
| `--before`, `-b` | `HourBucket` | none | |
| `--format` | `json` \| `tsv` \| `tsv-noheader` | `json` | Any other value is a clean parse error listing the three valid options. |

Passing both `--query` and `--raw` is a clean error: `--raw and --query are mutually
exclusive (--raw takes a literal substring, not a DSL expression)`.

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

# Design: Unified query layer for `siemctl search`

**Status:** implemented (siemctl `query.rs` DSL/AST/compiler/executor + `db.rs` UDFs)
**Scope:** `siemctl` only — **no change to `indexd`, `normalized`, the index schema, or the on-disk layout.**
**Author context:** written for a cold implementation session. Everything needed is in this file; you should not need the conversation that produced it.

---

## 1. Problem

`siemctl search` today has **four disjoint code paths** that cannot compose:

| Path | Trigger | Where it runs | File refs |
|------|---------|---------------|-----------|
| index field search | `--field F --value V` | SQLite per-bucket DBs | `main.rs:398`, `search_by_index` `main.rs:496`, `db::query_bucket` `db.rs:159` |
| grouping | `--group f1,f2` | SQLite, `GROUP BY`, merged in Rust | `main.rs:368`, `search_group` `main.rs:566`, `db::group_bucket` `db.rs:282` |
| full-text | `--query TEXT` | substring scan over **raw JSONL files** | `search_by_grep` `main.rs:652` |
| range dump | `--source/--after/--before` only | raw JSONL files | `search_dump` `main.rs:682` |

The pain points the user raised:

1. You cannot combine multiple conditions (several `--field`/`--value`, or field + text) in one search — `--field`/`--value`/`--query` are single `Option<String>` that overwrite on repeat (`main.rs:304-306`), and the dispatch is a mutually-exclusive `if/else` chain (`main.rs:398-454`).
2. `--group` is explicitly **rejected** when combined with `--field`/`--query` (`main.rs:368-376`) — it is a standalone aggregate over the whole index, so you cannot "filter, then group."
3. The root awkwardness: **text search runs over raw files while field/group search runs over SQLite**, so the two surfaces don't meet. Composing them naïvely would require a raw→index reverse mapping.

## 2. Key insight (the thing that makes this simple)

**The index → raw pointer already exists, and the index is a complete row-set over the raw data.** Therefore you never need a raw→index reverse mapping; you make **the SQLite index the single entry point for every query**.

- Every index row stores `raw_file` (path relative to `data_dir`) + `byte_offset` (indexd `parser.rs:57-58`, schema `indexd/db.rs:137`). `siemctl`'s `resolve_raw_line(data_dir, raw_file, byte_offset)` (`db.rs:131`) already seeks+reads the exact original line — this is what `--full` uses.
- **Completeness is verified.** `normalized`'s `flatten()` *always* emits a `timestamp` (falls back to receive time; `event.rs:192-197`, test `event.rs:352`). It's the single output path for every line, including plaintext passthrough (`_normalized:false`). indexd's `parse_line` only skips lines that are malformed JSON, non-object JSON, or missing `timestamp` (`parser.rs:24-51`) — none of which occur for normalized output. So **every raw JSONL line normalized writes gets exactly one index row**, carrying both its indexed columns and a pointer to its own raw line.

Consequence: any query — field filter, text filter, grouping, or any combination — is just an operation over index rows:
- **field predicate** → SQL `WHERE` on a column;
- **text predicate** → resolve *that row's* raw line on demand and substring-check it;
- **group** → SQL `GROUP BY` on columns, counts merged across buckets in Rust (already built).

All three compose because they are predicates/operations on the same row. No reverse mapping, no second query surface.

## 3. Two caveats this design must own (and surface to users)

Routing **text** search through the index (instead of scanning raw files) changes two correctness properties. Both are acceptable but must be handled:

1. **Index dependency.** Text search now requires a present, healthy index. Mitigation: a `--raw` flag that bypasses the index and scans raw files directly (this is exactly today's `search_by_grep`/`search_dump`, kept alive). If the index dir is missing, error with a hint to use `--raw`.
2. **Indexing lag.** indexd is inotify-driven and eventually consistent; the newest raw lines may not be indexed yet, so an index-driven search can miss events that are seconds old. This is fine for historical search. `tail` (live) is a separate command and is unaffected. Document it; `--raw` is the escape hatch when you need the absolute latest.

These are the *only* behavioral regressions versus today, and `--raw` covers both.

## 4. Design

### 4.1 Make text & CIDR first-class SQL predicates via SQLite UDFs

`rusqlite` supports **user-defined scalar functions** natively (`Connection::create_scalar_function`, requires the `functions` cargo feature) — **no C extension, no loadable plugin.** Register two functions on every bucket connection:

- `cidr_match(col, 'a.b.c.d/n') -> bool` — moves the existing Rust CIDR logic (`db::cidr_contains` `db.rs:38`) *into* SQL. This **deletes** the special-case `print_rows_cidr` path (`db.rs:225`). Register as **deterministic** (`FunctionFlags::SQLITE_DETERMINISTIC | SQLITE_UTF8`).
- `raw_contains(raw_file, byte_offset, 'needle') -> bool` — a UDF that captures `data_dir`, calls `resolve_raw_line`, and returns whether the raw line contains `needle` (exact substring, matching today's grep semantics). Register **non-deterministic** (file contents are not a pure function of args) and `SQLITE_UTF8`.

With `raw_contains`, a full-text condition is a normal `WHERE` term over the deferred pointer: **substring semantics, zero duplication of raw data, and full composition with `GROUP BY`** — the elegant middle path. The only cost is a file seek per row the UDF is evaluated against (see §4.4 perf).

**UDF error policy:** on any IO error (missing/short raw file, seek failure), `raw_contains` returns `false` (= "no match"), never `Err`. Returning `Err` would abort the whole bucket statement and let one unreadable file kill an entire hour's results. Optionally `eprintln!` once per failure. `resolve_raw_line` already returns `Result<String,String>`, so map `Err(_) => false`.

### 4.2 A Query AST fed by a small DSL (compiled to SQL — *not* raw SQL passthrough)

The query predicate is written as **one text expression in a small SQL-ish DSL** (see §5 for the grammar) that `siemctl` **tokenizes and parses itself** into the AST below, then compiles to per-bucket SQL and merges in Rust. This is *not* raw-SQL passthrough: the blocker for passthrough was never injection (read-only conn; identifiers validated; values bound) — it's that **the index is sharded one-DB-per-hour**, so a user's single `SELECT … GROUP BY` cannot span a time range without `ATTACH`-ing N DBs, and it would leak SQLite's dialect + the dynamic schema. Parsing our own DSL keeps cross-bucket merge under our control and keeps every safety guarantee, while replacing the awkward pile of repeatable CLI flags with one parser. The code already anticipates the structured model (`db.rs:71-73`: "a wrapper `Query` struct that holds `Vec<Condition>`").

The AST is a **boolean expression tree** (so `AND`/`OR`/`NOT`/parens fall out naturally), not a flat `Vec` of ANDed conditions:

```rust
// new: src/siemctl/src/query.rs
pub struct Query {
    pub expr: Option<Expr>,            // parsed predicate tree; None => match all rows
    pub group_by: Option<Vec<String>>, // from DSL `GROUP BY`; Some => aggregate (COUNT per combo)
    pub limit: Option<usize>,          // from DSL `LIMIT`
    pub after: Option<time::HourBucket>, // from --after flag (bucket pruning only)
    pub before: Option<time::HourBucket>,// from --before flag (bucket pruning only)
}

pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Cond(Condition),
}

pub enum Condition {
    Field { field: String, value: String, mode: MatchMode }, // reuse existing MatchMode (db.rs:13)
    Text  { needle: String },                                // substring over the raw line
}
```

Everything that used to be its own flag now lives **inside** the parsed query: `source` is just the indexed column `source` (so `--source sshd` becomes `source == 'sshd'`), grouping is `GROUP BY`, limit is `LIMIT`. The only survivors as flags are the two **time-range** bounds, because they drive *bucket pruning* (skipping whole `.db` files by filename) which is a scope/perf concern outside any single bucket's SQL. Result: no row-record vs index-record mode, no `--full`/`--source`/`--field`/`--value`/`--group` branches — row mode always resolves and emits the raw line (the old `--full` default).

`MatchMode` already has `Exact/StartsWith/EndsWith/Contains/Cidr/Any` (`db.rs:13-22`); **add `NotExact`** for `!=`. `Condition::Field` is essentially today's `FieldFilter` (`db.rs:74`); fold `FieldFilter` into it. Note `expr` is `Option` — an empty DSL string (range/source-only search) yields `None` and matches every row.

### 4.3 Compiler: `Query` → (SQL string, bound params)

Each **leaf** `Condition` emits a predicate and (usually) a bound param; the **tree** combines them by emitting `(left AND right)`, `(left OR right)`, `(NOT inner)` recursively (in-order traversal, params pushed in evaluation order):

| Condition | SQL predicate | bound param |
|-----------|---------------|-------------|
| Field Exact | `col = ?` | value |
| Field NotExact | `col != ?` | value |
| Field StartsWith | `col LIKE ?` | `value%` |
| Field EndsWith | `col LIKE ?` | `%value` |
| Field Contains | `col LIKE ? COLLATE NOCASE` | `%value%` |
| Field Cidr | `cidr_match(col, ?)` | `value` (the CIDR) |
| Field Any | `col != ''` | — |
| Text | `raw_contains(raw_file, byte_offset, ?)` | `needle` |

Let `<expr>` be the compiled tree. There is no separate `source` handling any more — `source` is an ordinary column predicate inside `expr`. When `expr` is `None`, drop the `WHERE` clause entirely. Then:
- **Row mode** (`group_by == None`): `SELECT * FROM events [WHERE <expr>] [LIMIT n]`.
- **Group mode** (`group_by == Some(fields)`): `SELECT <fields>, COUNT(*) FROM events [WHERE <expr>] GROUP BY <fields>` (LIMIT applied after the cross-bucket merge + sort, not per bucket).

**Identifier safety:** column names (`col`, function column args, group fields) are interpolated, not bindable in SQL. Run **every** field name and group field through the existing `is_sql_ident` guard (`main.rs:642`) **and** the `valid_fields` membership check (`main.rs:377-390`, `423-432`) — at parse time, so a bad identifier is a clean DSL error, not a SQL error. All *values/needles/CIDRs* are bound parameters. Function names come from a fixed allowlist (§5); an unknown function is a parse error. The net guarantee is identical to a switch-based design: nothing from the user string reaches SQL except validated identifiers.

**Predicate ordering:** with a boolean tree you can't freely reorder across `OR`, so leave planning to SQLite (every indexed field has a btree index, indexd `db.rs:152-164`). The only degenerate case is a predicate that is *only* UDFs (e.g. a lone `raw_contains(...)`, or UDFs under an `OR`): SQLite full-scans the bucket and runs the UDF per row — same work as today's grep plus a file seek per row (see §4.4). Acceptable at hour-bucket scale; do not hand-roll a query planner.

### 4.4 Performance note

- Field-only and group queries: same as today (index-backed).
- Queries containing a Text condition AND a selective field condition: the field index narrows rows, `raw_contains` only runs on survivors — cheap.
- **Text-only** query (no field condition): degrades to a full scan of the bucket plus one file seek per row. This is the same work as today's `grep` path, plus the seeks. Acceptable at hour-bucket scale. If profiling ever shows pain, the **future** option is to store the raw line in an FTS5 virtual table or a raw `TEXT` column in the index (the "duplicate the raw text" idea) — explicitly a **non-goal for v1** because it ~doubles index disk and changes indexd. A cheaper interim optimization: within a bucket, an LRU of open file handles keyed by `raw_file` so repeated rows in the same `.jsonl` don't re-open it.

### 4.5 Execution & cross-bucket merge

Reuse the existing per-bucket loop structure from `search_by_index` (`main.rs:530-554`) and `search_group` (`main.rs:595-614`):

```
for each bucket .db in index/ within [after, before]:
    conn = open read-only
    register cidr_match + raw_contains (capture data_dir) on conn
    (sql, params) = compile(query)
    if group mode: run, fold COUNT(*) into shared BTreeMap<Vec<String>, u64> acc
    else:          run, emit rows via renderer (always resolve the raw line)
    skip buckets missing a column/table (today's "no such column"/"no such table" swallow, main.rs:546-551 / 607-612)
group mode: after all buckets, sort by count desc then key asc, render (main.rs:621-635)
```

Renderer (`render::Renderer`), `--format`, `is_done()` short-circuiting all stay as-is. `LIMIT` comes from the DSL.

### 4.6 The four old paths collapse to one

- `search_by_index` → `Query { expr: Some(Field…), group_by: None }`.
- `search_group` → `Query { group_by: Some(fields) }` (+ optional `expr` — **the new "filter then group" capability**).
- `search_by_grep` → `Query { expr: Some(Text…) }` (now index-driven). **Keep the old raw-file scan as the `--raw` implementation** for fallback/parity.
- `search_dump` → `Query { expr: None }` with a time range.

## 5. CLI surface — one DSL string, not a pile of flags

`siemctl` is still in development, so we **deliberately delete most of the existing search flags** rather than carry them. The **entire predicate, grouping, and limit is one expression string** in a small SQL-ish DSL that `siemctl` parses itself. Almost everything that used to be a flag folds into that string — `--field`/`--value` → comparisons, `--source` → a `source` predicate, `--group` → `GROUP BY`, `--limit` → `LIMIT`, `--full`/`--index-record` → gone (row mode always emits the raw line). The point is the **collapse**: the 4-way dispatch (`main.rs:368-454`) and all its per-flag validation branches become a single "parse DSL → `run_query`, else `--raw` → grep." A later "query generator" can synthesize the DSL string from friendly switches; that's an additive layer on top, not part of this work.

### 5.1 Target example (parses exactly)

```
siemctl search --query "source == 'unifi' AND app_name == 'apache' \
                         AND raw_contains('GET HTTPS') \
                         OR cidr_match('src_ip','10.0.0.0/8') \
                         GROUP BY dst_ip, url" \
               --after 2026-06-22T08 --format tsv
```

Note `source == 'unifi'` is now *in the DSL* (it's just an indexed column), not a `--source` flag. Standard precedence (`AND` binds tighter than `OR`) parses the predicate as
`( (source=='unifi' AND app_name=='apache' AND raw_contains('GET HTTPS')) OR cidr_match('src_ip','10.0.0.0/8') )`.
Use parentheses to override.

### 5.2 Grammar (recursive-descent / Pratt; ~150–250 lines + tests)

```
query      := [ "WHERE" ] [ expr ] [ "GROUP" "BY" identlist ] [ "LIMIT" int ]
expr       := or_expr
or_expr    := and_expr { "OR" and_expr }
and_expr   := not_expr { "AND" not_expr }
not_expr   := [ "NOT" ] primary
primary    := "(" expr ")" | comparison | func_call
comparison := field ( "==" | "=" | "!=" | "<>" ) literal
func_call  := fname "(" [ arg { "," arg } ] ")"
identlist  := field { "," field }
field      := word | quoted      // a column name
literal    := quoted | word      // a string value
```

Leading `WHERE` is **optional** (accepted and ignored), so both `"WHERE app_name == 'apache'"` and `"app_name == 'apache'"` work. An **empty** predicate ⇒ `expr = None` (match-all; useful with just a `GROUP BY`, or with no `--query` at all and just a `--after`/`--before` range).

### 5.3 Lexing — why this is easy

Tokens: keywords (case-insensitive `WHERE GROUP BY LIMIT AND OR NOT`), words (`[A-Za-z_][A-Za-z0-9_.]*` plus things like IPs/CIDRs when unquoted), quoted strings (`'…'` or `"…"`), operators (`==` `=` `!=` `<>`), and punctuation `( ) ,`. **Quotes are optional everywhere and simply stripped** — the grammar fixes each slot's role by *position*, so we never need quoting to tell an identifier from a string:
- left of a comparison operator → **field** (column);
- right of a comparison operator → **literal** (bound value);
- each function argument's kind is fixed by the function signature (below).

This is exactly why the user's `'app_name'` and `cidr_match('src_ip', …)` both parse even though one quotes the column: position decides, quotes are noise. The lexer is a flat single-pass tokenizer; no ident/string ambiguity to resolve.

### 5.4 Function allowlist → `Condition` mapping

All field predicates are expressed as either a comparison or one of these fixed-arity functions (unknown name ⇒ parse error):

| DSL | Condition | Notes |
|-----|-----------|-------|
| `field == 'v'` / `field = 'v'` | `Field{Exact}` | |
| `field != 'v'` / `field <> 'v'` | `Field{NotExact}` | new `MatchMode::NotExact` |
| `startswith(field,'v')` | `Field{StartsWith}` | |
| `endswith(field,'v')` | `Field{EndsWith}` | |
| `contains(field,'v')` | `Field{Contains}` | |
| `any(field)` | `Field{Any}` | 1 arg, no value |
| `cidr_match(field,'a.b.c.d/n')` | `Field{Cidr}` | compiles to the `cidr_match` UDF |
| `raw_contains('needle')` | `Text{needle}` | **1 DSL arg**; compiler injects `raw_file, byte_offset` → 3-arg UDF |

This unifies every predicate under comparisons + functions and **retires the `field|modifier` suffix syntax** at the DSL layer (the suffix can live on only if the future switch-generator wants it).

### 5.5 The whole surviving flag set

After the strip, `siemctl search` accepts **five** flags total:

- `--query "<dsl>"` — the predicate / `GROUP BY` / `LIMIT` expression (§5.2). This is the one and only query surface. (Previously `--query TEXT` meant raw substring; that meaning is gone — plain substring is now `--query "raw_contains('TEXT')"`. Free to change: `siemctl` is pre-release.)
- `--raw [SUBSTRING]` — bypass the index entirely; substring/range scan straight over raw files (the kept `search_by_grep`/`search_dump`). Escape hatch for "index missing/stale" or "need the very latest, not-yet-indexed events." In `--raw` mode the DSL is **not** parsed; the argument is a literal substring (legacy grep semantics). This is the *only* reason any non-DSL search code survives.
- `--after` / `--before` — time-range bucket pruning (skip whole `.db` files by filename). Kept as flags because pruning is cross-bucket scope, not a row predicate.
- `--format` — output format (`json` / `tsv` / `tsv-noheader`), unchanged.
- `--data-dir` / `--help` — infra, unchanged.

**Deleted:** `--field`, `--value`, `--group`, `--source`, `--render`, `--limit`, `--full`, `--index-record`. `--source`/`--group`/`--limit` fold into the DSL; `--field`/`--value` become comparisons; `--full`/`--index-record` collapse into "always emit the raw line." `--render` (column projection) is dropped **for now** — emit all columns; re-add later as a DSL `SELECT`-list or a small flag if wanted. With `--field`/`--value`/`--group` gone, the mutual-exclusion validation at `main.rs:368-396` is deleted outright rather than ported.

`GROUP BY` in the DSL replaces the old `--group` flag. `AND`/`OR`/`NOT`/parens are **in scope for v1** (they're free once the tree exists) — no half-implementation needed.

Update `print_search_help` (`main.rs:457`) and `docs/` examples accordingly, with a short DSL reference.

## 6. Concrete change list (ordered for the implementer)

1. **Cargo:** enable the `functions` feature on `rusqlite` in `src/siemctl/Cargo.toml` (check the version already pinned in the workspace `Cargo.lock`; `create_scalar_function` + read-only conns are stable). Build to confirm.
2. **UDFs** (in `db.rs` or new `udf.rs`): `register_udfs(conn, data_dir)` adding `cidr_match` (deterministic, wraps `cidr_contains`) and `raw_contains` (non-deterministic, wraps `resolve_raw_line`, IO error → `false`).
3. **DSL parser + Query AST + compiler** (`query.rs`): tokenizer (§5.3) → recursive-descent/Pratt parser (§5.2) producing `Expr`/`Condition`; `MatchMode` reuse + new `NotExact`; `compile(&Query) -> (String, Vec<String>)` doing the in-order tree traversal (§4.3). Validate every field identifier (`is_sql_ident` + `valid_fields`) and function name **at parse time**. Fold `FieldFilter` (`db.rs:74-125`) into `Condition::Field`.
4. **Executor:** `run_query(data_dir, &Query, &mut Renderer) -> Result<i32>` that does the per-bucket loop, registers UDFs per connection, handles row vs group mode, merges, sorts, renders. Replaces `query_bucket`/`print_rows`/`print_rows_cidr`/`group_bucket` (delete or thin to compiler calls).
5. **`cmd_search` rewrite** (`main.rs:285-455`): reduce to the five-flag surface (§5.5). Parse `--query "<dsl>"` into a `Query`, merge `--after`/`--before` (bucket pruning) and `--format`/`--data-dir`, dispatch to `run_query`; under `--raw` take the legacy bare-substring path over raw files. **Delete** `--field`/`--value`/`--group`/`--source`/`--render`/`--limit`/`--full`/`--index-record` and the entire mutual-exclusion / per-flag validation block (`main.rs:368-396`) — not ported. This is where the bulk of the line-count drop happens.
6. **Help + docs:** rewrite `print_search_help` (`main.rs:457`); update examples in `CLAUDE.md`'s "Useful Dev Patterns" and any `docs/*usage*.md`.
7. **Tests** (§7). Run `make test` (cargo + integration). Remember integration tests use **debug** binaries (`cargo build`, no `--release`) per `CLAUDE.md`.

## 7. Test plan

- **Parser unit tests** (pure, no DB): `AND`/`OR` precedence (`A AND B OR C` ⇒ `(A AND B) OR C`); parentheses override; optional leading `WHERE`; optional quotes (`'app_name'` == `app_name`); each function maps to the right `Condition`; `GROUP BY a, b` and `LIMIT n` parse; **error cases** — unknown function, bad identifier (fails `is_sql_ident`/`valid_fields`), wrong arity, dangling operator, unbalanced parens. Parse the exact §5.1 example and assert the tree.
- **Compiler unit tests** (pure, no DB): assert `(sql, params)` for: single field; `A AND B`; `A OR B`; `NOT A`; field+`raw_contains`; `cidr_match`; `any`; empty expr (match-all); group-only; group+predicate. Confirm values/needles/CIDRs are **always bound** (no literal ever appears inline in the SQL string) and that field identifiers are the only interpolated text.
- **UDF unit tests** over a temp bucket + raw `.jsonl` (pattern: existing `db.rs` tests build buckets via `Connection::open` and temp dirs, e.g. `db.rs:548` `make_bucket`, `db.rs:485` `TempDir`):
  - `raw_contains`: match / no-match / missing-file → false / empty `raw_file` → false.
  - `cidr_match`: reuse the `cidr_contains` cases (`db.rs:381-437`).
- **Executor / integration:** build an index from a fixture (see `tests/integration/`, and indexd's `index_file` end-to-end test `parser.rs:312` as a model), then run: multi-condition AND, field+text, filter-then-group, and assert row sets / counts. Confirm cross-bucket count merge (model: `db.rs:567` `group_single_field_merges_across_buckets`).
- **Grouping behavior preserved:** adapt the current `group_bucket` tests (`db.rs:567-650`) to drive the new compiler/executor, so the cross-bucket count-merge semantics stay verified even though the `--group` flag is gone. (No `--field`/`--group` CLI back-compat to test — those flags are deleted.)
- **`--raw` parity:** `--raw 'SUBSTRING'` matches the old grep output and works with the index dir absent/empty.

## 8. Explicit non-goals (v1)

- No raw SQL passthrough to users — we parse our own DSL and compile it (§4.2).
- No FTS5 / no raw-line column / no schema or indexd change (keep retention = `rm file`, append-only, headless).
- `AND`/`OR`/`NOT`/parentheses **are** in v1 (free once the tree exists). What's deferred: comparison on numeric ranges (`<`, `>`, `BETWEEN`), `IN (…)` lists, and a CLI switch-generator that synthesizes the DSL string — all additive later.
- No swap of storage engine — per-bucket SQLite fits the headless/append-only/retention model; the features that tempted a swap (reverse mapping, custom search keyword) are reachable in-engine via start-from-index + UDFs.

## 9. Model / effort for the build

Genuine architecture change with correctness subtleties (a hand-written DSL tokenizer/parser with precedence + error handling, UDF file IO inside SQL, IO-error policy mid-statement, cross-bucket merge). The DSL parser raises the bar a notch versus the earlier flag-based draft — it's more code, but principled and well-bounded by tests. Recommended: **Opus, high effort**, with **xhigh for the first pass** that lands the parser + AST + compiler + executor + UDF registration cleanly (§6 steps 2–4), dropping to **high** for the mechanical follow-through (step 5 wiring, help text, test fan-out — steps 1, 5–7).

---

### Appendix: ground-truth file map (for a cold session)

- `src/siemctl/src/main.rs` — `cmd_search` `:285`, dispatch `:368-454`, `search_by_index` `:496`, `search_group` `:566`, `search_by_grep` `:652`, `search_dump` `:682`, `is_sql_ident` `:642`, help `:457`.
- `src/siemctl/src/db.rs` — `MatchMode` `:13`, `cidr_contains` `:38`, `FieldFilter` `:74`, `resolve_raw_line` `:131`, `query_bucket` `:159`, `print_rows_cidr` `:225`, `group_bucket` `:282`, tests `:375+`.
- `src/indexd/src/parser.rs` — `parse_line` skip rules `:24-51`, `index_file` `:100`.
- `src/indexd/src/db.rs` — dynamic schema `:106-170`, per-field indexes `:152-164`.
- `src/normalized/src/event.rs` — `flatten` always-timestamp `:173-231` (`:192-197`).
- `config/sources.toml` — `index_fields` per source (defines the index columns).
</content>
</invoke>

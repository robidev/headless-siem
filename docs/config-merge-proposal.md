# Proposal: should `sources.toml` and `normalized.toml` be merged?

**Status:** recommendation — no code change implied by accepting it, except the
optional validation cross-check in the final section.
**Decision:** **keep the files separate**; close the one real gap with a
`siemctl validate` cross-check rather than a structural merge.

This responds to the NOTES backlog item: *"discussion: consider merging
sources.toml and normalized.toml."*

---

## 1. What each file is, and who reads it

### `config/normalized.toml` (~319 lines)
Configuration for the **`normalized`** binary only:

- `[listen]` — UDP/TCP ports.
- `[storage]` — `data_dir`.
- `[[overrides.rule]]` — force a parser, relabel the `source`, remap fields.
- `[[extract.rule]]` — regex named-capture extraction, in two passes
  (pass 1 captures fields; pass 2 assigns `event_type` from a discriminator).

Extract/override rules are keyed by **`app_name`** (and matched on message
content), e.g. `app_name = "sshd"`.

### `config/sources.toml` (~35 lines)
Index-field definitions:

```toml
[source.sshd]
index_fields = ["src_ip", "event_type", "username"]
```

Keyed by the **final source label** (`[source.<label>]`). Lists which fields a
source contributes to the per-bucket SQLite index. The union across all sources
determines the SQLite schema; a `[source.default]` catch-all covers unmatched
labels.

### Consumer matrix

| File | `normalized` | `indexd` | `siemctl` | `correlated` |
|------|:---:|:---:|:---:|:---:|
| `normalized.toml` | ✅ | — | — | — |
| `sources.toml`    | — | ✅ | ✅ | — |

The consumers are **disjoint**. `normalized` never reads `index_fields`;
`indexd`/`siemctl` never read extract or override rules. (`correlated` reads
neither — it loads its own `correlations.toml`.)

How they parse also differs:

- `indexd` parses `sources.toml` with the real **`toml` crate**
  (`src/indexd/src/config.rs`) to build the SQLite schema.
- `siemctl` deliberately **hand-rolls a line scanner** for `index_fields`
  (`src/siemctl/src/sources.rs`) to avoid pulling in the `toml` dependency —
  it only needs the flat set of valid field names for search/`--group`
  validation.
- `normalized` parses `normalized.toml` with its own loader and `regex`.

---

## 2. The keys do not align

A naïve merge imagines one block per source:

```toml
[source.sshd]
patterns = [ ... ]
index_fields = ["src_ip", "username", "event_type"]
```

But the two files are keyed differently and **cannot nest cleanly**:

- `normalized.toml` extract rules key on **`app_name`**; `sources.toml` keys on
  the **source label**. These are not the same. `normalized.toml` even contains
  an override that relabels kernel UFW lines to source `iptables` while the
  extract rules still condition on `app_name = "kernel"`. The label is a
  *derived* value, not the rule key.
- `sources.toml` has entries with **no matching extract rule** (`router`,
  `unifi`, `dnsmasq`, and the `default` catch-all) — they rely on the
  zero-config format chain, not on `[[extract.rule]]`.
- The mapping is therefore **many-to-one and partial**, not 1:1. A merged
  `[source.x]` section would routinely have a populated `index_fields` and an
  empty/foreign rule set, or vice versa.

So the intuitive "one section per source" structure that motivates a merge
doesn't actually exist in this data model.

---

## 3. Options considered

### (a) Single merged file with namespaced sections
One `siem.toml` containing `[listen]`, `[storage]`, `[[overrides.rule]]`,
`[[extract.rule]]`, **and** `[source.*]`; each tool reads only the sections it
needs.

- **Pro:** one file to open; superficially "one place per source."
- **Con:** couples disjoint consumers (see §4); the keys don't align (§2), so
  it does *not* deliver the "edit one block" ergonomics; forces `siemctl` to
  cope with a 300+-line file full of regex it must skip — likely pulling the
  `toml` dependency into `siemctl` just to ignore those sections.

### (b) Keep split, share a `--config-dir` convention
Both files live in a known directory; each tool loads the file(s) it needs.
`normalized` already accepts `--config`; `indexd`/`siemctl` already locate
`sources.toml`.

- **Pro:** reduces "where do my configs live" friction; **zero coupling**;
  no parser changes.
- **Con:** still two files (which is fine — they're two concerns).

### (c) Status quo
Two files, located independently.

- **Pro:** simplest; clean separation.
- **Con:** the one real gap (§5) stays unaddressed.

---

## 4. Trade-offs that drive the decision

- **Blast radius / failure domains.** Disjoint consumers mean a typo in the
  volatile 319-line extraction ruleset can't break `indexd` startup, and a
  schema edit can't break `normalized`. Merging collapses two independent
  failure domains into one.
- **Edit cadence.** Extract rules churn constantly (every new parser, per the
  "Adding a New Log Parser" workflow). `index_fields` change rarely (only when
  you want a new *searchable* column). Coupling a stable 35-line schema to a
  churning 319-line ruleset is the wrong dependency direction.
- **Parsing cost.** A merge most likely forces the `toml` crate into `siemctl`,
  which today intentionally avoids it. Net added coupling for no functional
  gain.
- **Single responsibility.** "What gets parsed out of logs" (normalize stage)
  vs. "what gets indexed/searched" (index + query stage) are genuinely two
  concerns, owned by different pipeline stages. The split mirrors the pipeline.

The only meaningful pull toward merging is ergonomic ("one place per source"),
and §2 shows that benefit doesn't materialize because the keys don't align.

---

## 5. The real gap, and how to close it without merging

The legitimate pain a merge is *trying* to solve is a silent mismatch:

> You add a named capture in `normalized.toml` (e.g. a new `query` field) but
> forget to add it to a source's `index_fields` — so the field is normalized
> and stored, but **not searchable** (no index column, and `siemctl search
> --field query` / `--group query` rejects it as unknown). The reverse also
> bites: an `index_field` that no rule ever produces yields a permanently empty
> column.

Merging does **not** cleanly fix this (mismatched keys). A targeted check does.

> **Status: implemented.** `siemctl validate --normalized-config <normalized.toml>`
> now performs this cross-check (see below). It is opt-in (omitting the flag
> preserves the previous behavior) and advisory (it never changes the exit code).

**Recommendation:** extend `siemctl validate` (which already validates
`sources.toml` and the Sigma rules) with an optional cross-check against
`normalized.toml`:

- Parse the named captures and `set` keys from `normalized.toml`'s
  `[[extract.rule]]` blocks → the set of **producible** fields.
- Compare against the union of `index_fields` in `sources.toml`.
- **WARN** (not error) on:
  - producible fields that are indexed by **no** source (searchability gap), and
  - `index_fields` that **no** rule produces (dead column) — excluding the
    always-present core fields (`timestamp`, `source`, `raw_file`,
    `byte_offset`).

This is advisory, opt-in, and keeps the files — and their failure domains —
separate while delivering the safety net that motivated the merge idea.

Run it with:

```bash
siemctl validate --config config/sources.toml --rules config/rules \
  --normalized-config config/normalized.toml
```

Internal/discriminator captures (those consumed only as a later rule's match
condition, e.g. `auth_action`) are excluded from the "producible output fields"
so they aren't mistaken for searchable telemetry.

---

## 6. Recommendation summary

1. **Keep `sources.toml` and `normalized.toml` separate.** Disjoint consumers,
   misaligned keys, divergent edit cadence, and divergent parsers all argue
   against a structural merge.
2. **Optionally** adopt a shared `--config-dir` convention (Option b) to reduce
   file-location friction — no coupling, no parser changes.
3. **Close the real gap** with a `siemctl validate` cross-check (§5) that warns
   on field mismatches between the two files.

Items 2 and 3 are independent follow-ups; neither is required to accept the
core decision (keep separate). No behavior changes from this document alone.

# normalized — Parser Chain Behavior

`siemctl` doesn't parse logs itself, but `dry-run`'s match rate and `stats`/`search`'s
field coverage are governed entirely by how `normalized` (`src/normalized/src/parsers/mod.rs`)
decides which parser claims a line. This reference exists because low match rates or
missing fields in `siemctl` output usually trace back to chain order, not a `siemctl`
bug.

## Order of decision

For every raw line, in this order:

### 1. Override rules (config, checked first)

`normalized.toml`'s `[[overrides.rule]]` entries are checked **in file order**; the
**first rule whose conditions all match wins** — subsequent rules are not consulted
even if they'd also match. A rule's conditions (`source_ip` prefix match on the sender
address, `starts_with`/`contains` substring match on the raw line) are ANDed together;
an absent condition is treated as "no constraint" (auto-true).

If a matching rule sets `force_format`, that single named parser runs (falling back to
plain-text if the forced parser itself rejects the line — e.g. forcing `csv` on a line
with inconsistent delimiters). Otherwise the full auto-detection chain (below) runs.
After parsing, `remap` renames fields, and either `reparse`/`reparse_as` (explicit
second pass) or the same auto-reparse logic as the no-override path runs.

### 2. Auto-detection chain (no override matched)

Fixed order, first successful parse wins — **this is the actual code order**, which
matches the doc comment at the top of `parsers/mod.rs`:

| # | Trigger | Parser | Notes |
|---|---|---|---|
| 1 | Starts with `<` (a digit after, forming `<N>`) | RFC 5424, then RFC 3164 | Standard syslog `<PRI>` framing. Tried before anything else. |
| 2 | Starts with `{` | JSON object | `json::parse_object` |
| 3 | Starts with `[` | JSON array | `json::parse_array` |
| 4 | Starts with `CEF:` | CEF | |
| 5 | Starts with `LEEF:` | LEEF | |
| 6 | (always tried next) | RFC 3164 **without** a `<PRI>` prefix | Catches BSD syslog like `/var/log/syslog` or plain journald output. Self-gating: only succeeds if it finds a leading syslog timestamp, so it can't steal logfmt/CSV/plain lines. Tried before logfmt/CSV specifically because a syslog message body may itself contain `=` or commas that would otherwise false-positive as logfmt/CSV. |
| 7 | `looks_like_logfmt()` — ≥2 `key=value` pairs with identifier-shaped keys | Logfmt | |
| 8 | (always tried if not yet claimed) | CSV/TSV/pipe-delimited | Detects a consistent delimiter. |
| 9 | `looks_like_xml()` — `<?xml`, `<!--`, or `<tag`/`</tag` shape | XML | |
| 10 | `looks_like_yaml()` — leading `---`, or a `key:` line | YAML | |
| 11 | (always) | Plain text | **Always succeeds.** `_normalized: false`, only `_raw` populated. |

Each numbered detector is a `Some`/`None` self-validating parse — e.g. a line starting
with `CEF:` that isn't actually valid CEF returns `None` and falls through to the next
step rather than claiming the line incorrectly. This is what makes the chain
false-positive-resistant despite being prefix/shape-based rather than exhaustively
tried.

### 3. No-match / tie-breaking

There is no scoring or "best match" competition — the chain is strictly sequential and
the **first parser to return `Some` wins**, full stop. Because each step's trigger
condition is checked before attempting that parser, and the plain-text fallback has no
trigger condition (it's unconditional), **every line is guaranteed to produce an
event** — this is the "never drops" invariant from `CLAUDE.md`. A line matching none of
steps 1–10's shape heuristics, or whose shape heuristic matched but whose parser then
returned `None`, falls through to plain text.

## Second pass: wrapped payloads (CEF/LEEF/JSON-inside-syslog)

After the outer parse (chain or override), `normalized` optionally runs a **second
pass** to unwrap a structured payload embedded inside a syslog message body — e.g. a
device that sends `<134>Jun 22 ... myapp: CEF:0|Vendor|Product|...`. This only applies
when the outer format is `Rfc3164`/`Rfc5424` (a payload wrapped in JSON-in-JSON etc.
isn't attempted).

- **Automatic** (no override, or an override without `reparse`/`reparse_as`): triggers
  only if the raw line contains `CEF:` or `LEEF:` **anywhere** (not just at message
  start — the syslog tag parser can swallow the `CEF`/`LEEF` token as the program name,
  so the marker may not survive at the start of `message`), or if `message` (trimmed)
  starts with `{`.
- **Config-forced** (`reparse = true` in an override rule): runs regardless of outer
  transport format if `reparse_as` names a format; otherwise falls back to the same
  auto-detect logic.
- **Merge semantics**: the inner (payload) parse's fields win over the outer transport
  event's fields on conflict. The outer event keeps `hostname`/`app_name`/`timestamp`
  from the syslog envelope *only if* the inner payload didn't set them. `outer.raw`
  always stays the original, unmodified full line — `_raw` in the JSON output is never
  the unwrapped payload, always the complete original line.

## Practical implications for `siemctl` users

- **`dry-run`'s "Unmatched" count should always be 0.** Because of the plain-text
  fallback, every line is "matched" in the sense of producing *an* event — but
  `"_normalized":true` (which is what `dry-run` actually counts as "Matched") only
  applies to lines that hit a structured parser, not the plain-text fallback. A high
  unmatched rate means lines are shape-heuristic misses, not chain failures — check
  `siemctl search --raw` or inspect `_raw` directly to see what didn't classify.
- **A field missing from `search`/`stats`** despite the source clearly matching a
  parser usually means either (a) the field isn't in that source's `index_fields` in
  `sources.toml` (indexed but not searchable — add it and re-run `indexd`), or (b) the
  extraction rule that would produce it wasn't configured (`normalized --config` wasn't
  passed, or no matching `[[extract.rule]]` exists for that `app_name`) — check with
  `siemctl status --verbose`, which cross-references what `normalized.toml` can produce
  against what `sources.toml` indexes.
- **Override rules can silently prevent the auto-detection chain from ever running**
  for lines matching their condition — if a source stops parsing correctly after adding
  an override rule, check whether an earlier, broader rule (e.g. a bare `source_ip`
  prefix match) is intercepting lines meant for a later, more specific rule. First
  match wins; order rules from most-specific to least-specific in `normalized.toml`.

# normalized — Writing Parsers

This guide explains how `normalized` turns a raw line into a normalized record,
and how to extend it. Reach for these in order — most don't need code:

1. **An override rule** — force an existing parser, rename fields, assign a
   source. Config only. ([usage: override rules](normalized-usage.md#override-rules))
2. **The second pass** — for a structured payload (CEF/LEEF/JSON) wrapped in
   syslog; automatic, or `reparse`/`reparse_as` in config.
   ([usage: second pass](normalized-usage.md#second-pass-nested-payloads))
3. **Extraction rules** — regex with named captures to pull fields out of
   free-text messages (e.g. sshd `src_ip`). Config only.
   ([usage: extraction rules](normalized-usage.md#extraction-rules))
4. **A new parser module** — add a brand-new wire *format* to the chain. Code.

A parser module handles a *wire format* (e.g. "Cisco ASA binary", "Zeek JSON"),
not a regex per message type. If your source emits a supported format (JSON,
CEF, LEEF, logfmt, syslog…), you need no code — use options 1–3. Write a
module (this guide) only when the *format* itself is new.

> **Which do I want?** Structured payload the chain doesn't recognize at all →
> new parser module. Structured payload inside syslog → second pass. Values
> buried in free-text prose (sshd, named, kernel messages) → extraction rules.
> Relabeling / forcing / field renames → override rule.

---

## Table of contents

1. [How parsing works](#how-parsing-works)
2. [The `Event` model](#the-event-model)
3. [The no-code paths (try these first)](#the-no-code-paths-try-these-first)
4. [Writing a new parser module](#writing-a-new-parser-module)
5. [Detection heuristics](#detection-heuristics)
6. [How fields reach the output](#how-fields-reach-the-output)
7. [Testing a parser](#testing-a-parser)
8. [Checklist](#checklist)

---

## How parsing works

Every input line flows through this sequence (`src/normalized/src/`):

```
raw line
  │
  ├─ envelope::unwrap          (if it's a {"_raw":…} rsyslog/fixture envelope,
  │                             unwrap to the inner line + sidecar metadata)
  ▼
parsers::parse(raw, source_addr, &rules)
  │
  ├─ 1. override rules         first matching rule wins → force format / remap / source
  │
  └─ 2. run_chain              deterministic format detection, first match wins:
         <N>   → rfc5424 → rfc3164
         {     → json object
         [     → json array
         CEF:  → cef
         LEEF: → leef
         (ts)  → rfc3164 without <PRI>   (e.g. /var/log/syslog)
         k=v…  → logfmt
         delim → csv / tsv / pipe
         <tag> → xml
         k: v  → yaml
         else  → plain         (always succeeds — nothing is dropped)
  │
  ├─ second pass               if message is CEF/LEEF/JSON (auto), or an override
  │                            rule asked (reparse) → re-parse + merge payload
  ▼
Event  ──derive_source──▶ source label
       ──extract::apply──▶ config regex rules add fields (e.g. src_ip)
       ──flatten + serialize_flat──▶ one JSON line
  ▼
stdout  +  OutputRouter (time-bucketed jsonl + tsv)
```

Key files:

| File | Role |
|------|------|
| `parsers/mod.rs` | The chain (`run_chain`), override matching, `force_parse`, second pass, heuristics. |
| `parsers/<format>.rs` | One parser per format; each exposes `pub fn parse(raw: &[u8], source_addr: &str) -> Option<Event>`. |
| `event.rs` | The `Event` struct, `derive_source`, `flatten`, `serialize_flat`. |
| `envelope.rs` | `_raw` envelope detection/unwrapping. |
| `extract.rs` | Config-driven regex field extraction (`[[extract.rule]]`). |
| `config.rs` | Config + `OverrideRule` + `ExtractRuleConfig`. |
| `output.rs` | Time-bucketed filesystem storage. |

**First match wins** at every level: override rules in declaration order, then
the chain in the order above. Order parsers from most-specific to most-generic.

---

## The `Event` model

A parser's job is to fill in an `Event` (`event.rs`):

```rust
pub struct Event {
    pub format:      Format,              // which parser produced this
    pub source_addr: String,             // sender IP, or "stdin"
    pub facility:    Option<Facility>,   // syslog facility
    pub severity:    Option<Severity>,   // syslog severity (enum)
    pub timestamp:   Option<String>,     // event time (RFC 3339 or original)
    pub hostname:    Option<String>,
    pub app_name:    Option<String>,
    pub proc_id:     Option<String>,
    pub msg_id:      Option<String>,
    pub message:     String,             // the human-readable message body
    pub fields:      HashMap<String, String>,  // everything else, structured
    pub raw:         Vec<u8>,            // the unmodified input bytes
}
```

Guidelines:

- Put **well-known envelope data** in the dedicated fields (`hostname`,
  `app_name`, `timestamp`, `severity`, …). They are emitted as canonical
  top-level keys and feed source derivation.
- Put **everything else** in `fields`. Each entry becomes a top-level key in the
  output. Prefer canonical names (`src_ip`, `dst_ip`, `dst_port`, `username`,
  `event_type`); the synonyms `src`/`dst`/`spt`/`dpt` are auto-canonicalized.
- Always set `raw: raw.to_vec()` so the original line is preserved.
- Return `None` if the line clearly isn't your format, so the chain moves on.
  Only the `plain` parser returns unconditionally.

---

## The no-code paths (try these first)

Most sources need no Rust at all — they need config. All three are documented in
full in [normalized-usage.md](normalized-usage.md); in short:

- **Override rule** — force an existing parser, assign a source, rename fields:

  ```toml
  [[overrides.rule]]
  source_ip = "192.168.10.1"
  source    = "pfsense"
  format    = "csv"
  remap     = { field4 = "src_ip", field6 = "dst_ip" }
  ```

- **Second pass** — a CEF/LEEF/JSON payload inside syslog is re-parsed
  automatically; for other wrapped payloads add `reparse`/`reparse_as` to an
  override rule.

- **Extraction rule** — pull fields out of free-text messages with regex:

  ```toml
  [[extract.rule]]
  app_name = "sshd"
  pattern  = "from (?P<src_ip>[0-9.]+) port (?P<src_port>[0-9]+)"
  ```

Write a parser module (below) only when the *wire format itself* is new and
none of the above fit.

---

## Writing a new parser module

Suppose you want a parser for a hypothetical `KV2` format:
`KV2|key:val|key:val|…`.

### 1. Create the module

`src/normalized/src/parsers/kv2.rs`:

```rust
/// KV2 parser:  KV2|host:web1|sev:err|msg:disk full
use std::collections::HashMap;
use crate::event::{Event, Format, Severity};

pub fn parse(raw: &[u8], source_addr: &str) -> Option<Event> {
    let s = std::str::from_utf8(raw).ok()?;
    let body = s.strip_prefix("KV2|")?;   // not our format → None

    let mut fields = HashMap::new();
    for pair in body.split('|') {
        if let Some((k, v)) = pair.split_once(':') {
            fields.insert(k.trim().to_owned(), v.trim().to_owned());
        }
    }
    if fields.is_empty() {
        return None;
    }

    // Promote well-known keys into the envelope; leave the rest in `fields`.
    let severity = fields.remove("sev").and_then(|w| match w.as_str() {
        "err" | "error" => Some(Severity::Error),
        "warn"          => Some(Severity::Warning),
        _               => None,
    });

    Some(Event {
        format: Format::Plain,   // or add a Format::Kv2 variant (see step 3)
        source_addr: source_addr.to_owned(),
        facility: None,
        severity,
        timestamp: fields.remove("ts"),
        hostname: fields.remove("host"),
        app_name: None,
        proc_id: None,
        msg_id: None,
        message: fields.remove("msg").unwrap_or_default(),
        fields,
        raw: raw.to_vec(),
    })
}
```

### 2. Register it in the chain

In `parsers/mod.rs`, declare the module and insert it in `run_chain` at the
right priority (specific before generic — here, before `logfmt`/`csv`, which
could otherwise claim a `|`-delimited line):

```rust
pub mod kv2;
// …
if text.starts_with("KV2|") {
    if let Some(ev) = kv2::parse(trimmed, source_addr) {
        return ev;
    }
}
```

Also add it to `force_parse` so an override rule can force it by name:

```rust
"kv2" => kv2::parse(raw, source_addr),
```

### 3. (Optional) add a `Format` variant

If you want `_format: "kv2"` instead of reusing an existing variant, add a
variant to the `Format` enum in `event.rs` and a match arm in
`Format::as_str()`. Remember: `_normalized` is `true` for every format except
`Plain`, so a dedicated variant also makes the record count as normalized.

That's the whole surface area: one `parse` function, one line in the chain, one
line in `force_parse`.

---

## Detection heuristics

Some formats have no unique prefix, so the chain gates them with cheap
heuristics (`parsers/mod.rs`) before attempting the parser:

- `looks_like_logfmt` — ≥ 2 `key=value` pairs with identifier-like keys.
- `looks_like_xml` — starts with `<tag`, `<?xml`, or `<!--`.
- `looks_like_yaml` — a `key: value` line or a leading `---`.
- RFC 3164 without `<PRI>` is **self-gating**: its parser only succeeds when it
  finds a leading syslog timestamp, so it can be attempted without a heuristic.

If your parser has a distinctive prefix (like `KV2|`), gate on that. If not,
either add a `looks_like_*` heuristic or rely on the parser returning `None`
quickly — but be careful about ordering so you don't shadow other formats.

---

## How fields reach the output

`Event::flatten()` (`event.rs`) turns the event into the flat output map:

1. `fields` are lifted to top-level keys. Canonical keys are inserted first,
   then synonyms (`src`→`src_ip`, `dst`→`dst_ip`, `spt`→`src_port`,
   `dpt`→`dst_port`) fill only still-empty canonical slots.
2. Envelope fields (`hostname`, `app_name`, `severity`, `message`, …) are
   inserted next and **win** on collision with a structured field.
3. `timestamp` is the event timestamp, or the receive time if absent.
4. `_received`, `_source_type`, `_format`, `_normalized`, `source_addr`, and
   `_raw` are added.

So: choose canonical field names in your parser to control the final output, and
promote anything that should drive source derivation or bucketing into the
envelope fields.

---

## Testing a parser

Use `--dry-run` to see output without writing files:

```bash
BIN=./target/debug/normalized

# Single line
echo 'KV2|host:web1|sev:err|msg:disk full' | $BIN --stdin --dry-run

# A sample file; confirm the format and fields you expect
cat samples/kv2.log | $BIN --stdin --dry-run \
  | grep -o '"_format":"[^"]*"' | sort | uniq -c

# Force your parser regardless of detection
cat samples/ambiguous.log | $BIN --stdin --dry-run --source kv2   # label
```

Add unit tests next to the chain in `parsers/mod.rs` (or in your module). The
existing tests in `main.rs`, `event.rs`, and `output.rs` are good templates —
build a line, call `parsers::parse`, and assert on `event.format`, the promoted
envelope fields, and the flattened JSON:

```rust
#[test]
fn kv2_is_detected_and_flattened() {
    let o = parsers::parse(b"KV2|host:web1|sev:err|msg:disk full", "127.0.0.1", &[]);
    assert_eq!(o.event.hostname.as_deref(), Some("web1"));
    let json = crate::event::serialize_flat(
        &o.event.flatten("kv2", "2026-06-27T00:00:00Z"),
    );
    assert!(json.contains(r#""severity":"error""#));
}
```

Run the suite:

```bash
cargo test -p normalized
```

---

## Checklist

Adding a new parser module:

- [ ] Create `parsers/<format>.rs` with `pub fn parse(&[u8], &str) -> Option<Event>`.
- [ ] Return `None` unless the line is clearly your format.
- [ ] Promote envelope data to dedicated `Event` fields; use canonical names in `fields`.
- [ ] Set `raw: raw.to_vec()`.
- [ ] `pub mod <format>;` + insert into `run_chain` at the right priority.
- [ ] Add a `"<format>" => …` arm to `force_parse`.
- [ ] (Optional) add a `Format` variant + `as_str()` arm.
- [ ] Add unit tests; verify with `--dry-run`.

Before writing any code, check whether an **override rule** (force format +
remap) already solves it — that's the preferred path.

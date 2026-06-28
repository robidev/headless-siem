# Headless SIEM — Log Normalization Prompt

Use this file as the system prompt (or first user turn) when asking an LLM to
generate `config/normalized.toml` entries for a new log source. Paste this
entire file, then append the log lines you want normalized.

---

## Recommended models

| Model | Effort | Notes |
|---|---|---|
| Claude Opus | Low | Best regex correctness; reliable two-pass design; minimal review needed |
| Claude Sonnet | Low | Excellent quality; good default choice |
| DeepSeek V3 Pro | Low-Medium | Strong structured output and regex; occasionally misses edge cases |
| Claude Haiku | Medium | Fast and cheap; regex sometimes too greedy; spot-check output |
| DeepSeek V3 Flash | Medium | Good for simple sources; review patterns for multi-branch messages |
| Qwen3 (14B+) | Medium | Solid TOML output; regex quality varies with message complexity |
| Gemma4 (27B) | High | Needs detailed examples in prompt; regex often requires hand-tuning |
| Qwen3 (≤7B) | High | Structured output unreliable at this size; use only for simple sources |

> **Recommendation**: Use Sonnet or DeepSeek V3 Pro for new sources.
> Use Haiku or Flash only for simple, single-pattern sources to save cost.
> Regardless of model: always test output with
> `cat sample.log | ./normalized --stdin --dry-run --config config/normalized.toml | jq .`

---

## Your task

You are generating TOML configuration for **Headless SIEM's `normalized` binary**.
The goal is to extract structured fields from raw log lines produced by a specific
log source, and assign meaningful `event_type` values to each distinct event class.

You will be given sample log lines at the bottom of this prompt. Analyze them,
then emit the TOML rules described below. Output **only valid TOML** — no prose,
no markdown fences, no explanation.

---

## How normalization works

`normalized` runs every log line through this sequence:

```
raw line
  │
  ├─ envelope unwrap   (if {"_raw": "…"} rsyslog wrapper — strips it, keeps metadata)
  │
  ├─ override rules    (first matching rule wins → force parser, assign source, remap fields)
  │
  ├─ format chain      (auto-detect: RFC 5424/3164, JSON, CEF, LEEF, logfmt, CSV, XML, YAML, plain)
  │
  ├─ second pass       (re-parse structured payload inside syslog, if configured)
  │
  └─ extraction rules  (regex named captures pull fields from free-text message body)
```

Two rule types exist in `normalized.toml`:

- **`[[overrides.rule]]`** — runs before parsing. Force a format, rename a source
  label, or remap field names from a wire-format that uses non-canonical names.
- **`[[extract.rule]]`** — runs after parsing. Pull fields out of free-text
  message bodies using regex named captures.

Most sources only need extraction rules. Override rules are for unusual wire
formats (CSV with positional columns, non-standard source names, multi-source
hosts).

---

## Two-pass extraction pattern

This is the standard pattern for sources with multiple event types:

**Pass 1** — one `[[extract.rule]]` block, conditions on `app_name`, multiple
`pattern =` lines. Each pattern extracts a discriminating field (e.g.
`auth_action`, `session_action`) plus data fields (`src_ip`, `username`, etc.).
Do **not** use `set =` in pass 1 — conditions on `app_name` alone would apply
`set` to *every* event from that source.

**Pass 2** — one `[[extract.rule]]` per event class. Condition on the
discriminating field captured in pass 1. Use `set = { event_type = "…" }` to
assign the final event type.

Rules run in **declaration order**. A later `set` overwrites an earlier one —
use this intentionally when one event type overrides another (e.g. a session
start line matches both `action = "Started"` and `systemd_session = "Session"`;
the later, more specific rule sets the correct `event_type`).

---

## `[[overrides.rule]]` schema

All fields optional; all present conditions are ANDed; first match wins.

```toml
[[overrides.rule]]
# Conditions (AND):
source_ip  = "192.168.10."   # sender IP prefix match
starts_with = "filterlog,"   # raw line prefix
contains   = "[UFW "         # raw line substring

# Actions (apply when matched):
source = "iptables"          # assign this source label (bucket name + _source_type)
format = "csv"               # force parser: rfc5424 rfc3164 json json_array cef leef
                             #               logfmt csv tsv xml yaml plain
remap  = { src = "src_ip", dst = "dst_ip" }   # rename parsed fields (old = "new")
reparse    = true            # re-parse message body (for structured payload in syslog)
reparse_as = "logfmt"        # force second-pass format (omit to auto-detect by prefix)
```

---

## `[[extract.rule]]` schema

```toml
[[extract.rule]]
# Conditions (AND; all are exact-match string equality):
app_name    = "sshd"         # matched against the syslog app_name / process name
hostname    = "fw01"
source_addr = "10.0.0.1"     # sender IP (or "stdin")
_format     = "rfc3164"      # which parser claimed the line
source      = "iptables"     # the derived source label (_source_type)
# …any other captured field:
auth_action = "Failed"       # field captured by an earlier extraction rule

# What to search:
from = "message"             # field to apply patterns to (default: "message")
                             # alternatives: "_raw", or any parsed field name

# Patterns (each is tried independently; named captures add fields):
pattern = "from (?P<src_ip>[\d.]+) port (?P<src_port>\d+)"
pattern = "for (?P<username>\S+) from"
# Multiple pattern = lines in one block are all tried independently.
# Named captures fill only EMPTY slots — they never clobber existing values.
# Exception: set = always overwrites.

# Static fields to add when conditions match:
set = { event_type = "ssh_auth_failure", severity = "warning" }
```

---

## Canonical field names

Use these exact names. The synonyms `src`/`dst`/`spt`/`dpt` are auto-renamed but
prefer the canonical forms directly.

| Field | Meaning |
|---|---|
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source port |
| `dst_port` | Destination port |
| `username` | Authenticated or acting user |
| `target_user` | User being switched to (sudo, su, etc.) |
| `event_type` | Snake-case event class (see conventions below) |
| `severity` | Log severity word (`info`, `warning`, `error`, `critical`) |
| `hostname` | Host that generated the event |
| `command` | Full command string |
| `protocol` | Network protocol (`TCP`, `UDP`, `ICMP`, …) |
| `query` | DNS query name or search term |
| `action` | Firewall or policy action (`BLOCK`, `ALLOW`, `DROP`, …) |
| `unit` | systemd unit name |
| `session_id` | Session identifier |
| `pid` | Process ID |
| `url` | HTTP request URL |
| `method` | HTTP method (`GET`, `POST`, …) |
| `status_code` | HTTP response status |

---

## `event_type` naming conventions

Use lowercase snake_case. Follow this pattern: `<source>_<action>`.

Examples:
- `ssh_auth_failure`, `ssh_auth_success`, `ssh_session_open`, `ssh_session_close`
- `sudo_command`, `sudo_auth_failure`, `sudo_session_open`
- `firewall_block`, `firewall_allow`
- `unit_started`, `unit_failed`, `session_start`
- `dns_query`, `dns_nxdomain`
- `http_request`, `http_error`
- `login_success`, `login_failure`
- `process_start`, `process_stop`

---

## Regex rules

- Use Rust regex syntax. Named captures: `(?P<field_name>…)`.
- Use `\d` not `\\d` (no TOML escaping inside quoted strings).
- Anchor with `^` where the match must start at the beginning; `$` at the end.
- Use `\S+` for non-whitespace tokens, `[\d.]+` for IPv4, `\w+` for identifiers.
- Prefer non-greedy `.*?` when matching variable-length middle sections.
- Non-capturing groups for alternatives: `(?:word1|word2)`.
- Optional non-capturing group: `(?:…)?`.
- If a capture is optional (field absent in some lines), make the whole group
  optional: `(?:for (?P<username>\S+))?`.
- Patterns that should only match at word boundaries can use `\b`.
- A `#` inside a pattern string is not a comment — it is literal. The TOML
  parser is quote-aware, so `#` inside `"…"` is safe.

---

## What to emit

For each new log source, emit in this order:

1. An `[[overrides.rule]]` block **only if** the source needs it (non-standard
   wire format, positional CSV, source relabeling, field renames). Skip if not
   needed.

2. One pass-1 `[[extract.rule]]` block with `app_name = "<source>"` (or
   `source = "<source>"` if a prior override rule changed the source label) and
   all patterns that extract discriminating and data fields.

3. One pass-2 `[[extract.rule]]` block per distinct `event_type`, each
   conditioned on a discriminating field set in pass 1.

4. If the source needs an entry in `config/sources.toml`, append it at the end
   as a comment block (prefixed `# sources.toml:`), listing which fields to index.

Start the block with a comment header like:
```
# ─────────────────────────────────────────────────
# <source name>
#
# Patterns handled:
#   <brief description of each message type>
# ─────────────────────────────────────────────────
```

---

## Example output (sshd — for reference only, already in config)

```toml
# ─────────────────────────────────────────────────────────────────────────────
# sshd
#
# Patterns handled:
#   Failed/Accepted (password|publickey) for [invalid user] <user> from <ip> port <port>
#   pam_unix(sshd:session): session (opened|closed) for user <user>
#   Invalid user <user> from <ip> port <port>
# ─────────────────────────────────────────────────────────────────────────────

[[extract.rule]]
app_name = "sshd"
from = "message"
pattern = "^(?P<auth_action>Failed|Accepted) (?P<auth_method>\w+) for (?:invalid user )?(?P<username>\S+) from (?P<src_ip>[\d.]+) port (?P<src_port>\d+)"
pattern = "session (?P<session_action>opened|closed) for user (?P<username>\S+)"
pattern = "^(?P<sshd_invalid>Invalid user) (?P<username>\S+) from (?P<src_ip>[\d.]+) port (?P<src_port>\d+)"

[[extract.rule]]
app_name = "sshd"
auth_action = "Failed"
set = { event_type = "ssh_auth_failure" }

[[extract.rule]]
app_name = "sshd"
auth_action = "Accepted"
set = { event_type = "ssh_auth_success" }

[[extract.rule]]
app_name = "sshd"
session_action = "opened"
set = { event_type = "ssh_session_open" }

[[extract.rule]]
app_name = "sshd"
session_action = "closed"
set = { event_type = "ssh_session_close" }

[[extract.rule]]
app_name = "sshd"
sshd_invalid = "Invalid user"
set = { event_type = "ssh_invalid_user" }

# sources.toml:
# [source.sshd]
# index_fields = ["src_ip", "event_type", "username"]
```

---

## Common mistakes to avoid

- **Don't use `set` in the pass-1 block** — conditions are too broad; set would
  apply to every event from the source, not just one type.
- **Don't clobber canonical fields with non-canonical names** — use `src_ip`,
  not `source_ip` or `ip` as capture names.
- **Don't emit an override rule for syslog sources** — syslog format (RFC 3164)
  is auto-detected. Override rules are for CSV, non-standard formats, or source
  relabeling.
- **Don't use `.*` as a catch-all capture** — it matches too aggressively. Use
  `[^"]+`, `\S+`, `[^\]]+`, or `.*?` with an anchor.
- **Don't put `set` and `pattern` in the same block** unless the intent is to
  set a field on every event that matches the block's conditions (rarely correct).
- **Don't forget to anchor auth/command patterns with `^`** when the match must
  start at the beginning of the message — otherwise overlapping patterns can
  partially match the wrong line.
- **Don't use `source_ip` as a capture name** — it is reserved as an override
  rule condition (sender address prefix). Use `src_ip` instead.

---

## Log lines to normalize

Paste the raw log lines below. Include at least one example of each distinct
event type the source can emit.

```
PASTE LOG LINES HERE
```

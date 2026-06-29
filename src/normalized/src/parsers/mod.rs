/// Deterministic parser chain.
///
/// Detection order (first to claim the line wins):
///   1. Starts with `<N>`   → RFC 5424, falling back to RFC 3164
///   2. Starts with `{`     → JSON object
///   3. Starts with `[`     → JSON array
///   4. Starts with `CEF:`  → CEF
///   5. Starts with `LEEF:` → LEEF
///   6. Many `key=value`    → Logfmt
///   7. Consistent delim    → CSV / TSV / pipe
///   8. Looks like XML      → XML
///   9. Looks like YAML     → YAML
///  10. Otherwise           → Plain text (always succeeds)
///
/// Config-driven override rules are checked before the chain. A matching rule
/// may force a parser format, rename fields, and/or assign a source label.

pub mod rfc5424;
pub mod rfc3164;
pub mod json;
pub mod cef;
pub mod leef;
pub mod logfmt;
pub mod csv;
pub mod xml;
pub mod yaml;
pub mod filterlog;
pub mod plain;

use std::collections::HashMap;

use crate::config::OverrideRule;
use crate::event::{Event, Format};

/// The result of parsing one line: the normalized event plus any explicit
/// source label assigned by a matching override rule.
pub struct ParseOutcome {
    pub event: Event,
    pub source: Option<String>,
}

/// Parse one raw line into an `Event`, honoring override rules first.
///
/// `source_addr` is the sender (peer IP, or "stdin"); it is recorded on the
/// event and used to match `source_ip` conditions.
pub fn parse(raw: &[u8], source_addr: &str, rules: &[OverrideRule]) -> ParseOutcome {
    let text = std::str::from_utf8(raw).unwrap_or("");

    for rule in rules {
        if rule_matches(rule, text, source_addr) {
            let mut event = match &rule.force_format {
                Some(fmt) => force_parse(fmt, raw, source_addr)
                    .unwrap_or_else(|| plain::parse(raw, source_addr)),
                None => run_chain(raw, source_addr),
            };
            apply_remap(&mut event.fields, &rule.remap);
            if rule.reparse {
                // Explicit second pass: forced format, or auto-detect by prefix.
                forced_reparse(&mut event, rule.reparse_as.as_deref());
            } else {
                auto_reparse(&mut event);
            }
            return ParseOutcome {
                event,
                source: rule.source.clone(),
            };
        }
    }

    let mut event = run_chain(raw, source_addr);
    auto_reparse(&mut event);
    ParseOutcome {
        event,
        source: None,
    }
}

/// Locate a wrapped structured payload and its format. CEF/LEEF are found by
/// their marker *anywhere in the raw line* — the syslog tag parser can swallow
/// the `CEF`/`LEEF` token as the program tag, so the marker may not survive at
/// the start of `message`. JSON is detected by a leading `{` in the message.
/// The inner parsers self-validate (a bogus `CEF:` in prose yields `None`),
/// so this stays false-positive-free.
fn detect_wrapped(raw: &[u8], message: &str) -> Option<(&'static str, Vec<u8>)> {
    let s = String::from_utf8_lossy(raw);
    if let Some(i) = s.find("CEF:") {
        return Some(("cef", s[i..].as_bytes().to_vec()));
    }
    if let Some(i) = s.find("LEEF:") {
        return Some(("leef", s[i..].as_bytes().to_vec()));
    }
    let m = message.trim_start();
    if m.starts_with('{') {
        return Some(("json", m.as_bytes().to_vec()));
    }
    None
}

/// Automatic second pass: only for syslog-transported lines carrying an
/// unambiguous CEF / LEEF / JSON payload.
fn auto_reparse(event: &mut Event) {
    if !matches!(event.format, Format::Rfc3164 | Format::Rfc5424) {
        return;
    }
    if let Some((fmt, payload)) = detect_wrapped(&event.raw, &event.message) {
        reparse_into(event, fmt, &payload);
    }
}

/// Config-requested second pass: force the given format (locating the payload
/// for cef/leef), or auto-detect if none was specified. Runs regardless of
/// transport.
fn forced_reparse(event: &mut Event, fmt: Option<&str>) {
    match fmt {
        Some(f) => {
            let payload = locate_payload(&event.raw, &event.message, f);
            reparse_into(event, f, &payload);
        }
        None => {
            if let Some((f, payload)) = detect_wrapped(&event.raw, &event.message) {
                reparse_into(event, f, &payload);
            }
        }
    }
}

/// Find the byte slice to feed a forced reparse: from the CEF/LEEF marker in the
/// raw line, or the whole message for any other format.
fn locate_payload(raw: &[u8], message: &str, fmt: &str) -> Vec<u8> {
    let marker = match fmt {
        "cef" => "CEF:",
        "leef" => "LEEF:",
        _ => "",
    };
    if !marker.is_empty() {
        let s = String::from_utf8_lossy(raw);
        if let Some(i) = s.find(marker) {
            return s[i..].as_bytes().to_vec();
        }
    }
    message.as_bytes().to_vec()
}

/// Parse `payload` as `fmt` and merge the result into `event`.
fn reparse_into(event: &mut Event, fmt: &str, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    if let Some(inner) = force_parse(fmt, payload, &event.source_addr) {
        merge_reparsed(event, inner);
    }
}

/// Merge a re-parsed payload into the transporting event. The payload is the
/// real event, so its structured fields and severity win; the syslog envelope
/// keeps host/app/timestamp (filled from the payload only when absent).
fn merge_reparsed(outer: &mut Event, inner: Event) {
    outer
        .fields
        .insert("_transport".to_string(), outer.format.as_str().to_string());
    outer.format = inner.format;

    for (k, v) in inner.fields {
        outer.fields.insert(k, v); // payload fields win
    }
    if inner.severity.is_some() {
        outer.severity = inner.severity;
    }
    if inner.msg_id.is_some() {
        outer.msg_id = inner.msg_id;
    }
    if outer.hostname.is_none() {
        outer.hostname = inner.hostname;
    }
    if outer.app_name.is_none() {
        outer.app_name = inner.app_name;
    }
    if outer.timestamp.is_none() {
        outer.timestamp = inner.timestamp;
    }
    if !inner.message.is_empty() {
        outer.message = inner.message;
    }
    // outer.raw stays the original full line.
}

/// True when every present condition on the rule matches.
fn rule_matches(rule: &OverrideRule, text: &str, source_addr: &str) -> bool {
    if let Some(ip) = &rule.source_ip {
        if !source_addr.starts_with(ip.as_str()) {
            return false;
        }
    }
    if let Some(sw) = &rule.starts_with {
        if !text.starts_with(sw.as_str()) {
            return false;
        }
    }
    if let Some(needle) = &rule.contains {
        if !text.contains(needle.as_str()) {
            return false;
        }
    }
    true
}

/// Run the full auto-detection chain (no overrides).
fn run_chain(raw: &[u8], source_addr: &str) -> Event {
    // Strip trailing newline / CR for detection but keep `raw` intact.
    let trimmed = raw
        .iter()
        .rposition(|&b| b != b'\n' && b != b'\r')
        .map(|i| &raw[..=i])
        .unwrap_or(raw);

    let text = std::str::from_utf8(trimmed).unwrap_or("");

    if text.starts_with('<') {
        if let Some(ev) = rfc5424::parse(trimmed, source_addr) {
            return ev;
        }
        if let Some(ev) = rfc3164::parse(trimmed, source_addr) {
            return ev;
        }
    }
    if text.starts_with('{') {
        if let Some(ev) = json::parse_object(trimmed, source_addr) {
            return ev;
        }
    }
    if text.starts_with('[') {
        if let Some(ev) = json::parse_array(trimmed, source_addr) {
            return ev;
        }
    }
    if text.starts_with("CEF:") {
        if let Some(ev) = cef::parse(trimmed, source_addr) {
            return ev;
        }
    }
    if text.starts_with("LEEF:") {
        if let Some(ev) = leef::parse(trimmed, source_addr) {
            return ev;
        }
    }
    // BSD syslog without a <PRI> prefix (e.g. /var/log/syslog, journald plain).
    // Self-gating: rfc3164::parse only succeeds when it finds a leading syslog
    // timestamp, so it won't steal logfmt/csv/plain lines. Tried before
    // logfmt/csv because a syslog message body may contain `=` or commas.
    if let Some(ev) = rfc3164::parse(trimmed, source_addr) {
        return ev;
    }
    if looks_like_logfmt(text) {
        if let Some(ev) = logfmt::parse(trimmed, source_addr) {
            return ev;
        }
    }
    if let Some(ev) = csv::parse(trimmed, source_addr) {
        return ev;
    }
    if looks_like_xml(text) {
        if let Some(ev) = xml::parse(trimmed, source_addr) {
            return ev;
        }
    }
    if looks_like_yaml(text) {
        if let Some(ev) = yaml::parse(trimmed, source_addr) {
            return ev;
        }
    }
    plain::parse(raw, source_addr)
}

/// Run a single named parser (used when an override forces a format).
fn force_parse(fmt: &str, raw: &[u8], source_addr: &str) -> Option<Event> {
    match fmt {
        "rfc5424" => rfc5424::parse(raw, source_addr),
        "rfc3164" => rfc3164::parse(raw, source_addr),
        "json" => json::parse_object(raw, source_addr),
        "json_array" => json::parse_array(raw, source_addr),
        "cef" => cef::parse(raw, source_addr),
        "leef" => leef::parse(raw, source_addr),
        "logfmt" => logfmt::parse(raw, source_addr),
        "csv" => csv::parse(raw, source_addr),
        "xml" => xml::parse(raw, source_addr),
        "yaml" => yaml::parse(raw, source_addr),
        "filterlog" => filterlog::parse(raw, source_addr),
        "plain" => Some(plain::parse(raw, source_addr)),
        other => {
            eprintln!("[normalized] unknown forced format '{}', using plain", other);
            Some(plain::parse(raw, source_addr))
        }
    }
}

/// Rename fields: old_key → new_key.
fn apply_remap(fields: &mut HashMap<String, String>, remap: &HashMap<String, String>) {
    for (old_key, new_key) in remap {
        if let Some(val) = fields.remove(old_key.as_str()) {
            fields.insert(new_key.clone(), val);
        }
    }
}

// ── detection heuristics ────────────────────────────────────────────────────

/// True when the string contains at least 2 `key=value` pairs whose keys look
/// like identifiers (no whitespace, not pure numbers).
pub fn looks_like_logfmt(s: &str) -> bool {
    let mut count = 0usize;
    for part in s.split_whitespace() {
        if let Some(eq) = part.find('=') {
            let key = &part[..eq];
            if !key.is_empty()
                && !key.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(true)
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
            {
                count += 1;
                if count >= 2 {
                    return true;
                }
            }
        }
    }
    false
}

/// True when the string starts with `<tag`, `<?xml`, or `<!--`.
pub fn looks_like_xml(s: &str) -> bool {
    let s = s.trim_start();
    s.starts_with("<?xml")
        || s.starts_with("<!--")
        || (s.starts_with('<') && s.len() > 1 && {
            let second = s.as_bytes().get(1).copied().unwrap_or(0);
            second.is_ascii_alphabetic() || second == b'/'
        })
}

/// True when the string has a `key: value` line or a leading `---` separator.
pub fn looks_like_yaml(s: &str) -> bool {
    if s.starts_with("---") {
        return true;
    }
    s.lines().any(|line| {
        if let Some(colon) = line.find(':') {
            let key = line[..colon].trim();
            !key.is_empty() && !key.contains(' ') && !key.starts_with(|c: char| c == '#' || c == '-')
        } else {
            false
        }
    })
}

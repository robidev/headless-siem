/// Minimal hand-rolled JSON parser (no serde).
///
/// Supports object and array top-level documents.
/// We only need string/number/bool/null scalars — nested objects are
/// flattened with dot-notation keys.

use std::collections::HashMap;
use crate::event::{Event, Format};

pub fn parse_object(raw: &[u8], source_addr: &str) -> Option<Event> {
    let s = std::str::from_utf8(raw).ok()?;
    let mut fields = HashMap::new();
    parse_obj(s.trim(), "", &mut fields)?;

    let message = fields
        .remove("message")
        .or_else(|| fields.remove("msg"))
        .or_else(|| fields.remove("text"))
        .unwrap_or_default();

    Some(Event {
        format: Format::Json,
        source_addr: source_addr.to_owned(),
        facility: None,
        severity: None,
        timestamp: fields.remove("timestamp").or_else(|| fields.remove("time").or_else(|| fields.remove("@timestamp"))),
        hostname: fields.remove("hostname").or_else(|| fields.remove("host")),
        app_name: fields.remove("app_name").or_else(|| fields.remove("appname").or_else(|| fields.remove("application"))),
        proc_id: fields.remove("pid").or_else(|| fields.remove("proc_id")),
        msg_id: None,
        message,
        fields,
        raw: raw.to_vec(),
    })
}

pub fn parse_array(raw: &[u8], source_addr: &str) -> Option<Event> {
    let s = std::str::from_utf8(raw).ok()?;
    let s = s.trim();
    // Must start with `[`
    if !s.starts_with('[') {
        return None;
    }
    // Quick sanity: try to find matching `]`
    if !s.ends_with(']') {
        return None;
    }

    let mut fields = HashMap::new();
    // Flatten array elements as indexed keys
    let inner = &s[1..s.len() - 1].trim();
    let items = split_json_values(inner);
    for (i, item) in items.iter().enumerate() {
        let item = item.trim();
        let prefix = i.to_string();
        if item.starts_with('{') {
            let _ = parse_obj(item, &prefix, &mut fields);
        } else {
            fields.insert(prefix, scalar_to_string(item));
        }
    }

    let message = format!("{} JSON array elements", items.len());

    Some(Event {
        format: Format::JsonArray,
        source_addr: source_addr.to_owned(),
        facility: None,
        severity: None,
        timestamp: None,
        hostname: None,
        app_name: None,
        proc_id: None,
        msg_id: None,
        message,
        fields,
        raw: raw.to_vec(),
    })
}

// ── internal helpers ──────────────────────────────────────────────────────────

/// Recursively parse a JSON object `{ ... }` into flat `prefix.key` entries.
/// Returns `Some(())` on success, `None` if it doesn't look like a JSON object.
fn parse_obj(s: &str, prefix: &str, fields: &mut HashMap<String, String>) -> Option<()> {
    let s = s.trim();
    let inner = s.strip_prefix('{')?.strip_suffix('}')?;

    // Split by `,` respecting nesting
    let pairs = split_json_values(inner);
    for pair in &pairs {
        let pair = pair.trim();
        // Each pair: "key": value
        if pair.is_empty() { continue; }
        let (raw_key, rest) = parse_json_string(pair)?;
        let rest = rest.trim_start().strip_prefix(':')?.trim_start();

        let full_key = if prefix.is_empty() {
            raw_key.clone()
        } else {
            format!("{}.{}", prefix, raw_key)
        };

        if rest.starts_with('{') {
            // Nested object → recurse
            parse_obj(rest, &full_key, fields)?;
        } else if rest.starts_with('[') {
            // Nested array → store as string
            fields.insert(full_key, rest.to_owned());
        } else {
            fields.insert(full_key, scalar_to_string(rest));
        }
    }
    Some(())
}

/// Parse a JSON string literal at the start of `s`.
/// Returns (unescaped_string, remainder_after_closing_quote).
fn parse_json_string(s: &str) -> Option<(String, &str)> {
    let s = s.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => match chars.next()?.1 {
                '"'  => out.push('"'),
                '\\' => out.push('\\'),
                '/'  => out.push('/'),
                'n'  => out.push('\n'),
                'r'  => out.push('\r'),
                't'  => out.push('\t'),
                'u'  => {
                    // 4 hex digits
                    let mut hex = String::new();
                    for _ in 0..4 { hex.push(chars.next()?.1); }
                    if let Ok(n) = u32::from_str_radix(&hex, 16) {
                        if let Some(c) = char::from_u32(n) { out.push(c); }
                    }
                }
                other => { out.push('\\'); out.push(other); }
            },
            '"' => return Some((out, &s[i + 1..])),
            other => out.push(other),
        }
    }
    None
}

/// Split a JSON value list by `,`, respecting `{}`, `[]`, and `""` nesting.
fn split_json_values(s: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    let mut start = 0;
    let bytes = s.as_bytes();

    for (i, &b) in bytes.iter().enumerate() {
        if escape { escape = false; continue; }
        if b == b'\\' && in_string { escape = true; continue; }
        if b == b'"' { in_string = !in_string; continue; }
        if in_string { continue; }
        match b {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth -= 1,
            b',' if depth == 0 => {
                items.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        items.push(&s[start..]);
    }
    items
}

/// Convert a JSON scalar token to a plain string.
fn scalar_to_string(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') {
        // Parse as JSON string
        parse_json_string(s)
            .map(|(v, _)| v)
            .unwrap_or_else(|| s.to_owned())
    } else {
        s.to_owned()
    }
}

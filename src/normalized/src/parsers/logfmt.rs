/// Logfmt / key=value parser.
///
/// Handles:
///   key=value key2="quoted value" bare_key key3=
///
/// Values may be double-quoted (supporting `\"` escapes) or unquoted
/// (terminated by whitespace).

use std::collections::HashMap;
use crate::event::{Event, Format, Severity};

pub fn parse(raw: &[u8], source_addr: &str) -> Option<Event> {
    let s = std::str::from_utf8(raw).ok()?;
    let mut fields = parse_pairs(s);

    if fields.is_empty() {
        return None;
    }

    let severity = fields
        .get("level")
        .or_else(|| fields.get("severity"))
        .or_else(|| fields.get("lvl"))
        .and_then(|l| level_to_severity(l));

    let message = fields
        .remove("msg")
        .or_else(|| fields.remove("message"))
        .or_else(|| fields.remove("text"))
        .unwrap_or_default();

    Some(Event {
        format: Format::Logfmt,
        source_addr: source_addr.to_owned(),
        facility: None,
        severity,
        timestamp: fields.remove("ts")
            .or_else(|| fields.remove("time"))
            .or_else(|| fields.remove("timestamp")),
        hostname: fields.remove("host")
            .or_else(|| fields.remove("hostname")),
        app_name: fields.remove("app")
            .or_else(|| fields.remove("service"))
            .or_else(|| fields.remove("caller")),
        proc_id: fields.remove("pid"),
        msg_id: None,
        message,
        fields,
        force_severity: false,
        raw: raw.to_vec(),
    })
}

pub fn parse_pairs(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut rest = s.trim();

    while !rest.is_empty() {
        rest = rest.trim_start();
        if rest.is_empty() { break; }

        // Find `=`
        if let Some(eq) = rest.find('=') {
            let key = rest[..eq].trim().to_owned();
            rest = &rest[eq + 1..];

            let (val, tail) = if rest.starts_with('"') {
                extract_quoted_value(&rest[1..])
            } else {
                // Unquoted: up to next whitespace
                let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
                (rest[..end].to_owned(), &rest[end..])
            };

            if !key.is_empty() {
                map.insert(key, val);
            }
            rest = tail;
        } else {
            // Bare key (no `=`): treat as boolean flag
            let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
            if end > 0 {
                map.insert(rest[..end].to_owned(), "true".to_owned());
            }
            rest = &rest[end..];
        }
    }
    map
}

fn extract_quoted_value(s: &str) -> (String, &str) {
    let mut out = String::new();
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                match chars.next().map(|(_, c)| c) {
                    Some('"')  => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('n')  => out.push('\n'),
                    Some(other) => { out.push('\\'); out.push(other); }
                    None => {}
                }
            }
            '"' => return (out, &s[i + 1..]),
            other => out.push(other),
        }
    }
    (out, "")
}

fn level_to_severity(level: &str) -> Option<Severity> {
    match level.to_ascii_lowercase().as_str() {
        "emergency" | "emerg" | "panic" => Some(Severity::Emergency),
        "alert"                          => Some(Severity::Alert),
        "critical" | "crit"             => Some(Severity::Critical),
        "error" | "err"                  => Some(Severity::Error),
        "warning" | "warn"               => Some(Severity::Warning),
        "notice"                         => Some(Severity::Notice),
        "info" | "information" | "informational" => Some(Severity::Informational),
        "debug" | "trace"               => Some(Severity::Debug),
        _ => None,
    }
}

/// RFC 5424 syslog parser.
///
/// Format: `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`
///
/// Example:
///   <34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 [exampleSDID@32473 ...] BOM'su root'

use std::collections::HashMap;
use crate::event::{Event, Facility, Format, Severity};

pub fn parse(raw: &[u8], source_addr: &str) -> Option<Event> {
    let s = std::str::from_utf8(raw).ok()?;

    // ── 1. PRI ───────────────────────────────────────────────────────────────
    let s = s.strip_prefix('<')?;
    let close = s.find('>')?;
    let pri: u8 = s[..close].parse().ok()?;
    let facility = Facility(pri >> 3);
    let severity = Severity::from_code(pri);
    let rest = &s[close + 1..];

    // ── 2. VERSION (must be "1") ──────────────────────────────────────────────
    let rest = rest.strip_prefix("1 ")?;

    // ── 3. TIMESTAMP ─────────────────────────────────────────────────────────
    let (timestamp, rest) = split_sp(rest)?;

    // ── 4. HOSTNAME ───────────────────────────────────────────────────────────
    let (hostname, rest) = split_sp(rest)?;

    // ── 5. APP-NAME ───────────────────────────────────────────────────────────
    let (app_name, rest) = split_sp(rest)?;

    // ── 6. PROCID ─────────────────────────────────────────────────────────────
    let (proc_id, rest) = split_sp(rest)?;

    // ── 7. MSGID ──────────────────────────────────────────────────────────────
    let (msg_id, rest) = split_sp(rest)?;

    // ── 8. STRUCTURED-DATA ────────────────────────────────────────────────────
    let mut fields = HashMap::new();
    let rest = if rest.starts_with('-') {
        &rest[1..]
    } else if rest.starts_with('[') {
        parse_structured_data(rest, &mut fields)
    } else {
        rest
    };

    // ── 9. MSG (optional BOM strip) ───────────────────────────────────────────
    let rest = rest.trim_start_matches(' ');
    // Strip UTF-8 BOM if present
    let message = rest
        .strip_prefix('\u{FEFF}')
        .unwrap_or(rest)
        .to_owned();

    let nilval = |s: &str| if s == "-" { None } else { Some(s.to_owned()) };

    Some(Event {
        format: Format::Rfc5424,
        source_addr: source_addr.to_owned(),
        facility: Some(facility),
        severity: Some(severity),
        timestamp: nilval(timestamp),
        hostname: nilval(hostname),
        app_name: nilval(app_name),
        proc_id: nilval(proc_id),
        msg_id: nilval(msg_id),
        message,
        fields,
        force_severity: false,
        raw: raw.to_vec(),
    })
}

/// Split at the first space, returning (before, after).
fn split_sp(s: &str) -> Option<(&str, &str)> {
    let i = s.find(' ')?;
    Some((&s[..i], &s[i + 1..]))
}

/// Parse one or more `[id key="val" ...]` blocks.
/// Returns the remainder after the structured-data section.
fn parse_structured_data<'a>(
    mut s: &'a str,
    fields: &mut HashMap<String, String>,
) -> &'a str {
    while let Some(rest) = s.strip_prefix('[') {
        // SD-ID
        let id_end = rest.find(|c: char| c == ' ' || c == ']').unwrap_or(rest.len());
        let _sd_id = &rest[..id_end];
        let mut inner = &rest[id_end..];

        // Params: key="value"
        loop {
            inner = inner.trim_start_matches(' ');
            if inner.starts_with(']') {
                inner = &inner[1..];
                break;
            }
            // key="value"
            if let Some(eq) = inner.find('=') {
                let key = inner[..eq].to_owned();
                let after_eq = &inner[eq + 1..];
                if after_eq.starts_with('"') {
                    let val_start = &after_eq[1..];
                    // find closing unescaped quote
                    let (val, consumed) = extract_quoted(val_start);
                    fields.insert(key, val);
                    inner = &val_start[consumed..];
                } else {
                    // unquoted value (shouldn't happen per spec, but be lenient)
                    let end = after_eq.find(|c: char| c == ' ' || c == ']').unwrap_or(after_eq.len());
                    fields.insert(key, after_eq[..end].to_owned());
                    inner = &after_eq[end..];
                }
            } else {
                break;
            }
        }
        s = inner;
        if s.starts_with(' ') {
            s = &s[1..];
        }
    }
    s
}

/// Extract a quoted string starting *after* the opening `"`, up to the closing
/// unescaped `"`. Returns (value, bytes_consumed_including_closing_quote).
fn extract_quoted(s: &str) -> (String, usize) {
    let mut val = String::new();
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                if let Some((_, next)) = chars.next() {
                    val.push(next);
                }
            }
            '"' => return (val, i + 1),
            other => val.push(other),
        }
    }
    (val, s.len())
}

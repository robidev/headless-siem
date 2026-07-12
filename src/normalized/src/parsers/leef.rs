/// LEEF (IBM QRadar Log Event Extended Format) parser.
///
/// LEEF 1.0: `LEEF:1.0|Vendor|Product|Version|EventID|key\tvalue\t…`
/// LEEF 2.0: `LEEF:2.0|Vendor|Product|Version|EventID|{delimiter}|key{d}value{d}…`
///
/// Default delimiter is TAB; LEEF 2.0 can specify an alternate single char.

use std::collections::HashMap;
use crate::event::{Event, Format, Severity};

pub fn parse(raw: &[u8], source_addr: &str) -> Option<Event> {
    let s = std::str::from_utf8(raw).ok()?;
    let s = s.strip_prefix("LEEF:")?;

    // Version token
    let pipe1 = s.find('|')?;
    let version = &s[..pipe1];
    let rest = &s[pipe1 + 1..];

    // Vendor
    let p = rest.find('|')?;
    let vendor = rest[..p].to_owned();
    let rest = &rest[p + 1..];

    // Product
    let p = rest.find('|')?;
    let product = rest[..p].to_owned();
    let rest = &rest[p + 1..];

    // Dev Version
    let p = rest.find('|')?;
    let _dev_ver = &rest[..p];
    let rest = &rest[p + 1..];

    // EventID
    let p = rest.find('|')?;
    let event_id = rest[..p].to_owned();
    let rest = &rest[p + 1..];

    // LEEF 2.0 has an optional delimiter field
    let (delimiter, attrs_str) = if version == "2.0" || version == "2" {
        if let Some(p) = rest.find('|') {
            let delim_field = &rest[..p];
            let attr_rest = &rest[p + 1..];
            // Delimiter field can be `^` (hat notation) or a literal char
            let delim = if delim_field.starts_with('^') {
                delim_field.chars().nth(1).unwrap_or('\t')
            } else {
                delim_field.chars().next().unwrap_or('\t')
            };
            (delim, attr_rest)
        } else {
            ('\t', rest)
        }
    } else {
        ('\t', rest)
    };

    let mut fields = parse_attributes(attrs_str, delimiter);
    fields.insert("leef.vendor".to_owned(), vendor.clone());
    fields.insert("leef.product".to_owned(), product.clone());
    fields.insert("leef.event_id".to_owned(), event_id.clone());

    let severity = fields.get("sev")
        .or_else(|| fields.get("severity"))
        .and_then(|s| s.parse::<u8>().ok())
        .map(|n| Severity::from_code(match n {
            0..=2   => 7,
            3..=5   => 5,
            6..=8   => 4,
            _       => 3,
        }));

    let message = fields
        .remove("msg")
        .or_else(|| fields.remove("message"))
        .unwrap_or_else(|| event_id.clone());

    Some(Event {
        format: Format::Leef,
        source_addr: source_addr.to_owned(),
        facility: None,
        severity,
        timestamp: fields.remove("devTime"),
        // Keep src in fields so it canonicalizes to src_ip; use srcName as host.
        hostname: fields.remove("srcName"),
        app_name: Some(product),
        proc_id: None,
        msg_id: Some(event_id),
        message,
        fields,
        force_severity: false,
        raw: raw.to_vec(),
    })
}

fn parse_attributes(s: &str, delim: char) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if s.contains(delim) {
        for token in s.split(delim) {
            let token = token.trim();
            if let Some(eq) = token.find('=') {
                let key = token[..eq].trim().to_owned();
                let val = token[eq + 1..].trim().to_owned();
                if !key.is_empty() {
                    map.insert(key, val);
                }
            }
        }
    } else {
        // Delimiter not present (e.g. space-separated LEEF). Scan for
        // `identifier=` boundaries: each key's value extends to the next key.
        parse_kv_boundary(s, &mut map);
    }
    map
}

/// Scan `s` for `key=value` pairs where `key` is an identifier preceded by
/// start-of-string or whitespace. Values run up to the start of the next key,
/// so values that contain spaces (e.g. `devTime=2018-09-24 16:23:36 PDT`) are
/// captured intact.
fn parse_kv_boundary(s: &str, map: &mut HashMap<String, String>) {
    let bytes = s.as_bytes();
    let mut positions: Vec<(usize, usize)> = Vec::new(); // (key_start, eq_idx)
    let mut i = 0;
    while i < bytes.len() {
        let at_boundary = i == 0 || bytes[i - 1].is_ascii_whitespace();
        if at_boundary && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
            let key_start = i;
            let mut j = i;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' || bytes[j] == b'.')
            {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' {
                positions.push((key_start, j));
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    for k in 0..positions.len() {
        let (key_start, eq_idx) = positions[k];
        let val_start = eq_idx + 1;
        let val_end = if k + 1 < positions.len() {
            positions[k + 1].0
        } else {
            s.len()
        };
        let key = s[key_start..eq_idx].to_owned();
        let val = s[val_start..val_end].trim().to_owned();
        if !key.is_empty() {
            map.insert(key, val);
        }
    }
}

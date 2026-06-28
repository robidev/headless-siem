/// CEF (ArcSight Common Event Format) parser.
///
/// Format:
///   `CEF:Version|Device Vendor|Device Product|Device Version|
///    Signature ID|Name|Severity|Extension`
///
/// Extension: space-separated `key=value` pairs where value may be
/// quoted or contain escaped `\|` and `\\`.

use std::collections::HashMap;
use crate::event::{Event, Format, Severity};

pub fn parse(raw: &[u8], source_addr: &str) -> Option<Event> {
    let s = std::str::from_utf8(raw).ok()?;
    let s = s.strip_prefix("CEF:")?;

    // Split the fixed header on `|`, respecting `\|` escapes
    let mut headers = Vec::with_capacity(8);
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(&next) = chars.peek() {
                    if next == '|' || next == '\\' {
                        cur.push(chars.next().unwrap());
                    } else {
                        cur.push(c);
                    }
                } else {
                    cur.push(c);
                }
            }
            '|' => {
                headers.push(cur.clone());
                cur.clear();
                // After 7 pipes the rest is the extension
                if headers.len() == 7 {
                    let remaining: String = chars.collect();
                    cur = remaining;
                    break;
                }
            }
            other => cur.push(other),
        }
    }
    headers.push(cur);

    if headers.len() < 7 {
        return None;
    }

    let _version    = &headers[0];
    let _vendor     = &headers[1];
    let _product    = &headers[2];
    let _dev_ver    = &headers[3];
    let sig_id      = &headers[4];
    let name        = &headers[5];
    let cef_sev     = &headers[6];
    let extension   = headers.get(7).map(String::as_str).unwrap_or("");

    // Map CEF severity 0-10 to our enum
    let severity = cef_sev.parse::<u8>().ok().map(|n| {
        // CEF: 0-3 low, 4-6 medium, 7-8 high, 9-10 very high
        Severity::from_code(match n {
            0..=3  => 7, // debug-ish → map to lowest
            4..=6  => 5, // notice
            7..=8  => 4, // warning
            _      => 3, // error
        })
    });

    // Parse extension key=value pairs
    let mut fields = parse_extension(extension);
    fields.insert("cef.signature_id".to_owned(), sig_id.clone());
    fields.insert("cef.name".to_owned(), name.clone());
    fields.insert("cef.severity".to_owned(), cef_sev.clone());
    fields.insert("cef.vendor".to_owned(), headers[1].clone());
    fields.insert("cef.product".to_owned(), headers[2].clone());
    fields.insert("cef.device_version".to_owned(), headers[3].clone());

    let message = name.clone();

    Some(Event {
        format: Format::Cef,
        source_addr: source_addr.to_owned(),
        facility: None,
        severity,
        timestamp: fields.remove("rt").or_else(|| fields.remove("end")),
        // Keep src/dst in fields so they canonicalize to src_ip/dst_ip;
        // use dhost (destination host) as the hostname when present.
        hostname: fields.remove("dhost"),
        app_name: Some(headers[2].clone()),
        proc_id: None,
        msg_id: Some(sig_id.clone()),
        message,
        fields,
        raw: raw.to_vec(),
    })
}

/// Parse CEF extension: `key=value key2=value2 ...`
///
/// Values run until the next unescaped `key=` token.
fn parse_extension(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    // Collect (position, key) for each `key=` token
    let mut tokens: Vec<(usize, &str)> = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Find next `=`
        if let Some(eq_off) = bytes[i..].iter().position(|&b| b == b'=') {
            let eq = i + eq_off;
            // Walk backwards to find start of key: stop at any character that
            // is not a valid key char (alphanumeric, `_`, `.`). This handles
            // both space-delimited (standard CEF) and pipe-delimited extensions.
            let key_start = bytes[..eq]
                .iter()
                .rposition(|&b| !b.is_ascii_alphanumeric() && b != b'_' && b != b'.')
                .map(|p| p + 1)
                .unwrap_or(0);
            // Only record if key looks sane
            let key = &s[key_start..eq];
            if !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') {
                tokens.push((key_start, key));
            }
            i = eq + 1;
        } else {
            break;
        }
    }

    for t in 0..tokens.len() {
        let (key_start, key) = tokens[t];
        let val_start = key_start + key.len() + 1; // skip `=`
        let val_end = if t + 1 < tokens.len() {
            // value ends just before the next key token (including its leading space)
            tokens[t + 1].0.saturating_sub(1)
        } else {
            s.len()
        };
        if val_start <= val_end && val_end <= s.len() {
            let val = unescape_cef(&s[val_start..val_end]);
            map.insert(key.to_owned(), val);
        }
    }
    map
}

fn unescape_cef(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('\\') => { chars.next(); out.push('\\'); }
                Some('=')  => { chars.next(); out.push('='); }
                Some('n')  => { chars.next(); out.push('\n'); }
                Some('r')  => { chars.next(); out.push('\r'); }
                _          => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    out
}

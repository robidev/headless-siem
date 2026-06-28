/// RFC 3164 "BSD syslog" parser.
///
/// Format: `[<PRI>]TIMESTAMP HOSTNAME TAG: MSG`
///
/// The `<PRI>` prefix is optional: files like `/var/log/syslog` (and journald
/// plain output) omit it, so we accept lines that begin directly with a
/// recognizable timestamp. The required timestamp keeps this from matching
/// arbitrary prose.
///
/// Timestamp formats accepted:
///   - `Mon DD HH:MM:SS`      (classic BSD, no year)
///   - `Mon  D HH:MM:SS`      (single-digit day with leading space)
///   - `YYYY-MM-DDTHH:MM:SS…` (ISO variant sometimes emitted by older rsyslog)

use std::collections::HashMap;
use crate::event::{Event, Facility, Format, Severity};

// Month abbreviations → two-digit string used in the stored timestamp
const MONTHS: [&str; 12] = [
    "Jan","Feb","Mar","Apr","May","Jun",
    "Jul","Aug","Sep","Oct","Nov","Dec",
];

pub fn parse(raw: &[u8], source_addr: &str) -> Option<Event> {
    let s = std::str::from_utf8(raw).ok()?;

    // ── PRI (optional) ─────────────────────────────────────────────────────────
    let (facility, severity, rest) = match s.strip_prefix('<').and_then(|a| {
        a.find('>')
            .and_then(|c| a[..c].parse::<u8>().ok().map(|pri| (pri, &a[c + 1..])))
    }) {
        Some((pri, rest)) => (
            Some(Facility(pri >> 3)),
            Some(Severity::from_code(pri)),
            rest,
        ),
        None => (None, None, s),
    };

    // ── TIMESTAMP (required) ───────────────────────────────────────────────────
    let (timestamp, rest) = try_parse_timestamp(rest)?;

    // ── HOSTNAME ──────────────────────────────────────────────────────────────
    let rest = rest.trim_start();
    let host_end = rest.find(' ').unwrap_or(rest.len());
    let hostname = rest[..host_end].to_owned();
    let rest = rest[host_end..].trim_start();

    // ── TAG (app_name + optional proc_id) ────────────────────────────────────
    // TAG is `identifier` optionally followed by `[pid]` and then `:` or space
    let (app_name, proc_id, message) = parse_tag_and_msg(rest);

    Some(Event {
        format: Format::Rfc3164,
        source_addr: source_addr.to_owned(),
        facility,
        severity,
        timestamp: Some(timestamp),
        hostname: Some(hostname),
        app_name,
        proc_id,
        msg_id: None,
        message,
        fields: HashMap::new(),
        raw: raw.to_vec(),
    })
}

/// Returns (timestamp_string, remainder) if a known timestamp format is found.
fn try_parse_timestamp(s: &str) -> Option<(String, &str)> {
    // Classic: "Jan 15 12:34:56 " (3+1+2+1+8 = 15 chars minimum)
    if s.len() >= 15 {
        let month = &s[..3];
        if MONTHS.contains(&month) && s.as_bytes()[3] == b' ' {
            // consume "Mon DD HH:MM:SS " or "Mon  D HH:MM:SS "
            let ts = &s[..15];
            let rest = &s[15..];
            return Some((ts.to_owned(), rest));
        }
    }
    // ISO-ish fallback: up to the first space
    if s.starts_with(|c: char| c.is_ascii_digit()) {
        if let Some(sp) = s.find(' ') {
            let candidate = &s[..sp];
            if candidate.contains('-') && candidate.contains('T') {
                return Some((candidate.to_owned(), &s[sp + 1..]));
            }
        }
    }
    None
}

/// Split `sshd[1234]: message` → (Some("sshd"), Some("1234"), "message")
fn parse_tag_and_msg(s: &str) -> (Option<String>, Option<String>, String) {
    // Find the first `:` which conventionally ends the tag
    let colon = s.find(':');
    // Find `[pid]` if present before the colon
    let bracket = s.find('[');

    match (bracket, colon) {
        (Some(b), Some(c)) if b < c => {
            let app = s[..b].to_owned();
            let close = s[b + 1..].find(']').map(|i| b + 1 + i);
            let pid = close.map(|e| s[b + 1..e].to_owned());
            let msg_start = colon.map(|i| i + 1).unwrap_or(0);
            let msg = s[msg_start..].trim_start().to_owned();
            (Some(app), pid, msg)
        }
        (_, Some(c)) => {
            let app = s[..c].to_owned();
            let msg = s[c + 1..].trim_start().to_owned();
            (Some(app), None, msg)
        }
        _ => (None, None, s.to_owned()),
    }
}

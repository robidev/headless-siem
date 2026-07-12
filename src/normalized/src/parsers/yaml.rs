/// Minimal YAML extractor.
///
/// Only handles the subset of YAML actually seen in log payloads:
///   - `---` document separator
///   - Top-level `key: value` pairs (scalar values only)
///   - Block sequences `- item` at top level
///
/// Nested mappings / sequences are stored as their raw string representation.

use std::collections::HashMap;
use crate::event::{Event, Format};

pub fn parse(raw: &[u8], source_addr: &str) -> Option<Event> {
    let s = std::str::from_utf8(raw).ok()?;
    let mut fields = HashMap::new();

    let s = s.trim_start_matches("---").trim();
    if s.is_empty() {
        return None;
    }

    let mut seq_index = 0usize;
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line == "---" || line == "..." {
            continue;
        }

        if line.starts_with("- ") {
            // Top-level sequence item
            let val = line[2..].trim().to_owned();
            fields.insert(format!("[{}]", seq_index), val);
            seq_index += 1;
            continue;
        }

        if let Some(colon) = line.find(": ") {
            let key = line[..colon].trim().to_owned();
            let val = line[colon + 2..].trim().to_owned();
            if !key.is_empty() {
                fields.insert(key, val);
            }
        } else if line.ends_with(':') {
            // Key with no value (block mapping start) — store empty
            let key = line[..line.len() - 1].trim().to_owned();
            if !key.is_empty() {
                fields.insert(key, String::new());
            }
        }
    }

    if fields.is_empty() {
        return None;
    }

    let message = fields
        .remove("message")
        .or_else(|| fields.remove("msg"))
        .unwrap_or_default();

    Some(Event {
        format: Format::Yaml,
        source_addr: source_addr.to_owned(),
        facility: None,
        severity: None,
        timestamp: fields.remove("timestamp").or_else(|| fields.remove("time")),
        hostname: fields.remove("hostname").or_else(|| fields.remove("host")),
        app_name: fields.remove("app_name").or_else(|| fields.remove("service")),
        proc_id: None,
        msg_id: None,
        message,
        fields,
        force_severity: false,
        raw: raw.to_vec(),
    })
}

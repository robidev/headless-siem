/// rsyslog / fixture envelope unwrapping.
///
/// The production feed (rsyslog `omprog`, see `config/rsyslog.d/`) wraps each
/// message as a JSON object whose `_raw` field holds the real log line, with
/// sidecar metadata tagged by rsyslog:
///
/// ```json
/// {"_source_type":"sshd","_host":"h","_facility":"auth",
///  "_severity":"info","_timestamp":"2026-…","_raw":"Failed password …"}
/// ```
///
/// The test fixtures use an older `{"_source":"sshd","_raw":"…"}` variant.
///
/// This module recognizes that envelope (deterministically: a JSON object with
/// a `_raw` key) and unwraps it so the inner line runs through the normal
/// parser chain. Anything else — plain syslog, journald JSON (no `_raw`), CEF,
/// etc. — returns `None` and is parsed as-is.
use crate::event::Severity;
use crate::parsers::json;

pub struct Envelope {
    pub raw: String,
    pub source: Option<String>,
    pub timestamp: Option<String>,
    pub hostname: Option<String>,
    pub severity: Option<String>,
}

/// Detect and unwrap the rsyslog/fixture envelope. `None` if `line` is not a
/// JSON object carrying a `_raw` field.
pub fn unwrap(line: &[u8]) -> Option<Envelope> {
    let text = std::str::from_utf8(line).ok()?;
    if !text.trim_start().starts_with('{') {
        return None;
    }
    // Reuse the JSON parser: every key lands in `fields`, except the few it
    // promotes to the envelope — none of which collide with our `_`-prefixed
    // keys, so `_raw`/`_source_type`/… are all present in `fields`.
    let ev = json::parse_object(line, "")?;
    let raw = ev.fields.get("_raw")?.clone();
    Some(Envelope {
        raw,
        source: ev
            .fields
            .get("_source_type")
            .or_else(|| ev.fields.get("_source"))
            .cloned(),
        timestamp: ev.fields.get("_timestamp").cloned(),
        hostname: ev.fields.get("_host").cloned(),
        severity: ev.fields.get("_severity").cloned(),
    })
}

/// Map an rsyslog severity-text token (or full word) to our `Severity`.
pub fn severity_from_word(s: &str) -> Option<Severity> {
    match s.trim().to_ascii_lowercase().as_str() {
        "emerg" | "emergency" | "panic" => Some(Severity::Emergency),
        "alert" => Some(Severity::Alert),
        "crit" | "critical" => Some(Severity::Critical),
        "err" | "error" => Some(Severity::Error),
        "warn" | "warning" => Some(Severity::Warning),
        "notice" => Some(Severity::Notice),
        "info" | "informational" => Some(Severity::Informational),
        "debug" => Some(Severity::Debug),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwraps_rsyslog_envelope() {
        let line = br#"{"_source_type":"sshd","_host":"h","_severity":"info","_timestamp":"2026-06-27T08:55:03Z","_raw":"Failed password for root from 10.0.0.5"}"#;
        let e = unwrap(line).unwrap();
        assert_eq!(e.raw, "Failed password for root from 10.0.0.5");
        assert_eq!(e.source.as_deref(), Some("sshd"));
        assert_eq!(e.hostname.as_deref(), Some("h"));
        assert_eq!(e.timestamp.as_deref(), Some("2026-06-27T08:55:03Z"));
        assert_eq!(e.severity.as_deref(), Some("info"));
    }

    #[test]
    fn unwraps_fixture_source_variant() {
        let line = br#"{"_raw":"Jun 22 08:55:03 myhost sshd[1234]: hi","_source":"sshd"}"#;
        let e = unwrap(line).unwrap();
        assert_eq!(e.source.as_deref(), Some("sshd"));
        assert!(e.raw.contains("sshd[1234]"));
    }

    #[test]
    fn plain_json_without_raw_is_not_an_envelope() {
        let line = br#"{"host":"web1","message":"ok","status":"200"}"#;
        assert!(unwrap(line).is_none());
    }

    #[test]
    fn non_json_is_not_an_envelope() {
        assert!(unwrap(b"Jun 22 08:55:03 myhost sshd[1234]: hi").is_none());
    }

    #[test]
    fn severity_word_mapping() {
        assert_eq!(severity_from_word("err"), Some(Severity::Error));
        assert_eq!(severity_from_word("WARNING"), Some(Severity::Warning));
        assert_eq!(severity_from_word("nope"), None);
    }
}

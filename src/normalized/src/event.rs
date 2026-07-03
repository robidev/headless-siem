/// The canonical normalized event produced by every parser, plus the
/// flattening logic that turns it into the flat, downstream-compatible
/// JSON schema consumed by `indexd`, `ruled`, and `siemctl`.
///
/// The parser chain (see `parsers/`) builds an `Event`. The storage and
/// stdout layers call `Event::flatten()` + `serialize_flat()` to emit one
/// JSON object per line with top-level keys (no nested `fields {}`), which
/// is what the rest of the pipeline expects.
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, PartialEq)]
pub enum Format {
    Rfc5424,
    Rfc3164,
    Json,
    JsonArray,
    Cef,
    Leef,
    Logfmt,
    Csv,
    Xml,
    Yaml,
    Filterlog,
    Plain,
}

impl Format {
    pub fn as_str(&self) -> &'static str {
        match self {
            Format::Rfc5424    => "rfc5424",
            Format::Rfc3164    => "rfc3164",
            Format::Json       => "json",
            Format::JsonArray  => "json_array",
            Format::Cef        => "cef",
            Format::Leef       => "leef",
            Format::Logfmt     => "logfmt",
            Format::Csv        => "csv",
            Format::Xml        => "xml",
            Format::Yaml       => "yaml",
            Format::Filterlog  => "filterlog",
            Format::Plain      => "plain",
        }
    }

    /// True for wire formats that are themselves the identity of the
    /// source — their parsers never populate `app_name` at all (there's no
    /// separate "which app wrote this" concept to extract), so falling
    /// back to the format name in [`Event::derive_source`] is correct by
    /// design rather than a loss of information.
    ///
    /// False for syslog-envelope formats that *wrap* an arbitrary
    /// application (rfc3164, rfc5424, cef, leef, logfmt, json, xml, yaml):
    /// for these, a missing `app_name` means the wrapped app's identity
    /// failed to parse, and using the format name would silently merge
    /// events from many unrelated apps into one meaningless bucket (seen
    /// live: a truncated snapd tag producing a literal `rfc3164` source).
    pub fn self_describing(&self) -> bool {
        matches!(self, Format::Filterlog | Format::Csv | Format::Plain)
    }
}

/// Syslog severity (RFC 5424 §6.2.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Informational,
    Debug,
}

impl Severity {
    pub fn from_code(n: u8) -> Self {
        match n & 0x07 {
            0 => Severity::Emergency,
            1 => Severity::Alert,
            2 => Severity::Critical,
            3 => Severity::Error,
            4 => Severity::Warning,
            5 => Severity::Notice,
            6 => Severity::Informational,
            _ => Severity::Debug,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Emergency     => "emergency",
            Severity::Alert         => "alert",
            Severity::Critical      => "critical",
            Severity::Error         => "error",
            Severity::Warning       => "warning",
            Severity::Notice        => "notice",
            Severity::Informational => "informational",
            Severity::Debug         => "debug",
        }
    }
}

/// Syslog facility (RFC 5424 §6.2.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facility(pub u8);

impl Facility {
    pub fn as_str(&self) -> &'static str {
        match self.0 {
            0  => "kern",
            1  => "user",
            2  => "mail",
            3  => "daemon",
            4  => "auth",
            5  => "syslog",
            6  => "lpr",
            7  => "news",
            8  => "uucp",
            9  => "cron",
            10 => "authpriv",
            11 => "ftp",
            16 => "local0",
            17 => "local1",
            18 => "local2",
            19 => "local3",
            20 => "local4",
            21 => "local5",
            22 => "local6",
            23 => "local7",
            _  => "unknown",
        }
    }
}

/// The single normalized event, as produced by a parser.
#[derive(Debug, Clone)]
pub struct Event {
    /// Which parser produced this event.
    pub format: Format,

    /// Source IP / socket address (or "stdin") of the sender.
    pub source_addr: String,

    // ── syslog envelope (populated by RFC5424 / RFC3164 / CEF / LEEF) ──
    pub facility:  Option<Facility>,
    pub severity:  Option<Severity>,
    pub timestamp: Option<String>, // ISO-8601 or original string
    pub hostname:  Option<String>,
    pub app_name:  Option<String>,
    pub proc_id:   Option<String>,
    pub msg_id:    Option<String>,

    // ── message body ──
    pub message: String,

    // ── structured fields (CEF extensions, JSON keys, logfmt pairs, …) ──
    pub fields: HashMap<String, String>,

    /// The unmodified input bytes, for debugging / passthrough.
    pub raw: Vec<u8>,
}

impl Event {
    /// Derive the source label used for both the bucket filename and the
    /// `_source_type` field: explicit override → syslog app_name → hostname
    /// → format name (only for formats whose identity *is* the wire format,
    /// e.g. filterlog; see [`Format::self_describing`]) → `"unknown"`.
    /// `override_source` carries the CLI `--source` value or a matching
    /// override rule's `source` (already resolved by the caller, CLI first).
    /// The result is sanitized for safe use as a path component.
    ///
    /// Known same-daemon case variants (e.g. Debian cron's `CRON` vs the
    /// lowercase convention every other source uses) are folded upstream by
    /// `canonical_app_name` in `main.rs`, before `app_name` ever reaches
    /// here — deliberately an explicit allowlist rather than a blanket
    /// lowercase, so legitimately mixed-case service names (NetworkManager,
    /// PackageKit, ...) aren't cosmetically mangled without cause.
    ///
    /// `app_name` itself is never rewritten here — only the label derived
    /// from it. See `flatten()`, which always includes the raw `app_name`
    /// field unchanged.
    pub fn derive_source(&self, override_source: Option<&str>) -> String {
        let candidate = override_source
            .filter(|s| !s.trim().is_empty())
            .or(self.app_name.as_deref().filter(|s| !s.trim().is_empty()));

        let resolved = match candidate {
            Some(s) => s.trim().to_string(),
            None if self.format.self_describing() => self.format.as_str().to_string(),
            None => self
                .hostname
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        };
        sanitize_source(&resolved)
    }

    /// Flatten this event into the downstream-compatible schema: a sorted
    /// map of top-level keys. `source` is the already-derived source label,
    /// `received_iso` is the wall-clock receive time (RFC 3339).
    ///
    /// Key rules:
    /// - `timestamp` is the event's own timestamp, falling back to the
    ///   receive time so the field is always present (indexd drops lines
    ///   without one).
    /// - `_received` is always the receive time.
    /// - structured `fields` are lifted to the top level; the common SIEM
    ///   synonyms `src`/`dst`/`spt`/`dpt` are canonicalized to
    ///   `src_ip`/`dst_ip`/`src_port`/`dst_port`, with already-canonical
    ///   keys winning.
    /// - envelope keys take precedence over structured fields on collision.
    pub fn flatten(&self, source: &str, received_iso: &str) -> BTreeMap<String, FlatVal> {
        let mut m: BTreeMap<String, FlatVal> = BTreeMap::new();

        // ── structured fields first (lowest precedence) ──
        // Pass 1: canonical/non-synonym keys, so they win over synonyms.
        for (k, v) in &self.fields {
            if synonym_target(k).is_none() {
                m.insert(k.clone(), FlatVal::Str(v.clone()));
            }
        }
        // Pass 2: synonyms only fill a canonical slot that's still empty.
        for (k, v) in &self.fields {
            if let Some(target) = synonym_target(k) {
                m.entry(target.to_string())
                    .or_insert_with(|| FlatVal::Str(v.clone()));
            }
        }

        // ── envelope (higher precedence: overwrite field collisions) ──
        let ts = self
            .timestamp
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| received_iso.to_string());
        m.insert("timestamp".into(), FlatVal::Str(ts));
        m.insert("_received".into(), FlatVal::Str(received_iso.to_string()));
        m.insert("_source_type".into(), FlatVal::Str(source.to_string()));
        m.insert("_format".into(), FlatVal::Str(self.format.as_str().to_string()));
        m.insert("_normalized".into(), FlatVal::Bool(self.format != Format::Plain));
        m.insert("source_addr".into(), FlatVal::Str(self.source_addr.clone()));

        if let Some(v) = &self.hostname {
            m.insert("hostname".into(), FlatVal::Str(v.clone()));
        }
        if let Some(v) = &self.app_name {
            m.insert("app_name".into(), FlatVal::Str(v.clone()));
        }
        if let Some(v) = &self.proc_id {
            m.insert("proc_id".into(), FlatVal::Str(v.clone()));
        }
        if let Some(v) = &self.msg_id {
            m.insert("msg_id".into(), FlatVal::Str(v.clone()));
        }
        if let Some(s) = &self.severity {
            m.insert("severity".into(), FlatVal::Str(s.as_str().to_string()));
        }
        if let Some(f) = &self.facility {
            m.insert("facility".into(), FlatVal::Str(f.as_str().to_string()));
        }
        if !self.message.is_empty() {
            m.insert("message".into(), FlatVal::Str(self.message.clone()));
        }

        // ── raw passthrough (never lose the original line) ──
        let raw = String::from_utf8_lossy(&self.raw).trim().to_string();
        m.insert("_raw".into(), FlatVal::Str(raw));

        m
    }
}

/// A flattened value: either a JSON string or a JSON boolean.
#[derive(Debug, Clone, PartialEq)]
pub enum FlatVal {
    Str(String),
    Bool(bool),
}

/// Serialize a sorted flat map into a single deterministic JSON line.
pub fn serialize_flat(map: &BTreeMap<String, FlatVal>) -> String {
    let mut out = String::with_capacity(256);
    out.push('{');
    let mut first = true;
    for (k, v) in map {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&json_string(k));
        out.push(':');
        match v {
            FlatVal::Str(s) => out.push_str(&json_string(s)),
            FlatVal::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        }
    }
    out.push('}');
    out
}

/// Map common SIEM field synonyms to canonical names; `None` if not a synonym.
fn synonym_target(key: &str) -> Option<&'static str> {
    match key {
        "src" => Some("src_ip"),
        "dst" => Some("dst_ip"),
        "spt" => Some("src_port"),
        "dpt" => Some("dst_port"),
        _ => None,
    }
}

/// Sanitize a source label for safe use as a filesystem path component.
/// Allows `[A-Za-z0-9._-]`; everything else becomes `_`. Leading/trailing
/// runs of the `_` substitution character are then trimmed — a tag wrapped
/// in punctuation (seen live: `(sd-pam)`, or a truncated `gdm-password]`
/// tag missing its opening bracket) would otherwise sanitize to
/// `_sd-pam_`/`gdm-password_`, polluting the source list with a
/// least-effort variant of the same daemon's real name. Pure-dot,
/// pure-underscore, or empty results collapse to `"unknown"`.
fn sanitize_source(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('_');
    if trimmed.is_empty() || trimmed.chars().all(|c| c == '.') {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Minimal hand-rolled JSON string escaper (no serde).
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"'  => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_event() -> Event {
        Event {
            format: Format::Rfc3164,
            source_addr: "10.0.0.9".into(),
            facility: None,
            severity: Some(Severity::Error),
            timestamp: Some("2026-06-27T08:55:03Z".into()),
            hostname: Some("myhost".into()),
            app_name: Some("sshd".into()),
            proc_id: Some("1234".into()),
            msg_id: None,
            message: "Failed password".into(),
            fields: HashMap::new(),
            raw: b"<13>...".to_vec(),
        }
    }

    #[test]
    fn derive_source_prefers_override_then_app_name_then_hostname() {
        let mut ev = base_event();
        assert_eq!(ev.derive_source(None), "sshd"); // app_name
        assert_eq!(ev.derive_source(Some("pfsense")), "pfsense"); // override wins
        ev.app_name = None;
        // rfc3164 is not self-describing (it wraps an arbitrary app), so a
        // missing app_name falls back to hostname, never the format name.
        assert_eq!(ev.derive_source(None), "myhost");
    }

    #[test]
    fn derive_source_falls_back_to_unknown_when_nothing_identifies_the_source() {
        let mut ev = base_event();
        ev.app_name = None;
        ev.hostname = None;
        assert_eq!(ev.derive_source(None), "unknown");
    }

    #[test]
    fn derive_source_uses_format_name_for_self_describing_formats() {
        // filterlog/csv/plain never populate app_name by design — the
        // format name *is* the source identity for these, so the fallback
        // there is correct rather than a "format name leaked in" bug.
        let mut ev = base_event();
        ev.format = Format::Filterlog;
        ev.app_name = None;
        ev.hostname = None;
        assert_eq!(ev.derive_source(None), "filterlog");
    }

    #[test]
    fn derive_source_does_not_leak_format_name_for_wrapper_formats() {
        // The bug this guards: a truncated/unparseable tag in a syslog
        // envelope format used to fall back to the format name itself
        // (e.g. a literal "rfc3164" source polluting the source list).
        for format in [Format::Rfc3164, Format::Rfc5424, Format::Cef, Format::Leef,
                        Format::Logfmt, Format::Json, Format::Xml, Format::Yaml] {
            let mut ev = base_event();
            ev.format = format.clone();
            ev.app_name = None;
            ev.hostname = None;
            assert_eq!(
                ev.derive_source(None),
                "unknown",
                "{:?} must not fall back to its own format name",
                format
            );
        }
    }

    #[test]
    fn derive_source_sanitizes_path_separators() {
        let ev = base_event();
        assert_eq!(ev.derive_source(Some("../etc/passwd")), ".._etc_passwd");
    }

    #[test]
    fn derive_source_trims_punctuation_wrapped_tags() {
        // Seen live: systemd-logind's "(sd-pam)" pseudo-tag sanitizing to
        // "_sd-pam_" (parens -> underscores, then left in place at the
        // edges) instead of the much more legible "sd-pam".
        let mut ev = base_event();
        ev.app_name = Some("(sd-pam)".into());
        assert_eq!(ev.derive_source(None), "sd-pam");
    }

    #[test]
    fn derive_source_trims_stray_trailing_bracket() {
        // Seen live: a truncated tag missing its opening `[`
        // ("gdm-password]: message" instead of "gdm-password[123]: message")
        // sanitizing to "gdm-password_" instead of "gdm-password".
        let mut ev = base_event();
        ev.app_name = Some("gdm-password]".into());
        assert_eq!(ev.derive_source(None), "gdm-password");
    }

    #[test]
    fn flatten_always_has_timestamp_and_falls_back_to_received() {
        let mut ev = base_event();
        ev.timestamp = None;
        let m = ev.flatten("sshd", "2026-06-27T09:00:00+00:00");
        assert_eq!(
            m.get("timestamp"),
            Some(&FlatVal::Str("2026-06-27T09:00:00+00:00".into()))
        );
        assert_eq!(
            m.get("_received"),
            Some(&FlatVal::Str("2026-06-27T09:00:00+00:00".into()))
        );
    }

    #[test]
    fn flatten_canonicalizes_src_dst_and_envelope_wins() {
        let mut ev = base_event();
        ev.fields.insert("src".into(), "1.1.1.1".into());
        ev.fields.insert("dst".into(), "2.2.2.2".into());
        ev.fields.insert("severity".into(), "ignored".into());
        let m = ev.flatten("sshd", "2026-06-27T09:00:00Z");
        assert_eq!(m.get("src_ip"), Some(&FlatVal::Str("1.1.1.1".into())));
        assert_eq!(m.get("dst_ip"), Some(&FlatVal::Str("2.2.2.2".into())));
        // envelope severity (error) overrides a stray "severity" field
        assert_eq!(m.get("severity"), Some(&FlatVal::Str("error".into())));
    }

    #[test]
    fn flatten_prefers_already_canonical_key_over_synonym() {
        let mut ev = base_event();
        ev.fields.insert("src".into(), "synonym".into());
        ev.fields.insert("src_ip".into(), "canonical".into());
        let m = ev.flatten("sshd", "2026-06-27T09:00:00Z");
        assert_eq!(m.get("src_ip"), Some(&FlatVal::Str("canonical".into())));
    }

    #[test]
    fn normalized_flag_false_only_for_plain() {
        let mut ev = base_event();
        let m = ev.flatten("sshd", "now");
        assert_eq!(m.get("_normalized"), Some(&FlatVal::Bool(true)));
        ev.format = Format::Plain;
        let m = ev.flatten("plain", "now");
        assert_eq!(m.get("_normalized"), Some(&FlatVal::Bool(false)));
    }

    #[test]
    fn serialize_flat_is_sorted_and_deterministic() {
        let mut m: BTreeMap<String, FlatVal> = BTreeMap::new();
        m.insert("b".into(), FlatVal::Str("two".into()));
        m.insert("a".into(), FlatVal::Bool(true));
        let s = serialize_flat(&m);
        assert_eq!(s, r#"{"a":true,"b":"two"}"#);
    }
}

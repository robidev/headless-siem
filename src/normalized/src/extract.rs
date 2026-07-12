/// Config-driven field extraction (a flexible, regex-based evolution of the
/// legacy grok/heuristic layer).
///
/// Each `[[extract.rule]]` matches on already-parsed fields (e.g. `app_name`,
/// `hostname`, `source`, or any structured field) and, on a match, applies one
/// or more regexes with named captures to a chosen source field (`message` by
/// default, or `_raw`, or any field). Named captures and `set` values become
/// new fields. Rules run in order; captured fields fill only empty slots (so
/// they never clobber first-pass data), while `set` always wins.
///
/// Fail-open: a regex that fails to compile is logged once at startup and
/// skipped; it never stops the rest from working.
use regex::Regex;

use crate::config::ExtractRuleConfig;
use crate::event::Event;

pub struct ExtractRule {
    conditions: Vec<(String, String)>,
    from: String,
    patterns: Vec<Regex>,
    set: Vec<(String, String)>,
    force_severity: bool,
}

/// Compile config extract rules. Bad patterns are reported and dropped.
pub fn build(cfgs: &[ExtractRuleConfig]) -> Vec<ExtractRule> {
    cfgs.iter()
        .map(|c| {
            let mut patterns = Vec::new();
            for p in &c.patterns {
                match Regex::new(p) {
                    Ok(re) => patterns.push(re),
                    Err(e) => {
                        eprintln!("[normalized] ignoring invalid extract pattern {:?}: {}", p, e)
                    }
                }
            }
            ExtractRule {
                conditions: c.conditions.clone(),
                from: c.from.clone().unwrap_or_else(|| "message".to_string()),
                patterns,
                set: c.set.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                force_severity: c.force_severity,
            }
        })
        .collect()
}

/// Apply all matching rules in order, mutating `event.fields`.
/// `source` is the already-derived source label.
pub fn apply(rules: &[ExtractRule], event: &mut Event, source: &str) {
    for rule in rules {
        let matched = rule.conditions.iter().all(|(field, want)| {
            field_value(event, source, field).as_deref() == Some(want.as_str())
        });
        if !matched {
            continue;
        }

        let haystack = match field_value(event, source, &rule.from) {
            Some(s) => s,
            None => continue,
        };

        for re in &rule.patterns {
            if let Some(caps) = re.captures(&haystack) {
                for name in re.capture_names().flatten() {
                    if let Some(m) = caps.name(name) {
                        event
                            .fields
                            .entry(name.to_string())
                            .or_insert_with(|| m.as_str().to_string());
                    }
                }
            }
        }
        for (k, v) in &rule.set {
            event.fields.insert(k.clone(), v.clone());
        }
        if rule.force_severity {
            event.force_severity = true;
        }
    }
}

/// Resolve a field name to a value: envelope fields, the derived source,
/// `_raw`, `message`, or a structured field.
fn field_value(event: &Event, source: &str, name: &str) -> Option<String> {
    match name {
        "message" => Some(event.message.clone()),
        "_raw" => Some(String::from_utf8_lossy(&event.raw).to_string()),
        "source" | "_source_type" => Some(source.to_string()),
        "app_name" => event.app_name.clone(),
        "hostname" => event.hostname.clone(),
        "source_addr" => Some(event.source_addr.clone()),
        "proc_id" => event.proc_id.clone(),
        "msg_id" => event.msg_id.clone(),
        "severity" => event.severity.as_ref().map(|s| s.as_str().to_string()),
        "timestamp" => event.timestamp.clone(),
        "_format" => Some(event.format.as_str().to_string()),
        other => event.fields.get(other).cloned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExtractRuleConfig;
    use crate::event::Format;
    use std::collections::HashMap;

    fn sshd_event() -> Event {
        Event {
            format: Format::Rfc3164,
            source_addr: "stdin".into(),
            facility: None,
            severity: None,
            timestamp: Some("Jun 22 08:55:03".into()),
            hostname: Some("myhost".into()),
            app_name: Some("sshd".into()),
            proc_id: Some("1234".into()),
            msg_id: None,
            message: "Failed password for root from 10.0.0.5 port 22 ssh2".into(),
            fields: HashMap::new(),
            force_severity: false,
            raw: b"...".to_vec(),
        }
    }

    fn cfg(conditions: &[(&str, &str)], from: &str, patterns: &[&str], set: &[(&str, &str)]) -> ExtractRuleConfig {
        ExtractRuleConfig {
            conditions: conditions.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
            from: Some(from.to_string()),
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
            set: set.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
            force_severity: false,
        }
    }

    #[test]
    fn extracts_named_captures_when_condition_matches() {
        let rules = build(&[cfg(
            &[("app_name", "sshd")],
            "message",
            &[
                r"from (?P<src_ip>[0-9.]+) port (?P<src_port>[0-9]+)",
                r"for (?P<username>\S+) from",
            ],
            &[("event_type", "ssh_auth_fail")],
        )]);
        let mut ev = sshd_event();
        apply(&rules, &mut ev, "sshd");
        assert_eq!(ev.fields.get("src_ip").map(String::as_str), Some("10.0.0.5"));
        assert_eq!(ev.fields.get("src_port").map(String::as_str), Some("22"));
        assert_eq!(ev.fields.get("username").map(String::as_str), Some("root"));
        assert_eq!(ev.fields.get("event_type").map(String::as_str), Some("ssh_auth_fail"));
    }

    #[test]
    fn condition_mismatch_skips_rule() {
        let rules = build(&[cfg(&[("app_name", "nginx")], "message", &[r"(?P<x>\d+)"], &[])]);
        let mut ev = sshd_event();
        apply(&rules, &mut ev, "sshd");
        assert!(ev.fields.is_empty());
    }

    #[test]
    fn capture_does_not_clobber_existing_field_but_set_does() {
        let mut ev = sshd_event();
        ev.fields.insert("src_ip".into(), "1.1.1.1".into());
        ev.fields.insert("event_type".into(), "old".into());
        let rules = build(&[cfg(
            &[],
            "message",
            &[r"from (?P<src_ip>[0-9.]+)"],
            &[("event_type", "new")],
        )]);
        apply(&rules, &mut ev, "sshd");
        assert_eq!(ev.fields.get("src_ip").map(String::as_str), Some("1.1.1.1")); // kept
        assert_eq!(ev.fields.get("event_type").map(String::as_str), Some("new")); // set overwrote
    }

    #[test]
    fn can_match_on_source_and_read_from_raw() {
        let rules = build(&[cfg(&[("source", "sshd")], "_raw", &[r"(?P<host_in_raw>myhost)"], &[])]);
        let mut ev = sshd_event();
        ev.raw = b"Jun 22 myhost sshd: x".to_vec();
        apply(&rules, &mut ev, "sshd");
        assert_eq!(ev.fields.get("host_in_raw").map(String::as_str), Some("myhost"));
    }

    #[test]
    fn invalid_regex_is_skipped_not_fatal() {
        let rules = build(&[cfg(&[], "message", &[r"(?P<bad>", r"port (?P<src_port>\d+)"], &[])]);
        let mut ev = sshd_event();
        apply(&rules, &mut ev, "sshd");
        assert_eq!(ev.fields.get("src_port").map(String::as_str), Some("22"));
    }
}

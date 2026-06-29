//! Lightweight scan of `normalized.toml` to learn which fields `normalized`
//! can emit — used by `siemctl validate`'s cross-check against `sources.toml`.
//!
//! Like `sources.rs`, this hand-scans the file rather than pulling in the
//! `toml`/`regex` crates. **It only sees config-driven extraction**: fields
//! produced by `normalized`'s zero-config format chain (CEF/LEEF/JSON/logfmt/…)
//! are invisible here, so the cross-check treats its findings as advisory.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

/// TOML keys that are part of the rule grammar, not extracted fields. A
/// top-level `key = "..."` whose key is one of these is structural, not a
/// capture used as a match condition.
const RESERVED: &[&str] = &[
    "app_name", "from", "pattern", "set", "contains", "source", "data_dir",
    "udp_port", "tcp_port", "equals", "starts_with", "ends_with", "rename",
    "second_pass", "force_parser",
];

/// What a normalized.toml config can produce.
pub struct Producible {
    /// Output-candidate fields: named captures + `set` keys, minus the internal
    /// discriminator captures (those consumed as a later rule's match condition)
    /// and reserved grammar keys. These are the fields a user would plausibly
    /// want to index/search.
    pub output_fields: HashSet<String>,
    /// Every named capture or `set` key seen, *including* internal discriminators.
    /// Used to decide whether a declared `index_field` is produced at all.
    pub all_fields: HashSet<String>,
}

/// Read and scan a normalized.toml file. Returns `None` if it can't be read.
pub fn load(path: &Path) -> Option<Producible> {
    let content = std::fs::read_to_string(path).ok()?;
    Some(parse(&content))
}

/// Load fields grouped by `app_name` from a normalized.toml file.
/// Returns a sorted map: app_name → sorted set of all fields the source produces
/// (named captures from patterns + keys from `set = { ... }` blocks).
pub fn load_per_source(path: &Path) -> BTreeMap<String, BTreeSet<String>> {
    std::fs::read_to_string(path)
        .ok()
        .map(|c| parse_per_source(&c))
        .unwrap_or_default()
}

/// Parse normalized.toml content into a per-app_name field map.
pub fn parse_per_source(content: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut result: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut current_app: Option<String> = None;

    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        // A new [[...]] block resets the app_name context.
        if line.starts_with("[[") {
            current_app = None;
            continue;
        }
        // app_name = "source" sets the context for the current block.
        if line.starts_with("app_name") {
            if let Some(eq) = line.find('=') {
                let val = line[eq + 1..].trim().trim_matches('"').trim_matches('\'');
                if !val.is_empty() {
                    current_app = Some(val.to_string());
                }
            }
            continue;
        }
        let Some(ref app) = current_app else { continue };
        // Named regex captures: (?P<name>...)
        let mut rest = line;
        while let Some(i) = rest.find("(?P<") {
            rest = &rest[i + 4..];
            if let Some(j) = rest.find('>') {
                let name = &rest[..j];
                if is_ident(name) && !RESERVED.contains(&name) {
                    result.entry(app.clone()).or_default().insert(name.to_string());
                }
                rest = &rest[j + 1..];
            } else {
                break;
            }
        }
        // set = { key = "value", ... }
        if let Some(open) = line.find('{') {
            if line[..open].contains("set") {
                let close = line.rfind('}').unwrap_or(line.len());
                let inner = &line[open + 1..close];
                for part in inner.split(',') {
                    if let Some(k) = part.split('=').next() {
                        let k = k.trim();
                        if is_ident(k) && !RESERVED.contains(&k) {
                            result.entry(app.clone()).or_default().insert(k.to_string());
                        }
                    }
                }
            }
        }
    }
    result
}

/// Locate `config/normalized.toml` relative to cwd or the running binary.
pub fn find_normalized_toml() -> Option<PathBuf> {
    for rel in &["config/normalized.toml", "../config/normalized.toml"] {
        let p = Path::new(rel);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?;
    for _ in 0..6 {
        let c = dir.join("config").join("normalized.toml");
        if c.is_file() {
            return Some(c);
        }
        dir = dir.parent()?;
    }
    None
}

/// Scan normalized.toml content. Split out from [`load`] for unit testing.
pub fn parse(content: &str) -> Producible {
    let mut captures: HashSet<String> = HashSet::new();
    let mut set_keys: HashSet<String> = HashSet::new();
    // Capture names that are later used as a rule match condition (e.g.
    // `auth_action = "Failed"`) — internal pass-2 discriminators, not output.
    let mut condition_keys: HashSet<String> = HashSet::new();

    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        // 1. Named captures: every `(?P<name>` on the line (patterns may have many).
        let mut rest = line;
        while let Some(i) = rest.find("(?P<") {
            rest = &rest[i + 4..];
            if let Some(j) = rest.find('>') {
                let name = &rest[..j];
                if is_ident(name) {
                    captures.insert(name.to_string());
                }
                rest = &rest[j + 1..];
            } else {
                break;
            }
        }

        // 2. `set = { k = "v", ... }` → collect the assigned field names.
        //    3. otherwise a top-level `key = "..."` is a match condition.
        if let Some(open) = line.find('{') {
            if line[..open].contains("set") {
                let inner = &line[open + 1..];
                let inner = inner.split('}').next().unwrap_or(inner);
                for part in inner.split(',') {
                    if let Some(k) = part.split('=').next() {
                        let k = k.trim();
                        if is_ident(k) {
                            set_keys.insert(k.to_string());
                        }
                    }
                }
            }
        } else if let Some(eq) = line.find('=') {
            let key = line[..eq].trim();
            let val = line[eq + 1..].trim_start();
            // A field condition is `ident = "string"` and not a grammar key.
            if is_ident(key) && !RESERVED.contains(&key) && val.starts_with('"') {
                condition_keys.insert(key.to_string());
            }
        }
    }

    // All produced names (condition keys were captured in pass 1, so they are
    // already in `captures`).
    let all_fields: HashSet<String> = captures.union(&set_keys).cloned().collect();

    // Output candidates = everything produced, minus internal discriminators
    // and any reserved grammar key that slipped through.
    let output_fields: HashSet<String> = all_fields
        .iter()
        .filter(|f| !condition_keys.contains(*f) && !RESERVED.contains(&f.as_str()))
        .cloned()
        .collect();

    Producible { output_fields, all_fields }
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[listen]
udp_port = 514

[storage]
data_dir = "data"

[[overrides.rule]]
contains = "[UFW "
source = "iptables"

[[extract.rule]]
app_name = "sshd"
from = "message"
pattern = "^(?P<auth_action>Failed|Accepted) (?P<auth_method>\w+) for (?P<username>\S+) from (?P<src_ip>[\d.]+) port (?P<src_port>\d+)"
pattern = "(?P<sshd_event>Connection reset) by (?P<src_ip>[\d.]+)"

[[extract.rule]]
app_name = "sshd"
auth_action = "Failed"
set = { event_type = "ssh_auth_failure", severity = "high" }

[[extract.rule]]
app_name = "sshd"
sshd_event = "Connection reset"
set = { event_type = "ssh_conn_reset" }
"#;

    #[test]
    fn captures_and_set_keys_are_collected() {
        let p = parse(SAMPLE);
        // Every capture + set key shows up in all_fields.
        for f in ["auth_action", "auth_method", "username", "src_ip", "src_port",
                  "sshd_event", "event_type", "severity"] {
            assert!(p.all_fields.contains(f), "all_fields missing {f}");
        }
    }

    #[test]
    fn discriminators_excluded_from_output_fields() {
        let p = parse(SAMPLE);
        // auth_action and sshd_event are used as match conditions → internal.
        assert!(!p.output_fields.contains("auth_action"), "auth_action leaked");
        assert!(!p.output_fields.contains("sshd_event"), "sshd_event leaked");
        // Real output fields remain.
        for f in ["auth_method", "username", "src_ip", "src_port", "event_type", "severity"] {
            assert!(p.output_fields.contains(f), "output_fields missing {f}");
        }
    }

    #[test]
    fn reserved_grammar_keys_are_not_fields() {
        let p = parse(SAMPLE);
        for k in ["app_name", "from", "pattern", "source", "contains", "data_dir", "udp_port"] {
            assert!(!p.all_fields.contains(k), "{k} wrongly treated as a field");
            assert!(!p.output_fields.contains(k), "{k} wrongly an output field");
        }
    }

    #[test]
    fn empty_config_produces_nothing() {
        let p = parse("");
        assert!(p.all_fields.is_empty());
        assert!(p.output_fields.is_empty());
    }
}

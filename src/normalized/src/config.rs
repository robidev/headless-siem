/// Configuration for `normalized`.
///
/// The config file is a minimal hand-parsed TOML subset (zero extra deps).
/// Everything is optional — with no config file the defaults are used
/// (UDP+TCP :514, buckets under ./data).
///
/// Example `normalized.conf`:
///
/// ```toml
/// [listen]
/// bind     = "0.0.0.0"
/// udp_port = 514
/// tcp_port = 514
///
/// [storage]
/// data_dir = "/var/log/siem"   # CLI --data-dir overrides this
///
/// # Override rules are checked in order; first match wins. All present
/// # conditions are ANDed. A matched rule may force a parser format, assign
/// # an explicit source label, and/or rename fields.
/// [[overrides.rule]]
/// source_ip = "192.168.10.1"   # match if sender IP starts with this
/// contains  = "filterlog"      # match if the raw line contains this
/// source    = "pfsense"        # assign this source label (bucket + _source_type)
/// format    = "csv"            # force this parser instead of auto-detection
/// remap     = { src = "src_ip", dst = "dst_ip" }   # rename fields after parsing
/// ```
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ListenConfig {
    pub bind: String,
    pub udp_port: u16,
    pub tcp_port: u16,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".to_owned(),
            udp_port: 514,
            tcp_port: 514,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct StorageConfig {
    /// Bucket root directory. `None` → use the CLI default (./data).
    pub data_dir: Option<String>,
}

/// A single override rule. All present conditions must match.
#[derive(Debug, Clone, Default)]
pub struct OverrideRule {
    /// Match if the sender address starts with this prefix.
    pub source_ip: Option<String>,
    /// Match if the raw message starts with this string.
    pub starts_with: Option<String>,
    /// Match if the raw message contains this substring.
    pub contains: Option<String>,
    /// On match, force detection to this parser format name.
    pub force_format: Option<String>,
    /// On match, assign this explicit source label.
    pub source: Option<String>,
    /// On match, rename parsed fields: old_key → new_key.
    pub remap: HashMap<String, String>,
    /// On match, re-parse the message body (second pass).
    pub reparse: bool,
    /// Force the second pass to use this format (else auto-detect by prefix).
    pub reparse_as: Option<String>,
}

/// A config-driven extraction rule: match on already-parsed fields, then apply
/// regex(es) with named captures to a source field to add new fields.
#[derive(Debug, Clone, Default)]
pub struct ExtractRuleConfig {
    /// Conditions (field == value), all of which must match. Matched against
    /// parsed envelope fields, structured fields, and `source`/`_source_type`.
    pub conditions: Vec<(String, String)>,
    /// Field to run the regex(es) against: "message" (default), "_raw", or any
    /// parsed field name.
    pub from: Option<String>,
    /// One or more regexes with named captures `(?P<name>…)` → new fields.
    pub patterns: Vec<String>,
    /// Static fields to set when the rule matches.
    pub set: HashMap<String, String>,
    /// Opt-in: let this rule's `set.severity` win over the envelope-derived
    /// severity at flatten time, instead of being silently clobbered.
    pub force_severity: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub listen: ListenConfig,
    pub storage: StorageConfig,
    pub rules: Vec<OverrideRule>,
    pub extract: Vec<ExtractRuleConfig>,
    /// True if a `[listen]` section was explicitly present in the parsed input.
    listen_set: bool,
}

impl Config {
    pub fn from_file(path: &str) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::parse(&content))
    }

    /// Load and merge all `*.toml` files from a directory, sorted by filename.
    ///
    /// Files are processed in ascending filename order so users can control
    /// rule precedence with numeric prefixes (`10-sshd.toml`, `20-sudo.toml`).
    /// Extraction rules are order-sensitive — a source's pass-1 patterns and
    /// pass-2 `set` rules must be in the same file to preserve relative order.
    ///
    /// `listen` and `storage` use last-wins: the last file that sets them wins.
    /// `rules` and `extract` are concatenated in filename order.
    pub fn from_dir(dir: &str) -> std::io::Result<Self> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .flatten()
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .map(|x| x == "toml")
                    .unwrap_or(false)
            })
            .collect();

        entries.sort_by_key(|e| e.file_name());

        let mut merged = Config::default();
        for entry in entries {
            let path = entry.path();
            let content = std::fs::read_to_string(&path)?;
            let file_cfg = Self::parse(&content);
            merged.merge(file_cfg);
        }
        Ok(merged)
    }

    /// Merge `other` into `self`.
    ///
    /// - `rules` and `extract`: appended in order (other comes after self).
    /// - `listen`: other wins only if a `[listen]` section was present (last-wins).
    /// - `storage.data_dir`: other wins if it sets a value (last-wins).
    pub fn merge(&mut self, other: Config) {
        // Append override and extraction rules
        self.rules.extend(other.rules);
        self.extract.extend(other.extract);

        // listen: last-wins only when the other file had a [listen] section
        if other.listen_set {
            self.listen = other.listen;
            self.listen_set = true;
        }

        // storage.data_dir: last-wins if set
        if other.storage.data_dir.is_some() {
            self.storage.data_dir = other.storage.data_dir;
        }
    }

    pub fn parse(s: &str) -> Self {
        let mut cfg = Config::default();
        let mut section = String::new();
        let mut override_rule: Option<OverrideRule> = None;
        let mut extract_rule: Option<ExtractRuleConfig> = None;
        let mut in_remap = false;

        // Flush a pending rule into the config.
        macro_rules! flush {
            ($cfg:expr, $ov:expr, $ex:expr) => {{
                if let Some(r) = $ov.take() {
                    $cfg.rules.push(r);
                }
                if let Some(r) = $ex.take() {
                    $cfg.extract.push(r);
                }
            }};
        }

        for raw_line in s.lines() {
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            // Section header
            if line.starts_with('[') {
                flush!(cfg, override_rule, extract_rule);
                in_remap = false;
                section = line.trim_matches(|c| c == '[' || c == ']').to_owned();
                match section.as_str() {
                    "overrides.rule" => override_rule = Some(OverrideRule::default()),
                    "extract.rule" => extract_rule = Some(ExtractRuleConfig::default()),
                    "listen" => cfg.listen_set = true,
                    _ => {}
                }
                continue;
            }

            // key = value (split on the first '='; value un-quoted at the ends)
            let (k, v) = match line.find('=') {
                Some(eq) => (line[..eq].trim(), line[eq + 1..].trim().trim_matches('"')),
                None => continue,
            };

            match section.as_str() {
                "listen" => match k {
                    "bind" => cfg.listen.bind = v.to_owned(),
                    "udp_port" => cfg.listen.udp_port = v.parse().unwrap_or(514),
                    "tcp_port" => cfg.listen.tcp_port = v.parse().unwrap_or(514),
                    _ => {}
                },
                "storage" => {
                    if k == "data_dir" {
                        cfg.storage.data_dir = Some(v.to_owned());
                    }
                }
                "overrides.rule" => {
                    if let Some(rule) = override_rule.as_mut() {
                        if k == "remap" {
                            in_remap = true;
                            parse_inline_map(v, &mut rule.remap);
                        } else if in_remap {
                            rule.remap.insert(k.to_owned(), v.to_owned());
                        } else {
                            match k {
                                "source_ip" => rule.source_ip = Some(v.to_owned()),
                                "starts_with" => rule.starts_with = Some(v.to_owned()),
                                "contains" => rule.contains = Some(v.to_owned()),
                                "format" => rule.force_format = Some(v.to_owned()),
                                "source" => rule.source = Some(v.to_owned()),
                                "reparse" => rule.reparse = v == "true",
                                "reparse_as" => rule.reparse_as = Some(v.to_owned()),
                                _ => {}
                            }
                        }
                    }
                }
                "extract.rule" => {
                    if let Some(rule) = extract_rule.as_mut() {
                        match k {
                            // Reserved keys; everything else is a condition.
                            "from" => rule.from = Some(v.to_owned()),
                            "pattern" => rule.patterns.push(v.to_owned()),
                            "set" => parse_inline_map(v, &mut rule.set),
                            "force_severity" => rule.force_severity = v == "true",
                            _ => rule.conditions.push((k.to_owned(), v.to_owned())),
                        }
                    }
                }
                _ => {}
            }
        }

        flush!(cfg, override_rule, extract_rule);
        cfg
    }
}

/// Parse an inline-table value like `{ src = "src_ip", dst = "dst_ip" }`.
fn parse_inline_map(v: &str, map: &mut HashMap<String, String>) {
    let inner = v
        .trim()
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or("");
    for pair in inner.split(',') {
        if let Some(eq) = pair.find('=') {
            let k = pair[..eq].trim().trim_matches('"');
            let val = pair[eq + 1..].trim().trim_matches('"');
            if !k.is_empty() && !val.is_empty() {
                map.insert(k.to_owned(), val.to_owned());
            }
        }
    }
}

/// Strip a `#` comment, but ignore `#` inside double-quoted values so regex
/// patterns and other values may contain `#`.
fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    for (i, b) in line.bytes().enumerate() {
        match b {
            b'"' => in_quotes = !in_quotes,
            b'#' if !in_quotes => return &line[..i],
            _ => {}
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listen_and_storage() {
        let cfg = Config::parse(
            r#"
[listen]
bind = "127.0.0.1"
udp_port = 1514
tcp_port = 1515

[storage]
data_dir = "/var/log/siem"
"#,
        );
        assert_eq!(cfg.listen.bind, "127.0.0.1");
        assert_eq!(cfg.listen.udp_port, 1514);
        assert_eq!(cfg.listen.tcp_port, 1515);
        assert_eq!(cfg.storage.data_dir.as_deref(), Some("/var/log/siem"));
    }

    #[test]
    fn parses_override_rule_with_source_and_format() {
        let cfg = Config::parse(
            r#"
[[overrides.rule]]
source_ip = "192.168.10.1"
contains = "filterlog"
source = "pfsense"
format = "csv"
"#,
        );
        assert_eq!(cfg.rules.len(), 1);
        let r = &cfg.rules[0];
        assert_eq!(r.source_ip.as_deref(), Some("192.168.10.1"));
        assert_eq!(r.contains.as_deref(), Some("filterlog"));
        assert_eq!(r.source.as_deref(), Some("pfsense"));
        assert_eq!(r.force_format.as_deref(), Some("csv"));
    }

    #[test]
    fn parses_inline_remap() {
        let cfg = Config::parse(
            r#"
[[overrides.rule]]
contains = "x"
remap = { src = "src_ip", dst = "dst_ip" }
"#,
        );
        let r = &cfg.rules[0];
        assert_eq!(r.remap.get("src").map(String::as_str), Some("src_ip"));
        assert_eq!(r.remap.get("dst").map(String::as_str), Some("dst_ip"));
    }

    #[test]
    fn parses_multiline_remap() {
        let cfg = Config::parse(
            r#"
[[overrides.rule]]
contains = "x"
remap =
src = "src_ip"
dst = "dst_ip"
"#,
        );
        let r = &cfg.rules[0];
        assert_eq!(r.remap.get("src").map(String::as_str), Some("src_ip"));
        assert_eq!(r.remap.get("dst").map(String::as_str), Some("dst_ip"));
    }

    #[test]
    fn multiple_rules_flushed() {
        let cfg = Config::parse(
            r#"
[[overrides.rule]]
source_ip = "10.0.0.1"

[[overrides.rule]]
source_ip = "10.0.0.2"
"#,
        );
        assert_eq!(cfg.rules.len(), 2);
    }

    #[test]
    fn parses_reparse_flags() {
        let cfg = Config::parse(
            r#"
[[overrides.rule]]
contains = "CEF:"
reparse = true
reparse_as = "cef"
"#,
        );
        let r = &cfg.rules[0];
        assert!(r.reparse);
        assert_eq!(r.reparse_as.as_deref(), Some("cef"));
    }

    #[test]
    fn parses_extract_rule_with_conditions_and_patterns() {
        let cfg = Config::parse(
            r#"
[[extract.rule]]
app_name = "sshd"
from = "message"
pattern = "from (?P<src_ip>[0-9.]+) port (?P<src_port>[0-9]+)"
pattern = "for (?P<username>[^ ]+)"
set = { event_type = "ssh_auth" }
"#,
        );
        assert_eq!(cfg.extract.len(), 1);
        let e = &cfg.extract[0];
        assert_eq!(e.conditions, vec![("app_name".to_string(), "sshd".to_string())]);
        assert_eq!(e.from.as_deref(), Some("message"));
        assert_eq!(e.patterns.len(), 2);
        assert!(e.patterns[0].contains("(?P<src_ip>"));
        assert_eq!(e.set.get("event_type").map(String::as_str), Some("ssh_auth"));
    }

    #[test]
    fn comment_stripping_preserves_hash_in_quotes() {
        let cfg = Config::parse(
            r#"
[[extract.rule]]
from = "message"
pattern = "id=(?P<id>[A-Z0-9#]+)"   # trailing comment removed
"#,
        );
        assert_eq!(cfg.extract[0].patterns[0], "id=(?P<id>[A-Z0-9#]+)");
    }

    // ── merge() tests ─────────────────────────────────────────────────────

    #[test]
    fn merge_concatenates_rules_and_extract() {
        let mut base = Config::parse(
            r#"
[[overrides.rule]]
contains = "foo"
source = "a"

[[extract.rule]]
app_name = "sshd"
pattern = "from (?P<src_ip>[0-9.]+)"
"#,
        );
        let other = Config::parse(
            r#"
[[overrides.rule]]
contains = "bar"
source = "b"

[[extract.rule]]
app_name = "sudo"
pattern = "COMMAND=(?P<command>.+)"
"#,
        );
        base.merge(other);
        assert_eq!(base.rules.len(), 2);
        assert_eq!(base.rules[0].source.as_deref(), Some("a"));
        assert_eq!(base.rules[1].source.as_deref(), Some("b"));
        assert_eq!(base.extract.len(), 2);
        assert_eq!(base.extract[0].conditions[0].0, "app_name");
        assert_eq!(base.extract[0].conditions[0].1, "sshd");
        assert_eq!(base.extract[1].conditions[0].1, "sudo");
    }

    #[test]
    fn merge_listen_last_wins() {
        let mut base = Config::parse(
            r#"
[listen]
bind = "127.0.0.1"
udp_port = 1514
"#,
        );
        let other = Config::parse(
            r#"
[listen]
bind = "0.0.0.0"
udp_port = 5140
"#,
        );
        base.merge(other);
        assert_eq!(base.listen.bind, "0.0.0.0");
        assert_eq!(base.listen.udp_port, 5140);
    }

    #[test]
    fn merge_storage_last_wins() {
        let mut base = Config::parse(
            r#"
[storage]
data_dir = "/first"
"#,
        );
        let other = Config::parse(
            r#"
[storage]
data_dir = "/second"
"#,
        );
        base.merge(other);
        assert_eq!(base.storage.data_dir.as_deref(), Some("/second"));
    }

    #[test]
    fn merge_storage_unchanged_when_other_unset() {
        let mut base = Config::parse(
            r#"
[storage]
data_dir = "/first"
"#,
        );
        // other has no [storage] block
        let other = Config::parse("[[overrides.rule]]\ncontains = \"x\"\n");
        base.merge(other);
        assert_eq!(base.storage.data_dir.as_deref(), Some("/first"));
    }

    // ── from_dir() tests ──────────────────────────────────────────────────

    #[test]
    fn from_dir_empty_dir_gives_defaults() {
        let tmp = std::env::temp_dir().join(format!(
            "hsiem_cfg_test_empty_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let cfg = Config::from_dir(tmp.to_str().unwrap()).unwrap();
        assert_eq!(cfg.rules.len(), 0);
        assert_eq!(cfg.extract.len(), 0);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn from_dir_loads_sorted_and_merges() {
        let tmp = std::env::temp_dir().join(format!(
            "hsiem_cfg_test_dir_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        // Write two files — 20- should come after 10- in sort order
        std::fs::write(
            tmp.join("20-sudo.toml"),
            "[[extract.rule]]\napp_name = \"sudo\"\npattern = \"COMMAND=(?P<command>.+)\"\n",
        ).unwrap();
        std::fs::write(
            tmp.join("10-sshd.toml"),
            "[[extract.rule]]\napp_name = \"sshd\"\npattern = \"from (?P<src_ip>[0-9.]+)\"\n",
        ).unwrap();

        let cfg = Config::from_dir(tmp.to_str().unwrap()).unwrap();
        // 10-sshd must come first despite being written second
        assert_eq!(cfg.extract.len(), 2);
        assert_eq!(cfg.extract[0].conditions[0].1, "sshd");
        assert_eq!(cfg.extract[1].conditions[0].1, "sudo");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn from_dir_ignores_non_toml_files() {
        let tmp = std::env::temp_dir().join(format!(
            "hsiem_cfg_test_nontoml_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        std::fs::write(tmp.join("README.md"), "# docs").unwrap();
        std::fs::write(tmp.join("notes.txt"), "notes").unwrap();
        std::fs::write(
            tmp.join("10-sshd.toml"),
            "[[extract.rule]]\napp_name = \"sshd\"\npattern = \"x\"\n",
        ).unwrap();

        let cfg = Config::from_dir(tmp.to_str().unwrap()).unwrap();
        assert_eq!(cfg.extract.len(), 1);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn from_dir_missing_dir_is_error() {
        let result = Config::from_dir("/nonexistent/config/dir");
        assert!(result.is_err());
    }
}

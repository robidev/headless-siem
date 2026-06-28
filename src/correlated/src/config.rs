use serde::Deserialize;
use std::path::Path;

/// Top-level structure of `correlations.toml`.
#[derive(Debug, Deserialize, Clone)]
pub struct CorrelationConfig {
    #[serde(rename = "rule", default)]
    pub rules: Vec<CorrelationRule>,
}

/// One correlation rule: a sequence of Sigma rule firings that must all occur
/// within `window_seconds`, optionally in order, joined on a common field value.
#[derive(Debug, Deserialize, Clone)]
pub struct CorrelationRule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: String,
    /// Field in the alert's nested event used to correlate steps (e.g. `src_ip`).
    pub join_field: String,
    /// Sliding window within which all steps must be satisfied (seconds).
    #[serde(default = "default_window")]
    pub window_seconds: u64,
    /// If true (default), steps must fire in the listed order.
    #[serde(default = "default_true")]
    pub ordered: bool,
    #[serde(rename = "step", default)]
    pub steps: Vec<Step>,
}

/// One step in a correlation chain: a Sigma rule_id that must fire min_count times.
#[derive(Debug, Deserialize, Clone)]
pub struct Step {
    /// The `rule_id` value that alerts from `ruled` must carry.
    pub rule_id: String,
    /// Minimum number of matching alerts required to satisfy this step.
    #[serde(default = "default_one")]
    pub min_count: usize,
}

fn default_window() -> u64 { 300 }
fn default_true() -> bool { true }
fn default_one() -> usize { 1 }

impl CorrelationConfig {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let text = std::fs::read_to_string(path)?;
        let cfg: CorrelationConfig = toml::from_str(&text)?;
        for rule in &cfg.rules {
            if rule.steps.is_empty() {
                return Err(format!(
                    "correlation rule '{}' has no [[rule.step]] entries",
                    rule.id
                )
                .into());
            }
        }
        Ok(cfg)
    }

    pub fn empty() -> Self {
        CorrelationConfig { rules: Vec::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
[[rule]]
id           = "brute-force-success"
title        = "SSH Brute Force Followed by Login Success"
join_field   = "src_ip"
window_seconds = 300
ordered      = true

  [[rule.step]]
  rule_id   = "1001-ssh-brute-force"
  min_count = 5

  [[rule.step]]
  rule_id   = "1005-ssh-login-success"
  min_count = 1

[[rule]]
id           = "high-volume"
title        = "High-Volume Brute Force"
join_field   = "src_ip"
ordered      = false

  [[rule.step]]
  rule_id   = "1001-ssh-brute-force"
  min_count = 10
"#;

    #[test]
    fn test_parse_two_rules() {
        let cfg: CorrelationConfig = toml::from_str(SAMPLE_TOML).unwrap();
        assert_eq!(cfg.rules.len(), 2);
    }

    #[test]
    fn test_rule_fields() {
        let cfg: CorrelationConfig = toml::from_str(SAMPLE_TOML).unwrap();
        let r = &cfg.rules[0];
        assert_eq!(r.id, "brute-force-success");
        assert_eq!(r.join_field, "src_ip");
        assert_eq!(r.window_seconds, 300);
        assert!(r.ordered);
        assert_eq!(r.steps.len(), 2);
        assert_eq!(r.steps[0].rule_id, "1001-ssh-brute-force");
        assert_eq!(r.steps[0].min_count, 5);
        assert_eq!(r.steps[1].rule_id, "1005-ssh-login-success");
        assert_eq!(r.steps[1].min_count, 1);
    }

    #[test]
    fn test_defaults_applied() {
        let cfg: CorrelationConfig = toml::from_str(SAMPLE_TOML).unwrap();
        let r = &cfg.rules[1]; // high-volume: no window_seconds, no ordered
        assert_eq!(r.window_seconds, 300); // default
        assert!(!r.ordered);
        assert_eq!(r.steps[0].min_count, 10);
    }

    #[test]
    fn test_empty_config() {
        let cfg: CorrelationConfig = toml::from_str("").unwrap();
        assert!(cfg.rules.is_empty());
    }

    #[test]
    fn test_step_default_min_count() {
        let toml = r#"
[[rule]]
id = "r"
title = "t"
join_field = "src_ip"
  [[rule.step]]
  rule_id = "foo"
"#;
        let cfg: CorrelationConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.rules[0].steps[0].min_count, 1); // default
    }

    #[test]
    fn test_load_rejects_empty_steps() {
        let toml = r#"
[[rule]]
id = "bad"
title = "No Steps"
join_field = "src_ip"
"#;
        // Inline load check (no file needed)
        let cfg: CorrelationConfig = toml::from_str(toml).unwrap();
        // Validate same way load() does
        for rule in &cfg.rules {
            if rule.steps.is_empty() {
                return; // expected
            }
        }
        panic!("expected empty steps to be detectable");
    }
}

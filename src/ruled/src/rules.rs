use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

// ── Sigma Rule Structure ────────────────────────────────────────────

/// A fully parsed Sigma rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub level: String,
    pub status: String,
    pub tags: Vec<String>,
    pub logsource: LogSource,
    pub detection: Detection,
}

impl Rule {
    /// Check if this rule matches an event.
    ///
    /// Evaluates the detection condition against the event's JSON fields.
    /// Keyword-based detection searches the raw JSON string representation.
    pub fn matches(&self, event: &serde_json::Value) -> bool {
        // Optional logsource filtering
        if !self.logsource_matches(event) {
            return false;
        }

        // Evaluate the condition tree
        self.eval_condition(&self.detection.condition, event)
    }

    /// Check if the event's source matches this rule's logsource.
    fn logsource_matches(&self, event: &serde_json::Value) -> bool {
        let ls = &self.logsource;
        if ls.product.is_none() && ls.service.is_none() && ls.category.is_none() {
            return true; // no logsource filter
        }

        let source = event
            .get("_source_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Match service: source type should contain the service name
        if let Some(ref service) = ls.service {
            if !source.contains(service.as_str()) {
                return false;
            }
        }
        // Match product: source type should contain the product name
        if let Some(ref product) = ls.product {
            if !source.contains(product.as_str()) {
                return false;
            }
        }
        // Match category: source type should contain the category name
        if let Some(ref category) = ls.category {
            if !source.contains(category.as_str()) {
                return false;
            }
        }
        true
    }

    /// Evaluate a condition AST node against an event.
    fn eval_condition(&self, cond: &Condition, event: &serde_json::Value) -> bool {
        match cond {
            Condition::Ref(name) => {
                if name == "keywords" {
                    self.eval_keywords(event)
                } else if let Some(sel) = self.detection.selections.get(name) {
                    self.eval_selection(sel, event)
                } else {
                    false
                }
            }
            Condition::And(left, right) => {
                self.eval_condition(left, event) && self.eval_condition(right, event)
            }
            Condition::Or(left, right) => {
                self.eval_condition(left, event) || self.eval_condition(right, event)
            }
            Condition::Not(inner) => !self.eval_condition(inner, event),
            Condition::OneOfThem => {
                // Any named selection matches
                self.detection
                    .selections
                    .values()
                    .any(|sel| self.eval_selection(sel, event))
            }
            Condition::OneOfPattern(pattern) => {
                // Match selections whose names match the glob pattern
                self.detection
                    .selections
                    .iter()
                    .filter(|(name, _)| glob_match(pattern, name))
                    .any(|(_, sel)| self.eval_selection(sel, event))
            }
        }
    }

    /// Evaluate a selection (all field matches must succeed).
    fn eval_selection(&self, sel: &Selection, event: &serde_json::Value) -> bool {
        sel.fields
            .iter()
            .all(|fm| self.eval_field_match(fm, event))
    }

    /// Evaluate a single field match against an event.
    fn eval_field_match(&self, fm: &FieldMatch, event: &serde_json::Value) -> bool {
        match fm {
            FieldMatch::Equals { field, value } => {
                let event_val = event.get(field);
                match event_val {
                    Some(serde_json::Value::String(s)) => s == value,
                    Some(serde_json::Value::Number(n)) => n.to_string() == *value,
                    Some(serde_json::Value::Bool(b)) => b.to_string() == *value,
                    _ => false,
                }
            }
            FieldMatch::Contains { field, value } => {
                let event_val = event.get(field).and_then(|v| v.as_str());
                match event_val {
                    Some(s) => s.to_lowercase().contains(&value.to_lowercase()),
                    None => false,
                }
            }
            FieldMatch::StartsWith { field, value } => {
                let event_val = event.get(field).and_then(|v| v.as_str());
                match event_val {
                    Some(s) => s.starts_with(value.as_str()),
                    None => false,
                }
            }
            FieldMatch::EndsWith { field, value } => {
                let event_val = event.get(field).and_then(|v| v.as_str());
                match event_val {
                    Some(s) => s.ends_with(value.as_str()),
                    None => false,
                }
            }
        }
    }

    /// Check if any keyword matches the raw event text.
    fn eval_keywords(&self, event: &serde_json::Value) -> bool {
        let raw = serde_json::to_string(event).unwrap_or_default().to_lowercase();
        self.detection
            .keywords
            .iter()
            .any(|kw| raw.contains(&kw.to_lowercase()))
    }
}

/// Simple glob matching for selection names.
/// Supports * as wildcard (matches any sequence of characters).
fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == name;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let mut remaining = name;

    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // First part: must match at start
            if !remaining.starts_with(part) {
                return false;
            }
            remaining = &remaining[part.len()..];
        } else if i == parts.len() - 1 && !pattern.ends_with('*') {
            // Last part with no trailing *: must match at end
            if !remaining.ends_with(part) {
                return false;
            }
        } else {
            // Middle part: find and skip
            if let Some(pos) = remaining.find(part) {
                remaining = &remaining[pos + part.len()..];
            } else {
                return false;
            }
        }
    }
    true
}

/// Log source specification.
#[derive(Debug, Clone, Default)]
pub struct LogSource {
    pub product: Option<String>,
    pub service: Option<String>,
    pub category: Option<String>,
}

/// Parsed detection section.
#[derive(Debug, Clone)]
pub struct Detection {
    /// Named selections: "selection" → field-value pairs, "filter" → field-value pairs
    pub selections: BTreeMap<String, Selection>,
    /// Keyword-based detection: list of strings to search for in raw event
    pub keywords: Vec<String>,
    /// Parsed condition expression
    pub condition: Condition,
}

/// A single selection: a set of field-value pairs that must all match.
#[derive(Debug, Clone)]
pub struct Selection {
    pub fields: Vec<FieldMatch>,
}

/// A single field match within a selection.
#[derive(Debug, Clone)]
pub enum FieldMatch {
    /// Exact match: field == value
    Equals { field: String, value: String },
    /// Contains match: field contains value (case-insensitive)
    Contains { field: String, value: String },
    /// Starts-with match
    StartsWith { field: String, value: String },
    /// Ends-with match
    EndsWith { field: String, value: String },
}

/// Parsed condition expression.
#[derive(Debug, Clone)]
pub enum Condition {
    /// Reference to a named selection or "keywords"
    Ref(String),
    /// AND of two conditions
    And(Box<Condition>, Box<Condition>),
    /// OR of two conditions
    Or(Box<Condition>, Box<Condition>),
    /// NOT of a condition
    Not(Box<Condition>),
    /// 1 of them (any selection matches)
    OneOfThem,
    /// 1 of pattern (any selection matching glob)
    OneOfPattern(String),
}

// ── YAML Deserialization (intermediate) ─────────────────────────────

/// Raw YAML rule as deserialized from file.
#[derive(Debug, Deserialize)]
struct RawRule {
    id: Option<String>,
    title: Option<String>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    level: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    logsource: serde_yaml::Value,
    #[serde(default)]
    detection: serde_yaml::Value,
}

// ── Rule Loading ────────────────────────────────────────────────────

/// A collection of loaded rules.
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

/// Load all Sigma YAML rules from a directory (recursive).
pub fn load_rules(rules_path: &Path) -> Result<RuleSet, Box<dyn std::error::Error>> {
    let mut rules = Vec::new();

    for entry in walkdir::WalkDir::new(rules_path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yml" && ext != "yaml" {
            continue;
        }

        let content = std::fs::read_to_string(path)?;
        match parse_rule(&content, path) {
            Ok(rule) => {
                if rule.status == "deprecated" {
                    eprintln!("ruled: skipping deprecated rule: {}", rule.id);
                    continue;
                }
                rules.push(rule);
            }
            Err(e) => {
                eprintln!(
                    "ruled: skipping invalid rule file {}: {}",
                    path.display(),
                    e
                );
            }
        }
    }

    Ok(RuleSet { rules })
}

/// Parse a single Sigma rule from YAML content.
fn parse_rule(yaml: &str, _path: &Path) -> Result<Rule, String> {
    let raw: RawRule = serde_yaml::from_str(yaml)
        .map_err(|e| format!("YAML parse error: {}", e))?;

    let id = raw.id.ok_or_else(|| "missing 'id' field".to_string())?;
    let title = raw.title.ok_or_else(|| "missing 'title' field".to_string())?;

    // Parse logsource
    let logsource = parse_logsource(&raw.logsource)?;

    // Parse detection
    let detection = parse_detection(&raw.detection)?;

    Ok(Rule {
        id,
        title,
        description: raw.description,
        level: raw.level,
        status: raw.status,
        tags: raw.tags,
        logsource,
        detection,
    })
}

/// Parse the logsource section.
fn parse_logsource(value: &serde_yaml::Value) -> Result<LogSource, String> {
    let mapping = match value {
        serde_yaml::Value::Mapping(m) => m,
        serde_yaml::Value::Null => return Ok(LogSource::default()),
        _ => return Err("logsource must be a mapping".to_string()),
    };

    let get_str = |key: &str| -> Option<String> {
        mapping
            .get(&serde_yaml::Value::String(key.to_string()))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

    Ok(LogSource {
        product: get_str("product"),
        service: get_str("service"),
        category: get_str("category"),
    })
}

/// Parse the detection section.
fn parse_detection(value: &serde_yaml::Value) -> Result<Detection, String> {
    let mapping = match value {
        serde_yaml::Value::Mapping(m) => m,
        _ => return Err("detection must be a mapping".to_string()),
    };

    let mut selections = BTreeMap::new();
    let mut keywords = Vec::new();
    let mut condition_str = String::new();

    for (key, val) in mapping {
        let key_str = key.as_str().unwrap_or("");
        match key_str {
            "condition" => {
                condition_str = val
                    .as_str()
                    .ok_or_else(|| "condition must be a string".to_string())?
                    .to_string();
            }
            "keywords" => {
                if let serde_yaml::Value::Sequence(seq) = val {
                    for item in seq {
                        if let Some(s) = item.as_str() {
                            keywords.push(s.to_string());
                        }
                    }
                }
            }
            // Everything else is a named selection
            name => {
                let sel = parse_selection(val)?;
                selections.insert(name.to_string(), sel);
            }
        }
    }

    if condition_str.is_empty() {
        return Err("detection must have a 'condition' field".to_string());
    }

    let condition = parse_condition(&condition_str)?;

    Ok(Detection {
        selections,
        keywords,
        condition,
    })
}

/// Parse a selection (field-value pairs).
fn parse_selection(value: &serde_yaml::Value) -> Result<Selection, String> {
    let mapping = match value {
        serde_yaml::Value::Mapping(m) => m,
        _ => return Err("selection must be a mapping".to_string()),
    };

    let mut fields = Vec::new();

    for (key, val) in mapping {
        let key_str = key.as_str().unwrap_or("");
        let val_str = match val {
            serde_yaml::Value::String(s) => s.clone(),
            serde_yaml::Value::Number(n) => n.to_string(),
            serde_yaml::Value::Bool(b) => b.to_string(),
            _ => continue,
        };

        // Check for modifiers: field|contains, field|startswith, field|endswith
        if let Some((field, modifier)) = key_str.split_once('|') {
            match modifier {
                "contains" => fields.push(FieldMatch::Contains {
                    field: field.to_string(),
                    value: val_str,
                }),
                "startswith" => fields.push(FieldMatch::StartsWith {
                    field: field.to_string(),
                    value: val_str,
                }),
                "endswith" => fields.push(FieldMatch::EndsWith {
                    field: field.to_string(),
                    value: val_str,
                }),
                other => {
                    eprintln!("ruled: unknown field modifier '|{}' in selection, treating as equals", other);
                    fields.push(FieldMatch::Equals {
                        field: key_str.to_string(),
                        value: val_str,
                    });
                }
            }
        } else {
            fields.push(FieldMatch::Equals {
                field: key_str.to_string(),
                value: val_str,
            });
        }
    }

    Ok(Selection { fields })
}

/// Parse a condition expression string into a Condition AST.
fn parse_condition(input: &str) -> Result<Condition, String> {
    let input = input.trim();

    // Special cases
    if input == "1 of them" {
        return Ok(Condition::OneOfThem);
    }
    if input.starts_with("1 of ") && input.ends_with('*') {
        let pattern = &input[5..]; // strip "1 of "
        return Ok(Condition::OneOfPattern(pattern.to_string()));
    }

    // Try to split on "and not" (highest precedence boundary)
    if let Some(pos) = find_outer_operator(input, "and not") {
        let left = parse_condition(&input[..pos])?;
        let right = parse_condition(&input[pos + 7..])?;
        return Ok(Condition::And(Box::new(left), Box::new(Condition::Not(Box::new(right)))));
    }

    // Try to split on " or " (lowest precedence)
    if let Some(pos) = find_outer_operator(input, " or ") {
        let left = parse_condition(&input[..pos])?;
        let right = parse_condition(&input[pos + 4..])?;
        return Ok(Condition::Or(Box::new(left), Box::new(right)));
    }

    // Try to split on " and "
    if let Some(pos) = find_outer_operator(input, " and ") {
        let left = parse_condition(&input[..pos])?;
        let right = parse_condition(&input[pos + 5..])?;
        return Ok(Condition::And(Box::new(left), Box::new(right)));
    }

    // Try "not " prefix
    if let Some(rest) = input.strip_prefix("not ") {
        let inner = parse_condition(rest)?;
        return Ok(Condition::Not(Box::new(inner)));
    }

    // Parenthesized expression
    if input.starts_with('(') && input.ends_with(')') {
        return parse_condition(&input[1..input.len() - 1]);
    }

    // Simple reference
    if input.is_empty() {
        return Err("empty condition".to_string());
    }

    Ok(Condition::Ref(input.to_string()))
}

/// Find the position of an operator outside any parentheses.
fn find_outer_operator(input: &str, op: &str) -> Option<usize> {
    let mut depth = 0i32;
    let bytes = input.as_bytes();
    let op_bytes = op.as_bytes();

    for i in 0..bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && i + op_bytes.len() <= bytes.len() {
            if &bytes[i..i + op_bytes.len()] == op_bytes {
                return Some(i);
            }
        }
    }
    None
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Condition parsing ────────────────────────────────────────

    #[test]
    fn test_parse_condition_simple_ref() {
        let c = parse_condition("selection").unwrap();
        assert!(matches!(c, Condition::Ref(ref s) if s == "selection"));
    }

    #[test]
    fn test_parse_condition_keywords() {
        let c = parse_condition("keywords").unwrap();
        assert!(matches!(c, Condition::Ref(ref s) if s == "keywords"));
    }

    #[test]
    fn test_parse_condition_and() {
        let c = parse_condition("sel1 and sel2").unwrap();
        match c {
            Condition::And(left, right) => {
                assert!(matches!(*left, Condition::Ref(ref s) if s == "sel1"));
                assert!(matches!(*right, Condition::Ref(ref s) if s == "sel2"));
            }
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn test_parse_condition_or() {
        let c = parse_condition("sel1 or sel2").unwrap();
        match c {
            Condition::Or(left, right) => {
                assert!(matches!(*left, Condition::Ref(ref s) if s == "sel1"));
                assert!(matches!(*right, Condition::Ref(ref s) if s == "sel2"));
            }
            _ => panic!("expected Or"),
        }
    }

    #[test]
    fn test_parse_condition_and_not() {
        let c = parse_condition("sel1 and not filter").unwrap();
        match c {
            Condition::And(left, right) => {
                assert!(matches!(*left, Condition::Ref(ref s) if s == "sel1"));
                assert!(matches!(*right, Condition::Not(_)));
            }
            _ => panic!("expected And with Not"),
        }
    }

    #[test]
    fn test_parse_condition_one_of_them() {
        let c = parse_condition("1 of them").unwrap();
        assert!(matches!(c, Condition::OneOfThem));
    }

    #[test]
    fn test_parse_condition_one_of_pattern() {
        let c = parse_condition("1 of selection*").unwrap();
        match c {
            Condition::OneOfPattern(ref p) => assert_eq!(p, "selection*"),
            _ => panic!("expected OneOfPattern"),
        }
    }

    #[test]
    fn test_parse_condition_parenthesized() {
        let c = parse_condition("(sel1 or sel2) and not filter").unwrap();
        match c {
            Condition::And(left, right) => {
                assert!(matches!(*left, Condition::Or(_, _)));
                assert!(matches!(*right, Condition::Not(_)));
            }
            _ => panic!("expected And(Or, Not)"),
        }
    }

    #[test]
    fn test_parse_condition_not_prefix() {
        let c = parse_condition("not filter").unwrap();
        match c {
            Condition::Not(inner) => {
                assert!(matches!(*inner, Condition::Ref(ref s) if s == "filter"));
            }
            _ => panic!("expected Not"),
        }
    }

    // ── Detection parsing ────────────────────────────────────────

    #[test]
    fn test_parse_detection_keywords() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
keywords:
  - "Failed password"
  - "authentication failure"
condition: keywords
"#,
        )
        .unwrap();
        let det = parse_detection(&yaml).unwrap();
        assert_eq!(det.keywords.len(), 2);
        assert!(matches!(det.condition, Condition::Ref(ref s) if s == "keywords"));
    }

    #[test]
    fn test_parse_detection_selection() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
selection:
  event_type: SSH_FAILED_PASSWORD
  severity: WARN
condition: selection
"#,
        )
        .unwrap();
        let det = parse_detection(&yaml).unwrap();
        assert_eq!(det.selections.len(), 1);
        let sel = det.selections.get("selection").unwrap();
        assert_eq!(sel.fields.len(), 2);
    }

    #[test]
    fn test_parse_detection_with_modifiers() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
selection:
  event_type|contains: "FAILED"
  src_ip|startswith: "10.0."
  user|endswith: "admin"
condition: selection
"#,
        )
        .unwrap();
        let det = parse_detection(&yaml).unwrap();
        let sel = det.selections.get("selection").unwrap();
        assert_eq!(sel.fields.len(), 3);
        assert!(matches!(sel.fields[0], FieldMatch::Contains { .. }));
        assert!(matches!(sel.fields[1], FieldMatch::StartsWith { .. }));
        assert!(matches!(sel.fields[2], FieldMatch::EndsWith { .. }));
    }

    #[test]
    fn test_parse_detection_missing_condition() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("selection:\n  foo: bar\n").unwrap();
        let result = parse_detection(&yaml);
        assert!(result.is_err());
    }

    // ── Full rule parsing ────────────────────────────────────────

    #[test]
    fn test_parse_rule_complete() {
        let yaml = r#"
title: Suspicious SSH Failed Logins
id: abc-123
status: stable
level: medium
logsource:
  product: linux
  service: sshd
detection:
  keywords:
    - "Failed password"
    - "authentication failure"
  condition: keywords
"#;
        let path = Path::new("test.yml");
        let rule = parse_rule(yaml, path).unwrap();
        assert_eq!(rule.id, "abc-123");
        assert_eq!(rule.title, "Suspicious SSH Failed Logins");
        assert_eq!(rule.logsource.product.as_deref(), Some("linux"));
        assert_eq!(rule.logsource.service.as_deref(), Some("sshd"));
        assert_eq!(rule.detection.keywords.len(), 2);
    }

    #[test]
    fn test_parse_rule_missing_id() {
        let yaml = r#"
title: No ID Rule
detection:
  condition: keywords
"#;
        let result = parse_rule(yaml, Path::new("test.yml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rule_missing_title() {
        let yaml = r#"
id: no-title
detection:
  condition: keywords
"#;
        let result = parse_rule(yaml, Path::new("test.yml"));
        assert!(result.is_err());
    }

    // ── Logsource parsing ────────────────────────────────────────

    #[test]
    fn test_parse_logsource_full() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
product: linux
service: sshd
category: authentication
"#,
        )
        .unwrap();
        let ls = parse_logsource(&yaml).unwrap();
        assert_eq!(ls.product.as_deref(), Some("linux"));
        assert_eq!(ls.service.as_deref(), Some("sshd"));
        assert_eq!(ls.category.as_deref(), Some("authentication"));
    }

    #[test]
    fn test_parse_logsource_empty() {
        let ls = parse_logsource(&serde_yaml::Value::Null).unwrap();
        assert!(ls.product.is_none());
    }

    // ── Rule loading integration ─────────────────────────────────

    #[test]
    fn test_load_rules_valid_rule() {
        let tmp = tempfile::tempdir().unwrap();
        let rule_yaml = r#"
id: test-001
title: Test Rule
description: A test rule
level: medium
status: stable
logsource:
  product: linux
  service: sshd
detection:
  keywords:
    - "Failed password"
  condition: keywords
"#;
        let rule_path = tmp.path().join("test-001.yml");
        std::fs::write(&rule_path, rule_yaml).unwrap();

        let rules = load_rules(tmp.path()).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules.rules[0].id, "test-001");
        assert_eq!(rules.rules[0].title, "Test Rule");
    }

    #[test]
    fn test_load_rules_skips_deprecated() {
        let tmp = tempfile::tempdir().unwrap();
        let rule_yaml = r#"
id: test-deprecated
title: Old Rule
status: deprecated
logsource:
  product: linux
detection:
  keywords: ["test"]
  condition: keywords
"#;
        std::fs::write(tmp.path().join("deprecated.yml"), rule_yaml).unwrap();

        let rules = load_rules(tmp.path()).unwrap();
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn test_load_rules_skips_invalid_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bad.yml"), "not: valid: yaml: [").unwrap();

        let rules = load_rules(tmp.path()).unwrap();
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn test_load_rules_skips_non_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::File::create(tmp.path().join("README.md")).unwrap();

        let rules = load_rules(tmp.path()).unwrap();
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn test_load_rules_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = load_rules(tmp.path()).unwrap();
        assert_eq!(rules.len(), 0);
    }

    // ── Matching engine tests ────────────────────────────────────

    fn make_rule(detection_yaml: &str) -> Rule {
        let det: serde_yaml::Value = serde_yaml::from_str(detection_yaml).unwrap();
        let detection = parse_detection(&det).unwrap();
        Rule {
            id: "test-001".into(),
            title: "Test Rule".into(),
            description: "".into(),
            level: "medium".into(),
            status: "stable".into(),
            tags: vec![],
            logsource: LogSource::default(),
            detection,
        }
    }

    #[test]
    fn test_match_equals() {
        let rule = make_rule(
            r#"
selection:
  event_type: SSH_FAILED_PASSWORD
condition: selection
"#,
        );
        let event = serde_json::json!({"event_type": "SSH_FAILED_PASSWORD"});
        assert!(rule.matches(&event));

        let event2 = serde_json::json!({"event_type": "SSH_SUCCESS"});
        assert!(!rule.matches(&event2));
    }

    #[test]
    fn test_match_contains() {
        let rule = make_rule(
            r#"
selection:
  event_type|contains: "FAILED"
condition: selection
"#,
        );
        let event = serde_json::json!({"event_type": "SSH_FAILED_PASSWORD"});
        assert!(rule.matches(&event));

        let event2 = serde_json::json!({"event_type": "SSH_SUCCESS"});
        assert!(!rule.matches(&event2));
    }

    #[test]
    fn test_match_startswith() {
        let rule = make_rule(
            r#"
selection:
  src_ip|startswith: "10.0."
condition: selection
"#,
        );
        let event = serde_json::json!({"src_ip": "10.0.0.5"});
        assert!(rule.matches(&event));

        let event2 = serde_json::json!({"src_ip": "192.168.1.1"});
        assert!(!rule.matches(&event2));
    }

    #[test]
    fn test_match_endswith() {
        let rule = make_rule(
            r#"
selection:
  user|endswith: "admin"
condition: selection
"#,
        );
        let event = serde_json::json!({"user": "rootadmin"});
        assert!(rule.matches(&event));

        let event2 = serde_json::json!({"user": "adminroot"});
        assert!(!rule.matches(&event2));
    }

    #[test]
    fn test_match_keywords() {
        let rule = make_rule(
            r#"
keywords:
  - "Failed password"
  - "authentication failure"
condition: keywords
"#,
        );
        let event = serde_json::json!({"message": "Failed password for root from 10.0.0.5"});
        assert!(rule.matches(&event));

        let event2 = serde_json::json!({"message": "Accepted publickey for root"});
        assert!(!rule.matches(&event2));
    }

    #[test]
    fn test_match_and_condition() {
        let rule = make_rule(
            r#"
sel1:
  event_type: SSH_FAILED_PASSWORD
sel2:
  severity: WARN
condition: sel1 and sel2
"#,
        );
        let event = serde_json::json!({"event_type": "SSH_FAILED_PASSWORD", "severity": "WARN"});
        assert!(rule.matches(&event));

        let event2 = serde_json::json!({"event_type": "SSH_FAILED_PASSWORD", "severity": "INFO"});
        assert!(!rule.matches(&event2));
    }

    #[test]
    fn test_match_or_condition() {
        let rule = make_rule(
            r#"
sel1:
  event_type: SSH_FAILED_PASSWORD
sel2:
  event_type: SSH_FAILED_KEY
condition: sel1 or sel2
"#,
        );
        let event = serde_json::json!({"event_type": "SSH_FAILED_PASSWORD"});
        assert!(rule.matches(&event));

        let event2 = serde_json::json!({"event_type": "SSH_FAILED_KEY"});
        assert!(rule.matches(&event2));

        let event3 = serde_json::json!({"event_type": "SSH_SUCCESS"});
        assert!(!rule.matches(&event3));
    }

    #[test]
    fn test_match_not_condition() {
        let rule = make_rule(
            r#"
sel1:
  event_type: SSH_FAILED_PASSWORD
filter:
  src_ip|startswith: "10.0."
condition: sel1 and not filter
"#,
        );
        // Matches sel1 but not filter
        let event = serde_json::json!({"event_type": "SSH_FAILED_PASSWORD", "src_ip": "192.168.1.1"});
        assert!(rule.matches(&event));

        // Matches both — should be excluded
        let event2 = serde_json::json!({"event_type": "SSH_FAILED_PASSWORD", "src_ip": "10.0.0.5"});
        assert!(!rule.matches(&event2));
    }

    #[test]
    fn test_match_one_of_them() {
        let rule = make_rule(
            r#"
sel1:
  event_type: SSH_FAILED_PASSWORD
sel2:
  event_type: SSH_FAILED_KEY
sel3:
  event_type: SSH_BRUTE_FORCE
condition: 1 of them
"#,
        );
        let event = serde_json::json!({"event_type": "SSH_FAILED_KEY"});
        assert!(rule.matches(&event));

        let event2 = serde_json::json!({"event_type": "SSH_SUCCESS"});
        assert!(!rule.matches(&event2));
    }

    #[test]
    fn test_match_one_of_pattern() {
        let rule = make_rule(
            r#"
sel_ssh:
  event_type: SSH_FAILED_PASSWORD
sel_sudo:
  event_type: SUDO_FAILED
sel_other:
  event_type: OTHER
condition: 1 of sel_*
"#,
        );
        let event = serde_json::json!({"event_type": "SSH_FAILED_PASSWORD"});
        assert!(rule.matches(&event));

        let event2 = serde_json::json!({"event_type": "SUDO_FAILED"});
        assert!(rule.matches(&event2));

        let event3 = serde_json::json!({"event_type": "OTHER"});
        assert!(rule.matches(&event3));
    }

    #[test]
    fn test_match_logsource_filter() {
        let rule_yaml = r#"
id: ssh-rule
title: SSH Rule
status: stable
logsource:
  service: sshd
detection:
  keywords:
    - "Failed password"
  condition: keywords
"#;
        let rule = parse_rule(rule_yaml, Path::new("test.yml")).unwrap();

        // Matching source
        let event = serde_json::json!({
            "_source_type": "sshd",
            "message": "Failed password for root"
        });
        assert!(rule.matches(&event));

        // Non-matching source
        let event2 = serde_json::json!({
            "_source_type": "iptables",
            "message": "Failed password for root"
        });
        assert!(!rule.matches(&event2));
    }

    #[test]
    fn test_match_missing_field() {
        let rule = make_rule(
            r#"
selection:
  nonexistent_field: some_value
condition: selection
"#,
        );
        let event = serde_json::json!({"event_type": "SSH_FAILED"});
        assert!(!rule.matches(&event));
    }

    #[test]
    fn test_match_numeric_field() {
        let rule = make_rule(
            r#"
selection:
  port: "22"
condition: selection
"#,
        );
        let event = serde_json::json!({"port": 22});
        assert!(rule.matches(&event));

        let event2 = serde_json::json!({"port": 80});
        assert!(!rule.matches(&event2));
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("sel_*", "sel_ssh"));
        assert!(glob_match("sel_*", "sel_sudo"));
        assert!(!glob_match("sel_*", "other"));
        assert!(glob_match("*_ssh", "sel_ssh"));
        assert!(!glob_match("*_ssh", "sel_sudo"));
        assert!(glob_match("sel_*_test", "sel_ssh_test"));
        assert!(!glob_match("sel_*_test", "sel_ssh_other"));
    }
}

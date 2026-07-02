//! Alert suppression: `[[suppress]]` blocks in a TOML file (conventionally
//! `config/rules/suppress.toml` — `rules::load_rules` already only loads
//! `.yml`/`.yaml` files from that directory, so a `.toml` file sitting next
//! to the Sigma rules is automatically ignored by rule loading) that skip
//! alert emission when a condition matches the event that triggered a rule.
//! See `docs/roadmap-soc-improvements.md` item 4.
//!
//! Not reusing siemctl's query DSL (`src/siemctl/src/query.rs`): that's a
//! different crate, and a much richer grammar (SELECT/GROUP BY/LIMIT) that
//! suppression doesn't need. A small hand-rolled boolean-expression
//! parser/evaluator lives here instead, matching this codebase's existing
//! convention of duplicating small parsers per-crate rather than
//! centralizing (see siemctl's `sources.rs` vs. `normconfig.rs`).
//!
//! Grammar:
//! ```text
//! expr    := or_expr
//! or_expr := and_expr { "OR" and_expr }
//! and_expr:= not_expr { "AND" not_expr }
//! not_expr:= [ "NOT" ] primary
//! primary := "(" expr ")" | "cidr_match(" field "," literal ")" | field ("=="|"!=") literal
//! ```
//! Quotes around literals are optional (a slot's role is fixed by position,
//! same convention as siemctl's DSL); keywords are case-insensitive.

use chrono::Utc;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct SuppressFile {
    #[serde(default)]
    suppress: Vec<SuppressRuleToml>,
}

#[derive(Debug, Deserialize)]
struct SuppressRuleToml {
    rule_id: String,
    condition: String,
    expires: Option<String>,
    #[allow(dead_code)] // not consumed at runtime — documentation for the config author
    note: Option<String>,
}

/// One loaded, parsed suppression rule ready for fast per-event evaluation.
struct SuppressRule {
    rule_id: String,
    condition: Expr,
}

/// All suppression rules loaded from one file.
pub struct SuppressSet {
    rules: Vec<SuppressRule>,
}

impl SuppressSet {
    /// True if any loaded rule for `rule_id` matches `event` — i.e. the
    /// alert that would otherwise fire for `rule_id` should be dropped.
    pub fn is_suppressed(&self, rule_id: &str, event: &serde_json::Value) -> bool {
        self.rules.iter().any(|r| r.rule_id == rule_id && r.condition.eval(event))
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

/// Load and parse `path`. A suppression rule with an unparseable `condition`
/// is skipped with a warning (not fatal) — matching `rules::load_rules`'s
/// own "warn and skip one bad file" posture, so one typo doesn't take down
/// the whole pipeline. An `expires` date in the past logs a one-time warning
/// at startup but the rule still suppresses — it just nags for review.
pub fn load(path: &Path) -> Result<SuppressSet, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let file: SuppressFile = toml::from_str(&text)?;
    let today = Utc::now().format("%Y-%m-%d").to_string();

    let mut rules = Vec::with_capacity(file.suppress.len());
    for r in file.suppress {
        let condition = match parse_condition(&r.condition) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "[ruled] warning: skipping suppression rule '{}' — invalid condition '{}': {e}",
                    r.rule_id, r.condition
                );
                continue;
            }
        };
        if let Some(expires) = &r.expires {
            if expires.as_str() < today.as_str() {
                eprintln!(
                    "[ruled] warning: suppression rule '{}' expired on {} — please review \
                     (still suppressing)",
                    r.rule_id, expires
                );
            }
        }
        rules.push(SuppressRule { rule_id: r.rule_id, condition });
    }
    Ok(SuppressSet { rules })
}

// ── Condition AST + evaluator ────────────────────────────────────────────

enum Cmp {
    Eq,
    Ne,
}

enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Compare { field: String, value: String, cmp: Cmp },
    CidrMatch { field: String, cidr: String },
}

impl Expr {
    fn eval(&self, event: &serde_json::Value) -> bool {
        match self {
            Expr::And(a, b) => a.eval(event) && b.eval(event),
            Expr::Or(a, b) => a.eval(event) || b.eval(event),
            Expr::Not(e) => !e.eval(event),
            Expr::Compare { field, value, cmp } => {
                let actual = field_as_string(event, field);
                match cmp {
                    Cmp::Eq => actual.as_deref() == Some(value.as_str()),
                    // Mirrors SQL/eval_json NULL semantics: an absent field
                    // never satisfies `!=` either (it's "unknown", not "true").
                    Cmp::Ne => actual.as_deref().map(|a| a != value).unwrap_or(false),
                }
            }
            Expr::CidrMatch { field, cidr } => field_as_string(event, field)
                .map(|ip| cidr_contains(cidr, &ip).unwrap_or(false))
                .unwrap_or(false),
        }
    }
}

fn field_as_string(event: &serde_json::Value, field: &str) -> Option<String> {
    match event.get(field) {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        Some(serde_json::Value::Bool(b)) => Some(b.to_string()),
        _ => None, // absent, null, array, or object
    }
}

/// IPv4-only CIDR containment check — deliberately minimal (suppression's
/// only documented use case is IPv4 CDN ranges); an IPv6 literal or address
/// simply never matches rather than erroring.
fn cidr_contains(cidr: &str, ip: &str) -> Result<bool, String> {
    let (net_str, prefix_str) =
        cidr.split_once('/').ok_or_else(|| format!("invalid CIDR (missing /): {cidr}"))?;
    let prefix_len: u32 =
        prefix_str.parse().map_err(|_| format!("invalid CIDR prefix length: {prefix_str}"))?;
    if prefix_len > 32 {
        return Err(format!("CIDR prefix length out of range (0-32): {prefix_len}"));
    }
    let Some(net) = ipv4_to_u32(net_str) else {
        return Err(format!("invalid CIDR network address: {net_str}"));
    };
    let Some(ip_u32) = ipv4_to_u32(ip) else {
        return Ok(false); // stored value isn't a valid IPv4 — skip it, not an error
    };
    if prefix_len == 0 {
        return Ok(true);
    }
    let mask = !0u32 << (32 - prefix_len);
    Ok((ip_u32 & mask) == (net & mask))
}

fn ipv4_to_u32(s: &str) -> Option<u32> {
    let mut parts = s.split('.');
    let a: u32 = parts.next()?.parse().ok()?;
    let b: u32 = parts.next()?.parse().ok()?;
    let c: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    if a > 255 || b > 255 || c > 255 || d > 255 {
        return None;
    }
    Some((a << 24) | (b << 16) | (c << 8) | d)
}

// ── Lexer ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    LParen,
    RParen,
    Comma,
    And,
    Or,
    Not,
    Eq,
    Ne,
    Word(String),
    Str(String),
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | ':' | '-')
}

fn lex(s: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = s.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            ',' => {
                toks.push(Tok::Comma);
                i += 1;
            }
            '\'' | '"' => {
                let quote = c;
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != quote {
                    i += 1;
                }
                if i >= chars.len() {
                    return Err("unterminated quoted string".to_string());
                }
                let val: String = chars[start..i].iter().collect();
                i += 1; // closing quote
                toks.push(Tok::Str(val));
            }
            '=' => {
                i += if i + 1 < chars.len() && chars[i + 1] == '=' { 2 } else { 1 };
                toks.push(Tok::Eq);
            }
            '!' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    toks.push(Tok::Ne);
                    i += 2;
                } else {
                    return Err("expected '=' after '!'".to_string());
                }
            }
            c if c.is_ascii_alphanumeric() || c == '_' => {
                let start = i;
                while i < chars.len() && is_word_char(chars[i]) {
                    i += 1;
                }
                let w: String = chars[start..i].iter().collect();
                toks.push(match w.to_ascii_uppercase().as_str() {
                    "AND" => Tok::And,
                    "OR" => Tok::Or,
                    "NOT" => Tok::Not,
                    _ => Tok::Word(w),
                });
            }
            other => return Err(format!("unexpected character '{other}'")),
        }
    }
    Ok(toks)
}

// ── Parser ───────────────────────────────────────────────────────────────

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn advance(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, want: &Tok) -> Result<(), String> {
        match self.advance() {
            Some(ref t) if t == want => Ok(()),
            other => Err(format!("expected {want:?}, got {}", describe(&other))),
        }
    }

    /// A field name: a bare word only (not a quoted string).
    fn expect_field(&mut self) -> Result<String, String> {
        match self.advance() {
            Some(Tok::Word(w)) => Ok(w),
            other => Err(format!("expected a field name, got {}", describe(&other))),
        }
    }

    /// A literal value: quoted or bare, either token form.
    fn expect_literal(&mut self) -> Result<String, String> {
        match self.advance() {
            Some(Tok::Word(w)) => Ok(w),
            Some(Tok::Str(s)) => Ok(s),
            other => Err(format!("expected a value, got {}", describe(&other))),
        }
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.advance();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.advance();
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.advance();
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some(Tok::LParen) => {
                self.advance();
                let e = self.parse_or()?;
                self.expect(&Tok::RParen)?;
                Ok(e)
            }
            Some(Tok::Word(w)) if w.eq_ignore_ascii_case("cidr_match") => {
                self.advance();
                self.expect(&Tok::LParen)?;
                let field = self.expect_field()?;
                self.expect(&Tok::Comma)?;
                let cidr = self.expect_literal()?;
                self.expect(&Tok::RParen)?;
                Ok(Expr::CidrMatch { field, cidr })
            }
            Some(Tok::Word(_)) => {
                let field = self.expect_field()?;
                let cmp = match self.advance() {
                    Some(Tok::Eq) => Cmp::Eq,
                    Some(Tok::Ne) => Cmp::Ne,
                    other => {
                        return Err(format!(
                            "expected '==' or '!=' after field '{field}', got {}",
                            describe(&other)
                        ))
                    }
                };
                let value = self.expect_literal()?;
                Ok(Expr::Compare { field, value, cmp })
            }
            other => Err(format!("unexpected token: {}", describe(&other.cloned()))),
        }
    }
}

fn describe(t: &Option<Tok>) -> String {
    match t {
        None => "end of input".to_string(),
        Some(t) => format!("{t:?}"),
    }
}

fn parse_condition(s: &str) -> Result<Expr, String> {
    let toks = lex(s)?;
    let mut p = Parser { toks, pos: 0 };
    let expr = p.parse_or()?;
    if p.pos != p.toks.len() {
        return Err(format!("unexpected trailing input near {}", describe(&p.toks.get(p.pos).cloned())));
    }
    Ok(expr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_CTR: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let n = TMP_CTR.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("ruled_suppress_test_{}_{}", std::process::id(), n));
            std::fs::create_dir_all(&p).unwrap();
            TempDir { path: p }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn eval(condition: &str, event: &serde_json::Value) -> bool {
        parse_condition(condition).unwrap().eval(event)
    }

    // ── condition parser/evaluator ───────────────────────────────────────

    #[test]
    fn equality_and_inequality() {
        let event = json!({"src_ip": "10.0.0.5", "action": "BLOCK"});
        assert!(eval("action == BLOCK", &event));
        assert!(eval("action == \"BLOCK\"", &event));
        assert!(!eval("action == ALLOW", &event));
        assert!(eval("action != ALLOW", &event));
        assert!(!eval("action != BLOCK", &event));
        // A single '=' is accepted as equality too, same lenient convention
        // as siemctl's DSL (query.rs's lexer).
        assert!(eval("action = BLOCK", &event));
    }

    #[test]
    fn not_exact_false_when_field_absent() {
        // Mirrors SQL/eval_json NULL semantics: NULL != 'x' is not true.
        let event = json!({"action": "BLOCK"});
        assert!(!eval("nonexistent != anything", &event));
    }

    #[test]
    fn cidr_match_ipv4() {
        let event = json!({"src_ip": "172.64.1.1"});
        assert!(eval("cidr_match(src_ip, \"172.64.0.0/13\")", &event));
        assert!(!eval("cidr_match(src_ip, \"10.0.0.0/8\")", &event));
    }

    #[test]
    fn cidr_match_field_absent_is_false() {
        let event = json!({"other_field": "x"});
        assert!(!eval("cidr_match(src_ip, \"172.64.0.0/13\")", &event));
    }

    #[test]
    fn and_or_not_compose() {
        let event = json!({"rule_id": "suricata-2210020", "src_ip": "172.64.1.1"});
        assert!(eval("rule_id == suricata-2210020 AND cidr_match(src_ip, \"172.64.0.0/13\")", &event));
        assert!(!eval("rule_id == other AND cidr_match(src_ip, \"172.64.0.0/13\")", &event));
        assert!(eval("rule_id == other OR cidr_match(src_ip, \"172.64.0.0/13\")", &event));
        assert!(eval("NOT rule_id == other", &event));
        assert!(eval("(rule_id == other OR cidr_match(src_ip, \"172.64.0.0/13\")) AND NOT rule_id == other", &event));
    }

    #[test]
    fn malformed_condition_strings_are_rejected() {
        assert!(parse_condition("").is_err());
        assert!(parse_condition("src_ip ==").is_err());
        assert!(parse_condition("src_ip == 'unterminated").is_err());
        assert!(parse_condition("cidr_match(src_ip)").is_err());
        assert!(parse_condition("src_ip == a AND").is_err());
        assert!(parse_condition("src_ip == a extra_trailing_token").is_err());
    }

    // ── load() ───────────────────────────────────────────────────────────

    #[test]
    fn load_parses_the_documented_example() {
        let tmp = TempDir::new();
        let path = tmp.path.join("suppress.toml");
        std::fs::write(
            &path,
            r#"
[[suppress]]
rule_id = "suricata-2210020"
condition = 'cidr_match(src_ip, "172.64.0.0/13")'
expires = "2099-12-31"
note = "Cloudflare CDN TCP teardown false positives"

[[suppress]]
rule_id = "suricata-2210029"
condition = 'cidr_match(src_ip, "172.64.0.0/13")'
"#,
        )
        .unwrap();

        let set = load(&path).unwrap();
        assert_eq!(set.len(), 2);
        let event = json!({"src_ip": "172.64.1.1"});
        assert!(set.is_suppressed("suricata-2210020", &event));
        assert!(set.is_suppressed("suricata-2210029", &event));
        assert!(!set.is_suppressed("some-other-rule", &event));
    }

    #[test]
    fn load_skips_invalid_condition_but_keeps_the_rest() {
        let tmp = TempDir::new();
        let path = tmp.path.join("suppress.toml");
        std::fs::write(
            &path,
            r#"
[[suppress]]
rule_id = "bad-rule"
condition = "src_ip =="

[[suppress]]
rule_id = "good-rule"
condition = 'src_ip == "10.0.0.5"'
"#,
        )
        .unwrap();

        let set = load(&path).unwrap();
        assert_eq!(set.len(), 1);
        let event = json!({"src_ip": "10.0.0.5"});
        assert!(set.is_suppressed("good-rule", &event));
        assert!(!set.is_suppressed("bad-rule", &event));
    }

    #[test]
    fn load_rejects_malformed_toml() {
        let tmp = TempDir::new();
        let path = tmp.path.join("suppress.toml");
        std::fs::write(&path, "not valid toml [[[").unwrap();
        assert!(load(&path).is_err());
    }

    #[test]
    fn load_empty_file_has_no_rules() {
        let tmp = TempDir::new();
        let path = tmp.path.join("suppress.toml");
        std::fs::write(&path, "").unwrap();
        let set = load(&path).unwrap();
        assert_eq!(set.len(), 0);
        assert!(!set.is_suppressed("anything", &json!({})));
    }

    #[test]
    fn expired_rule_still_suppresses() {
        let tmp = TempDir::new();
        let path = tmp.path.join("suppress.toml");
        std::fs::write(
            &path,
            r#"
[[suppress]]
rule_id = "old-rule"
condition = 'src_ip == "10.0.0.5"'
expires = "2000-01-01"
"#,
        )
        .unwrap();

        // Loading a file with an expired rule must not error or drop the
        // rule — it should still suppress (the warning is stderr-only,
        // which this test doesn't capture, but the resulting behavior is
        // what's checked here).
        let set = load(&path).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.is_suppressed("old-rule", &json!({"src_ip": "10.0.0.5"})));
    }
}

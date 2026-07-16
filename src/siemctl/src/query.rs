//! Unified query layer for `siemctl search`.
//!
//! A single SQL-ish DSL string is tokenized and parsed here into a boolean
//! [`Expr`] tree (plus optional `GROUP BY` / `LIMIT`), then compiled to
//! per-bucket SQL and executed across the index, merging results in Rust. This
//! replaces the four disjoint legacy search paths (field / group / full-text /
//! range) with one composable surface — text search runs through the index via
//! the `raw_contains` UDF so it composes with field filters and grouping.
//!
//! Grammar (recursive descent):
//! ```text
//! query      := [ "SELECT" identlist ] [ "WHERE" ] [ expr ] [ "GROUP" "BY" identlist ] [ "LIMIT" int ]
//! expr       := or_expr
//! or_expr    := and_expr { "OR" and_expr }
//! and_expr   := not_expr { "AND" not_expr }
//! not_expr   := [ "NOT" ] primary
//! primary    := "(" expr ")" | comparison | func_call
//! comparison := field ( "==" | "=" | "!=" | "<>" ) literal
//! func_call  := fname "(" [ arg { "," arg } ] ")"
//! identlist  := field { "," field }
//! ```
//! Keywords are case-insensitive; quotes (`'…'` / `"…"`) are optional everywhere
//! and simply stripped — a slot's role (field vs. literal) is fixed by position.
//!
//! `SELECT` fields are output projections: they are not validated against the
//! indexed-field set, so non-indexed JSON keys (e.g. `message`, `_raw`) are
//! allowed. Missing fields render as `null` in JSON or empty in TSV.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use crate::db::{self, MatchMode};
use crate::render::{Record, Renderer, Val};
use crate::time;

/// Default row cap applied by `siemctl search` when the DSL gives no explicit
/// `LIMIT` and `--no-limit` wasn't passed (see `main.rs`'s `cmd_search`) — an
/// unbounded index query with no `GROUP BY`, or one grouped on a
/// near-unique field, dumps thousands of raw rows straight into whatever
/// consumed the output (three `context_balloon` tickets from the same root
/// cause on 2026-07-16, see
/// `ticketing-system/tuner-dev/20260716T192600.100_siemctl-search-default-output-cap.md`).
///
/// Sized against the *worst* observed per-row JSON width — a full-row query
/// with no `SELECT` projection — measured against real data in this clone:
/// `kernel` and `filterlog` both ran close to 950-960 bytes/row, the widest
/// of several sources sampled. Using 1000 bytes/row as a rounded-up margin,
/// 150 rows is ~150KB, comfortably (~25%) under `context-balloon-scan`'s
/// 200KB threshold even in that worst case. A `SELECT` with a handful of
/// projected fields, or a low-cardinality `GROUP BY`, runs far smaller per
/// row in practice and rarely reaches this cap at all.
pub const DEFAULT_ROW_CAP: usize = 150;

// ── AST ──────────────────────────────────────────────────────────────────────

/// A parsed `--query` expression: predicate tree + optional grouping/limit, plus
/// the `--after`/`--before` bucket-pruning bounds (set from flags after parsing).
#[derive(Debug, PartialEq)]
pub struct Query {
    /// `SELECT` output projection; `None` = emit all fields.
    pub select: Option<Vec<String>>,
    /// Parsed predicate tree; `None` matches all rows.
    pub expr: Option<Expr>,
    /// `GROUP BY` columns; `Some` switches to aggregate (COUNT per combo) mode.
    pub group_by: Option<Vec<String>>,
    /// `LIMIT` from the DSL.
    pub limit: Option<usize>,
    /// `--after` bound (bucket pruning only).
    pub after: Option<time::HourBucket>,
    /// `--before` bound (bucket pruning only).
    pub before: Option<time::HourBucket>,
}

/// A boolean predicate tree.
#[derive(Debug, PartialEq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Cond(Condition),
}

/// A leaf predicate.
#[derive(Debug, PartialEq)]
pub enum Condition {
    /// A comparison/function over an indexed column.
    Field { field: String, value: String, mode: MatchMode },
    /// A substring test over the row's raw JSONL line (`raw_contains`).
    Text { needle: String },
}

// ── Lexer ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Select,
    Where,
    Group,
    By,
    Limit,
    And,
    Or,
    Not,
    Eq,
    Ne,
    LParen,
    RParen,
    Comma,
    Word(String),
    Str(String),
}

fn is_word_start(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
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
                let mut val = String::new();
                while i < chars.len() && chars[i] != quote {
                    val.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err("unterminated quoted string".to_string());
                }
                i += 1; // closing quote
                toks.push(Tok::Str(val));
            }
            '=' => {
                // accept both `==` and `=`
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
            '<' => {
                if i + 1 < chars.len() && chars[i + 1] == '>' {
                    toks.push(Tok::Ne);
                    i += 2;
                } else {
                    return Err("expected '>' after '<'".to_string());
                }
            }
            c if is_word_start(c) => {
                let start = i;
                while i < chars.len() && is_word_char(chars[i]) {
                    i += 1;
                }
                let w: String = chars[start..i].iter().collect();
                toks.push(keyword_or_word(w));
            }
            other => return Err(format!("unexpected character '{other}'")),
        }
    }
    Ok(toks)
}

fn keyword_or_word(w: String) -> Tok {
    match w.to_ascii_uppercase().as_str() {
        "SELECT" => Tok::Select,
        "WHERE" => Tok::Where,
        "GROUP" => Tok::Group,
        "BY" => Tok::By,
        "LIMIT" => Tok::Limit,
        "AND" => Tok::And,
        "OR" => Tok::Or,
        "NOT" => Tok::Not,
        _ => Tok::Word(w),
    }
}

// ── Parser ───────────────────────────────────────────────────────────────────

struct Parser<'a> {
    toks: Vec<Tok>,
    pos: usize,
    valid: &'a HashSet<String>,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_query(
        &mut self,
    ) -> Result<(Option<Vec<String>>, Option<Expr>, Option<Vec<String>>, Option<usize>), String>
    {
        // Optional leading SELECT.
        let select = if matches!(self.peek(), Some(Tok::Select)) {
            self.next();
            Some(self.parse_select_fields()?)
        } else {
            None
        };

        // Optional leading WHERE.
        if matches!(self.peek(), Some(Tok::Where)) {
            self.next();
        }

        // Empty predicate (just a GROUP BY / LIMIT / nothing) => match-all.
        let expr = match self.peek() {
            None | Some(Tok::Group) | Some(Tok::Limit) => None,
            _ => Some(self.parse_or()?),
        };

        let mut group_by = None;
        if matches!(self.peek(), Some(Tok::Group)) {
            self.next();
            match self.next() {
                Some(Tok::By) => {}
                _ => return Err("expected BY after GROUP".to_string()),
            }
            group_by = Some(self.parse_identlist()?);
        }

        let mut limit = None;
        if matches!(self.peek(), Some(Tok::Limit)) {
            self.next();
            let w = match self.next() {
                Some(Tok::Word(w)) => w,
                other => return Err(format!("expected a number after LIMIT, found {}", describe(&other))),
            };
            let n: usize = w.parse().map_err(|_| format!("invalid LIMIT value '{w}'"))?;
            limit = Some(n);
        }

        if self.pos != self.toks.len() {
            return Err(format!(
                "unexpected trailing input near {}",
                describe(&self.peek().cloned())
            ));
        }
        Ok((select, expr, group_by, limit))
    }

    /// Parse a comma-separated list of output field names. Unlike
    /// [`parse_identlist`], these are NOT validated against the indexed-field
    /// set — any valid identifier is accepted so that non-indexed JSON keys
    /// (e.g. `message`, `_raw`) can be projected.
    fn parse_select_fields(&mut self) -> Result<Vec<String>, String> {
        let mut v = vec![self.parse_output_field()?];
        while matches!(self.peek(), Some(Tok::Comma)) {
            self.next();
            v.push(self.parse_output_field()?);
        }
        Ok(v)
    }

    fn parse_output_field(&mut self) -> Result<String, String> {
        let name = match self.next() {
            Some(Tok::Word(w)) => w,
            Some(Tok::Str(s)) => s,
            other => return Err(format!("expected a field name, found {}", describe(&other))),
        };
        if !crate::is_sql_ident(&name) {
            return Err(format!(
                "invalid field name '{name}' (only letters, digits and underscore allowed)"
            ));
        }
        Ok(name)
    }

    fn parse_identlist(&mut self) -> Result<Vec<String>, String> {
        let mut v = vec![self.parse_field_name()?];
        while matches!(self.peek(), Some(Tok::Comma)) {
            self.next();
            v.push(self.parse_field_name()?);
        }
        Ok(v)
    }

    fn parse_field_name(&mut self) -> Result<String, String> {
        let name = match self.next() {
            Some(Tok::Word(w)) => w,
            Some(Tok::Str(s)) => s,
            other => return Err(format!("expected a field name, found {}", describe(&other))),
        };
        validate_field(&name, self.valid)?;
        Ok(name)
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.next();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.next();
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.next();
            Ok(Expr::Not(Box::new(self.parse_not()?)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some(Tok::LParen) => {
                self.next();
                let e = self.parse_or()?;
                match self.next() {
                    Some(Tok::RParen) => Ok(e),
                    other => Err(format!("expected ')', found {}", describe(&other))),
                }
            }
            Some(Tok::Word(_)) | Some(Tok::Str(_)) => {
                let name = match self.next() {
                    Some(Tok::Word(w)) => w,
                    Some(Tok::Str(s)) => s,
                    _ => unreachable!(),
                };
                match self.peek() {
                    Some(Tok::LParen) => self.parse_func_call(name),
                    Some(Tok::Eq) | Some(Tok::Ne) => self.parse_comparison(name),
                    other => Err(format!(
                        "expected an operator or '(' after '{name}', found {}",
                        describe(&other.cloned())
                    )),
                }
            }
            other => Err(format!("expected a condition, found {}", describe(&other.cloned()))),
        }
    }

    fn parse_comparison(&mut self, field: String) -> Result<Expr, String> {
        let op = self.next().expect("operator present (peeked)");
        let value = match self.next() {
            Some(Tok::Word(w)) => w,
            Some(Tok::Str(s)) => s,
            other => return Err(format!("expected a value after operator, found {}", describe(&other))),
        };
        validate_field(&field, self.valid)?;
        let mode = match op {
            Tok::Eq => MatchMode::Exact,
            Tok::Ne => MatchMode::NotExact,
            _ => unreachable!(),
        };
        Ok(Expr::Cond(Condition::Field { field, value, mode }))
    }

    fn parse_func_call(&mut self, name: String) -> Result<Expr, String> {
        self.next(); // consume '('
        let mut args: Vec<String> = Vec::new();
        if !matches!(self.peek(), Some(Tok::RParen)) {
            loop {
                let a = match self.next() {
                    Some(Tok::Word(w)) => w,
                    Some(Tok::Str(s)) => s,
                    other => {
                        return Err(format!("expected a function argument, found {}", describe(&other)))
                    }
                };
                args.push(a);
                match self.peek() {
                    Some(Tok::Comma) => {
                        self.next();
                    }
                    Some(Tok::RParen) => break,
                    other => {
                        return Err(format!(
                            "expected ',' or ')' in argument list, found {}",
                            describe(&other.cloned())
                        ))
                    }
                }
            }
        }
        match self.next() {
            Some(Tok::RParen) => {}
            other => return Err(format!("expected ')', found {}", describe(&other))),
        }

        let cond = self.map_function(&name, args)?;
        Ok(Expr::Cond(cond))
    }

    fn map_function(&self, name: &str, args: Vec<String>) -> Result<Condition, String> {
        let fname = name.to_ascii_lowercase();
        let arity = |args: &Vec<String>, n: usize| -> Result<(), String> {
            if args.len() == n {
                Ok(())
            } else {
                Err(format!("{fname}() expects {n} argument(s), got {}", args.len()))
            }
        };
        let field_fn = |args: Vec<String>, mode: MatchMode| -> Result<Condition, String> {
            arity(&args, 2)?;
            validate_field(&args[0], self.valid)?;
            Ok(Condition::Field { field: args[0].clone(), value: args[1].clone(), mode })
        };

        match fname.as_str() {
            "startswith" => field_fn(args, MatchMode::StartsWith),
            "endswith" => field_fn(args, MatchMode::EndsWith),
            "contains" => field_fn(args, MatchMode::Contains),
            "cidr_match" => {
                arity(&args, 2)?;
                validate_field(&args[0], self.valid)?;
                // Validate the CIDR literal now so a malformed range is a clean
                // parse error rather than silently matching nothing at runtime.
                db::cidr_contains(&args[1], "0.0.0.0").map_err(|e| format!("cidr_match: {e}"))?;
                Ok(Condition::Field { field: args[0].clone(), value: args[1].clone(), mode: MatchMode::Cidr })
            }
            "any" => {
                arity(&args, 1)?;
                validate_field(&args[0], self.valid)?;
                Ok(Condition::Field { field: args[0].clone(), value: String::new(), mode: MatchMode::Any })
            }
            "raw_contains" => {
                arity(&args, 1)?;
                Ok(Condition::Text { needle: args[0].clone() })
            }
            other => Err(format!("unknown function '{other}'")),
        }
    }
}

fn describe(t: &Option<Tok>) -> String {
    match t {
        None => "end of input".to_string(),
        Some(t) => format!("{t:?}"),
    }
}

/// Validate a field identifier at parse time: it must be a bare SQL identifier
/// (interpolated, not bound) and — when `sources.toml` defines fields — a known
/// indexed column. An empty `valid` set skips the membership check.
fn validate_field(name: &str, valid: &HashSet<String>) -> Result<(), String> {
    if !crate::is_sql_ident(name) {
        return Err(format!(
            "invalid field name '{name}' (only letters, digits and underscore allowed)"
        ));
    }
    if !valid.is_empty() && !valid.contains(name) {
        let mut known: Vec<_> = valid.iter().map(String::as_str).collect();
        known.sort_unstable();
        return Err(format!("unknown field '{name}'. Known fields: {}", known.join(", ")));
    }
    Ok(())
}

// ── Compiler ─────────────────────────────────────────────────────────────────

impl Condition {
    /// Emit this leaf's SQL predicate, pushing any bound param onto `params`.
    fn to_sql(&self, params: &mut Vec<String>) -> String {
        match self {
            Condition::Field { field, value, mode } => match mode {
                MatchMode::Exact => {
                    params.push(value.clone());
                    format!("{field} = ?")
                }
                MatchMode::NotExact => {
                    params.push(value.clone());
                    format!("{field} != ?")
                }
                MatchMode::StartsWith => {
                    params.push(format!("{value}%"));
                    format!("{field} LIKE ?")
                }
                MatchMode::EndsWith => {
                    params.push(format!("%{value}"));
                    format!("{field} LIKE ?")
                }
                MatchMode::Contains => {
                    params.push(format!("%{value}%"));
                    format!("{field} LIKE ? COLLATE NOCASE")
                }
                MatchMode::Cidr => {
                    params.push(value.clone());
                    format!("cidr_match({field}, ?)")
                }
                MatchMode::Any => format!("{field} != ''"),
            },
            Condition::Text { needle } => {
                params.push(needle.clone());
                "raw_contains(raw_file, byte_offset, ?)".to_string()
            }
        }
    }

    /// Evaluate this leaf directly against a JSON record — used by
    /// `siemctl alerts`, which has no SQLite backing (alerts are flat
    /// JSONL, not indexed). Field-comparison semantics mirror `to_sql`'s
    /// SQL exactly: `Exact`/`NotExact` are case-sensitive (SQL `=`/`!=`);
    /// `StartsWith`/`EndsWith`/`Contains` are case-insensitive (SQLite's
    /// default `LIKE` behavior for ASCII, and the explicit `COLLATE
    /// NOCASE` on `Contains`). A field that doesn't resolve on this record
    /// behaves like SQL `NULL` — every comparison against it is false,
    /// including `NotExact` (SQL `NULL != 'x'` is `NULL`, not `TRUE`).
    fn eval_json(&self, record: &serde_json::Value) -> bool {
        match self {
            Condition::Field { field, value, mode } => {
                let resolved = resolve_json_field(record, field).and_then(json_scalar_to_string);
                match mode {
                    MatchMode::Exact => resolved.as_deref() == Some(value.as_str()),
                    MatchMode::NotExact => {
                        resolved.as_deref().map(|r| r != value).unwrap_or(false)
                    }
                    MatchMode::StartsWith => resolved
                        .map(|r| r.to_lowercase().starts_with(&value.to_lowercase()))
                        .unwrap_or(false),
                    MatchMode::EndsWith => resolved
                        .map(|r| r.to_lowercase().ends_with(&value.to_lowercase()))
                        .unwrap_or(false),
                    MatchMode::Contains => resolved
                        .map(|r| r.to_lowercase().contains(&value.to_lowercase()))
                        .unwrap_or(false),
                    MatchMode::Cidr => {
                        resolved.map(|r| db::cidr_contains(value, &r).unwrap_or(false)).unwrap_or(false)
                    }
                    MatchMode::Any => resolved.map(|r| !r.is_empty()).unwrap_or(false),
                }
            }
            // No `raw_file`/`byte_offset` backing exists for an alert record —
            // the record itself is the payload, so "full text" search is a
            // substring test over its whole serialized form. Case-sensitive,
            // matching `raw_contains`'s `line.contains(&needle)` in db.rs.
            Condition::Text { needle } => {
                serde_json::to_string(record).map(|s| s.contains(needle.as_str())).unwrap_or(false)
            }
        }
    }
}

/// Resolve `field` against an alert record, checking (in order): the
/// top-level key, then `event.<field>` (a `ruled` alert's embedded event),
/// then `sample_events[0].<field>` (a correlated alert's first sample).
/// `null` resolves to "absent", same as a `NULL` SQL column. Returns the
/// native JSON value (not stringified) so `siemctl alerts`' `SELECT`
/// projection (in `alerts.rs`) can keep numeric/bool typing in its JSON
/// output; `eval_json`'s WHERE-clause matching collapses it to a string via
/// [`json_scalar_to_string`] below. Both must share this one traversal so a
/// field resolves identically whether it's filtered on or projected.
pub(crate) fn resolve_json_field<'a>(
    record: &'a serde_json::Value,
    field: &str,
) -> Option<&'a serde_json::Value> {
    record
        .get(field)
        .or_else(|| record.get("event").and_then(|e| e.get(field)))
        .or_else(|| record.get("sample_events").and_then(|arr| arr.get(0)).and_then(|e| e.get(field)))
        .filter(|v| !v.is_null())
}

pub(crate) fn json_scalar_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None, // array or object: not comparable as a scalar
    }
}

impl Expr {
    /// Emit this tree's SQL predicate (in-order), pushing bound params in
    /// evaluation order.
    fn to_sql(&self, params: &mut Vec<String>) -> String {
        match self {
            Expr::And(a, b) => format!("({} AND {})", a.to_sql(params), b.to_sql(params)),
            Expr::Or(a, b) => format!("({} OR {})", a.to_sql(params), b.to_sql(params)),
            Expr::Not(e) => format!("(NOT {})", e.to_sql(params)),
            Expr::Cond(c) => c.to_sql(params),
        }
    }

    /// Evaluate this tree directly against a JSON record. See
    /// [`Condition::eval_json`] for leaf semantics.
    pub(crate) fn eval_json(&self, record: &serde_json::Value) -> bool {
        match self {
            Expr::And(a, b) => a.eval_json(record) && b.eval_json(record),
            Expr::Or(a, b) => a.eval_json(record) || b.eval_json(record),
            Expr::Not(e) => !e.eval_json(record),
            Expr::Cond(c) => c.eval_json(record),
        }
    }
}

impl Query {
    /// Parse a DSL string into a [`Query`]. `valid` is the set of indexed field
    /// names from `sources.toml` (empty = skip the membership check).
    pub fn parse(dsl: &str, valid: &HashSet<String>) -> Result<Query, String> {
        let toks = lex(dsl)?;
        let mut p = Parser { toks, pos: 0, valid };
        let (select, expr, group_by, limit) = p.parse_query()?;
        Ok(Query { select, expr, group_by, limit, after: None, before: None })
    }

    /// Compile to per-bucket `(sql, params)`. Row mode selects whole rows (the
    /// executor resolves each to its raw line); group mode emits per-combo counts
    /// (LIMIT is applied after the cross-bucket merge, not here).
    pub fn to_sql(&self) -> (String, Vec<String>) {
        let mut params = Vec::new();
        let where_clause = match &self.expr {
            Some(e) => format!(" WHERE {}", e.to_sql(&mut params)),
            None => String::new(),
        };
        let sql = match &self.group_by {
            Some(fields) => {
                let cols = fields.join(", ");
                format!("SELECT {cols}, COUNT(*) FROM events{where_clause} GROUP BY {cols}")
            }
            None => {
                let limit_clause = match self.limit {
                    Some(n) => format!(" LIMIT {n}"),
                    None => String::new(),
                };
                format!("SELECT * FROM events{where_clause}{limit_clause}")
            }
        };
        (sql, params)
    }

    /// True if `db_path`'s hour bucket falls outside the `[after, before]` range.
    fn bucket_pruned(&self, db_path: &Path) -> bool {
        let Some(name) = db_path.file_name().and_then(|n| n.to_str()) else {
            return false;
        };
        let Some(bkt) = time::HourBucket::from_filename(name) else {
            return false;
        };
        self.after.map(|a| bkt < a).unwrap_or(false) || self.before.map(|b| bkt > b).unwrap_or(false)
    }
}

// ── Executor ─────────────────────────────────────────────────────────────────

/// Collect, sorted, the `.db` bucket files under `data_dir/index/`.
pub(crate) fn index_buckets(data_dir: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let idx_dir = data_dir.join("index");
    if !idx_dir.is_dir() {
        return Err("no index directory found — run 'indexd' to build the index first, \
                    or use --raw for a direct raw-file scan"
            .into());
    }
    let mut dbs: Vec<PathBuf> = std::fs::read_dir(&idx_dir)?
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "db").unwrap_or(false))
        .map(|e| e.path())
        .collect();
    dbs.sort();
    if dbs.is_empty() {
        return Err("index directory exists but contains no buckets — run 'indexd' to index \
                    your logs, or use --raw for a direct raw-file scan"
            .into());
    }
    Ok(dbs)
}

/// True for the benign per-bucket errors we swallow: a bucket whose schema
/// lacks a referenced column or the `events` table entirely (e.g. an older or
/// differently-configured bucket). Any other error is surfaced.
pub(crate) fn is_benign(msg: &str) -> bool {
    msg.contains("no such column") || msg.contains("no such table")
}

/// Extract the column name from a SQLite "no such column: X" error, if present.
fn extract_missing_col(msg: &str) -> Option<String> {
    let prefix = "no such column: ";
    let pos = msg.find(prefix)?;
    Some(msg[pos + prefix.len()..].trim().to_string())
}

fn warn_schema_skipped(count: usize, cols: &BTreeSet<String>) {
    if cols.is_empty() {
        eprintln!("siemctl: warning: {count} bucket(s) skipped — schema mismatch \
                   (add fields to sources.toml and run 'reload index')");
    } else {
        let quoted: Vec<_> = cols.iter().map(|c| format!("'{c}'")).collect();
        let noun = if quoted.len() == 1 { "column" } else { "columns" };
        eprintln!(
            "siemctl: warning: {count} bucket(s) skipped — {noun} {} not in schema \
             (add to sources.toml and run 'reload index', or use raw_contains() for ad-hoc searches)",
            quoted.join(", ")
        );
    }
}

/// Execute a parsed [`Query`] across the index and render results. Returns the
/// process exit code (0 = hits, 1 = no matches).
pub fn run_query<W: std::io::Write>(
    data_dir: &Path,
    query: &Query,
    renderer: &mut Renderer<W>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let dbs = index_buckets(data_dir)?;
    let (sql, params) = query.to_sql();

    match &query.group_by {
        Some(fields) => run_group(data_dir, query, &dbs, &sql, &params, fields, renderer),
        None => run_rows(data_dir, query, &dbs, &sql, &params, renderer),
    }
}

fn run_rows<W: std::io::Write>(
    data_dir: &Path,
    query: &Query,
    dbs: &[PathBuf],
    sql: &str,
    params: &[String],
    renderer: &mut Renderer<W>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let mut total = 0usize;
    let mut schema_skipped = 0usize;
    let mut missing_cols: BTreeSet<String> = BTreeSet::new();
    for db_path in dbs {
        if query.bucket_pruned(db_path) {
            continue;
        }
        let conn = match db::open_bucket_conn(db_path, data_dir) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("siemctl: {}: {e}", db_path.display());
                continue;
            }
        };
        match db::run_row_query(&conn, sql, params, data_dir, renderer) {
            Ok(n) => total += n,
            Err(e) => {
                let msg = e.to_string();
                if is_benign(&msg) {
                    schema_skipped += 1;
                    if let Some(col) = extract_missing_col(&msg) {
                        missing_cols.insert(col);
                    }
                } else {
                    eprintln!("siemctl: {}: {e}", db_path.display());
                }
            }
        }
        if renderer.is_done() {
            break;
        }
    }
    if schema_skipped > 0 {
        warn_schema_skipped(schema_skipped, &missing_cols);
    }
    if total == 0 {
        eprintln!("siemctl: no matches found");
        return Ok(1);
    }
    Ok(0)
}

fn run_group<W: std::io::Write>(
    data_dir: &Path,
    query: &Query,
    dbs: &[PathBuf],
    sql: &str,
    params: &[String],
    fields: &[String],
    renderer: &mut Renderer<W>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let mut acc: BTreeMap<Vec<String>, u64> = BTreeMap::new();
    let mut schema_skipped = 0usize;
    let mut missing_cols: BTreeSet<String> = BTreeSet::new();
    for db_path in dbs {
        if query.bucket_pruned(db_path) {
            continue;
        }
        let conn = match db::open_bucket_conn(db_path, data_dir) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("siemctl: {}: {e}", db_path.display());
                continue;
            }
        };
        if let Err(e) = db::fold_group_sql(&conn, sql, params, fields.len(), &mut acc) {
            let msg = e.to_string();
            if is_benign(&msg) {
                schema_skipped += 1;
                if let Some(col) = extract_missing_col(&msg) {
                    missing_cols.insert(col);
                }
            } else {
                eprintln!("siemctl: {}: {e}", db_path.display());
            }
        }
    }

    if schema_skipped > 0 {
        warn_schema_skipped(schema_skipped, &missing_cols);
    }
    if acc.is_empty() {
        eprintln!("siemctl: no matches found");
        return Ok(1);
    }

    // Sort by count descending, ties broken by the group key ascending.
    let mut entries: Vec<(Vec<String>, u64)> = acc.into_iter().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    for (keyvals, count) in entries {
        let mut rec: Record = Vec::with_capacity(fields.len() + 1);
        for (f, v) in fields.iter().zip(keyvals.iter()) {
            rec.push((f.clone(), Val::Str(v.clone())));
        }
        rec.push(("count".to_string(), Val::Int(count as i64)));
        let _ = renderer.emit_record(&rec);
        if renderer.is_done() {
            break;
        }
    }
    Ok(0)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> HashSet<String> {
        HashSet::new()
    }

    fn parse(dsl: &str) -> Result<Query, String> {
        Query::parse(dsl, &empty())
    }

    fn cond_field(field: &str, value: &str, mode: MatchMode) -> Expr {
        Expr::Cond(Condition::Field { field: field.into(), value: value.into(), mode })
    }

    // ── parser ────────────────────────────────────────────────────────────

    #[test]
    fn optional_where_and_quotes_equivalent() {
        let a = parse("WHERE app_name == 'apache'").unwrap();
        let b = parse("app_name == apache").unwrap();
        let c = parse("'app_name' = \"apache\"").unwrap();
        let expected = Some(cond_field("app_name", "apache", MatchMode::Exact));
        assert_eq!(a.expr, expected);
        assert_eq!(b.expr, expected);
        assert_eq!(c.expr, expected);
    }

    #[test]
    fn and_binds_tighter_than_or() {
        // A AND B OR C  =>  (A AND B) OR C
        let q = parse("a == 1 AND b == 2 OR c == 3").unwrap();
        let expected = Expr::Or(
            Box::new(Expr::And(
                Box::new(cond_field("a", "1", MatchMode::Exact)),
                Box::new(cond_field("b", "2", MatchMode::Exact)),
            )),
            Box::new(cond_field("c", "3", MatchMode::Exact)),
        );
        assert_eq!(q.expr, Some(expected));
    }

    #[test]
    fn parens_override_precedence() {
        let q = parse("a == 1 AND (b == 2 OR c == 3)").unwrap();
        let expected = Expr::And(
            Box::new(cond_field("a", "1", MatchMode::Exact)),
            Box::new(Expr::Or(
                Box::new(cond_field("b", "2", MatchMode::Exact)),
                Box::new(cond_field("c", "3", MatchMode::Exact)),
            )),
        );
        assert_eq!(q.expr, Some(expected));
    }

    #[test]
    fn not_and_neq() {
        assert_eq!(
            parse("NOT a == 1").unwrap().expr,
            Some(Expr::Not(Box::new(cond_field("a", "1", MatchMode::Exact))))
        );
        assert_eq!(
            parse("a != 1").unwrap().expr,
            Some(cond_field("a", "1", MatchMode::NotExact))
        );
        assert_eq!(
            parse("a <> 1").unwrap().expr,
            Some(cond_field("a", "1", MatchMode::NotExact))
        );
    }

    #[test]
    fn functions_map_to_conditions() {
        assert_eq!(parse("startswith(x,'v')").unwrap().expr, Some(cond_field("x", "v", MatchMode::StartsWith)));
        assert_eq!(parse("endswith(x,'v')").unwrap().expr, Some(cond_field("x", "v", MatchMode::EndsWith)));
        assert_eq!(parse("contains(x,'v')").unwrap().expr, Some(cond_field("x", "v", MatchMode::Contains)));
        assert_eq!(parse("any(x)").unwrap().expr, Some(cond_field("x", "", MatchMode::Any)));
        assert_eq!(parse("cidr_match(src_ip,'10.0.0.0/8')").unwrap().expr, Some(cond_field("src_ip", "10.0.0.0/8", MatchMode::Cidr)));
        assert_eq!(
            parse("raw_contains('GET HTTPS')").unwrap().expr,
            Some(Expr::Cond(Condition::Text { needle: "GET HTTPS".into() }))
        );
    }

    #[test]
    fn group_by_and_limit() {
        let q = parse("a == 1 GROUP BY dst_ip, url LIMIT 5").unwrap();
        assert_eq!(q.group_by, Some(vec!["dst_ip".to_string(), "url".to_string()]));
        assert_eq!(q.limit, Some(5));
        assert!(q.expr.is_some());
    }

    #[test]
    fn empty_and_group_only_match_all() {
        assert_eq!(parse("").unwrap().expr, None);
        let q = parse("GROUP BY src_ip").unwrap();
        assert_eq!(q.expr, None);
        assert_eq!(q.group_by, Some(vec!["src_ip".to_string()]));
    }

    #[test]
    fn select_fields_parsed() {
        let q = parse("SELECT timestamp,src_ip,username WHERE src_ip == 10.0.0.1").unwrap();
        assert_eq!(q.select, Some(vec!["timestamp".into(), "src_ip".into(), "username".into()]));
        assert!(q.expr.is_some());
    }

    #[test]
    fn select_standalone_match_all() {
        let q = parse("SELECT src_ip,event_type").unwrap();
        assert_eq!(q.select, Some(vec!["src_ip".into(), "event_type".into()]));
        assert_eq!(q.expr, None);
        assert_eq!(q.group_by, None);
    }

    #[test]
    fn select_with_group_by_and_limit() {
        let q = parse("SELECT src_ip,count GROUP BY src_ip LIMIT 10").unwrap();
        assert_eq!(q.select, Some(vec!["src_ip".into(), "count".into()]));
        assert_eq!(q.group_by, Some(vec!["src_ip".into()]));
        assert_eq!(q.limit, Some(10));
    }

    #[test]
    fn select_allows_non_indexed_fields() {
        // Non-indexed fields (e.g. `message`) should parse without error even
        // when a non-empty valid set is provided.
        let mut valid = HashSet::new();
        valid.insert("src_ip".to_string());
        let q = Query::parse("SELECT message,src_ip", &valid).unwrap();
        assert_eq!(q.select, Some(vec!["message".into(), "src_ip".into()]));
    }

    #[test]
    fn select_absent_means_none() {
        let q = parse("src_ip == 10.0.0.1").unwrap();
        assert_eq!(q.select, None);
    }

    #[test]
    fn design_doc_example_tree() {
        // From §5.1 — AND binds tighter than OR.
        let dsl = "source == 'unifi' AND app_name == 'apache' \
                   AND raw_contains('GET HTTPS') \
                   OR cidr_match('src_ip','10.0.0.0/8') \
                   GROUP BY dst_ip, url";
        let q = parse(dsl).unwrap();
        let left = Expr::And(
            Box::new(Expr::And(
                Box::new(cond_field("source", "unifi", MatchMode::Exact)),
                Box::new(cond_field("app_name", "apache", MatchMode::Exact)),
            )),
            Box::new(Expr::Cond(Condition::Text { needle: "GET HTTPS".into() })),
        );
        let expected = Expr::Or(
            Box::new(left),
            Box::new(cond_field("src_ip", "10.0.0.0/8", MatchMode::Cidr)),
        );
        assert_eq!(q.expr, Some(expected));
        assert_eq!(q.group_by, Some(vec!["dst_ip".to_string(), "url".to_string()]));
    }

    // ── parser errors ───────────────────────────────────────────────────────

    #[test]
    fn error_unknown_function() {
        assert!(parse("frobnicate(x,'v')").unwrap_err().contains("unknown function"));
    }

    #[test]
    fn error_bad_identifier() {
        // is_sql_ident rejects a leading digit.
        assert!(parse("1bad == x").unwrap_err().contains("invalid field name"));
    }

    #[test]
    fn error_unknown_field_when_valid_set_nonempty() {
        let mut valid = HashSet::new();
        valid.insert("src_ip".to_string());
        let err = Query::parse("dst_ip == 1", &valid).unwrap_err();
        assert!(err.contains("unknown field 'dst_ip'"), "got: {err}");
    }

    #[test]
    fn error_wrong_arity() {
        assert!(parse("any(a,b)").unwrap_err().contains("expects 1"));
        assert!(parse("startswith(a)").unwrap_err().contains("expects 2"));
    }

    #[test]
    fn error_dangling_operator_and_unbalanced_parens() {
        assert!(parse("a ==").is_err());
        assert!(parse("(a == 1").is_err());
        assert!(parse("a == 1)").is_err());
    }

    #[test]
    fn error_bad_cidr_literal() {
        assert!(parse("cidr_match(src_ip,'10.0.0.0/99')").is_err());
        assert!(parse("cidr_match(src_ip,'not-a-cidr')").is_err());
    }

    // ── compiler ──────────────────────────────────────────────────────────

    fn sql_of(dsl: &str) -> (String, Vec<String>) {
        parse(dsl).unwrap().to_sql()
    }

    #[test]
    fn compile_single_field() {
        let (sql, params) = sql_of("src_ip == 10.0.0.5");
        assert_eq!(sql, "SELECT * FROM events WHERE src_ip = ?");
        assert_eq!(params, vec!["10.0.0.5".to_string()]);
    }

    #[test]
    fn compile_and_or_not() {
        let (sql, params) = sql_of("a == 1 AND b == 2");
        assert_eq!(sql, "SELECT * FROM events WHERE (a = ? AND b = ?)");
        assert_eq!(params, vec!["1".to_string(), "2".to_string()]);

        let (sql, _) = sql_of("a == 1 OR b == 2");
        assert_eq!(sql, "SELECT * FROM events WHERE (a = ? OR b = ?)");

        let (sql, _) = sql_of("NOT a == 1");
        assert_eq!(sql, "SELECT * FROM events WHERE (NOT a = ?)");
    }

    #[test]
    fn compile_field_plus_raw_contains() {
        let (sql, params) = sql_of("app_name == apache AND raw_contains('GET')");
        assert_eq!(
            sql,
            "SELECT * FROM events WHERE (app_name = ? AND raw_contains(raw_file, byte_offset, ?))"
        );
        assert_eq!(params, vec!["apache".to_string(), "GET".to_string()]);
    }

    #[test]
    fn compile_like_and_cidr_and_any() {
        let (sql, params) = sql_of("startswith(event_type,'ssh')");
        assert_eq!(sql, "SELECT * FROM events WHERE event_type LIKE ?");
        assert_eq!(params, vec!["ssh%".to_string()]);

        let (sql, params) = sql_of("contains(msg,'fail')");
        assert_eq!(sql, "SELECT * FROM events WHERE msg LIKE ? COLLATE NOCASE");
        assert_eq!(params, vec!["%fail%".to_string()]);

        let (sql, params) = sql_of("cidr_match(src_ip,'10.0.0.0/8')");
        assert_eq!(sql, "SELECT * FROM events WHERE cidr_match(src_ip, ?)");
        assert_eq!(params, vec!["10.0.0.0/8".to_string()]);

        let (sql, params) = sql_of("any(username)");
        assert_eq!(sql, "SELECT * FROM events WHERE username != ''");
        assert!(params.is_empty());
    }

    #[test]
    fn compile_match_all_and_group() {
        let (sql, params) = sql_of("");
        assert_eq!(sql, "SELECT * FROM events");
        assert!(params.is_empty());

        let (sql, params) = sql_of("GROUP BY src_ip, dst_ip");
        assert_eq!(sql, "SELECT src_ip, dst_ip, COUNT(*) FROM events GROUP BY src_ip, dst_ip");
        assert!(params.is_empty());

        let (sql, params) = sql_of("source == sshd GROUP BY src_ip");
        assert_eq!(sql, "SELECT src_ip, COUNT(*) FROM events WHERE source = ? GROUP BY src_ip");
        assert_eq!(params, vec!["sshd".to_string()]);
    }

    #[test]
    fn compile_row_limit_in_sql() {
        let (sql, _) = sql_of("a == 1 LIMIT 10");
        assert_eq!(sql, "SELECT * FROM events WHERE a = ? LIMIT 10");
    }

    #[test]
    fn values_are_always_bound_never_inline() {
        // No user value should appear literally in the SQL string.
        let (sql, params) = sql_of("a == secret123 OR contains(b,'topsecret')");
        assert!(!sql.contains("secret123"));
        assert!(!sql.contains("topsecret"));
        assert!(params.contains(&"secret123".to_string()));
        assert!(params.contains(&"%topsecret%".to_string()));
    }

    // ── schema-skip warning ───────────────────────────────────────────────────

    #[test]
    fn extract_missing_col_parses_sqlite_error() {
        assert_eq!(extract_missing_col("no such column: event_type"), Some("event_type".into()));
        assert_eq!(extract_missing_col("no such column: src_ip"), Some("src_ip".into()));
        // "no such table" has no column name to extract
        assert_eq!(extract_missing_col("no such table: events"), None);
        assert_eq!(extract_missing_col("some other error"), None);
    }

    // ── executor (end-to-end over a temp index) ──────────────────────────────

    use rusqlite::Connection;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_CTR: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        fn new() -> Self {
            let n = TMP_CTR.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir()
                .join(format!("siemctl_query_test_{}_{}", std::process::id(), n));
            fs::create_dir_all(&p).unwrap();
            TempDir { path: p }
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// Build a `data_dir` with one raw JSONL file and one index bucket whose
    /// rows point back into it via `raw_file` + `byte_offset`.
    fn build_index(data_dir: &Path, bucket: &str, src: &str, rows: &[(&str, &str, &str)]) {
        // rows: (source, src_ip, msg) → JSON line in raw/<src>.jsonl
        let raw_dir = data_dir.join("raw");
        fs::create_dir_all(&raw_dir).unwrap();
        let idx_dir = data_dir.join("index");
        fs::create_dir_all(&idx_dir).unwrap();

        let raw_rel = format!("raw/{src}.jsonl");
        let mut content = String::new();
        let mut offsets = Vec::new();
        for (source, src_ip, msg) in rows {
            offsets.push(content.len() as i64);
            content.push_str(&format!(
                "{{\"source\":\"{source}\",\"src_ip\":\"{src_ip}\",\"msg\":\"{msg}\"}}\n"
            ));
        }
        // Append, so multiple buckets can share the file with correct offsets.
        let existing = fs::read_to_string(data_dir.join(&raw_rel)).unwrap_or_default();
        let base = existing.len() as i64;
        fs::write(
            data_dir.join(&raw_rel),
            format!("{existing}{content}"),
        )
        .unwrap();

        let conn = Connection::open(idx_dir.join(format!("{bucket}.db"))).unwrap();
        conn.execute_batch(
            "CREATE TABLE events (source TEXT, src_ip TEXT, raw_file TEXT, byte_offset INTEGER);",
        )
        .unwrap();
        for (i, (source, src_ip, _)) in rows.iter().enumerate() {
            conn.execute(
                "INSERT INTO events (source, src_ip, raw_file, byte_offset) VALUES (?1,?2,?3,?4)",
                rusqlite::params![source, src_ip, raw_rel, base + offsets[i]],
            )
            .unwrap();
        }
    }

    fn run(data_dir: &Path, dsl: &str) -> (i32, String) {
        let q = Query::parse(dsl, &empty()).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        let rc = {
            let mut r = Renderer::new(crate::render::Format::Json, None, &mut buf, q.limit);
            let rc = run_query(data_dir, &q, &mut r).unwrap();
            r.flush().unwrap();
            rc
        };
        (rc, String::from_utf8(buf).unwrap())
    }

    #[test]
    fn exec_multi_condition_and_resolves_raw_lines() {
        let tmp = TempDir::new();
        build_index(
            &tmp.path,
            "2026-06-22-08",
            "sshd",
            &[
                ("sshd", "10.0.0.1", "Failed password for root"),
                ("sshd", "10.0.0.2", "Accepted publickey"),
                ("sudo", "10.0.0.3", "Failed password attempt"),
            ],
        );

        let (rc, out) = run(&tmp.path, "source == sshd AND raw_contains('Failed')");
        assert_eq!(rc, 0);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1, "only the sshd+Failed row, got: {out}");
        assert!(lines[0].contains("10.0.0.1"));
    }

    #[test]
    fn exec_field_plus_text() {
        let tmp = TempDir::new();
        build_index(
            &tmp.path,
            "2026-06-22-08",
            "sshd",
            &[
                ("sshd", "10.0.0.1", "Failed password"),
                ("sshd", "10.0.0.2", "Failed password"),
            ],
        );
        let (rc, out) = run(&tmp.path, "src_ip == 10.0.0.2 AND raw_contains('Failed')");
        assert_eq!(rc, 0);
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("10.0.0.2"));
    }

    #[test]
    fn exec_filter_then_group() {
        let tmp = TempDir::new();
        build_index(
            &tmp.path,
            "2026-06-22-08",
            "sshd",
            &[
                ("sshd", "10.0.0.1", "a"),
                ("sshd", "10.0.0.1", "b"),
                ("sshd", "10.0.0.2", "c"),
                ("sudo", "10.0.0.1", "d"),
            ],
        );
        let (rc, out) = run(&tmp.path, "source == sshd GROUP BY src_ip");
        assert_eq!(rc, 0);
        // sshd rows only: 10.0.0.1 x2 (sorted first by count desc), 10.0.0.2 x1.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("10.0.0.1") && lines[0].contains("\"count\":2"));
        assert!(lines[1].contains("10.0.0.2") && lines[1].contains("\"count\":1"));
    }

    #[test]
    fn exec_group_merges_across_buckets() {
        let tmp = TempDir::new();
        build_index(&tmp.path, "2026-06-22-08", "sshd", &[
            ("sshd", "10.0.0.1", "a"),
            ("sshd", "10.0.0.1", "b"),
        ]);
        build_index(&tmp.path, "2026-06-22-09", "sshd", &[
            ("sshd", "10.0.0.1", "c"),
            ("sshd", "10.0.0.2", "d"),
        ]);
        let (rc, out) = run(&tmp.path, "GROUP BY src_ip");
        assert_eq!(rc, 0);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].contains("10.0.0.1") && lines[0].contains("\"count\":3"));
        assert!(lines.iter().any(|l| l.contains("10.0.0.2") && l.contains("\"count\":1")));
    }

    #[test]
    fn exec_after_prunes_buckets() {
        let tmp = TempDir::new();
        build_index(&tmp.path, "2026-06-22-08", "sshd", &[("sshd", "10.0.0.1", "early")]);
        build_index(&tmp.path, "2026-06-22-10", "sshd", &[("sshd", "10.0.0.2", "late")]);

        let mut q = Query::parse("any(src_ip)", &empty()).unwrap();
        q.after = Some(time::HourBucket::parse("2026-06-22T09").unwrap());
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut r = Renderer::new(crate::render::Format::Json, None, &mut buf, None);
            run_query(&tmp.path, &q, &mut r).unwrap();
            r.flush().unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("late") && !out.contains("early"), "got: {out}");
    }

    #[test]
    fn exec_no_match_returns_1() {
        let tmp = TempDir::new();
        build_index(&tmp.path, "2026-06-22-08", "sshd", &[("sshd", "10.0.0.1", "x")]);
        let (rc, out) = run(&tmp.path, "src_ip == 9.9.9.9");
        assert_eq!(rc, 1);
        assert!(out.is_empty());
    }

    // ── eval_json (siemctl alerts' JSON-backed evaluation path) ────────────

    fn ruled_alert() -> serde_json::Value {
        serde_json::json!({
            "_ruled": true,
            "rule_id": "1001-ssh-brute-force",
            "rule_title": "SSH Brute Force Detection",
            "level": "medium",
            "timestamp": 1783026390,
            "event": {
                "_source_type": "sshd",
                "event_type": "ssh_auth_failure",
                "src_ip": "10.0.0.5",
                "_raw": "Failed password for root from 10.0.0.5 port 22 ssh2"
            }
        })
    }

    fn correlated_alert() -> serde_json::Value {
        serde_json::json!({
            "_correlated": true,
            "correlation_id": "cred-guess",
            "correlation_title": "Credential Guessing",
            "join_field": "src_ip",
            "join_value": "10.0.0.5",
            "chain_start": 100,
            "chain_end": 200,
            "step_counts": [3, 1],
            "sample_events": [
                { "src_ip": "10.0.0.5", "username": "root" }
            ]
        })
    }

    fn eval(dsl: &str, record: &serde_json::Value) -> bool {
        parse(dsl).unwrap().expr.unwrap().eval_json(record)
    }

    #[test]
    fn eval_json_top_level_field_on_ruled_alert() {
        assert!(eval("rule_id == '1001-ssh-brute-force'", &ruled_alert()));
        assert!(eval("level == medium", &ruled_alert()));
        assert!(!eval("level == high", &ruled_alert()));
    }

    #[test]
    fn eval_json_falls_back_to_embedded_event() {
        // src_ip isn't top-level on a ruled alert — resolves via `event.src_ip`.
        assert!(eval("src_ip == 10.0.0.5", &ruled_alert()));
        assert!(eval("event_type == ssh_auth_failure", &ruled_alert()));
    }

    #[test]
    fn eval_json_falls_back_to_first_sample_event_for_correlated() {
        // No top-level or `event` object on a correlated alert — resolves
        // via `sample_events[0].<field>`.
        assert!(eval("src_ip == 10.0.0.5", &correlated_alert()));
        assert!(eval("username == root", &correlated_alert()));
    }

    #[test]
    fn eval_json_type_tag_distinguishes_alert_shapes() {
        let mut ruled = ruled_alert();
        ruled["type"] = serde_json::json!("ruled");
        let mut correlated = correlated_alert();
        correlated["type"] = serde_json::json!("correlated");

        assert!(eval("type == correlated", &correlated));
        assert!(!eval("type == correlated", &ruled));
        assert!(eval("type == ruled", &ruled));
    }

    #[test]
    fn eval_json_level_never_matches_correlated_alert() {
        // Correlated alerts carry no `level` field at all (see module doc
        // comment) — a level filter must simply not match, not error.
        assert!(!eval("level == high", &correlated_alert()));
        assert!(!eval("level == medium", &correlated_alert()));
    }

    #[test]
    fn eval_json_not_exact_is_false_when_field_absent() {
        // Mirrors SQL NULL semantics: NULL != 'x' is NULL (falsy), not true.
        assert!(!eval("nonexistent_field != anything", &ruled_alert()));
    }

    #[test]
    fn eval_json_any_requires_presence_and_non_empty() {
        assert!(eval("any(rule_id)", &ruled_alert()));
        assert!(!eval("any(nonexistent_field)", &ruled_alert()));
    }

    #[test]
    fn eval_json_startswith_endswith_contains_are_case_insensitive() {
        assert!(eval("startswith(rule_title,'SSH')", &ruled_alert()));
        assert!(eval("startswith(rule_title,'ssh')", &ruled_alert())); // case-insensitive
        assert!(eval("endswith(rule_title,'detection')", &ruled_alert()));
        assert!(eval("contains(rule_title,'BRUTE')", &ruled_alert()));
        assert!(!eval("contains(rule_title,'nonexistent')", &ruled_alert()));
    }

    #[test]
    fn eval_json_cidr_match_on_resolved_field() {
        assert!(eval("cidr_match(src_ip,'10.0.0.0/24')", &ruled_alert()));
        assert!(!eval("cidr_match(src_ip,'192.168.0.0/24')", &ruled_alert()));
    }

    #[test]
    fn eval_json_raw_contains_searches_whole_serialized_record() {
        // No raw_file/byte_offset backing for alerts — Text conditions search
        // the record's own serialized JSON instead.
        assert!(eval("raw_contains('Failed password')", &ruled_alert()));
        assert!(!eval("raw_contains('nonexistent phrase')", &ruled_alert()));
    }

    #[test]
    fn eval_json_and_or_not_compose() {
        let alert = ruled_alert();
        assert!(eval("rule_id == '1001-ssh-brute-force' AND src_ip == 10.0.0.5", &alert));
        assert!(!eval("rule_id == '1001-ssh-brute-force' AND src_ip == 9.9.9.9", &alert));
        assert!(eval("level == high OR level == medium", &alert));
        assert!(eval("NOT level == high", &alert));
    }

    #[test]
    fn eval_json_select_projection_resolves_nested_fields_too() {
        // resolve_json_field is shared between eval_json's WHERE matching and
        // alerts.rs's SELECT projection — confirm it round-trips a nested
        // field's native JSON type (not just a stringified comparison).
        let alert = ruled_alert();
        let v = resolve_json_field(&alert, "src_ip").unwrap();
        assert_eq!(v, &serde_json::json!("10.0.0.5"));
        assert_eq!(resolve_json_field(&alert, "nonexistent_field"), None);
    }
}

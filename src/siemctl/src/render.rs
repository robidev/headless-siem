//! Output rendering for `siemctl search`.
//!
//! Every search path — indexed rows, full-text grep, and time-range dump —
//! feeds its results through a single [`Renderer`] so that `--render` (field
//! selection) and `--format` (json / tsv) behave identically regardless of
//! where the record came from.
//!
//! Two entry points:
//!   - [`Renderer::emit_record`] for structured records (index rows).
//!   - [`Renderer::emit_raw_line`] for raw JSONL hits (grep / dump / a resolved
//!     `--full` record). In the common case (default JSON, no field selection)
//!     the line is passed through verbatim with no parse; otherwise it is
//!     parsed so field selection / TSV columns can apply.

use std::io::{self, Write};

/// Output format selected by `--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    /// Tab-separated values; `header` controls the leading header row.
    Tsv { header: bool },
}

impl Format {
    /// Parse a `--format` value: `json` | `tsv` | `tsv-noheader`.
    pub fn parse(s: &str) -> Result<Format, String> {
        match s {
            "json" => Ok(Format::Json),
            "tsv" => Ok(Format::Tsv { header: true }),
            "tsv-noheader" => Ok(Format::Tsv { header: false }),
            other => Err(format!(
                "invalid --format '{other}' (expected: json, tsv, tsv-noheader)"
            )),
        }
    }
}

/// A typed field value. Keeping the type (rather than stringifying early) lets
/// JSON re-serialization preserve string vs. number vs. bool vs. null.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Str(String),
    Int(i64),
    Real(f64),
    Bool(bool),
    Null,
}

impl Val {
    /// Render for a TSV cell: bare text, with tab/newline/CR neutralized to
    /// spaces so a value can't break the column layout.
    fn to_tsv(&self) -> String {
        match self {
            Val::Str(s) => s.replace(['\t', '\n', '\r'], " "),
            Val::Int(n) => n.to_string(),
            Val::Real(f) => f.to_string(),
            Val::Bool(b) => b.to_string(),
            Val::Null => String::new(),
        }
    }

    /// Render as a JSON value token.
    fn to_json(&self) -> String {
        match self {
            Val::Str(s) => format!("\"{}\"", json_escape(s)),
            Val::Int(n) => n.to_string(),
            Val::Real(f) => f.to_string(),
            Val::Bool(b) => b.to_string(),
            Val::Null => "null".to_string(),
        }
    }
}

/// An ordered record: (field, value) pairs preserving insertion order.
pub type Record = Vec<(String, Val)>;

/// Renders search results to a writer in the selected format.
pub struct Renderer<W: Write> {
    format: Format,
    /// `--render` allowlist: output these fields, in this order. `None` = all.
    fields: Option<Vec<String>>,
    out: W,
    /// Resolved TSV column set, fixed on the first emitted row.
    tsv_cols: Option<Vec<String>>,
    header_done: bool,
    limit: Option<usize>,
    emitted: usize,
}

impl<W: Write> Renderer<W> {
    pub fn new(format: Format, fields: Option<Vec<String>>, out: W, limit: Option<usize>) -> Self {
        Renderer { format, fields, out, tsv_cols: None, header_done: false, limit, emitted: 0 }
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    /// Returns true when the `--limit` has been reached and no more records
    /// will be emitted. Callers should break their scan loops on this signal.
    pub fn is_done(&self) -> bool {
        self.limit.map(|lim| self.emitted >= lim).unwrap_or(false)
    }

    /// Emit a structured record (e.g. one index row).
    pub fn emit_record(&mut self, rec: &Record) -> io::Result<()> {
        if self.is_done() { return Ok(()); }
        let r = self.write_rec(rec);
        self.emitted += 1;
        r
    }

    /// Emit a raw JSONL line (a grep/dump hit, or a resolved `--full` record).
    ///
    /// Default JSON with no field selection prints the line verbatim (no parse,
    /// exact byte-for-byte output). Otherwise the line is parsed so selection /
    /// TSV apply; an unparseable line passes through (JSON) or is skipped (TSV,
    /// where there are no columns to extract). Skipped TSV lines do not count
    /// against `--limit`.
    pub fn emit_raw_line(&mut self, line: &str) -> io::Result<()> {
        if self.is_done() { return Ok(()); }
        if self.format == Format::Json && self.fields.is_none() {
            self.emitted += 1;
            return writeln!(self.out, "{line}");
        }
        match parse_flat_object(line) {
            Some(rec) => {
                self.emitted += 1;
                self.write_rec(&rec)
            }
            None => match self.format {
                Format::Json => {
                    self.emitted += 1;
                    writeln!(self.out, "{line}")
                }
                Format::Tsv { .. } => Ok(()), // skip, don't count against limit
            },
        }
    }

    /// Internal write path: no limit check, no counting.
    fn write_rec(&mut self, rec: &Record) -> io::Result<()> {
        match self.format {
            Format::Json => {
                let json = self.render_json(rec);
                writeln!(self.out, "{json}")
            }
            Format::Tsv { header } => self.emit_tsv(rec, header),
        }
    }

    fn render_json(&self, rec: &Record) -> String {
        let parts: Vec<String> = match &self.fields {
            Some(fields) => fields
                .iter()
                .map(|f| {
                    let v = lookup(rec, f).cloned().unwrap_or(Val::Null);
                    format!("\"{}\":{}", json_escape(f), v.to_json())
                })
                .collect(),
            None => rec
                .iter()
                .map(|(k, v)| format!("\"{}\":{}", json_escape(k), v.to_json()))
                .collect(),
        };
        format!("{{{}}}", parts.join(","))
    }

    fn emit_tsv(&mut self, rec: &Record, header: bool) -> io::Result<()> {
        // Fix the column set on the first row: explicit --render fields, else
        // this record's keys (stable for the rest of the output).
        if self.tsv_cols.is_none() {
            let cols = match &self.fields {
                Some(f) => f.clone(),
                None => rec.iter().map(|(k, _)| k.clone()).collect(),
            };
            self.tsv_cols = Some(cols);
        }
        let cols = self.tsv_cols.clone().unwrap_or_default();

        if header && !self.header_done {
            writeln!(self.out, "{}", cols.join("\t"))?;
            self.header_done = true;
        }
        let row: Vec<String> = cols
            .iter()
            .map(|c| lookup(rec, c).map(Val::to_tsv).unwrap_or_default())
            .collect();
        writeln!(self.out, "{}", row.join("\t"))
    }
}

fn lookup<'a>(rec: &'a Record, key: &str) -> Option<&'a Val> {
    rec.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Parse one flat JSON object line into an ordered record. Returns `None` if
/// the line is not a JSON object. Nested arrays/objects (which normalized
/// output never produces) are kept as their raw JSON text.
fn parse_flat_object(line: &str) -> Option<Record> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let obj = value.as_object()?;
    Some(obj.iter().map(|(k, v)| (k.clone(), json_to_val(v))).collect())
}

pub(crate) fn json_to_val(v: &serde_json::Value) -> Val {
    use serde_json::Value;
    match v {
        Value::Null => Val::Null,
        Value::Bool(b) => Val::Bool(*b),
        Value::Number(n) => n
            .as_i64()
            .map(Val::Int)
            .unwrap_or_else(|| Val::Real(n.as_f64().unwrap_or(0.0))),
        Value::String(s) => Val::Str(s.clone()),
        other => Val::Str(other.to_string()),
    }
}

/// Escape a string for inclusion in a JSON double-quoted value.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(pairs: &[(&str, Val)]) -> Record {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    fn render(format: Format, fields: Option<Vec<String>>, recs: &[Record]) -> String {
        let mut buf = Vec::new();
        {
            let mut r = Renderer::new(format, fields, &mut buf, None);
            for rc in recs {
                r.emit_record(rc).unwrap();
            }
            r.flush().unwrap();
        }
        String::from_utf8(buf).unwrap()
    }

    fn flds(s: &str) -> Option<Vec<String>> {
        Some(s.split(',').map(String::from).collect())
    }

    #[test]
    fn format_parse_variants() {
        assert_eq!(Format::parse("json"), Ok(Format::Json));
        assert_eq!(Format::parse("tsv"), Ok(Format::Tsv { header: true }));
        assert_eq!(Format::parse("tsv-noheader"), Ok(Format::Tsv { header: false }));
        assert!(Format::parse("yaml").is_err());
    }

    #[test]
    fn json_all_fields_preserves_order_and_types() {
        let r = rec(&[
            ("src_ip", Val::Str("10.0.0.5".into())),
            ("dst_port", Val::Int(22)),
            ("ok", Val::Bool(true)),
            ("note", Val::Null),
        ]);
        let out = render(Format::Json, None, &[r]);
        assert_eq!(
            out,
            "{\"src_ip\":\"10.0.0.5\",\"dst_port\":22,\"ok\":true,\"note\":null}\n"
        );
    }

    #[test]
    fn json_field_selection_orders_by_render_and_nulls_missing() {
        let r = rec(&[
            ("src_ip", Val::Str("10.0.0.5".into())),
            ("username", Val::Str("root".into())),
        ]);
        let out = render(Format::Json, flds("username,absent"), &[r]);
        assert_eq!(out, "{\"username\":\"root\",\"absent\":null}\n");
    }

    #[test]
    fn tsv_with_header_and_selected_fields() {
        let recs = [
            rec(&[("src_ip", Val::Str("10.0.0.1".into())), ("username", Val::Str("a".into()))]),
            rec(&[("src_ip", Val::Str("10.0.0.2".into())), ("username", Val::Str("b".into()))]),
        ];
        let out = render(Format::Tsv { header: true }, flds("src_ip,username"), &recs);
        assert_eq!(out, "src_ip\tusername\n10.0.0.1\ta\n10.0.0.2\tb\n");
    }

    #[test]
    fn tsv_noheader_skips_header_row() {
        let recs = [rec(&[("a", Val::Str("1".into())), ("b", Val::Int(2))])];
        let out = render(Format::Tsv { header: false }, flds("a,b"), &recs);
        assert_eq!(out, "1\t2\n");
    }

    #[test]
    fn tsv_all_fields_uses_first_record_columns() {
        let recs = [
            rec(&[("a", Val::Str("1".into())), ("b", Val::Str("2".into()))]),
            // second record missing "b", extra "c" → only first-row columns shown
            rec(&[("a", Val::Str("3".into())), ("c", Val::Str("9".into()))]),
        ];
        let out = render(Format::Tsv { header: true }, None, &recs);
        assert_eq!(out, "a\tb\n1\t2\n3\t\n");
    }

    #[test]
    fn tsv_neutralizes_embedded_tabs_and_newlines() {
        let recs = [rec(&[("msg", Val::Str("a\tb\nc".into()))])];
        let out = render(Format::Tsv { header: false }, flds("msg"), &recs);
        assert_eq!(out, "a b c\n");
    }

    #[test]
    fn raw_line_passthrough_in_default_json() {
        let mut buf = Vec::new();
        {
            let mut r = Renderer::new(Format::Json, None, &mut buf, None);
            r.emit_raw_line("{\"z\":1,\"a\":\"x\"}").unwrap();
            r.flush().unwrap();
        }
        // Verbatim: order and formatting preserved exactly, no parse.
        assert_eq!(String::from_utf8(buf).unwrap(), "{\"z\":1,\"a\":\"x\"}\n");
    }

    #[test]
    fn raw_line_parsed_for_field_selection() {
        let mut buf = Vec::new();
        {
            let mut r = Renderer::new(Format::Json, flds("a"), &mut buf, None);
            r.emit_raw_line("{\"a\":\"x\",\"b\":2}").unwrap();
            r.flush().unwrap();
        }
        assert_eq!(String::from_utf8(buf).unwrap(), "{\"a\":\"x\"}\n");
    }

    #[test]
    fn raw_line_parsed_for_tsv() {
        let mut buf = Vec::new();
        {
            let mut r = Renderer::new(Format::Tsv { header: true }, flds("b,a"), &mut buf, None);
            r.emit_raw_line("{\"a\":\"x\",\"b\":7}").unwrap();
            r.flush().unwrap();
        }
        assert_eq!(String::from_utf8(buf).unwrap(), "b\ta\n7\tx\n");
    }

    #[test]
    fn unparseable_raw_line_passes_through_json_skipped_tsv() {
        // JSON + render: not an object → passthrough.
        let mut buf = Vec::new();
        {
            let mut r = Renderer::new(Format::Json, flds("a"), &mut buf, None);
            r.emit_raw_line("not json").unwrap();
            r.flush().unwrap();
        }
        assert_eq!(String::from_utf8(buf).unwrap(), "not json\n");

        // TSV: nothing to emit.
        let mut buf2 = Vec::new();
        {
            let mut r = Renderer::new(Format::Tsv { header: true }, flds("a"), &mut buf2, None);
            r.emit_raw_line("not json").unwrap();
            r.flush().unwrap();
        }
        assert_eq!(String::from_utf8(buf2).unwrap(), "");
    }

    #[test]
    fn limit_stops_emission_at_n() {
        let recs: Vec<Record> = (0..5)
            .map(|i| rec(&[("n", Val::Int(i))]))
            .collect();
        let mut buf = Vec::new();
        {
            let mut r = Renderer::new(Format::Json, None, &mut buf, Some(3));
            for rc in &recs {
                r.emit_record(rc).unwrap();
            }
            r.flush().unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(out.lines().count(), 3, "expected exactly 3 lines, got:\n{out}");
        assert!(out.contains("\"n\":0") && out.contains("\"n\":2"));
        assert!(!out.contains("\"n\":3"), "should not emit past limit");
    }

    #[test]
    fn limit_larger_than_total_passes_all() {
        let recs: Vec<Record> = (0..3)
            .map(|i| rec(&[("n", Val::Int(i))]))
            .collect();
        let out = render(Format::Json, None, &recs);
        assert_eq!(out.lines().count(), 3);
    }

    #[test]
    fn is_done_reflects_limit() {
        let mut buf = Vec::new();
        let mut r = Renderer::new(Format::Json, None, &mut buf, Some(2));
        assert!(!r.is_done());
        r.emit_record(&rec(&[("x", Val::Int(1))])).unwrap();
        assert!(!r.is_done());
        r.emit_record(&rec(&[("x", Val::Int(2))])).unwrap();
        assert!(r.is_done());
        // emit after done is a no-op
        r.emit_record(&rec(&[("x", Val::Int(3))])).unwrap();
        r.flush().unwrap();
        assert_eq!(String::from_utf8(buf).unwrap().lines().count(), 2);
    }
}

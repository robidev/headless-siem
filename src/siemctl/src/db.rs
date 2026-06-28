use rusqlite::{Connection, OpenFlags};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::Path;

use crate::render::{Record, Renderer, Val};

/// How to compare a field value in a WHERE clause.
///
/// Extension point: add variants here (e.g. `Regex`, `Range`, `Not`) and handle
/// them in `FieldFilter::to_sql` without touching any command-level code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    Exact,
    StartsWith,
    EndsWith,
    Contains,
    /// IPv4 CIDR range: fetch all non-empty rows and filter in Rust.
    Cidr,
    /// Match any non-empty value: `field != ''`. No --value needed.
    Any,
}

/// Parse an IPv4 address string into a u32 (big-endian).
fn ipv4_to_u32(s: &str) -> Option<u32> {
    let mut parts = s.split('.');
    let a: u32 = parts.next()?.parse().ok()?;
    let b: u32 = parts.next()?.parse().ok()?;
    let c: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() { return None; } // extra octets
    if a > 255 || b > 255 || c > 255 || d > 255 { return None; }
    Some((a << 24) | (b << 16) | (c << 8) | d)
}

/// Test whether `ip` falls within the CIDR range `cidr` (e.g. `"10.0.0.0/24"`).
/// Returns `Err` with a message if `cidr` is malformed.
pub fn cidr_contains(cidr: &str, ip: &str) -> Result<bool, String> {
    let (net_str, prefix_str) = cidr.split_once('/')
        .ok_or_else(|| format!("invalid CIDR (missing /): {cidr}"))?;

    let prefix_len: u32 = prefix_str.parse()
        .map_err(|_| format!("invalid CIDR prefix length: {prefix_str}"))?;
    if prefix_len > 32 {
        return Err(format!("CIDR prefix length out of range (0-32): {prefix_len}"));
    }

    // Reject IPv6 CIDRs early with a clear message
    if cidr.contains(':') {
        return Err("IPv6 CIDR not supported yet".to_string());
    }

    let net = ipv4_to_u32(net_str)
        .ok_or_else(|| format!("invalid CIDR network address: {net_str}"))?;

    let ip_u32 = match ipv4_to_u32(ip) {
        Some(v) => v,
        None => return Ok(false), // stored value isn't a valid IPv4 — skip it
    };

    if prefix_len == 0 {
        return Ok(true); // /0 matches everything
    }

    let mask = !0u32 << (32 - prefix_len);
    Ok((ip_u32 & mask) == (net & mask))
}

/// A single indexed-field search filter.
///
/// Future search features (multi-field AND, OR, exclusions, CIDR, numeric ranges)
/// can be added as additional fields or via a wrapper `Query` struct that holds
/// `Vec<Condition>` where `Condition` wraps `FieldFilter` and future variants.
#[derive(Debug, Clone)]
pub struct FieldFilter {
    pub field: String,
    pub value: String,
    pub mode: MatchMode,
}

impl FieldFilter {
    /// Parse `"field_name"` or `"field_name|modifier"` + a value string.
    /// For `|any`, value is ignored (pass `""` from the call site).
    pub fn parse(field_arg: &str, value: &str) -> Self {
        let (field, mode) = if let Some(b) = field_arg.strip_suffix("|startswith") {
            (b.to_string(), MatchMode::StartsWith)
        } else if let Some(b) = field_arg.strip_suffix("|endswith") {
            (b.to_string(), MatchMode::EndsWith)
        } else if let Some(b) = field_arg.strip_suffix("|contains") {
            (b.to_string(), MatchMode::Contains)
        } else if let Some(b) = field_arg.strip_suffix("|cidr") {
            (b.to_string(), MatchMode::Cidr)
        } else if let Some(b) = field_arg.strip_suffix("|any") {
            (b.to_string(), MatchMode::Any)
        } else {
            (field_arg.to_string(), MatchMode::Exact)
        };
        Self { field, value: value.to_string(), mode }
    }

    /// Base field name without any modifier suffix (used for validation).
    pub fn base_field(&self) -> &str {
        &self.field
    }

    fn sql_pattern(&self) -> String {
        match self.mode {
            MatchMode::Exact => self.value.clone(),
            MatchMode::StartsWith => format!("{}%", self.value),
            MatchMode::EndsWith => format!("%{}", self.value),
            MatchMode::Contains => format!("%{}%", self.value),
            MatchMode::Cidr | MatchMode::Any => String::new(), // no bind param
        }
    }

    fn sql_predicate(&self) -> String {
        let op = match self.mode {
            MatchMode::Exact => "= ?",
            MatchMode::Contains => "LIKE ? COLLATE NOCASE",
            MatchMode::Cidr | MatchMode::Any => "!= ''", // no bind param
            _ => "LIKE ?",
        };
        format!("{} {}", self.field, op)
    }
}

/// Resolve the original JSONL line for an index row using `raw_file` + `byte_offset`.
///
/// `raw_file` must be relative to `data_dir`. Returns `Err(reason)` on any
/// failure so the caller can fall back and log a useful message.
fn resolve_raw_line(data_dir: &Path, raw_file: &str, byte_offset: u64) -> Result<String, String> {
    if raw_file.is_empty() {
        return Err("no raw_file stored (pre-T5 index row)".to_string());
    }
    let path = data_dir.join(raw_file);
    let mut f = std::fs::File::open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.seek(SeekFrom::Start(byte_offset))
        .map_err(|e| format!("seek to {byte_offset} failed: {e}"))?;
    let mut line = String::new();
    BufReader::new(f)
        .read_line(&mut line)
        .map_err(|e| format!("read failed: {e}"))?;
    let trimmed = line.trim_end_matches(['\n', '\r']).to_string();
    if trimmed.is_empty() {
        Err(format!("empty line at offset {byte_offset} in {}", path.display()))
    } else {
        Ok(trimmed)
    }
}

/// Open a single SQLite index bucket (read-only) and emit matching rows through
/// `renderer`. Returns the row count emitted.
///
/// When `full` is true and `data_dir` is provided, each hit resolves the
/// original JSONL line via `raw_file` + `byte_offset` and emits that instead of
/// the index row. Falls back to the index row if the raw file is missing or the
/// row pre-dates T5 (no raw_file stored).
pub fn query_bucket<W: Write>(
    db_path: &Path,
    filter: &FieldFilter,
    source_filter: Option<&str>,
    data_dir: Option<&Path>,
    full: bool,
    renderer: &mut Renderer<W>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    if filter.mode == MatchMode::Cidr {
        // Validate CIDR once before touching the DB
        cidr_contains(&filter.value, "0.0.0.0")
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        return Ok(print_rows_cidr(&conn, filter, source_filter, data_dir, full, renderer)?);
    }

    let mut where_parts = vec![filter.sql_predicate()];
    // Any generates a static predicate (field != '') with no bind parameter
    let mut params: Vec<String> = if filter.mode == MatchMode::Any {
        vec![]
    } else {
        vec![filter.sql_pattern()]
    };

    if let Some(src) = source_filter {
        where_parts.push("source = ?".to_string());
        params.push(src.to_string());
    }

    let sql = format!("SELECT * FROM events WHERE {}", where_parts.join(" AND "));
    Ok(print_rows(&conn, &sql, &params, data_dir, full, renderer)?)
}

fn print_rows<W: Write>(
    conn: &Connection,
    sql: &str,
    params: &[String],
    data_dir: Option<&Path>,
    full: bool,
    renderer: &mut Renderer<W>,
) -> rusqlite::Result<usize> {
    let mut stmt = conn.prepare(sql)?;

    let col_names: Vec<String> = (0..stmt.column_count())
        .filter_map(|i| stmt.column_name(i).ok().map(str::to_string))
        .collect();

    let raw_file_col = col_names.iter().position(|c| c == "raw_file");
    let byte_offset_col = col_names.iter().position(|c| c == "byte_offset");

    let param_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let mut rows = stmt.query(param_refs.as_slice())?;
    let mut count = 0;

    while let Some(row) = rows.next()? {
        emit_row(row, &col_names, raw_file_col, byte_offset_col, data_dir, full, renderer);
        count += 1;
        if renderer.is_done() { break; }
    }
    Ok(count)
}

/// Fetch candidate rows for CIDR search (field != '') then filter in Rust.
fn print_rows_cidr<W: Write>(
    conn: &Connection,
    filter: &FieldFilter,
    source_filter: Option<&str>,
    data_dir: Option<&Path>,
    full: bool,
    renderer: &mut Renderer<W>,
) -> rusqlite::Result<usize> {
    let mut where_parts = vec![filter.sql_predicate()]; // "field != ''"
    let mut params: Vec<String> = vec![];

    if let Some(src) = source_filter {
        where_parts.push("source = ?".to_string());
        params.push(src.to_string());
    }

    let sql = format!("SELECT * FROM events WHERE {}", where_parts.join(" AND "));
    let mut stmt = conn.prepare(&sql)?;

    let col_names: Vec<String> = (0..stmt.column_count())
        .filter_map(|i| stmt.column_name(i).ok().map(str::to_string))
        .collect();

    let field_col = col_names.iter().position(|c| c == &filter.field);
    let raw_file_col = col_names.iter().position(|c| c == "raw_file");
    let byte_offset_col = col_names.iter().position(|c| c == "byte_offset");

    let param_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let mut rows = stmt.query(param_refs.as_slice())?;
    let mut count = 0;

    while let Some(row) = rows.next()? {
        let ip_val: String = field_col
            .and_then(|i| row.get::<_, String>(i).ok())
            .unwrap_or_default();

        if !cidr_contains(&filter.value, &ip_val).unwrap_or(false) {
            continue;
        }

        emit_row(row, &col_names, raw_file_col, byte_offset_col, data_dir, full, renderer);
        count += 1;
        if renderer.is_done() { break; }
    }
    Ok(count)
}

/// Run `SELECT f1,f2,…, COUNT(*) FROM events [WHERE source = ?] GROUP BY f1,f2,…`
/// against a single bucket and fold the counts into `acc`, keyed by the ordered
/// group-field values (NULL rendered as empty string). Because each bucket is a
/// separate DB, the caller calls this once per bucket against a shared `acc` to
/// merge counts across the whole time range.
///
/// `fields` must already be validated as safe SQL identifiers by the caller
/// (they are interpolated into the query, not bound).
pub fn group_bucket(
    db_path: &Path,
    fields: &[String],
    source_filter: Option<&str>,
    acc: &mut BTreeMap<Vec<String>, u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    use rusqlite::types::ValueRef;

    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let cols = fields.join(", ");
    let (where_clause, params): (String, Vec<String>) = match source_filter {
        Some(src) => (" WHERE source = ?".to_string(), vec![src.to_string()]),
        None => (String::new(), vec![]),
    };
    let sql = format!("SELECT {cols}, COUNT(*) FROM events{where_clause} GROUP BY {cols}");

    let mut stmt = conn.prepare(&sql)?;
    let n = fields.len();
    let param_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
    let mut rows = stmt.query(param_refs.as_slice())?;

    while let Some(row) = rows.next()? {
        let mut key = Vec::with_capacity(n);
        for i in 0..n {
            let part = match row.get_ref(i)? {
                ValueRef::Null => String::new(),
                ValueRef::Integer(v) => v.to_string(),
                ValueRef::Real(v) => v.to_string(),
                ValueRef::Text(b) => String::from_utf8_lossy(b).into_owned(),
                ValueRef::Blob(_) => String::new(),
            };
            key.push(part);
        }
        let count: i64 = row.get(n)?;
        *acc.entry(key).or_insert(0) += count as u64;
    }
    Ok(())
}

/// Emit one matched row: the resolved raw line when `full`, otherwise the index
/// row. On any `--full` resolution failure, warns and falls back to the index
/// row so a hit is never silently dropped. Write errors are ignored (matching
/// the previous best-effort `println!` behavior).
fn emit_row<W: Write>(
    row: &rusqlite::Row,
    col_names: &[String],
    raw_file_col: Option<usize>,
    byte_offset_col: Option<usize>,
    data_dir: Option<&Path>,
    full: bool,
    renderer: &mut Renderer<W>,
) {
    if full {
        if let (Some(rf_idx), Some(bo_idx), Some(dd)) = (raw_file_col, byte_offset_col, data_dir) {
            let raw_file: String = row.get::<_, String>(rf_idx).unwrap_or_default();
            let byte_offset: i64 = row.get::<_, i64>(bo_idx).unwrap_or(-1);
            if byte_offset >= 0 {
                match resolve_raw_line(dd, &raw_file, byte_offset as u64) {
                    Ok(line) => {
                        let _ = renderer.emit_raw_line(&line);
                        return;
                    }
                    Err(msg) => {
                        eprintln!("siemctl: --full retrieval failed ({msg}); showing index row");
                    }
                }
            } else {
                eprintln!("siemctl: --full: no raw_file/offset in this row (pre-T5 index?); showing index row");
            }
        }
    }
    let _ = renderer.emit_record(&row_to_record(row, col_names));
}

/// Convert a SQLite row into an ordered [`Record`], preserving column order.
fn row_to_record(row: &rusqlite::Row, cols: &[String]) -> Record {
    use rusqlite::types::ValueRef;
    let mut rec = Record::with_capacity(cols.len());
    for (i, col) in cols.iter().enumerate() {
        let val = match row.get_ref(i) {
            Ok(ValueRef::Null) | Err(_) => Val::Null,
            Ok(ValueRef::Integer(n)) => Val::Int(n),
            Ok(ValueRef::Real(f)) => Val::Real(f),
            Ok(ValueRef::Text(b)) => Val::Str(std::str::from_utf8(b).unwrap_or("").to_string()),
            Ok(ValueRef::Blob(_)) => Val::Null,
        };
        rec.push((col.clone(), val));
    }
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── cidr_contains unit tests ──────────────────────────────────────────

    #[test]
    fn cidr_exact_host_matches_itself() {
        assert!(cidr_contains("10.0.0.5/32", "10.0.0.5").unwrap());
    }

    #[test]
    fn cidr_exact_host_rejects_neighbor() {
        assert!(!cidr_contains("10.0.0.5/32", "10.0.0.6").unwrap());
    }

    #[test]
    fn cidr_slash24_matches_in_range() {
        assert!(cidr_contains("10.0.0.0/24", "10.0.0.1").unwrap());
        assert!(cidr_contains("10.0.0.0/24", "10.0.0.254").unwrap());
        assert!(cidr_contains("10.0.0.0/24", "10.0.0.0").unwrap());
    }

    #[test]
    fn cidr_slash24_rejects_outside_range() {
        assert!(!cidr_contains("10.0.0.0/24", "10.0.1.0").unwrap());
        assert!(!cidr_contains("10.0.0.0/24", "10.1.0.5").unwrap());
    }

    #[test]
    fn cidr_slash0_matches_all_valid_ipv4() {
        assert!(cidr_contains("0.0.0.0/0", "10.0.0.5").unwrap());
        assert!(cidr_contains("0.0.0.0/0", "192.168.1.1").unwrap());
        assert!(cidr_contains("0.0.0.0/0", "255.255.255.255").unwrap());
    }

    #[test]
    fn cidr_slash16_boundary() {
        assert!(cidr_contains("172.16.0.0/16", "172.16.255.255").unwrap());
        assert!(!cidr_contains("172.16.0.0/16", "172.17.0.0").unwrap());
    }

    #[test]
    fn cidr_invalid_prefix_len_is_error() {
        assert!(cidr_contains("10.0.0.0/33", "10.0.0.1").is_err());
    }

    #[test]
    fn cidr_missing_slash_is_error() {
        assert!(cidr_contains("10.0.0.0", "10.0.0.1").is_err());
    }

    #[test]
    fn cidr_invalid_ip_is_error() {
        assert!(cidr_contains("not-an-ip/24", "10.0.0.1").is_err());
    }

    #[test]
    fn cidr_non_ipv4_stored_value_skipped() {
        // Stored value that isn't a valid IP: returns false, not error
        assert!(!cidr_contains("10.0.0.0/24", "not-an-ip").unwrap());
        assert!(!cidr_contains("10.0.0.0/24", "").unwrap());
    }

    // ── FieldFilter::parse |cidr ──────────────────────────────────────────

    #[test]
    fn parse_cidr_modifier() {
        let f = FieldFilter::parse("src_ip|cidr", "10.0.0.0/24");
        assert_eq!(f.field, "src_ip");
        assert_eq!(f.mode, MatchMode::Cidr);
        assert_eq!(f.value, "10.0.0.0/24");
        assert_eq!(f.base_field(), "src_ip");
    }

    #[test]
    fn cidr_sql_predicate_fetches_non_empty() {
        let f = FieldFilter::parse("src_ip|cidr", "10.0.0.0/24");
        assert_eq!(f.sql_predicate(), "src_ip != ''");
    }

    // ── FieldFilter::parse |any ───────────────────────────────────────────

    #[test]
    fn parse_any_modifier() {
        let f = FieldFilter::parse("username|any", "");
        assert_eq!(f.field, "username");
        assert_eq!(f.mode, MatchMode::Any);
        assert_eq!(f.base_field(), "username");
    }

    #[test]
    fn any_sql_predicate_is_not_empty() {
        let f = FieldFilter::parse("username|any", "");
        assert_eq!(f.sql_predicate(), "username != ''");
    }

    #[test]
    fn any_sql_pattern_is_empty() {
        let f = FieldFilter::parse("username|any", "");
        assert_eq!(f.sql_pattern(), "");
    }

    // ── resolve_raw_line ──────────────────────────────────────────────────

    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_CTR: AtomicU64 = AtomicU64::new(0);

    struct TempDir { path: std::path::PathBuf }
    impl TempDir {
        fn new() -> Self {
            let n = TMP_CTR.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir()
                .join(format!("siemctl_db_test_{}_{}", std::process::id(), n));
            fs::create_dir_all(&p).unwrap();
            TempDir { path: p }
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.path); }
    }

    #[test]
    fn resolve_raw_line_first_line() {
        let tmp = TempDir::new();
        let jsonl = tmp.path.join("test.jsonl");
        fs::write(&jsonl, "{\"a\":1}\n{\"b\":2}\n").unwrap();
        let result = resolve_raw_line(&tmp.path, "test.jsonl", 0).unwrap();
        assert_eq!(result, "{\"a\":1}");
    }

    #[test]
    fn resolve_raw_line_second_line() {
        let tmp = TempDir::new();
        let line1 = "{\"timestamp\":\"Jun 22 08:55:01\",\"src_ip\":\"10.0.0.1\"}\n";
        let line2 = "{\"timestamp\":\"Jun 22 08:55:02\",\"src_ip\":\"10.0.0.2\"}\n";
        let jsonl = tmp.path.join("sshd.jsonl");
        fs::write(&jsonl, format!("{}{}", line1, line2)).unwrap();
        let offset = line1.len() as u64;
        let result = resolve_raw_line(&tmp.path, "sshd.jsonl", offset).unwrap();
        assert_eq!(result, line2.trim_end_matches(['\n', '\r']));
    }

    #[test]
    fn resolve_raw_line_empty_raw_file_returns_err() {
        let tmp = TempDir::new();
        let err = resolve_raw_line(&tmp.path, "", 0).unwrap_err();
        assert!(err.contains("no raw_file"), "got: {err}");
    }

    #[test]
    fn resolve_raw_line_missing_file_returns_err() {
        let tmp = TempDir::new();
        let err = resolve_raw_line(&tmp.path, "nonexistent.jsonl", 0).unwrap_err();
        // Error message contains the path
        assert!(err.contains("nonexistent.jsonl"), "got: {err}");
    }

    #[test]
    fn resolve_raw_line_crlf_line_stripped() {
        let tmp = TempDir::new();
        let jsonl = tmp.path.join("crlf.jsonl");
        fs::write(&jsonl, "{\"x\":1}\r\n").unwrap();
        let result = resolve_raw_line(&tmp.path, "crlf.jsonl", 0).unwrap();
        assert_eq!(result, "{\"x\":1}");
    }

    // ── group_bucket ──────────────────────────────────────────────────────

    /// Build a minimal index bucket with an `events(src_ip, dst_ip, source)`
    /// table populated from `rows`.
    fn make_bucket(path: &Path, rows: &[(&str, &str, &str)]) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE events (src_ip TEXT, dst_ip TEXT, source TEXT);",
        )
        .unwrap();
        for (src_ip, dst_ip, source) in rows {
            conn.execute(
                "INSERT INTO events (src_ip, dst_ip, source) VALUES (?1, ?2, ?3)",
                rusqlite::params![src_ip, dst_ip, source],
            )
            .unwrap();
        }
    }

    fn key(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn group_single_field_merges_across_buckets() {
        let tmp = TempDir::new();
        let db1 = tmp.path.join("2026-06-22-08.db");
        let db2 = tmp.path.join("2026-06-22-09.db");
        make_bucket(&db1, &[
            ("10.0.0.1", "a", "sshd"),
            ("10.0.0.1", "b", "sshd"),
            ("10.0.0.2", "c", "sshd"),
        ]);
        make_bucket(&db2, &[
            ("10.0.0.1", "d", "sshd"),
            ("10.0.0.3", "e", "sshd"),
        ]);

        let fields = vec!["src_ip".to_string()];
        let mut acc = BTreeMap::new();
        group_bucket(&db1, &fields, None, &mut acc).unwrap();
        group_bucket(&db2, &fields, None, &mut acc).unwrap();

        assert_eq!(acc.get(&key(&["10.0.0.1"])), Some(&3)); // 2 in db1 + 1 in db2
        assert_eq!(acc.get(&key(&["10.0.0.2"])), Some(&1));
        assert_eq!(acc.get(&key(&["10.0.0.3"])), Some(&1));
        assert_eq!(acc.len(), 3);
    }

    #[test]
    fn group_two_fields_combos_merge() {
        let tmp = TempDir::new();
        let db1 = tmp.path.join("2026-06-22-08.db");
        let db2 = tmp.path.join("2026-06-22-09.db");
        make_bucket(&db1, &[
            ("10.0.0.1", "192.168.0.1", "sshd"),
            ("10.0.0.1", "192.168.0.1", "sshd"),
            ("10.0.0.1", "192.168.0.2", "sshd"),
        ]);
        make_bucket(&db2, &[("10.0.0.1", "192.168.0.1", "sshd")]);

        let fields = vec!["src_ip".to_string(), "dst_ip".to_string()];
        let mut acc = BTreeMap::new();
        group_bucket(&db1, &fields, None, &mut acc).unwrap();
        group_bucket(&db2, &fields, None, &mut acc).unwrap();

        assert_eq!(acc.get(&key(&["10.0.0.1", "192.168.0.1"])), Some(&3)); // 2 + 1
        assert_eq!(acc.get(&key(&["10.0.0.1", "192.168.0.2"])), Some(&1));
        assert_eq!(acc.len(), 2);
    }

    #[test]
    fn group_source_filter_restricts_rows() {
        let tmp = TempDir::new();
        let db = tmp.path.join("2026-06-22-08.db");
        make_bucket(&db, &[
            ("10.0.0.1", "a", "sshd"),
            ("10.0.0.1", "b", "sudo"),
            ("10.0.0.2", "c", "sshd"),
        ]);

        let fields = vec!["src_ip".to_string()];
        let mut acc = BTreeMap::new();
        group_bucket(&db, &fields, Some("sshd"), &mut acc).unwrap();

        assert_eq!(acc.get(&key(&["10.0.0.1"])), Some(&1)); // sudo row excluded
        assert_eq!(acc.get(&key(&["10.0.0.2"])), Some(&1));
        assert_eq!(acc.len(), 2);
    }

    #[test]
    fn group_null_value_becomes_empty_key() {
        let tmp = TempDir::new();
        let db = tmp.path.join("2026-06-22-08.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE events (src_ip TEXT, source TEXT);").unwrap();
        conn.execute("INSERT INTO events (src_ip, source) VALUES (NULL, 'sshd')", []).unwrap();
        conn.execute("INSERT INTO events (src_ip, source) VALUES ('10.0.0.1', 'sshd')", []).unwrap();
        drop(conn);

        let fields = vec!["src_ip".to_string()];
        let mut acc = BTreeMap::new();
        group_bucket(&db, &fields, None, &mut acc).unwrap();

        assert_eq!(acc.get(&key(&[""])), Some(&1));
        assert_eq!(acc.get(&key(&["10.0.0.1"])), Some(&1));
    }
}

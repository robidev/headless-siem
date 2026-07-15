use rusqlite::{Connection, ErrorCode, OpenFlags};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::render::{Record, Renderer, Val};

/// How to compare a field value in a WHERE clause.
///
/// Used by the query compiler (`query.rs`) to turn a parsed `Condition::Field`
/// into a SQL predicate. `Cidr` compiles to the `cidr_match` UDF; the rest are
/// plain SQL comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    Exact,
    /// `!=` / `<>` — field does not equal the value.
    NotExact,
    StartsWith,
    EndsWith,
    Contains,
    /// IPv4 CIDR range, evaluated by the `cidr_match` SQLite UDF.
    Cidr,
    /// Match any non-empty value: `field != ''`. No value needed.
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

/// Register the `siemctl` SQLite UDFs on a per-bucket connection.
///
/// - `cidr_match(col, 'a.b.c.d/n') -> bool` — deterministic IPv4 CIDR test,
///   wrapping [`cidr_contains`]. A malformed CIDR yields `false` (CIDR literals
///   are validated at DSL parse time, so this is only a defensive net).
/// - `raw_contains(raw_file, byte_offset, 'needle') -> bool` — non-deterministic
///   substring test against the row's original raw JSONL line, resolved on
///   demand via [`resolve_raw_line`]. Any IO error yields `false` (never `Err`)
///   so one unreadable file can't abort the whole bucket statement.
pub fn register_udfs(conn: &Connection, data_dir: &Path) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;

    conn.create_scalar_function(
        "cidr_match",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let ip: String = ctx.get(0)?;
            let cidr: String = ctx.get(1)?;
            Ok(cidr_contains(&cidr, &ip).unwrap_or(false))
        },
    )?;

    let dd = data_dir.to_path_buf();
    conn.create_scalar_function(
        "raw_contains",
        3,
        FunctionFlags::SQLITE_UTF8,
        move |ctx| {
            let raw_file: String = ctx.get(0)?;
            let byte_offset: i64 = ctx.get(1)?;
            let needle: String = ctx.get(2)?;
            if byte_offset < 0 {
                return Ok(false);
            }
            Ok(match resolve_raw_line(&dd, &raw_file, byte_offset as u64) {
                Ok(line) => line.contains(&needle),
                Err(_) => false,
            })
        },
    )?;

    Ok(())
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

/// Number of attempts `open_bucket_conn` makes before giving up on a
/// `SQLITE_CANTOPEN` error, and the starting backoff delay (doubles each
/// attempt). 3 attempts at 200ms doubling = ~600ms worst case (200ms + 400ms).
///
/// Deliberately small. The "siem db unavailable during role runs" incidents
/// (llm-based-soc's archived plan issue #43 and its follow-ups) were long
/// *misdiagnosed* as a transient indexd bucket-rotation race and this retry
/// was once inflated to 9 attempts / ~51s chasing an imagined "~3-minute
/// self-heal." That is NOT what those incidents were: their real cause was
/// opening a WAL-mode bucket read-only as a different, non-owner uid (a
/// sandboxed SOC role with no write on the `user`-owned files/dir), which
/// fails deterministically with `SQLITE_READONLY`/`SQLITE_CANTOPEN` because a
/// WAL open must create/recover the `-shm`/`-wal`. Fixed at the source: indexd
/// now converts quiesced buckets out of WAL mode (`journal_mode=DELETE`) so
/// they open read-only with no write needed. Retrying a permission failure
/// never helped — it only stalled the synchronous agent run. What survives
/// here is cheap insurance against a genuine sub-second *filesystem* open race
/// (e.g. retention unlinking a bucket between the caller's `is_file()` check
/// and the open), nothing more.
const OPEN_BUCKET_MAX_ATTEMPTS: u32 = 3;
const OPEN_BUCKET_INITIAL_DELAY: Duration = Duration::from_millis(200);

/// Open a single SQLite index bucket read-only and register the `siemctl` UDFs
/// (`cidr_match`, `raw_contains`) on the connection, so a compiled query that
/// references them can run. `data_dir` is captured by `raw_contains`.
///
/// Retries a few times with a short backoff on `SQLITE_CANTOPEN` ("unable to
/// open database file") to ride out a genuine sub-second filesystem open race
/// (e.g. retention unlinking a bucket between the caller's `is_file()` check
/// and this open). This is NOT the fix for the historical "db unavailable
/// during role runs" incidents — see `OPEN_BUCKET_MAX_ATTEMPTS` for that story.
/// Other errors (including `SQLITE_READONLY`) fail immediately, unretried:
/// retrying a permission failure can't help.
pub fn open_bucket_conn(db_path: &Path, data_dir: &Path) -> rusqlite::Result<Connection> {
    open_bucket_conn_with_retry(
        db_path,
        data_dir,
        OPEN_BUCKET_MAX_ATTEMPTS,
        OPEN_BUCKET_INITIAL_DELAY,
    )
}

/// Retry-policy-parameterized core of `open_bucket_conn` — split out so
/// tests can exercise "gives up after max attempts" with a small attempt
/// count/delay instead of the real ~51s production budget.
fn open_bucket_conn_with_retry(
    db_path: &Path,
    data_dir: &Path,
    max_attempts: u32,
    initial_delay: Duration,
) -> rusqlite::Result<Connection> {
    let mut delay = initial_delay;
    for attempt in 1..=max_attempts {
        match Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(conn) => {
                register_udfs(&conn, data_dir)?;
                return Ok(conn);
            }
            Err(e) if attempt < max_attempts
                && e.sqlite_error_code() == Some(ErrorCode::CannotOpen) =>
            {
                thread::sleep(delay);
                delay *= 2;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("loop always returns by the last attempt")
}

/// Run a compiled row-mode query against one open bucket connection and emit the
/// resolved raw line for each matching row through `renderer`. Returns the row
/// count emitted. Thin wrapper over [`print_rows`] kept for symmetry with the
/// group path; the executor in `query.rs` calls it per bucket.
pub fn run_row_query<W: Write>(
    conn: &Connection,
    sql: &str,
    params: &[String],
    data_dir: &Path,
    renderer: &mut Renderer<W>,
) -> rusqlite::Result<usize> {
    // Row mode always resolves and emits the original raw line (the old
    // `--full` default), falling back to the index row when resolution fails.
    print_rows(conn, sql, params, Some(data_dir), true, renderer)
}

pub(crate) fn print_rows<W: Write>(
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

/// Run a compiled group-mode query (`SELECT f1,…, COUNT(*) … GROUP BY f1,…`)
/// against one open bucket connection and fold the counts into `acc`, keyed by
/// the ordered group-field values (NULL rendered as empty string). Because each
/// bucket is a separate DB, the executor calls this once per bucket against a
/// shared `acc` to merge counts across the whole time range.
///
/// `n_fields` is the number of leading group columns (the trailing column is the
/// `COUNT(*)`). The group fields are interpolated into `sql` by the compiler and
/// must already be validated as safe SQL identifiers.
/// Render a SQLite column value as a plain string: `NULL` → `""`, numbers via
/// their `Display` impl, text as-is (lossily, for stray non-UTF8 bytes),
/// blobs → `""` (none of siemctl's columns are ever blobs).
pub(crate) fn value_ref_to_string(v: rusqlite::types::ValueRef) -> String {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Null => String::new(),
        ValueRef::Integer(n) => n.to_string(),
        ValueRef::Real(n) => n.to_string(),
        ValueRef::Text(b) => String::from_utf8_lossy(b).into_owned(),
        ValueRef::Blob(_) => String::new(),
    }
}

pub fn fold_group_sql(
    conn: &Connection,
    sql: &str,
    params: &[String],
    n_fields: usize,
    acc: &mut BTreeMap<Vec<String>, u64>,
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(sql)?;
    let n = n_fields;
    let param_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
    let mut rows = stmt.query(param_refs.as_slice())?;

    while let Some(row) = rows.next()? {
        let mut key = Vec::with_capacity(n);
        for i in 0..n {
            key.push(value_ref_to_string(row.get_ref(i)?));
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

/// Return the column names of the `events` table in `conn` (via PRAGMA table_info).
pub fn bucket_columns(conn: &Connection) -> Vec<String> {
    let mut cols = Vec::new();
    let Ok(mut stmt) = conn.prepare("PRAGMA table_info(events)") else {
        return cols;
    };
    let Ok(mut rows) = stmt.query([]) else { return cols };
    while let Ok(Some(row)) = rows.next() {
        if let Ok(name) = row.get::<_, String>(1) {
            cols.push(name);
        }
    }
    cols
}

/// Count total events and per-field non-empty values in one SQL pass.
/// Fields that are absent from the bucket schema are silently skipped.
/// `source` optionally restricts the count to one `_source_type` value.
pub fn field_coverage(
    conn: &Connection,
    fields: &[String],
    source: Option<&str>,
) -> rusqlite::Result<(u64, HashMap<String, u64>)> {
    let cols = bucket_columns(conn);
    let existing: Vec<&String> = fields.iter().filter(|f| cols.contains(f)).collect();

    let where_clause = if source.is_some() { " WHERE _source_type = ?" } else { "" };

    if existing.is_empty() {
        let sql = format!("SELECT COUNT(*) FROM events{where_clause}");
        let total: i64 = if let Some(src) = source {
            conn.query_row(&sql, [src], |r| r.get(0))?
        } else {
            conn.query_row(&sql, [], |r| r.get(0))?
        };
        return Ok((total as u64, HashMap::new()));
    }

    let mut selects = vec!["COUNT(*)".to_string()];
    for f in &existing {
        selects.push(format!(
            "SUM(CASE WHEN {f} IS NOT NULL AND {f} != '' THEN 1 ELSE 0 END)"
        ));
    }
    let sql = format!("SELECT {} FROM events{}", selects.join(", "), where_clause);

    let row_fn = |row: &rusqlite::Row| {
        let total: i64 = row.get(0)?;
        let mut counts = HashMap::new();
        for (i, f) in existing.iter().enumerate() {
            let count: i64 = row.get(i + 1).unwrap_or(0);
            counts.insert((*f).clone(), count as u64);
        }
        Ok((total as u64, counts))
    };

    if let Some(src) = source {
        conn.query_row(&sql, [src], row_fn)
    } else {
        conn.query_row(&sql, [], row_fn)
    }
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

    // ── grouping (fold_group_sql) ─────────────────────────────────────────

    /// Test helper: open a bucket read-only and fold one bucket's grouped counts
    /// into `acc`, mirroring what the executor builds via the query compiler.
    fn group(
        db_path: &Path,
        fields: &[String],
        source: Option<&str>,
        acc: &mut BTreeMap<Vec<String>, u64>,
    ) {
        let conn =
            Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let cols = fields.join(", ");
        let (where_clause, params): (String, Vec<String>) = match source {
            Some(s) => (" WHERE source = ?".to_string(), vec![s.to_string()]),
            None => (String::new(), vec![]),
        };
        let sql = format!("SELECT {cols}, COUNT(*) FROM events{where_clause} GROUP BY {cols}");
        fold_group_sql(&conn, &sql, &params, fields.len(), acc).unwrap();
    }

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
        group(&db1, &fields, None, &mut acc);
        group(&db2, &fields, None, &mut acc);

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
        group(&db1, &fields, None, &mut acc);
        group(&db2, &fields, None, &mut acc);

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
        group(&db, &fields, Some("sshd"), &mut acc);

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
        group(&db, &fields, None, &mut acc);

        assert_eq!(acc.get(&key(&[""])), Some(&1));
        assert_eq!(acc.get(&key(&["10.0.0.1"])), Some(&1));
    }

    // ── UDFs: cidr_match / raw_contains ──────────────────────────────────────

    /// Build a bucket + matching raw `.jsonl` so `raw_contains` can resolve the
    /// row's original line. Each row stores `(src_ip, raw_file, byte_offset)`,
    /// where byte_offset points at the JSON line in `raw.jsonl`.
    fn make_udf_bucket(dir: &Path) -> std::path::PathBuf {
        let raw_dir = dir.join("raw");
        fs::create_dir_all(&raw_dir).unwrap();
        let lines = [
            "{\"src_ip\":\"10.0.0.1\",\"msg\":\"Failed password for root\"}\n",
            "{\"src_ip\":\"192.168.1.5\",\"msg\":\"Accepted publickey\"}\n",
        ];
        let mut content = String::new();
        let mut offsets = Vec::new();
        for l in &lines {
            offsets.push(content.len() as i64);
            content.push_str(l);
        }
        fs::write(raw_dir.join("sshd.jsonl"), &content).unwrap();

        let db = dir.join("2026-06-22-08.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE events (src_ip TEXT, raw_file TEXT, byte_offset INTEGER);",
        )
        .unwrap();
        for (i, off) in offsets.iter().enumerate() {
            conn.execute(
                "INSERT INTO events (src_ip, raw_file, byte_offset) VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    if i == 0 { "10.0.0.1" } else { "192.168.1.5" },
                    "raw/sshd.jsonl",
                    off
                ],
            )
            .unwrap();
        }
        db
    }

    fn scalar_count(conn: &Connection, sql: &str, params: &[&str]) -> i64 {
        let refs: Vec<&dyn rusqlite::ToSql> =
            params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        conn.query_row(sql, refs.as_slice(), |r| r.get(0)).unwrap()
    }

    #[test]
    fn raw_contains_matches_and_misses() {
        let tmp = TempDir::new();
        let db = make_udf_bucket(&tmp.path);
        let conn = open_bucket_conn(&db, &tmp.path).unwrap();

        // Matches the first row's raw line only.
        assert_eq!(
            scalar_count(
                &conn,
                "SELECT COUNT(*) FROM events WHERE raw_contains(raw_file, byte_offset, ?)",
                &["Failed password"],
            ),
            1
        );
        // Matches both rows on "src_ip".
        assert_eq!(
            scalar_count(
                &conn,
                "SELECT COUNT(*) FROM events WHERE raw_contains(raw_file, byte_offset, ?)",
                &["src_ip"],
            ),
            2
        );
        // No match.
        assert_eq!(
            scalar_count(
                &conn,
                "SELECT COUNT(*) FROM events WHERE raw_contains(raw_file, byte_offset, ?)",
                &["nonexistent-needle"],
            ),
            0
        );
    }

    #[test]
    fn raw_contains_missing_file_returns_false() {
        let tmp = TempDir::new();
        let db = tmp.path.join("2026-06-22-08.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE events (raw_file TEXT, byte_offset INTEGER);
             INSERT INTO events VALUES ('raw/missing.jsonl', 0);
             INSERT INTO events VALUES ('', 0);",
        )
        .unwrap();
        drop(conn);
        let conn = open_bucket_conn(&db, &tmp.path).unwrap();
        // Missing file and empty raw_file both resolve to no-match (not error).
        assert_eq!(
            scalar_count(
                &conn,
                "SELECT COUNT(*) FROM events WHERE raw_contains(raw_file, byte_offset, ?)",
                &["anything"],
            ),
            0
        );
    }

    #[test]
    fn open_bucket_conn_retries_transient_cantopen_then_succeeds() {
        let tmp = TempDir::new();
        let db = tmp.path.join("2026-06-22-08.db");
        // The file doesn't exist yet, so the first attempt hits SQLITE_CANTOPEN.
        // Create it shortly after — before the first backoff (200ms) elapses —
        // so the retry loop's second attempt should find it and succeed.
        let db2 = db.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            Connection::open(&db2).unwrap();
        });
        let conn = open_bucket_conn(&db, &tmp.path);
        assert!(conn.is_ok(), "expected recovery once the file appears: {:?}", conn.err());
    }

    #[test]
    fn open_bucket_conn_gives_up_after_max_attempts_on_persistent_cantopen() {
        let tmp = TempDir::new();
        // Parent directory doesn't exist and nothing will create it — CANTOPEN
        // persists, so open_bucket_conn must eventually return the error
        // instead of retrying forever. Uses the parameterized core with a
        // small attempt count/delay (not the real ~51s production budget) so
        // this test proves the same "gives up eventually" logic in
        // milliseconds instead of tens of seconds.
        let db = tmp.path.join("does-not-exist").join("2026-06-22-08.db");
        let result =
            open_bucket_conn_with_retry(&db, &tmp.path, 3, Duration::from_millis(5));
        let err = result.expect_err("expected CANTOPEN to persist and be returned");
        assert_eq!(err.sqlite_error_code(), Some(ErrorCode::CannotOpen));
    }

    #[test]
    fn cidr_match_udf_filters_by_range() {
        let tmp = TempDir::new();
        let db = make_udf_bucket(&tmp.path);
        let conn = open_bucket_conn(&db, &tmp.path).unwrap();

        // 10.0.0.1 is in 10.0.0.0/8; 192.168.1.5 is not.
        assert_eq!(
            scalar_count(&conn, "SELECT COUNT(*) FROM events WHERE cidr_match(src_ip, ?)", &["10.0.0.0/8"]),
            1
        );
        // /0 matches every valid IPv4.
        assert_eq!(
            scalar_count(&conn, "SELECT COUNT(*) FROM events WHERE cidr_match(src_ip, ?)", &["0.0.0.0/0"]),
            2
        );
        // Malformed CIDR → false for every row (defensive net).
        assert_eq!(
            scalar_count(&conn, "SELECT COUNT(*) FROM events WHERE cidr_match(src_ip, ?)", &["bogus"]),
            0
        );
    }
}

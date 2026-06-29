use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use crate::db::IndexDb;

/// Parse a single JSONL line into a map of field_name → field_value.
///
/// Only fields that appear in `index_fields` are extracted.
/// `timestamp` is required — if missing, returns `None`.
/// `_source_type` (the source label) is stored under its own name, defaulting
/// to `"unknown"` when absent — the index column matches the JSONL key, with no
/// renaming, so the same name is used by normalized, the Sigma rules, the index,
/// and siemctl.
/// `byte_offset` is the real byte offset of this line's start in the file.
/// `raw_file` is the path relative to data_dir stored as-is.
///
/// Returns `None` for malformed JSON or missing timestamp.
pub fn parse_line(
    line: &str,
    byte_offset: u64,
    raw_file: &str,
    index_fields: &[String],
) -> Option<HashMap<String, String>> {
    let raw: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("indexd: skipping malformed JSON at offset {}", byte_offset);
            return None;
        }
    };

    let obj = match &raw {
        Value::Object(map) => map,
        _ => {
            eprintln!("indexd: skipping non-object JSON at offset {}", byte_offset);
            return None;
        }
    };

    // timestamp is required
    let timestamp = obj
        .get("timestamp")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if timestamp.is_none() {
        eprintln!(
            "indexd: skipping event without timestamp at offset {}",
            byte_offset
        );
        return None;
    }

    let mut fields: HashMap<String, String> = HashMap::new();

    // Always set mandatory fields
    fields.insert("timestamp".to_string(), timestamp.unwrap());
    fields.insert("byte_offset".to_string(), byte_offset.to_string());
    fields.insert("raw_file".to_string(), raw_file.to_string());

    // Source label: stored under its own name (no remap), defaulting to
    // "unknown" when the payload omits it.
    let source_type = obj
        .get("_source_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    fields.insert("_source_type".to_string(), source_type.to_string());

    // Extract all other fields that are in index_fields
    for field_name in index_fields {
        // Skip mandatory fields already handled above
        if matches!(field_name.as_str(), "timestamp" | "_source_type" | "byte_offset" | "raw_file") {
            continue;
        }

        if let Some(value) = obj.get(field_name) {
            let str_val = match value {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => value.to_string(),
            };
            fields.insert(field_name.clone(), str_val);
        }
    }

    Some(fields)
}

/// Parse a .jsonl file and index all events into the appropriate bucket.
///
/// `data_dir` is used to compute the `raw_file` column as a path relative
/// to `data_dir` (e.g. `raw/2026/06/22/08/55/03/sshd.jsonl`), so the index
/// is portable if the whole data tree moves.
///
/// Uses `read_line` to track exact byte offsets (including the newline),
/// so `byte_offset` stored in the index can be used with `seek()` to
/// retrieve the original line.
///
/// Batches INSERTs every `batch_size` lines for performance.
/// Malformed lines and lines without timestamps are skipped with a warning.
pub fn index_file(
    db: &IndexDb,
    file_path: &Path,
    data_dir: &Path,
    batch_size: usize,
) -> io::Result<(usize, usize)> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);

    let bucket = IndexDb::derive_bucket(file_path).unwrap_or_else(|| {
        eprintln!(
            "indexd: could not derive bucket from path: {}",
            file_path.display()
        );
        "unknown".to_string()
    });

    let bucket_key = db.open_bucket(&bucket).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("failed to open bucket: {}", e))
    })?;

    // Compute raw_file as relative path from data_dir
    let raw_file: String = file_path
        .strip_prefix(data_dir)
        .ok()
        .and_then(|p| p.to_str())
        .unwrap_or_else(|| file_path.to_str().unwrap_or(""))
        .to_string();

    let index_fields = db.field_names().to_vec();
    let mut indexed = 0usize;
    let mut skipped = 0usize;
    let mut batch: Vec<HashMap<String, String>> = Vec::with_capacity(batch_size);
    let mut line_buf = String::new();
    let mut byte_offset: u64 = 0;
    let mut line_no = 0usize;

    loop {
        line_buf.clear();
        let bytes_read = reader.read_line(&mut line_buf)?;
        if bytes_read == 0 {
            break; // EOF
        }
        let line_start = byte_offset;
        byte_offset += bytes_read as u64;
        line_no += 1;

        let line = line_buf.trim_end_matches(['\n', '\r']);
        if line.is_empty() {
            continue;
        }

        match parse_line(line, line_start, &raw_file, &index_fields) {
            Some(fields) => {
                batch.push(fields);
                indexed += 1;

                if batch.len() >= batch_size {
                    flush_batch(db, &bucket_key, &batch)?;
                    batch.clear();
                }
            }
            None => {
                let _ = line_no; // suppress unused warning
                skipped += 1;
            }
        }
    }

    if !batch.is_empty() {
        flush_batch(db, &bucket_key, &batch)?;
    }

    Ok((indexed, skipped))
}

/// Flush a batch of events to the SQLite database in a single transaction.
fn flush_batch(
    db: &IndexDb,
    bucket_key: &str,
    batch: &[HashMap<String, String>],
) -> io::Result<()> {
    db.insert_batch(bucket_key, batch).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to insert batch: {}", e),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let n = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
            let dir = std::env::temp_dir()
                .join(format!("hsiem_parser_test_{}_{}", std::process::id(), n));
            fs::create_dir_all(&dir).unwrap();
            TempDir { path: dir }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn default_fields() -> Vec<String> {
        vec![
            "timestamp".to_string(),
            "_source_type".to_string(),
            "src_ip".to_string(),
            "dst_ip".to_string(),
            "event_type".to_string(),
            "severity".to_string(),
            "byte_offset".to_string(),
            "raw_file".to_string(),
        ]
    }

    #[test]
    fn test_parse_valid_line() {
        let fields = default_fields();
        let line = r#"{"timestamp":"Jun 22 08:55:03","src_ip":"10.0.0.5","_source_type":"sshd","_normalized":true}"#;
        let event = parse_line(line, 0, "raw/2026/06/22/08/55/03/sshd.jsonl", &fields).unwrap();
        assert_eq!(event.get("timestamp").unwrap(), "Jun 22 08:55:03");
        assert_eq!(event.get("_source_type").unwrap(), "sshd");
        assert_eq!(event.get("src_ip").unwrap(), "10.0.0.5");
        assert_eq!(event.get("byte_offset").unwrap(), "0");
        assert_eq!(event.get("raw_file").unwrap(), "raw/2026/06/22/08/55/03/sshd.jsonl");
    }

    #[test]
    fn test_parse_line_missing_timestamp_returns_none() {
        let fields = default_fields();
        let line = r#"{"src_ip":"10.0.0.5","_source_type":"sshd"}"#;
        let event = parse_line(line, 0, "raw/test.jsonl", &fields);
        assert!(event.is_none());
    }

    #[test]
    fn test_parse_line_malformed_json_returns_none() {
        let fields = default_fields();
        let line = "not json at all";
        let event = parse_line(line, 0, "raw/test.jsonl", &fields);
        assert!(event.is_none());
    }

    #[test]
    fn test_parse_line_missing_source_defaults_to_unknown() {
        let fields = default_fields();
        let line = r#"{"timestamp":"Jun 22 08:55:03","src_ip":"10.0.0.5"}"#;
        let event = parse_line(line, 0, "raw/test.jsonl", &fields).unwrap();
        assert_eq!(event.get("_source_type").unwrap(), "unknown");
    }

    #[test]
    fn test_parse_line_all_fields() {
        let fields = default_fields();
        let line = r#"{"timestamp":"Jun 22 08:55:03","src_ip":"10.0.0.5","dst_ip":"192.168.1.1","event_type":"SSH_FAILED","severity":"WARN","_source_type":"sshd"}"#;
        let event = parse_line(line, 0, "raw/test.jsonl", &fields).unwrap();
        assert_eq!(event.get("timestamp").unwrap(), "Jun 22 08:55:03");
        assert_eq!(event.get("_source_type").unwrap(), "sshd");
        assert_eq!(event.get("src_ip").unwrap(), "10.0.0.5");
        assert_eq!(event.get("dst_ip").unwrap(), "192.168.1.1");
        assert_eq!(event.get("event_type").unwrap(), "SSH_FAILED");
        assert_eq!(event.get("severity").unwrap(), "WARN");
    }

    #[test]
    fn test_parse_line_extra_fields_ignored() {
        let fields = default_fields();
        // JSONL has "username" but it's not in index_fields
        let line = r#"{"timestamp":"Jun 22 08:55:03","src_ip":"10.0.0.5","username":"root","_source_type":"sshd"}"#;
        let event = parse_line(line, 0, "raw/test.jsonl", &fields).unwrap();
        assert!(event.get("username").is_none());
    }

    #[test]
    fn test_parse_line_dynamic_fields() {
        // Simulate config with username and dst_port
        let fields = vec![
            "timestamp".to_string(),
            "_source_type".to_string(),
            "src_ip".to_string(),
            "dst_ip".to_string(),
            "dst_port".to_string(),
            "event_type".to_string(),
            "severity".to_string(),
            "username".to_string(),
            "byte_offset".to_string(),
            "raw_file".to_string(),
        ];
        let line = r#"{"timestamp":"Jun 22 08:55:03","src_ip":"10.0.0.5","dst_port":"22","username":"root","_source_type":"sshd"}"#;
        let event = parse_line(line, 0, "raw/test.jsonl", &fields).unwrap();
        assert_eq!(event.get("username").unwrap(), "root");
        assert_eq!(event.get("dst_port").unwrap(), "22");
    }

    #[test]
    fn test_index_file_end_to_end() {
        let tmp = TempDir::new();

        let raw_dir = tmp
            .path
            .join("raw")
            .join("2026")
            .join("06")
            .join("22")
            .join("08")
            .join("55")
            .join("03");
        fs::create_dir_all(&raw_dir).unwrap();
        let jsonl_path = raw_dir.join("sshd.jsonl");

        let mut f = File::create(&jsonl_path).unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"Jun 22 08:55:03","src_ip":"10.0.0.5","_source_type":"sshd","_normalized":true}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"Jun 22 08:55:07","src_ip":"10.0.0.5","_source_type":"sshd","_normalized":true}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"Jun 22 08:55:12","src_ip":"10.0.0.6","dst_ip":"192.168.1.1","event_type":"SSH_FAILED","severity":"WARN","_source_type":"sshd"}}"#
        )
        .unwrap();
        writeln!(f, "not json").unwrap();
        writeln!(
            f,
            r#"{{"src_ip":"10.0.0.7","_source_type":"sshd"}}"#
        )
        .unwrap(); // missing timestamp
        drop(f);

        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);
        let (indexed, skipped) = index_file(&db, &jsonl_path, &tmp.path, 100).unwrap();

        assert_eq!(indexed, 3);
        assert_eq!(skipped, 2);

        let bucket = IndexDb::derive_bucket(&jsonl_path).unwrap();
        let bucket_key = bucket.to_string();
        {
            let connections = db.connections.lock().unwrap();
            let conn = connections.get(&bucket_key).unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 3);

            let ip_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE src_ip = '10.0.0.5'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(ip_count, 2);

            // raw_file should be stored relative to tmp.path
            let raw_file: String = conn
                .query_row("SELECT raw_file FROM events LIMIT 1", [], |row| row.get(0))
                .unwrap();
            assert!(raw_file.starts_with("raw/"), "raw_file should be relative: {raw_file}");
            assert!(raw_file.ends_with("sshd.jsonl"), "raw_file ends with filename: {raw_file}");
        }

        db.close_all();
    }

    #[test]
    fn test_index_file_byte_offsets_are_real() {
        use std::io::{Seek, SeekFrom};
        use std::io::BufRead as _;

        let tmp = TempDir::new();
        let raw_dir = tmp
            .path
            .join("raw")
            .join("2026")
            .join("06")
            .join("22")
            .join("13")
            .join("00")
            .join("00");
        fs::create_dir_all(&raw_dir).unwrap();
        let jsonl_path = raw_dir.join("sshd.jsonl");

        let lines = [
            r#"{"timestamp":"Jun 22 13:00:01","src_ip":"10.1.0.1","_source_type":"sshd"}"#,
            r#"{"timestamp":"Jun 22 13:00:02","src_ip":"10.1.0.2","_source_type":"sshd"}"#,
            r#"{"timestamp":"Jun 22 13:00:03","src_ip":"10.1.0.3","_source_type":"sshd"}"#,
        ];
        let mut f = File::create(&jsonl_path).unwrap();
        for line in &lines {
            writeln!(f, "{}", line).unwrap();
        }
        drop(f);

        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);
        let (indexed, _) = index_file(&db, &jsonl_path, &tmp.path, 100).unwrap();
        assert_eq!(indexed, 3);

        let bucket = IndexDb::derive_bucket(&jsonl_path).unwrap();
        let bucket_key = bucket.to_string();

        let rows: Vec<(u64, String)> = {
            let connections = db.connections.lock().unwrap();
            let conn = connections.get(&bucket_key).unwrap();
            let mut stmt = conn
                .prepare("SELECT byte_offset, raw_file FROM events ORDER BY byte_offset")
                .unwrap();
            stmt.query_map([], |row| {
                let offset: i64 = row.get(0)?;
                let rf: String = row.get(1)?;
                Ok((offset as u64, rf))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
        };

        assert_eq!(rows.len(), 3);

        for (i, (offset, raw_file)) in rows.iter().enumerate() {
            let full_path = tmp.path.join(raw_file);
            let mut f2 = BufReader::new(File::open(&full_path).unwrap());
            f2.seek(SeekFrom::Start(*offset)).unwrap();
            let mut recovered = String::new();
            f2.read_line(&mut recovered).unwrap();
            let recovered = recovered.trim_end_matches(['\n', '\r']);
            assert_eq!(recovered, lines[i], "round-trip failed for row {i}");
        }

        db.close_all();
    }

    #[test]
    fn test_index_file_batching() {
        let tmp = TempDir::new();

        let raw_dir = tmp
            .path
            .join("raw")
            .join("2026")
            .join("06")
            .join("22")
            .join("09")
            .join("00")
            .join("00");
        fs::create_dir_all(&raw_dir).unwrap();
        let jsonl_path = raw_dir.join("sshd.jsonl");

        let mut f = File::create(&jsonl_path).unwrap();
        for i in 0..25 {
            writeln!(
                f,
                r#"{{"timestamp":"Jun 22 09:00:{:02}","src_ip":"10.0.0.{}","_source_type":"sshd"}}"#,
                i, i
            )
            .unwrap();
        }
        drop(f);

        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);
        let (indexed, skipped) = index_file(&db, &jsonl_path, &tmp.path, 10).unwrap();

        assert_eq!(indexed, 25);
        assert_eq!(skipped, 0);

        let bucket = IndexDb::derive_bucket(&jsonl_path).unwrap();
        let bucket_key = bucket.to_string();
        {
            let connections = db.connections.lock().unwrap();
            let conn = connections.get(&bucket_key).unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 25);
        }

        db.close_all();
    }

    #[test]
    fn test_index_file_empty_file() {
        let tmp = TempDir::new();

        let raw_dir = tmp
            .path
            .join("raw")
            .join("2026")
            .join("06")
            .join("22")
            .join("10")
            .join("00")
            .join("00");
        fs::create_dir_all(&raw_dir).unwrap();
        let jsonl_path = raw_dir.join("sshd.jsonl");
        File::create(&jsonl_path).unwrap();

        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);
        let (indexed, skipped) = index_file(&db, &jsonl_path, &tmp.path, 100).unwrap();

        assert_eq!(indexed, 0);
        assert_eq!(skipped, 0);

        db.close_all();
    }

    #[test]
    fn test_index_file_large_batch() {
        let tmp = TempDir::new();

        let raw_dir = tmp
            .path
            .join("raw")
            .join("2026")
            .join("06")
            .join("22")
            .join("11")
            .join("00")
            .join("00");
        fs::create_dir_all(&raw_dir).unwrap();
        let jsonl_path = raw_dir.join("sshd.jsonl");

        let mut f = File::create(&jsonl_path).unwrap();
        for i in 0..1500 {
            writeln!(
                f,
                r#"{{"timestamp":"Jun 22 11:00:{:02}","src_ip":"10.0.0.{}","_source_type":"sshd"}}"#,
                i % 60,
                i % 256
            )
            .unwrap();
        }
        drop(f);

        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);
        let (indexed, skipped) = index_file(&db, &jsonl_path, &tmp.path, 100).unwrap();

        assert_eq!(indexed, 1500);
        assert_eq!(skipped, 0);

        let bucket = IndexDb::derive_bucket(&jsonl_path).unwrap();
        let bucket_key = bucket.to_string();
        {
            let connections = db.connections.lock().unwrap();
            let conn = connections.get(&bucket_key).unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1500);
        }

        db.close_all();
    }

    #[test]
    fn test_index_file_all_malformed() {
        let tmp = TempDir::new();

        let raw_dir = tmp
            .path
            .join("raw")
            .join("2026")
            .join("06")
            .join("22")
            .join("12")
            .join("00")
            .join("00");
        fs::create_dir_all(&raw_dir).unwrap();
        let jsonl_path = raw_dir.join("sshd.jsonl");

        let mut f = File::create(&jsonl_path).unwrap();
        writeln!(f, "not json").unwrap();
        writeln!(f, "also not json").unwrap();
        writeln!(f, r#"{{"src_ip":"10.0.0.1"}}"#).unwrap(); // missing timestamp
        drop(f);

        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);
        let (indexed, skipped) = index_file(&db, &jsonl_path, &tmp.path, 100).unwrap();

        assert_eq!(indexed, 0);
        assert_eq!(skipped, 3);

        db.close_all();
    }
}

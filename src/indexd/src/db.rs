use rusqlite::{Connection, params_from_iter};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Manages per-bucket SQLite index databases.
///
/// Each time bucket (YYYY/MM/DD/HH) gets its own SQLite file at
/// `<data_dir>/index/<bucket>.db`. This keeps databases small,
/// avoids write contention, and makes retention trivial (delete
/// old .db files alongside old raw/ directories).
///
/// The schema is built dynamically from the union of all
/// `index_fields` declared in `config/sources.toml`. This means
/// adding a new field to `index_fields` in sources.toml and
/// restarting indexd is all that's needed to index it.
pub struct IndexDb {
    /// Base directory for index files (e.g. `data/index/`).
    index_dir: PathBuf,
    /// Ordered list of all indexed field names (deterministic, from config).
    index_fields: Vec<String>,
    /// Pre-computed INSERT statement for efficiency.
    insert_sql: String,
    /// Cache of open connections, keyed by bucket path.
    pub(crate) connections: Mutex<HashMap<String, Connection>>,
}

impl IndexDb {
    /// Create a new IndexDb manager.
    ///
    /// `data_dir` is the root data directory (e.g. `./data`).
    /// `index_fields` is the ordered list of all fields to index,
    /// from `Config::all_index_fields()`.
    ///
    /// Index files are stored under `<data_dir>/index/`.
    pub fn new(data_dir: &Path, index_fields: &[String]) -> Self {
        let index_dir = data_dir.join("index");

        // Pre-compute the INSERT statement
        let columns: Vec<&str> = index_fields.iter().map(|s| s.as_str()).collect();
        let placeholders: Vec<String> = (1..=columns.len())
            .map(|i| format!("?{}", i))
            .collect();
        let insert_sql = format!(
            "INSERT INTO events ({}) VALUES ({})",
            columns.join(", "),
            placeholders.join(", ")
        );

        IndexDb {
            index_dir,
            index_fields: index_fields.to_vec(),
            insert_sql,
            connections: Mutex::new(HashMap::new()),
        }
    }

    /// Return the ordered list of indexed field names.
    pub fn field_names(&self) -> &[String] {
        &self.index_fields
    }

    /// Derive the time bucket (YYYY/MM/DD/HH) from a .jsonl file path.
    ///
    /// The file path is expected to be under `data/raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl`.
    /// We walk up from the filename to find the HH directory.
    pub fn derive_bucket(file_path: &Path) -> Option<String> {
        let components: Vec<&str> = file_path
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect();

        if components.len() < 7 {
            return None;
        }

        let len = components.len();
        let year = components[len - 7];
        let month = components[len - 6];
        let day = components[len - 5];
        let hour = components[len - 4];

        if year.len() != 4 || !year.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if month.len() != 2 || !month.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if day.len() != 2 || !day.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if hour.len() != 2 || !hour.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }

        Some(format!("{}/{}/{}/{}", year, month, day, hour))
    }

    /// Open or create the SQLite database for a given bucket.
    ///
    /// Creates the schema dynamically from `index_fields` if this
    /// is the first time the bucket is opened. Every field gets a
    /// TEXT column and a corresponding index.
    ///
    /// Returns the bucket key used for subsequent operations.
    pub fn open_bucket(&self, bucket: &str) -> Result<String, rusqlite::Error> {
        let bucket_key = bucket.to_string();

        // Already open: skip the connection open + schema/index creation.
        // The initial scan touches thousands of files that map to only a
        // handful of hour buckets, so this avoids re-running CREATE TABLE +
        // CREATE INDEX once per file.
        {
            let connections = self.connections.lock().unwrap();
            if connections.contains_key(&bucket_key) {
                return Ok(bucket_key);
            }
        }

        let db_path = self.index_dir.join(format!("{}.db", bucket.replace('/', "-")));

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let conn = Connection::open(&db_path)?;
        // WAL + synchronous=NORMAL: durable against crashes (no corruption);
        // only the last few committed transactions can be lost on power loss,
        // which is acceptable for a rebuildable index and cuts fsyncs sharply.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

        // Build CREATE TABLE dynamically from index_fields
        let column_defs: Vec<String> = self
            .index_fields
            .iter()
            .map(|f| {
                if f == "byte_offset" {
                    format!("{} INTEGER NOT NULL DEFAULT 0", f)
                } else {
                    format!("{} TEXT NOT NULL DEFAULT ''", f)
                }
            })
            .collect();

        let create_table = format!(
            "CREATE TABLE IF NOT EXISTS events ({})",
            column_defs.join(", ")
        );
        conn.execute_batch(&create_table)?;

        // Create an index for every field (except byte_offset)
        for field in &self.index_fields {
            if field == "byte_offset" {
                continue;
            }
            let idx_name = format!("idx_events_{}", field);
            let create_idx = format!(
                "CREATE INDEX IF NOT EXISTS {} ON events({})",
                idx_name, field
            );
            // Ignore errors from duplicate index names (IF NOT EXISTS
            // should handle this, but be defensive)
            let _ = conn.execute_batch(&create_idx);
        }

        let mut connections = self.connections.lock().unwrap();
        connections.insert(bucket_key.clone(), conn);

        Ok(bucket_key)
    }

    /// Insert a batch of events in a single transaction.
    ///
    /// One transaction (and thus one WAL fsync) per call. `bucket_key` is the
    /// value returned by `open_bucket()`. Each map is field_name → value; only
    /// fields in `index_fields` are stored (extras ignored, missing → empty).
    /// This is the hot path for the initial scan — it dominates indexing time.
    pub fn insert_batch(
        &self,
        bucket_key: &str,
        batch: &[HashMap<String, String>],
    ) -> Result<(), rusqlite::Error> {
        if batch.is_empty() {
            return Ok(());
        }

        let mut connections = self.connections.lock().unwrap();
        let conn = connections.get_mut(bucket_key).ok_or_else(|| {
            rusqlite::Error::InvalidParameterName(format!("bucket not open: {}", bucket_key))
        })?;

        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(&self.insert_sql)?;
            for fields in batch {
                let values: Vec<String> = self
                    .index_fields
                    .iter()
                    .map(|f| fields.get(f).cloned().unwrap_or_default())
                    .collect();
                stmt.execute(params_from_iter(values.iter()))?;
            }
        }
        tx.commit()?;

        Ok(())
    }

    /// Close all open connections gracefully.
    pub fn close_all(&self) {
        let mut connections = self.connections.lock().unwrap();
        connections.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let n = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
            let dir = std::env::temp_dir()
                .join(format!("hsiem_indexd_test_{}_{}", std::process::id(), n));
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
            "source".to_string(),
            "src_ip".to_string(),
            "dst_ip".to_string(),
            "event_type".to_string(),
            "severity".to_string(),
            "byte_offset".to_string(),
            "raw_file".to_string(),
        ]
    }

    #[test]
    fn test_derive_bucket_from_path() {
        let path = Path::new("/data/raw/2026/06/22/08/55/03/sshd.jsonl");
        let bucket = IndexDb::derive_bucket(path);
        assert_eq!(bucket, Some("2026/06/22/08".to_string()));
    }

    #[test]
    fn test_derive_bucket_short_path_returns_none() {
        let path = Path::new("/data/raw/sshd.jsonl");
        let bucket = IndexDb::derive_bucket(path);
        assert_eq!(bucket, None);
    }

    #[test]
    fn test_derive_bucket_invalid_components_returns_none() {
        let path = Path::new("/data/raw/YYYY/MM/DD/HH/MM/SS/sshd.jsonl");
        let bucket = IndexDb::derive_bucket(path);
        assert_eq!(bucket, None);
    }

    #[test]
    fn test_open_bucket_creates_db_and_schema() {
        let tmp = TempDir::new();
        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);

        let key = db.open_bucket("2026/06/22/08").unwrap();
        assert_eq!(key, "2026/06/22/08");

        let db_path = tmp.path.join("index").join("2026-06-22-08.db");
        assert!(db_path.exists(), "expected {} to exist", db_path.display());

        {
            let connections = db.connections.lock().unwrap();
            let conn = connections.get(&key).unwrap();

            // Verify table exists
            let table_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='events'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(table_count, 1);

            // Verify all columns exist
            let mut stmt = conn.prepare("PRAGMA table_info(events)").unwrap();
            let col_names: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            for f in &fields {
                assert!(
                    col_names.contains(f),
                    "column '{}' should exist, got: {:?}",
                    f,
                    col_names
                );
            }

            // Verify indexes exist (one per field except byte_offset)
            let index_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name='events'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            // 7 indexes: timestamp, source, src_ip, dst_ip, event_type, severity, raw_file
            assert_eq!(index_count, 7);
        }

        db.close_all();
    }

    #[test]
    fn test_insert_and_query_event() {
        let tmp = TempDir::new();
        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);

        let key = db.open_bucket("2026/06/22/08").unwrap();

        let mut event1 = HashMap::new();
        event1.insert("timestamp".to_string(), "Jun 22 08:55:03".to_string());
        event1.insert("source".to_string(), "sshd".to_string());
        event1.insert("src_ip".to_string(), "10.0.0.5".to_string());
        event1.insert("severity".to_string(), "WARN".to_string());
        event1.insert("byte_offset".to_string(), "0".to_string());

        let mut event2 = HashMap::new();
        event2.insert("timestamp".to_string(), "Jun 22 08:55:07".to_string());
        event2.insert("source".to_string(), "sshd".to_string());
        event2.insert("src_ip".to_string(), "10.0.0.5".to_string());
        event2.insert("severity".to_string(), "WARN".to_string());
        event2.insert("byte_offset".to_string(), "150".to_string());

        db.insert_batch(&key, &[event1, event2]).unwrap();

        {
            let connections = db.connections.lock().unwrap();
            let conn = connections.get(&key).unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 2);

            let ip_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE src_ip = ?1",
                    rusqlite::params!["10.0.0.5"],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(ip_count, 2);
        }

        db.close_all();
    }

    #[test]
    fn test_insert_event_missing_fields_become_empty() {
        let tmp = TempDir::new();
        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);

        let key = db.open_bucket("2026/06/22/09").unwrap();

        // Only timestamp and source — all other fields missing
        let mut event = HashMap::new();
        event.insert("timestamp".to_string(), "Jun 22 09:00:00".to_string());
        event.insert("source".to_string(), "systemd".to_string());
        event.insert("byte_offset".to_string(), "0".to_string());

        db.insert_batch(&key, &[event]).unwrap();

        {
            let connections = db.connections.lock().unwrap();
            let conn = connections.get(&key).unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1);

            let (src_ip, severity): (String, String) = conn
                .query_row(
                    "SELECT src_ip, severity FROM events LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(src_ip, "");
            assert_eq!(severity, "");
        }

        db.close_all();
    }

    #[test]
    fn test_multiple_buckets() {
        let tmp = TempDir::new();
        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);

        let key1 = db.open_bucket("2026/06/22/08").unwrap();
        let key2 = db.open_bucket("2026/06/22/09").unwrap();

        let mut e1 = HashMap::new();
        e1.insert("timestamp".to_string(), "Jun 22 08:55:03".to_string());
        e1.insert("source".to_string(), "sshd".to_string());
        e1.insert("src_ip".to_string(), "10.0.0.5".to_string());
        e1.insert("byte_offset".to_string(), "0".to_string());

        let mut e2 = HashMap::new();
        e2.insert("timestamp".to_string(), "Jun 22 09:00:00".to_string());
        e2.insert("source".to_string(), "iptables".to_string());
        e2.insert("src_ip".to_string(), "10.0.0.6".to_string());
        e2.insert("dst_ip".to_string(), "192.168.1.1".to_string());
        e2.insert("byte_offset".to_string(), "0".to_string());

        db.insert_batch(&key1, &[e1]).unwrap();
        db.insert_batch(&key2, &[e2]).unwrap();

        {
            let connections = db.connections.lock().unwrap();
            let c1: i64 = connections
                .get(&key1)
                .unwrap()
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .unwrap();
            let c2: i64 = connections
                .get(&key2)
                .unwrap()
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .unwrap();
            assert_eq!(c1, 1);
            assert_eq!(c2, 1);
        }

        assert!(tmp.path.join("index").join("2026-06-22-08.db").exists());
        assert!(tmp.path.join("index").join("2026-06-22-09.db").exists());

        db.close_all();
    }

    #[test]
    fn test_dynamic_fields_from_config() {
        let tmp = TempDir::new();
        // Simulate what config.all_index_fields() would return
        // with extra fields like "username" and "dst_port"
        let fields = vec![
            "byte_offset".to_string(),
            "dst_ip".to_string(),
            "dst_port".to_string(),
            "event_type".to_string(),
            "severity".to_string(),
            "source".to_string(),
            "src_ip".to_string(),
            "timestamp".to_string(),
            "username".to_string(),
        ];
        let db = IndexDb::new(&tmp.path, &fields);

        let key = db.open_bucket("2026/06/22/10").unwrap();

        // Verify all columns exist
        {
            let connections = db.connections.lock().unwrap();
            let conn = connections.get(&key).unwrap();
            let mut stmt = conn.prepare("PRAGMA table_info(events)").unwrap();
            let col_names: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            for f in &fields {
                assert!(col_names.contains(f), "missing column: {}", f);
            }
        }

        // Insert with all fields
        let mut event = HashMap::new();
        event.insert("timestamp".to_string(), "Jun 22 10:00:00".to_string());
        event.insert("source".to_string(), "sshd".to_string());
        event.insert("src_ip".to_string(), "10.0.0.5".to_string());
        event.insert("dst_ip".to_string(), "192.168.1.1".to_string());
        event.insert("dst_port".to_string(), "22".to_string());
        event.insert("event_type".to_string(), "SSH_FAILED".to_string());
        event.insert("severity".to_string(), "WARN".to_string());
        event.insert("username".to_string(), "root".to_string());
        event.insert("byte_offset".to_string(), "0".to_string());

        db.insert_batch(&key, &[event]).unwrap();

        {
            let connections = db.connections.lock().unwrap();
            let conn = connections.get(&key).unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1);

            // Query by the new field
            let user_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE username = 'root'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(user_count, 1);

            let port_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE dst_port = '22'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(port_count, 1);
        }

        db.close_all();
    }
}

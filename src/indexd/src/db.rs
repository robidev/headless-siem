use rusqlite::{Connection, params_from_iter};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A cached bucket connection plus the last time it was written to.
///
/// `last_write` drives `evict_idle`'s decision to close (and checkpoint) a
/// connection that has gone quiet — see that method's doc comment for why
/// this exists. `Deref`s to `Connection` so callers (including tests) can
/// use a `&BucketConn` exactly like a `&Connection` for read-only access.
pub(crate) struct BucketConn {
    conn: Connection,
    last_write: Instant,
}

impl std::ops::Deref for BucketConn {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.conn
    }
}

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
///
/// Connections stay open (WAL mode) across inserts for the life of an hour
/// bucket, but a bucket goes permanently quiet once its hour passes — with
/// nothing left to trigger SQLite's own auto-checkpoint, a stale bucket's
/// final WAL (observed ~3-4 MB, right at the 1000-page auto-checkpoint
/// threshold) would otherwise sit on disk until the process exits. The
/// caller is expected to periodically call `evict_idle` to reclaim these.
///
/// On eviction (and clean shutdown) a quiescing bucket is switched out of WAL
/// mode entirely via `PRAGMA journal_mode=DELETE` — not merely checkpointed —
/// so that once its hour has passed it is a plain rollback-journal file with
/// no `-wal`/`-shm` sidecars. This is required for read access, not just
/// tidiness: `siemctl` is run by sandboxed SOC role accounts (a different uid
/// than the `user` that owns these files, and with no write permission on
/// them or the index dir). Opening a WAL-mode database *even read-only* forces
/// SQLite to create/recover the `-shm` shared-memory index, which needs write
/// access — so a read-only cross-user open of a quiesced WAL-mode bucket fails
/// with `SQLITE_READONLY` ("attempt to write a readonly database") or
/// `SQLITE_CANTOPEN`. A rollback-mode file needs no such write. See
/// `evict_idle` / `close_all`.
pub struct IndexDb {
    /// Base directory for index files (e.g. `data/index/`).
    index_dir: PathBuf,
    /// Ordered list of all indexed field names (deterministic, from config).
    index_fields: Vec<String>,
    /// Pre-computed INSERT statement for efficiency.
    insert_sql: String,
    /// Cache of open connections, keyed by bucket path. Idle entries are
    /// reclaimed by `evict_idle`.
    pub(crate) connections: Mutex<HashMap<String, BucketConn>>,
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
            "INSERT OR IGNORE INTO events ({}) VALUES ({})",
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
    /// TEXT column and a corresponding index. If the bucket's `.db` file
    /// already exists from a previous process lifetime with a narrower
    /// schema (e.g. `sources.toml` gained a field since it was created),
    /// any columns it's missing are added via `ALTER TABLE` — see the
    /// comment at that step for why this matters beyond tidiness.
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
            "CREATE TABLE IF NOT EXISTS events ({}, UNIQUE(raw_file, byte_offset))",
            column_defs.join(", ")
        );
        conn.execute_batch(&create_table)?;

        // Migrate: CREATE TABLE IF NOT EXISTS above is a no-op for a bucket
        // file left over from before a field was added to index_fields, so
        // without this, every insert into that bucket hard-fails with
        // "no such column" — not just noisy for a historical rescan, but a
        // real ongoing indexing failure for the current hour's bucket if it
        // was created earlier in this same process's uptime, before a
        // config reload picked up the new field. Add whatever columns are
        // missing; existing rows get the same default a fresh CREATE TABLE
        // would have used. This does not backfill real historical values
        // for the new field into already-indexed rows — that still needs
        // `--reindex-new`/`--reindex-all`.
        let mut stmt = conn.prepare("PRAGMA table_info(events)")?;
        let existing_columns: std::collections::HashSet<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);
        for field in &self.index_fields {
            if existing_columns.contains(field) {
                continue;
            }
            let column_def = if field == "byte_offset" {
                format!("{} INTEGER NOT NULL DEFAULT 0", field)
            } else {
                format!("{} TEXT NOT NULL DEFAULT ''", field)
            };
            if let Err(e) =
                conn.execute_batch(&format!("ALTER TABLE events ADD COLUMN {}", column_def))
            {
                eprintln!(
                    "[indexd] failed to add column '{}' to bucket {}: {}",
                    field, bucket, e
                );
            }
        }

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
        connections.insert(
            bucket_key.clone(),
            BucketConn { conn, last_write: Instant::now() },
        );

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
        let entry = connections.get_mut(bucket_key).ok_or_else(|| {
            rusqlite::Error::InvalidParameterName(format!("bucket not open: {}", bucket_key))
        })?;

        let tx = entry.conn.transaction()?;
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
        entry.last_write = Instant::now();

        Ok(())
    }

    /// Close connections that haven't been written to in at least `idle_after`.
    ///
    /// Switches each idle bucket out of WAL mode with `PRAGMA
    /// journal_mode=DELETE` before dropping the connection. This both reclaims
    /// the WAL immediately (it implicitly checkpoints — SQLite's own close-time
    /// checkpoint never runs here otherwise, since a bucket that has gone quiet
    /// for the rest of its life has nothing left to trigger an auto-checkpoint)
    /// *and*, crucially, rewrites the file header to rollback-journal mode and
    /// unlinks the `-wal`/`-shm` sidecars — leaving a plain file that a
    /// different-user, read-only client (`siemctl` run by a sandboxed SOC role)
    /// can open without needing write access it doesn't have. A bare
    /// checkpoint(TRUNCATE) would leave the header in WAL mode, so once the
    /// connection closed the bucket would be an unreadable-cross-user WAL-mode
    /// `.db` — the root cause of the recurring "siem db unavailable during role
    /// runs" incidents (SQLITE_READONLY / SQLITE_CANTOPEN). A failure is logged
    /// and the connection dropped anyway; a late event for that bucket just
    /// re-opens it (back in WAL mode) via `open_bucket`, and the next eviction
    /// converts it again. Returns the bucket keys that were evicted, for logging.
    pub fn evict_idle(&self, idle_after: Duration) -> Vec<String> {
        let now = Instant::now();
        let mut connections = self.connections.lock().unwrap();
        let idle_keys: Vec<String> = connections
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.last_write) >= idle_after)
            .map(|(k, _)| k.clone())
            .collect();

        for key in &idle_keys {
            if let Some(entry) = connections.get(key) {
                if let Err(e) = entry.conn.execute_batch("PRAGMA journal_mode=DELETE;") {
                    eprintln!("[indexd] journal_mode=DELETE failed for idle bucket {}: {}", key, e);
                }
            }
            connections.remove(key);
        }

        idle_keys
    }

    /// Close all open connections gracefully.
    ///
    /// Switches each bucket out of WAL mode (`PRAGMA journal_mode=DELETE`, same
    /// as `evict_idle`), so a clean shutdown never leaves a stranded WAL file —
    /// or, more importantly, a bare WAL-mode `.db` a cross-user read-only reader
    /// can't open — behind either.
    pub fn close_all(&self) {
        let mut connections = self.connections.lock().unwrap();
        for entry in connections.values() {
            let _ = entry.conn.execute_batch("PRAGMA journal_mode=DELETE;");
        }
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

            // Verify indexes exist: one per field except byte_offset, plus one
            // implicit index for the UNIQUE(raw_file, byte_offset) constraint.
            let index_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name='events'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            // 7 explicit (timestamp, source, src_ip, dst_ip, event_type, severity, raw_file)
            // + 1 implicit from UNIQUE(raw_file, byte_offset) = 8
            assert_eq!(index_count, 8);
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
    fn test_insert_or_ignore_deduplicates_by_raw_file_and_offset() {
        let tmp = TempDir::new();
        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);
        let key = db.open_bucket("2026/06/22/08").unwrap();

        let mut event = HashMap::new();
        event.insert("timestamp".to_string(), "Jun 22 08:55:03".to_string());
        event.insert("source".to_string(), "sshd".to_string());
        event.insert("src_ip".to_string(), "10.0.0.5".to_string());
        event.insert("byte_offset".to_string(), "0".to_string());
        event.insert("raw_file".to_string(), "raw/2026/06/22/08/55/03/sshd.jsonl".to_string());

        // Insert the same event twice — second should be silently ignored.
        db.insert_batch(&key, &[event.clone()]).unwrap();
        db.insert_batch(&key, &[event]).unwrap();

        let connections = db.connections.lock().unwrap();
        let conn = connections.get(&key).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1, "duplicate (raw_file, byte_offset) must be silently dropped");
    }

    #[test]
    fn test_evict_idle_leaves_fresh_connections_open() {
        let tmp = TempDir::new();
        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);
        let key = db.open_bucket("2026/06/22/08").unwrap();

        let mut event = HashMap::new();
        event.insert("timestamp".to_string(), "Jun 22 08:55:03".to_string());
        event.insert("byte_offset".to_string(), "0".to_string());
        db.insert_batch(&key, &[event]).unwrap();

        // Just wrote — nowhere near idle for a 1-hour threshold.
        let evicted = db.evict_idle(Duration::from_secs(3600));
        assert!(evicted.is_empty(), "fresh bucket should not be evicted");
        assert!(db.connections.lock().unwrap().contains_key(&key));

        db.close_all();
    }

    #[test]
    fn test_evict_idle_converts_out_of_wal_mode_and_preserves_data() {
        let tmp = TempDir::new();
        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);
        let key = db.open_bucket("2026/06/22/08").unwrap();

        let mut event = HashMap::new();
        event.insert("timestamp".to_string(), "Jun 22 08:55:03".to_string());
        event.insert("src_ip".to_string(), "10.0.0.5".to_string());
        event.insert("byte_offset".to_string(), "0".to_string());
        db.insert_batch(&key, &[event]).unwrap();

        let db_path = tmp.path.join("index").join("2026-06-22-08.db");
        let wal_path = tmp.path.join("index").join("2026-06-22-08.db-wal");
        assert!(wal_path.exists(), "WAL-mode SQLite should create a -wal file on first write");

        // Zero threshold: any elapsed time (even microseconds) qualifies —
        // deterministic without sleeping.
        let evicted = db.evict_idle(Duration::from_secs(0));
        assert_eq!(evicted, vec![key.clone()]);
        assert!(
            !db.connections.lock().unwrap().contains_key(&key),
            "connection should be dropped after eviction"
        );

        // The bucket must now be a plain rollback-journal file: journal_mode=DELETE
        // rewrites the header and removes the -wal sidecar. This is what makes it
        // openable read-only by a different, unprivileged user (the whole point of
        // the fix — see the struct/evict_idle docs).
        assert!(
            !wal_path.exists(),
            "journal_mode=DELETE should remove the -wal sidecar, leaving a plain file"
        );
        // Read the persistent journal-mode byte straight from the header:
        // offset 18 == 1 means rollback (DELETE/TRUNCATE/PERSIST), 2 means WAL.
        let header = std::fs::read(&db_path).unwrap();
        assert_eq!(
            header[18], 1,
            "db header must be rollback-journal mode (1), not WAL (2), after eviction"
        );

        // Data survives: re-opening the bucket sees the same row, not a
        // fresh empty table.
        let key2 = db.open_bucket("2026/06/22/08").unwrap();
        assert_eq!(key2, key, "bucket key is stable across evict + reopen");
        {
            let connections = db.connections.lock().unwrap();
            let conn = connections.get(&key2).unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1, "data must survive eviction + reopen");
        }

        db.close_all();
    }

    #[test]
    fn test_evicted_bucket_opens_read_only_without_write_access() {
        // Regression test for the "siem db unavailable during role runs" bug:
        // a quiesced bucket must be openable read-only by a client that has NO
        // write access to the file or its directory. A WAL-mode file fails this
        // (read-only open still needs to create/recover the -shm); a rollback
        // file passes. We approximate "no write access" by stripping write bits
        // from the file and its parent dir, then opening read-only.
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new();
        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);
        let key = db.open_bucket("2026/06/22/08").unwrap();

        let mut event = HashMap::new();
        event.insert("timestamp".to_string(), "Jun 22 08:55:03".to_string());
        event.insert("byte_offset".to_string(), "0".to_string());
        db.insert_batch(&key, &[event]).unwrap();
        db.evict_idle(Duration::from_secs(0)); // quiesce -> rollback mode
        db.close_all();

        let index_dir = tmp.path.join("index");
        let db_path = index_dir.join("2026-06-22-08.db");

        // Strip write permission from the db file and its directory, so a
        // read-only open cannot fall back to creating a -shm / -wal.
        let mut dir_perm = std::fs::metadata(&index_dir).unwrap().permissions();
        dir_perm.set_mode(0o555);
        std::fs::set_permissions(&index_dir, dir_perm).unwrap();
        let mut file_perm = std::fs::metadata(&db_path).unwrap().permissions();
        file_perm.set_mode(0o444);
        std::fs::set_permissions(&db_path, file_perm).unwrap();

        let opened = Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        );
        // Restore write perms before any assert so TempDir::drop can clean up.
        let mut dir_perm = std::fs::metadata(&index_dir).unwrap().permissions();
        dir_perm.set_mode(0o755);
        std::fs::set_permissions(&index_dir, dir_perm).unwrap();

        let conn = opened.expect("rollback-mode bucket must open read-only without write access");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_evict_idle_only_evicts_buckets_past_threshold() {
        let tmp = TempDir::new();
        let fields = default_fields();
        let db = IndexDb::new(&tmp.path, &fields);

        let key_old = db.open_bucket("2026/06/22/08").unwrap();
        let mut e1 = HashMap::new();
        e1.insert("timestamp".to_string(), "Jun 22 08:00:00".to_string());
        e1.insert("byte_offset".to_string(), "0".to_string());
        db.insert_batch(&key_old, &[e1]).unwrap();

        std::thread::sleep(Duration::from_millis(150));

        let key_fresh = db.open_bucket("2026/06/22/09").unwrap();
        let mut e2 = HashMap::new();
        e2.insert("timestamp".to_string(), "Jun 22 09:00:00".to_string());
        e2.insert("byte_offset".to_string(), "0".to_string());
        db.insert_batch(&key_fresh, &[e2]).unwrap();

        // Threshold sits between the two writes: only the older bucket
        // qualifies.
        let evicted = db.evict_idle(Duration::from_millis(75));
        assert_eq!(evicted, vec![key_old.clone()]);

        let connections = db.connections.lock().unwrap();
        assert!(!connections.contains_key(&key_old), "old bucket should be evicted");
        assert!(connections.contains_key(&key_fresh), "fresh bucket should remain open");
        drop(connections);

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
        // with extra fields like "username" and "dst_port".
        // raw_file and byte_offset are always present (UNIQUE constraint).
        let fields = vec![
            "byte_offset".to_string(),
            "dst_ip".to_string(),
            "dst_port".to_string(),
            "event_type".to_string(),
            "raw_file".to_string(),
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

    #[test]
    fn test_open_bucket_migrates_missing_columns_for_existing_file() {
        let tmp = TempDir::new();

        // First "process lifetime": narrow schema, no `username` field.
        let narrow_fields = vec![
            "timestamp".to_string(),
            "source".to_string(),
            "src_ip".to_string(),
            "byte_offset".to_string(),
            "raw_file".to_string(),
        ];
        {
            let db = IndexDb::new(&tmp.path, &narrow_fields);
            let key = db.open_bucket("2026/06/22/08").unwrap();
            let mut old_event = HashMap::new();
            old_event.insert("timestamp".to_string(), "Jun 22 08:00:00".to_string());
            old_event.insert("src_ip".to_string(), "10.0.0.1".to_string());
            old_event.insert("byte_offset".to_string(), "0".to_string());
            old_event.insert("raw_file".to_string(), "raw/old.jsonl".to_string());
            db.insert_batch(&key, &[old_event]).unwrap();
            db.close_all();
        }

        // Second "process lifetime" (simulates a restart after sources.toml
        // gained a new field): wider schema, same on-disk bucket file.
        let mut wide_fields = narrow_fields.clone();
        wide_fields.push("username".to_string());
        let db2 = IndexDb::new(&tmp.path, &wide_fields);
        let key2 = db2.open_bucket("2026/06/22/08").unwrap();

        // Migration must have added the missing column — a fresh insert
        // using it must succeed (previously this hard-failed with
        // "no such column").
        let mut new_event = HashMap::new();
        new_event.insert("timestamp".to_string(), "Jun 22 08:05:00".to_string());
        new_event.insert("src_ip".to_string(), "10.0.0.2".to_string());
        new_event.insert("username".to_string(), "root".to_string());
        new_event.insert("byte_offset".to_string(), "50".to_string());
        new_event.insert("raw_file".to_string(), "raw/new.jsonl".to_string());
        db2.insert_batch(&key2, &[new_event])
            .expect("insert using a newly migrated column must succeed");

        let connections = db2.connections.lock().unwrap();
        let conn = connections.get(&key2).unwrap();

        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(total, 2, "both the pre- and post-migration rows survive");

        // Old row predates the column: migration backfills the same empty
        // default a fresh CREATE TABLE would use, not a real historical
        // value — reindex-new/-all is the documented path for that.
        let old_username: String = conn
            .query_row(
                "SELECT username FROM events WHERE raw_file = 'raw/old.jsonl'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_username, "");

        let new_username: String = conn
            .query_row(
                "SELECT username FROM events WHERE raw_file = 'raw/new.jsonl'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(new_username, "root");

        drop(connections);
        db2.close_all();
    }
}

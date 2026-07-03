//! Query primitives for `siemctl digest` (added in a later batch).
//!
//! Unlike `query.rs` (compiles a user DSL string to SQL for `search`), this
//! module runs a small, fixed set of internally-constructed queries needed
//! by the digest's section builders: grouped counts and a per-minute time
//! series, both scoped to an arbitrary sub-hour [`crate::time::Window`]
//! rather than whole hour buckets.
//!
//! Sub-hour precision comes from the `raw_file` index column
//! (`raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl`, zero-padded so it sorts
//! lexicographically = chronologically) via `crate::time::raw_file_range` —
//! see that function's doc comment for why no new indexed column is needed.
//!
//! `extra_where`/`extra_params` in this module are trusted, internally
//! constructed SQL fragments (never raw user input) — the same contract
//! `query.rs`'s compiler already relies on for its own generated SQL.

use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::db;
use crate::query;
use crate::time::{self, Window};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Length of the `raw/YYYY/MM/DD/HH/MM` minute-precision prefix of a
/// `raw_file` value (drops the trailing `/SS/<source>.jsonl`).
const MINUTE_PREFIX_LEN: usize = 20;

fn truncate_to_hour(t: DateTime<Utc>) -> DateTime<Utc> {
    t.with_minute(0).unwrap().with_second(0).unwrap().with_nanosecond(0).unwrap()
}

/// Existing `data/index/YYYY-MM-DD-HH.db` bucket files overlapping `win`.
/// May include one extra hour beyond `win.end` when `win.end` lands exactly
/// on an hour boundary — harmless, since the `raw_file` range predicate
/// excludes any rows it would contain.
pub fn hour_bucket_files(data_dir: &Path, win: &Window) -> Vec<PathBuf> {
    let idx_dir = data_dir.join("index");
    let last = truncate_to_hour(win.end);
    let mut h = truncate_to_hour(win.start);
    let mut out = Vec::new();
    while h <= last {
        let name = format!("{:04}-{:02}-{:02}-{:02}.db", h.year(), h.month(), h.day(), h.hour());
        let path = idx_dir.join(name);
        if path.is_file() {
            out.push(path);
        }
        h += Duration::hours(1);
    }
    out
}

/// `GROUP BY group_cols` count over `events` rows falling in `win`, folded
/// across every overlapping hour bucket. `group_cols` must be trusted,
/// pre-validated column identifiers (same contract as `db::fold_group_sql`).
/// `extra_where`, if given, is ANDed into the predicate; its `?` placeholders
/// are filled by `extra_params`, positioned after the two range params.
pub fn group_count_in_range(
    data_dir: &Path,
    win: &Window,
    group_cols: &[&str],
    extra_where: Option<&str>,
    extra_params: &[String],
) -> Result<BTreeMap<Vec<String>, u64>> {
    let (lo, hi) = time::raw_file_range(win);
    let cols = group_cols.join(", ");
    let where_extra = extra_where.map(|w| format!(" AND ({w})")).unwrap_or_default();
    let sql = format!(
        "SELECT {cols}, COUNT(*) FROM events WHERE raw_file >= ? AND raw_file < ?{where_extra} \
         GROUP BY {cols}"
    );
    let mut params = vec![lo, hi];
    params.extend(extra_params.iter().cloned());

    let mut acc: BTreeMap<Vec<String>, u64> = BTreeMap::new();
    for path in hour_bucket_files(data_dir, win) {
        let conn = db::open_bucket_conn(&path, data_dir)?;
        if let Err(e) = db::fold_group_sql(&conn, &sql, &params, group_cols.len(), &mut acc) {
            let msg = e.to_string();
            if !query::is_benign(&msg) {
                return Err(e.into());
            }
        }
    }
    Ok(acc)
}

/// Per-minute event counts over `win`, keyed by the `raw/YYYY/MM/DD/HH/MM`
/// prefix. Feeds [`bucket_series`] to build the digest's sparkline.
pub fn minute_counts_in_range(
    data_dir: &Path,
    win: &Window,
    extra_where: Option<&str>,
    extra_params: &[String],
) -> Result<BTreeMap<String, u64>> {
    let (lo, hi) = time::raw_file_range(win);
    let where_extra = extra_where.map(|w| format!(" AND ({w})")).unwrap_or_default();
    let minute_expr = format!("substr(raw_file, 1, {MINUTE_PREFIX_LEN})");
    let sql = format!(
        "SELECT {minute_expr}, COUNT(*) FROM events WHERE raw_file >= ? AND raw_file < ?{where_extra} \
         GROUP BY {minute_expr}"
    );
    let mut params = vec![lo, hi];
    params.extend(extra_params.iter().cloned());

    let mut acc: BTreeMap<Vec<String>, u64> = BTreeMap::new();
    for path in hour_bucket_files(data_dir, win) {
        let conn = db::open_bucket_conn(&path, data_dir)?;
        if let Err(e) = db::fold_group_sql(&conn, &sql, &params, 1, &mut acc) {
            let msg = e.to_string();
            if !query::is_benign(&msg) {
                return Err(e.into());
            }
        }
    }
    Ok(acc
        .into_iter()
        .map(|(mut k, v)| (k.pop().unwrap_or_default(), v))
        .collect())
}

/// Parse a `raw/YYYY/MM/DD/HH/MM` minute-prefix key back into its instant
/// (seconds truncated to 0).
fn parse_minute_prefix(s: &str) -> Option<DateTime<Utc>> {
    let rest = s.strip_prefix("raw/")?;
    let mut p = rest.split('/');
    let year: i32 = p.next()?.parse().ok()?;
    let month: u32 = p.next()?.parse().ok()?;
    let day: u32 = p.next()?.parse().ok()?;
    let hour: u32 = p.next()?.parse().ok()?;
    let minute: u32 = p.next()?.parse().ok()?;
    if p.next().is_some() {
        return None;
    }
    Utc.with_ymd_and_hms(year, month, day, hour, minute, 0).single()
}

/// Fold per-minute counts (from [`minute_counts_in_range`]) into
/// `interval`-wide buckets spanning `win`, in chronological order. Bucket
/// `i` covers `[win.start + i*interval, win.start + (i+1)*interval)`; the
/// final bucket is short if `win`'s duration isn't a whole multiple of
/// `interval`. Minutes outside `[win.start, win.end)` are dropped.
pub fn bucket_series(
    minute_counts: &BTreeMap<String, u64>,
    win: &Window,
    interval: Duration,
) -> Vec<u64> {
    let interval_secs = interval.num_seconds().max(1);
    let win_secs = win.duration().num_seconds().max(0);
    let n_buckets = ((win_secs as f64) / (interval_secs as f64)).ceil() as usize;
    let mut buckets = vec![0u64; n_buckets.max(1)];

    for (minute_key, count) in minute_counts {
        let Some(t) = parse_minute_prefix(minute_key) else { continue };
        if t < win.start || t >= win.end {
            continue;
        }
        let offset_secs = (t - win.start).num_seconds();
        let idx = (offset_secs / interval_secs) as usize;
        let idx = idx.min(buckets.len() - 1);
        buckets[idx] += count;
    }
    buckets
}

/// Unaggregated row projection over `events` rows falling in `win`, folded
/// across every overlapping hour bucket. Each returned row is `columns.len()`
/// strings, in column order (`NULL` → `""`, numbers via their text form —
/// see `db::value_ref_to_string`). Used where a section needs individual
/// rows (e.g. a specific timestamp/command per event) rather than a count.
pub fn select_rows_in_range(
    data_dir: &Path,
    win: &Window,
    columns: &[&str],
    extra_where: Option<&str>,
    extra_params: &[String],
) -> Result<Vec<Vec<String>>> {
    let (lo, hi) = time::raw_file_range(win);
    let cols = columns.join(", ");
    let where_extra = extra_where.map(|w| format!(" AND ({w})")).unwrap_or_default();
    let sql = format!("SELECT {cols} FROM events WHERE raw_file >= ? AND raw_file < ?{where_extra}");
    let mut params = vec![lo, hi];
    params.extend(extra_params.iter().cloned());
    let param_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let mut out = Vec::new();
    for path in hour_bucket_files(data_dir, win) {
        let conn = db::open_bucket_conn(&path, data_dir)?;
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => {
                if query::is_benign(&e.to_string()) {
                    continue;
                }
                return Err(e.into());
            }
        };
        let n = columns.len();
        let result = stmt.query_map(param_refs.as_slice(), |row| {
            let mut vals = Vec::with_capacity(n);
            for i in 0..n {
                vals.push(db::value_ref_to_string(row.get_ref(i)?));
            }
            Ok(vals)
        });
        match result {
            Ok(mapped) => {
                for r in mapped {
                    out.push(r?);
                }
            }
            Err(e) => {
                if !query::is_benign(&e.to_string()) {
                    return Err(e.into());
                }
            }
        }
    }
    Ok(out)
}

/// Shared implementation for [`first_seen_in_range`]/[`last_seen_in_range`]:
/// `MIN`/`AGG(raw_file)` over rows matching `extra_where` in `win`, resolved
/// to the instant it encodes. `agg` is a trusted constant (`"MIN"`/`"MAX"`),
/// never user input.
fn extreme_seen_in_range(
    data_dir: &Path,
    win: &Window,
    agg: &str,
    extra_where: &str,
    extra_params: &[String],
) -> Result<Option<DateTime<Utc>>> {
    let (lo, hi) = time::raw_file_range(win);
    let sql =
        format!("SELECT {agg}(raw_file) FROM events WHERE raw_file >= ? AND raw_file < ? AND ({extra_where})");
    let mut params = vec![lo, hi];
    params.extend(extra_params.iter().cloned());
    let param_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let mut best: Option<String> = None;
    for path in hour_bucket_files(data_dir, win) {
        let conn = db::open_bucket_conn(&path, data_dir)?;
        let res: rusqlite::Result<Option<String>> =
            conn.query_row(&sql, param_refs.as_slice(), |r| r.get(0));
        match res {
            Ok(Some(rf)) => {
                let better = match &best {
                    None => true,
                    Some(cur) => if agg == "MIN" { rf < *cur } else { rf > *cur },
                };
                if better {
                    best = Some(rf);
                }
            }
            Ok(None) => {}
            Err(e) => {
                if !query::is_benign(&e.to_string()) {
                    return Err(e.into());
                }
            }
        }
    }
    Ok(best.and_then(|rf| time::parse_raw_file_time(&rf)))
}

/// Earliest event matching `extra_where` in `win`, as the instant its
/// `raw_file` encodes.
pub fn first_seen_in_range(
    data_dir: &Path,
    win: &Window,
    extra_where: &str,
    extra_params: &[String],
) -> Result<Option<DateTime<Utc>>> {
    extreme_seen_in_range(data_dir, win, "MIN", extra_where, extra_params)
}

/// Latest event matching `extra_where` in `win`, as the instant its
/// `raw_file` encodes.
pub fn last_seen_in_range(
    data_dir: &Path,
    win: &Window,
    extra_where: &str,
    extra_params: &[String],
) -> Result<Option<DateTime<Utc>>> {
    extreme_seen_in_range(data_dir, win, "MAX", extra_where, extra_params)
}

/// Real `data/raw/YYYY/MM/DD/HH/MM/SS/*.jsonl` files whose path-derived
/// instant falls in `[win.start, win.end)`. Unlike the indexed helpers
/// above, this reads the filesystem tree directly — for the digest's
/// "unparsed high-volume sources" check, which needs `_normalized`/`app_name`
/// off events that (by definition) failed to parse, so they were never
/// indexed at all.
pub fn raw_files_in_range(data_dir: &Path, win: &Window) -> Vec<PathBuf> {
    let raw_root = data_dir.join("raw");
    let last = truncate_to_hour(win.end);
    let mut h = truncate_to_hour(win.start);
    let mut out = Vec::new();
    while h <= last {
        let hour_dir = raw_root
            .join(format!("{:04}", h.year()))
            .join(format!("{:02}", h.month()))
            .join(format!("{:02}", h.day()))
            .join(format!("{:02}", h.hour()));
        if let Ok(minute_entries) = std::fs::read_dir(&hour_dir) {
            for minute_entry in minute_entries.flatten() {
                let minute_dir = minute_entry.path();
                let Ok(second_entries) = std::fs::read_dir(&minute_dir) else { continue };
                for second_entry in second_entries.flatten() {
                    let second_dir = second_entry.path();
                    let Ok(files) = std::fs::read_dir(&second_dir) else { continue };
                    for file_entry in files.flatten() {
                        let path = file_entry.path();
                        if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
                            out.push(path);
                        }
                    }
                }
            }
        }
        h += Duration::hours(1);
    }

    out.retain(|path| {
        let Ok(rel) = path.strip_prefix(data_dir) else { return false };
        let Some(rel) = rel.to_str() else { return false };
        let rel = rel.replace('\\', "/"); // Windows path separators, if ever run there
        match time::parse_raw_file_time(&rel) {
            Some(t) => t >= win.start && t < win.end,
            None => false,
        }
    });
    out
}

/// One hour bucket where the raw `.jsonl` line count exceeds what's
/// actually indexed for that bucket — a completeness gap, not just staleness.
#[derive(Debug, Clone)]
pub struct BucketCompleteness {
    pub bucket: String,
    pub raw_count: u64,
    pub indexed_count: u64,
}

/// Per-hour-bucket completeness check: raw `.jsonl` line count vs indexed
/// row count, for every hour bucket overlapping `win`. Returns only buckets
/// where the index is short — an index temporarily *ahead* of a raw file
/// still mid-write is not a completeness problem and isn't flagged.
///
/// Deliberately independent of [`latest_raw_event_time`]/
/// [`newest_indexed_event_time`] (the digest's existing lag check): that
/// check only compares the *newest* timestamp on each side, so a bucket in
/// the *middle* of the range that indexd silently missed (e.g. an inotify
/// race on a freshly created deep directory chain, or an out-of-order/
/// future event timestamp landing in a bucket indexd never watched in
/// time) stays invisible to it as long as *later* buckets indexed fine —
/// exactly the failure mode this function exists to catch.
pub fn completeness_in_range(data_dir: &Path, win: &Window) -> Vec<BucketCompleteness> {
    // Raw side: line-count every raw .jsonl file in range, grouped by hour bucket.
    let mut raw_counts: BTreeMap<String, u64> = BTreeMap::new();
    for path in raw_files_in_range(data_dir, win) {
        let Ok(rel) = path.strip_prefix(data_dir) else { continue };
        let Some(rel_str) = rel.to_str() else { continue };
        let rel_str = rel_str.replace('\\', "/");
        let Some(t) = time::parse_raw_file_time(&rel_str) else { continue };
        let bucket = format!("{:04}-{:02}-{:02}-{:02}", t.year(), t.month(), t.day(), t.hour());
        let lines = std::fs::read_to_string(&path).map(|s| s.lines().count() as u64).unwrap_or(0);
        *raw_counts.entry(bucket).or_default() += lines;
    }
    if raw_counts.is_empty() {
        return Vec::new();
    }

    // Indexed side: COUNT(*) scoped to the same [lo, hi) raw_file range used
    // throughout this module, per hour-bucket db (a missing db file, or one
    // that never picked up this bucket's rows, counts as 0 indexed).
    let (lo, hi) = time::raw_file_range(win);
    let idx_dir = data_dir.join("index");
    let mut out = Vec::new();
    for (bucket, raw_count) in raw_counts {
        let db_path = idx_dir.join(format!("{bucket}.db"));
        let indexed_count: u64 = if db_path.is_file() {
            db::open_bucket_conn(&db_path, data_dir)
                .ok()
                .and_then(|conn| {
                    conn.query_row(
                        "SELECT COUNT(*) FROM events WHERE raw_file >= ? AND raw_file < ?",
                        [lo.as_str(), hi.as_str()],
                        |r| r.get::<_, i64>(0),
                    )
                    .ok()
                })
                .map(|n| n as u64)
                .unwrap_or(0)
        } else {
            0
        };
        if indexed_count < raw_count {
            out.push(BucketCompleteness { bucket, raw_count, indexed_count });
        }
    }
    out
}

/// Numerically-named subdirectories of `dir` with exactly `width` digits
/// (e.g. `"08"` under an hour directory), as their raw names, largest first.
/// Fixed-width zero-padded names sort correctly as plain strings.
fn max_numeric_entry(dir: &Path, width: usize) -> Option<String> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.len() == width && n.chars().all(|c| c.is_ascii_digit()))
        .max()
}

/// Same as [`max_numeric_entry`] but smallest first — the earliest-data
/// analog, used for cold-start detection (see [`earliest_raw_event_time`]).
fn min_numeric_entry(dir: &Path, width: usize) -> Option<String> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.len() == width && n.chars().all(|c| c.is_ascii_digit()))
        .min()
}

/// The instant of the *oldest* raw event on disk, found by descending into
/// the lexicographically-smallest `YYYY/MM/DD/HH/MM/SS` path under
/// `data_dir/raw`. Used to detect a cold-start baseline: if a digest's
/// baseline window starts before data collection even began, comparing
/// against it is comparing against nothing, not "quiet" — every source
/// looks "new" because there's no real prior period to compare against.
/// This naturally stops firing once retention has aged the raw tree's
/// start point past any realistic baseline window (see
/// implementation-plan.md 1.8, item 29 / 2.4's retention cadence).
pub fn earliest_raw_event_time(data_dir: &Path) -> Option<DateTime<Utc>> {
    let raw_root = data_dir.join("raw");
    let year = min_numeric_entry(&raw_root, 4)?;
    let dir = raw_root.join(&year);
    let month = min_numeric_entry(&dir, 2)?;
    let dir = dir.join(&month);
    let day = min_numeric_entry(&dir, 2)?;
    let dir = dir.join(&day);
    let hour = min_numeric_entry(&dir, 2)?;
    let dir = dir.join(&hour);
    let minute = min_numeric_entry(&dir, 2)?;
    let dir = dir.join(&minute);
    let second = min_numeric_entry(&dir, 2)?;

    time::parse_raw_file_time(&format!("raw/{year}/{month}/{day}/{hour}/{minute}/{second}/x"))
}

/// The instant of the most recent raw event on disk, found by descending
/// into the lexicographically-largest `YYYY/MM/DD/HH/MM/SS` path under
/// `data_dir/raw` — the "is the pipeline still receiving data at all" half
/// of the coverage section's index-lag check.
pub fn latest_raw_event_time(data_dir: &Path) -> Option<DateTime<Utc>> {
    let raw_root = data_dir.join("raw");
    let year = max_numeric_entry(&raw_root, 4)?;
    let dir = raw_root.join(&year);
    let month = max_numeric_entry(&dir, 2)?;
    let dir = dir.join(&month);
    let day = max_numeric_entry(&dir, 2)?;
    let dir = dir.join(&day);
    let hour = max_numeric_entry(&dir, 2)?;
    let dir = dir.join(&hour);
    let minute = max_numeric_entry(&dir, 2)?;
    let dir = dir.join(&minute);
    let second = max_numeric_entry(&dir, 2)?;

    time::parse_raw_file_time(&format!("raw/{year}/{month}/{day}/{hour}/{minute}/{second}/x"))
}

/// The instant of the most recent event actually present in the index (the
/// "has indexd kept up" half of the coverage section's index-lag check) —
/// distinct from "does the newest hour bucket file exist", since indexd
/// creates a bucket file on the first row it indexes for that hour but rows
/// arrive continuously afterward via inotify.
pub fn newest_indexed_event_time(data_dir: &Path) -> Option<DateTime<Utc>> {
    let dbs = query::index_buckets(data_dir).ok()?;
    let latest_bucket = dbs.last()?;
    let conn = db::open_bucket_conn(latest_bucket, data_dir).ok()?;
    let raw_file: Option<String> = conn
        .query_row("SELECT MAX(raw_file) FROM events", [], |r| r.get::<_, Option<String>>(0))
        .ok()
        .flatten();
    raw_file.and_then(|rf| time::parse_raw_file_time(&rf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_CTR: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let n = TMP_CTR.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir()
                .join(format!("hsiem_digestq_test_{}_{}", std::process::id(), n));
            std::fs::create_dir_all(&p).unwrap();
            TempDir { path: p }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn ymdhms(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).single().unwrap()
    }

    // ── hour_bucket_files ────────────────────────────────────────────────

    #[test]
    fn hour_bucket_files_finds_only_existing_buckets_in_range() {
        let tmp = TempDir::new();
        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();
        for name in ["2026-06-29-14.db", "2026-06-29-17.db", "2026-06-29-19.db", "2026-06-29-23.db"] {
            std::fs::write(idx.join(name), b"").unwrap();
        }

        let win = Window { start: ymdhms(2026, 6, 29, 14, 30, 0), end: ymdhms(2026, 6, 29, 20, 0, 0) };
        let files: Vec<String> = hour_bucket_files(&tmp.path, &win)
            .into_iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();

        assert!(files.contains(&"2026-06-29-14.db".to_string()));
        assert!(files.contains(&"2026-06-29-17.db".to_string()));
        assert!(files.contains(&"2026-06-29-19.db".to_string()));
        assert!(!files.contains(&"2026-06-29-23.db".to_string()));
    }

    #[test]
    fn hour_bucket_files_missing_index_dir_returns_empty() {
        let tmp = TempDir::new();
        let win = Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 20, 0, 0) };
        assert!(hour_bucket_files(&tmp.path, &win).is_empty());
    }

    // ── group_count_in_range / minute_counts_in_range ───────────────────

    /// Build a bucket at `hour` with one row per `(raw_file_suffix, source)`.
    fn make_bucket(dir: &Path, hour_name: &str, rows: &[(&str, &str)]) -> PathBuf {
        let db = dir.join(hour_name);
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE events (raw_file TEXT, _source_type TEXT);").unwrap();
        for (raw_file, source) in rows {
            conn.execute(
                "INSERT INTO events (raw_file, _source_type) VALUES (?1, ?2)",
                rusqlite::params![raw_file, source],
            )
            .unwrap();
        }
        db
    }

    #[test]
    fn group_count_in_range_filters_by_window_and_groups() {
        let tmp = TempDir::new();
        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();

        make_bucket(
            &idx,
            "2026-06-29-14.db",
            &[
                ("raw/2026/06/29/14/05/00/sshd.jsonl", "sshd"),
                ("raw/2026/06/29/14/58/00/sshd.jsonl", "sshd"), // in window
                ("raw/2026/06/29/14/59/59/openvpn.jsonl", "openvpn"), // in window
            ],
        );
        make_bucket(
            &idx,
            "2026-06-29-15.db",
            &[
                ("raw/2026/06/29/15/00/00/sshd.jsonl", "sshd"), // outside window (>= end)
            ],
        );

        // Window: 14:30:00 .. 15:00:00 — should see the 14:58/14:59 rows but
        // not the 14:05 row (before start) or the 15:00 row (>= end).
        let win = Window { start: ymdhms(2026, 6, 29, 14, 30, 0), end: ymdhms(2026, 6, 29, 15, 0, 0) };
        let acc = group_count_in_range(&tmp.path, &win, &["_source_type"], None, &[]).unwrap();

        assert_eq!(acc.get(&vec!["sshd".to_string()]), Some(&1));
        assert_eq!(acc.get(&vec!["openvpn".to_string()]), Some(&1));
        assert_eq!(acc.values().sum::<u64>(), 2);
    }

    #[test]
    fn group_count_in_range_applies_extra_where() {
        let tmp = TempDir::new();
        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();

        make_bucket(
            &idx,
            "2026-06-29-14.db",
            &[
                ("raw/2026/06/29/14/10/00/sshd.jsonl", "sshd"),
                ("raw/2026/06/29/14/20/00/openvpn.jsonl", "openvpn"),
            ],
        );

        let win = Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 15, 0, 0) };
        let acc = group_count_in_range(
            &tmp.path,
            &win,
            &["_source_type"],
            Some("_source_type = ?"),
            &["sshd".to_string()],
        )
        .unwrap();

        assert_eq!(acc.len(), 1);
        assert_eq!(acc.get(&vec!["sshd".to_string()]), Some(&1));
    }

    #[test]
    fn group_count_in_range_skips_bucket_with_missing_column() {
        let tmp = TempDir::new();
        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();

        // Schema without _source_type — should be skipped, not error.
        let db = idx.join("2026-06-29-14.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE events (raw_file TEXT);").unwrap();
        conn.execute(
            "INSERT INTO events (raw_file) VALUES ('raw/2026/06/29/14/10/00/x.jsonl')",
            [],
        )
        .unwrap();
        drop(conn);

        let win = Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 15, 0, 0) };
        let acc = group_count_in_range(&tmp.path, &win, &["_source_type"], None, &[]).unwrap();
        assert!(acc.is_empty());
    }

    #[test]
    fn minute_counts_in_range_groups_by_minute() {
        let tmp = TempDir::new();
        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();

        make_bucket(
            &idx,
            "2026-06-29-14.db",
            &[
                ("raw/2026/06/29/14/05/01/a.jsonl", "x"),
                ("raw/2026/06/29/14/05/45/b.jsonl", "x"),
                ("raw/2026/06/29/14/06/00/c.jsonl", "x"),
            ],
        );

        let win = Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 15, 0, 0) };
        let counts = minute_counts_in_range(&tmp.path, &win, None, &[]).unwrap();

        assert_eq!(counts.get("raw/2026/06/29/14/05"), Some(&2));
        assert_eq!(counts.get("raw/2026/06/29/14/06"), Some(&1));
    }

    // ── bucket_series ────────────────────────────────────────────────────

    #[test]
    fn bucket_series_folds_minutes_into_intervals() {
        let win = Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 14, 30, 0) };
        let mut minute_counts = BTreeMap::new();
        minute_counts.insert("raw/2026/06/29/14/00".to_string(), 3);
        minute_counts.insert("raw/2026/06/29/14/09".to_string(), 2);
        minute_counts.insert("raw/2026/06/29/14/10".to_string(), 5); // next bucket
        minute_counts.insert("raw/2026/06/29/14/29".to_string(), 1);

        let series = bucket_series(&minute_counts, &win, Duration::minutes(10));
        assert_eq!(series, vec![5, 5, 1]);
    }

    #[test]
    fn bucket_series_drops_minutes_outside_window() {
        let win = Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 14, 10, 0) };
        let mut minute_counts = BTreeMap::new();
        minute_counts.insert("raw/2026/06/29/13/59".to_string(), 100); // before window
        minute_counts.insert("raw/2026/06/29/14/05".to_string(), 4);
        minute_counts.insert("raw/2026/06/29/14/10".to_string(), 100); // >= end

        let series = bucket_series(&minute_counts, &win, Duration::minutes(10));
        assert_eq!(series, vec![4]);
    }

    #[test]
    fn bucket_series_handles_partial_final_bucket() {
        // 25-minute window, 10-minute interval -> 3 buckets, last one 5 min wide.
        let win = Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 14, 25, 0) };
        let mut minute_counts = BTreeMap::new();
        minute_counts.insert("raw/2026/06/29/14/22".to_string(), 7);

        let series = bucket_series(&minute_counts, &win, Duration::minutes(10));
        assert_eq!(series.len(), 3);
        assert_eq!(series[2], 7);
    }

    // ── select_rows_in_range ─────────────────────────────────────────────

    #[test]
    fn select_rows_in_range_projects_and_filters() {
        let tmp = TempDir::new();
        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();

        let db = idx.join("2026-06-29-14.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE events (raw_file TEXT, username TEXT, command TEXT);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO events VALUES ('raw/2026/06/29/14/10/00/sudo.jsonl', 'robin', 'nano /etc/x')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO events VALUES ('raw/2026/06/29/14/20/00/sudo.jsonl', 'root', 'ls')",
            [],
        )
        .unwrap();
        drop(conn);

        let win = Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 15, 0, 0) };
        let rows = select_rows_in_range(
            &tmp.path,
            &win,
            &["username", "command"],
            Some("username = ?"),
            &["robin".to_string()],
        )
        .unwrap();

        assert_eq!(rows, vec![vec!["robin".to_string(), "nano /etc/x".to_string()]]);
    }

    // ── first_seen_in_range / last_seen_in_range ────────────────────────

    #[test]
    fn first_and_last_seen_span_multiple_buckets() {
        let tmp = TempDir::new();
        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();

        make_bucket(
            &idx,
            "2026-06-29-14.db",
            &[
                ("raw/2026/06/29/14/10/00/x.jsonl", "a"),
                ("raw/2026/06/29/14/50/00/x.jsonl", "a"),
            ],
        );
        make_bucket(&idx, "2026-06-29-15.db", &[("raw/2026/06/29/15/05/00/x.jsonl", "a")]);

        let win = Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 16, 0, 0) };
        let first = first_seen_in_range(&tmp.path, &win, "_source_type = ?", &["a".to_string()]).unwrap();
        let last = last_seen_in_range(&tmp.path, &win, "_source_type = ?", &["a".to_string()]).unwrap();

        assert_eq!(first, Some(ymdhms(2026, 6, 29, 14, 10, 0)));
        assert_eq!(last, Some(ymdhms(2026, 6, 29, 15, 5, 0)));
    }

    #[test]
    fn first_seen_in_range_none_when_no_match() {
        let tmp = TempDir::new();
        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();
        make_bucket(&idx, "2026-06-29-14.db", &[("raw/2026/06/29/14/10/00/x.jsonl", "a")]);

        let win = Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 15, 0, 0) };
        let first = first_seen_in_range(&tmp.path, &win, "_source_type = ?", &["nope".to_string()]).unwrap();
        assert_eq!(first, None);
    }

    // ── raw_files_in_range ───────────────────────────────────────────────

    fn touch_raw_file(data_dir: &Path, rel: &str) {
        let path = data_dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{}\n").unwrap();
    }

    #[test]
    fn raw_files_in_range_filters_by_exact_second() {
        let tmp = TempDir::new();
        touch_raw_file(&tmp.path, "raw/2026/06/29/14/05/00/sshd.jsonl"); // before window
        touch_raw_file(&tmp.path, "raw/2026/06/29/14/30/00/sshd.jsonl"); // in window
        touch_raw_file(&tmp.path, "raw/2026/06/29/14/59/59/sshd.jsonl"); // in window
        touch_raw_file(&tmp.path, "raw/2026/06/29/15/00/00/sshd.jsonl"); // >= end

        let win = Window { start: ymdhms(2026, 6, 29, 14, 10, 0), end: ymdhms(2026, 6, 29, 15, 0, 0) };
        let files = raw_files_in_range(&tmp.path, &win);

        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|p| p.ends_with("14/30/00/sshd.jsonl")));
        assert!(files.iter().any(|p| p.ends_with("14/59/59/sshd.jsonl")));
    }

    #[test]
    fn raw_files_in_range_empty_when_no_raw_dir() {
        let tmp = TempDir::new();
        let win = Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 15, 0, 0) };
        assert!(raw_files_in_range(&tmp.path, &win).is_empty());
    }

    // ── latest_raw_event_time / newest_indexed_event_time ───────────────

    #[test]
    fn latest_raw_event_time_finds_deepest_path() {
        let tmp = TempDir::new();
        touch_raw_file(&tmp.path, "raw/2026/06/29/14/05/00/sshd.jsonl");
        touch_raw_file(&tmp.path, "raw/2026/06/29/17/22/09/openvpn.jsonl");
        touch_raw_file(&tmp.path, "raw/2026/06/29/17/22/03/sshd.jsonl");

        let latest = latest_raw_event_time(&tmp.path);
        assert_eq!(latest, Some(ymdhms(2026, 6, 29, 17, 22, 9)));
    }

    #[test]
    fn latest_raw_event_time_none_when_missing() {
        let tmp = TempDir::new();
        assert_eq!(latest_raw_event_time(&tmp.path), None);
    }

    #[test]
    fn earliest_raw_event_time_finds_shallowest_path() {
        let tmp = TempDir::new();
        touch_raw_file(&tmp.path, "raw/2026/06/29/17/22/09/openvpn.jsonl");
        touch_raw_file(&tmp.path, "raw/2026/06/29/14/05/00/sshd.jsonl");
        touch_raw_file(&tmp.path, "raw/2026/06/29/14/05/03/sshd.jsonl");

        let earliest = earliest_raw_event_time(&tmp.path);
        assert_eq!(earliest, Some(ymdhms(2026, 6, 29, 14, 5, 0)));
    }

    #[test]
    fn earliest_raw_event_time_none_when_missing() {
        let tmp = TempDir::new();
        assert_eq!(earliest_raw_event_time(&tmp.path), None);
    }

    #[test]
    fn newest_indexed_event_time_reads_max_raw_file() {
        let tmp = TempDir::new();
        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();
        make_bucket(
            &idx,
            "2026-06-29-14.db",
            &[
                ("raw/2026/06/29/14/05/00/x.jsonl", "a"),
                ("raw/2026/06/29/14/58/30/x.jsonl", "a"),
            ],
        );
        make_bucket(&idx, "2026-06-29-15.db", &[("raw/2026/06/29/15/02/00/x.jsonl", "a")]);

        let latest = newest_indexed_event_time(&tmp.path);
        assert_eq!(latest, Some(ymdhms(2026, 6, 29, 15, 2, 0)));
    }

    #[test]
    fn newest_indexed_event_time_none_without_index() {
        let tmp = TempDir::new();
        assert_eq!(newest_indexed_event_time(&tmp.path), None);
    }

    // ── completeness_in_range ────────────────────────────────────────────

    fn write_raw_file(data_dir: &Path, rel_dir: &str, name: &str, lines: usize) {
        let dir = data_dir.join(rel_dir);
        std::fs::create_dir_all(&dir).unwrap();
        let content: String = (0..lines).map(|_| "{}\n").collect();
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn completeness_flags_bucket_with_no_index_at_all() {
        let tmp = TempDir::new();
        // 44 raw lines, matching the real-world gap this check exists for
        // (implementation-plan.md 1.6) — no index/ dir at all yet.
        write_raw_file(&tmp.path, "raw/2026/07/01/00/00/00", "sshd.jsonl", 44);

        let win = Window { start: ymdhms(2026, 7, 1, 0, 0, 0), end: ymdhms(2026, 7, 1, 1, 0, 0) };
        let gaps = completeness_in_range(&tmp.path, &win);

        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].bucket, "2026-07-01-00");
        assert_eq!(gaps[0].raw_count, 44);
        assert_eq!(gaps[0].indexed_count, 0);
    }

    #[test]
    fn completeness_flags_bucket_partially_indexed() {
        let tmp = TempDir::new();
        write_raw_file(&tmp.path, "raw/2026/07/01/00/00/00", "sshd.jsonl", 10);

        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();
        // Only 6 of the 10 raw lines made it into the index.
        make_bucket(
            &idx,
            "2026-07-01-00.db",
            &[
                ("raw/2026/07/01/00/00/00/sshd.jsonl", "sshd"),
                ("raw/2026/07/01/00/00/00/sshd.jsonl", "sshd"),
                ("raw/2026/07/01/00/00/00/sshd.jsonl", "sshd"),
                ("raw/2026/07/01/00/00/00/sshd.jsonl", "sshd"),
                ("raw/2026/07/01/00/00/00/sshd.jsonl", "sshd"),
                ("raw/2026/07/01/00/00/00/sshd.jsonl", "sshd"),
            ],
        );

        let win = Window { start: ymdhms(2026, 7, 1, 0, 0, 0), end: ymdhms(2026, 7, 1, 1, 0, 0) };
        let gaps = completeness_in_range(&tmp.path, &win);

        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].raw_count, 10);
        assert_eq!(gaps[0].indexed_count, 6);
    }

    #[test]
    fn completeness_not_flagged_when_fully_indexed() {
        let tmp = TempDir::new();
        write_raw_file(&tmp.path, "raw/2026/07/01/00/00/00", "sshd.jsonl", 3);

        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();
        make_bucket(
            &idx,
            "2026-07-01-00.db",
            &[
                ("raw/2026/07/01/00/00/00/sshd.jsonl", "sshd"),
                ("raw/2026/07/01/00/00/00/sshd.jsonl", "sshd"),
                ("raw/2026/07/01/00/00/00/sshd.jsonl", "sshd"),
            ],
        );

        let win = Window { start: ymdhms(2026, 7, 1, 0, 0, 0), end: ymdhms(2026, 7, 1, 1, 0, 0) };
        assert!(completeness_in_range(&tmp.path, &win).is_empty());
    }

    #[test]
    fn completeness_empty_when_no_raw_files() {
        let tmp = TempDir::new();
        let win = Window { start: ymdhms(2026, 7, 1, 0, 0, 0), end: ymdhms(2026, 7, 1, 1, 0, 0) };
        assert!(completeness_in_range(&tmp.path, &win).is_empty());
    }

    #[test]
    fn completeness_only_flags_the_gap_bucket_not_healthy_neighbors() {
        let tmp = TempDir::new();
        // Healthy bucket: 00:xx, fully indexed.
        write_raw_file(&tmp.path, "raw/2026/07/01/00/05/00", "sshd.jsonl", 2);
        // Gap bucket: 01:xx, never indexed — mirrors the real finding where
        // *later* buckets indexed fine while one in the middle was missed.
        write_raw_file(&tmp.path, "raw/2026/07/01/01/05/00", "sshd.jsonl", 5);

        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();
        make_bucket(
            &idx,
            "2026-07-01-00.db",
            &[
                ("raw/2026/07/01/00/05/00/sshd.jsonl", "sshd"),
                ("raw/2026/07/01/00/05/00/sshd.jsonl", "sshd"),
            ],
        );

        let win = Window { start: ymdhms(2026, 7, 1, 0, 0, 0), end: ymdhms(2026, 7, 1, 2, 0, 0) };
        let gaps = completeness_in_range(&tmp.path, &win);

        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].bucket, "2026-07-01-01");
        assert_eq!(gaps[0].raw_count, 5);
        assert_eq!(gaps[0].indexed_count, 0);
    }
}

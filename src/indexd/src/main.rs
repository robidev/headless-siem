mod config;
mod db;
mod parser;

use inotify::{EventMask, Inotify, WatchMask};
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// How often the initial scan logs an aggregate progress line.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(2);

/// Running totals for an initial/reindex scan, with throttled progress logging.
///
/// The scan touches one tiny `.jsonl` file per second-bucket (thousands of
/// files), so per-file logging is far too noisy and per-file silence makes a
/// working scan look hung. This logs an aggregate line every
/// [`PROGRESS_INTERVAL`] so the operator can see forward motion.
struct ScanProgress {
    files: usize,
    events: usize,
    skipped: usize,
    start: Instant,
    last_log: Instant,
}

impl ScanProgress {
    fn new() -> Self {
        let now = Instant::now();
        ScanProgress { files: 0, events: 0, skipped: 0, start: now, last_log: now }
    }

    /// Record one indexed file and emit a progress line if enough time passed.
    fn record(&mut self, indexed: usize, skipped: usize) {
        self.files += 1;
        self.events += indexed;
        self.skipped += skipped;
        if self.last_log.elapsed() >= PROGRESS_INTERVAL {
            info!(
                "progress: {} files, {} events indexed, {} skipped ({:.0}s elapsed)",
                self.files,
                self.events,
                self.skipped,
                self.start.elapsed().as_secs_f64()
            );
            self.last_log = Instant::now();
        }
    }

    /// Emit a final summary line for the scan.
    fn finish(&self) {
        info!(
            "scan complete: {} files, {} events indexed, {} skipped in {:.1}s",
            self.files,
            self.events,
            self.skipped,
            self.start.elapsed().as_secs_f64()
        );
    }
}

/// Delete all index database files under data_dir/index/ and exit.
/// Returns the count of files deleted.
fn clear_indexes(data_dir: &Path) -> std::io::Result<usize> {
    let index_dir = data_dir.join("index");
    if !index_dir.exists() {
        return Ok(0);
    }

    let mut count = 0usize;
    for entry in std::fs::read_dir(&index_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        if name.ends_with(".db") || name.ends_with(".db-wal") || name.ends_with(".db-shm") {
            std::fs::remove_file(&path)?;
            count += 1;
        }
    }
    Ok(count)
}

/// Print usage information.
fn print_help() {
    eprintln!("indexd — Headless SIEM filesystem watcher and SQLite indexer");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  indexd [FLAGS]");
    eprintln!();
    eprintln!("FLAGS:");
    eprintln!("  --data-dir <path>   Watch <path>/raw/ for new .jsonl files (default: ./data)");
    eprintln!("  --config <path>     Path to sources.toml (default: auto-detect)");
    eprintln!("  --clear             Delete all index DBs and exit");
    eprintln!("  --reindex-all       Clear indexes and re-scan all raw logs, then exit");
    eprintln!("  --reindex-new       Re-index only logs in hours >= the newest indexed bucket,");
    eprintln!("                      then exit. The boundary hour is cleared and re-indexed");
    eprintln!("                      to fix partial indexes. Falls back to --reindex-all");
    eprintln!("                      when no index exists yet.");
    eprintln!("  --no-watch          Index existing files then exit (do not watch for new");
    eprintln!("                      files). Useful for one-shot or cron-driven indexing.");
    eprintln!("  --help              Print this help message");
    eprintln!();
    eprintln!("SIGNALS:");
    eprintln!("  SIGTERM / SIGINT    Graceful shutdown (drain pending events, close DB)");
    eprintln!();
    eprintln!("ENVIRONMENT:");
    eprintln!("  HEADLESS_SIEM_ROOT  Project root directory (default: auto-detect)");
}

/// Return the stem of the newest `*.db` file in `index_dir` (e.g. `"2026-06-22-08"`).
/// Returns `None` if the directory is missing or contains no `.db` files.
fn newest_indexed_bucket(index_dir: &Path) -> Option<String> {
    std::fs::read_dir(index_dir)
        .ok()?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            name.strip_suffix(".db").map(|s| s.to_string())
        })
        .max()
}

/// Delete `{bucket}.db`, `{bucket}.db-wal`, and `{bucket}.db-shm` from `index_dir`.
fn clear_bucket(index_dir: &Path, bucket: &str) -> std::io::Result<()> {
    for suffix in &[".db", ".db-wal", ".db-shm"] {
        let path = index_dir.join(format!("{}{}", bucket, suffix));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

/// Walk `raw_dir` four levels deep (YYYY/MM/DD/HH) and return all hour-level
/// directories as `(bucket_string, path)` pairs, sorted by bucket string.
///
/// Bucket string format matches the index filename stem: `YYYY-MM-DD-HH`.
/// String ordering equals chronological ordering because values are zero-padded.
fn collect_hour_dirs(raw_dir: &Path) -> Vec<(String, PathBuf)> {
    let mut result = Vec::new();
    let Ok(years) = std::fs::read_dir(raw_dir) else { return result };
    for y in years.flatten() {
        let yp = y.path();
        if !yp.is_dir() { continue; }
        let ys = y.file_name().into_string().unwrap_or_default();
        let Ok(months) = std::fs::read_dir(&yp) else { continue };
        for mo in months.flatten() {
            let mp = mo.path();
            if !mp.is_dir() { continue; }
            let ms = mo.file_name().into_string().unwrap_or_default();
            let Ok(days) = std::fs::read_dir(&mp) else { continue };
            for d in days.flatten() {
                let dp = d.path();
                if !dp.is_dir() { continue; }
                let ds = d.file_name().into_string().unwrap_or_default();
                let Ok(hours) = std::fs::read_dir(&dp) else { continue };
                for h in hours.flatten() {
                    let hp = h.path();
                    if !hp.is_dir() { continue; }
                    let hs = h.file_name().into_string().unwrap_or_default();
                    result.push((format!("{ys}-{ms}-{ds}-{hs}"), hp));
                }
            }
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

/// Find the project root by walking up from the current directory
/// or using the HEADLESS_SIEM_ROOT environment variable.
fn find_project_root() -> Option<PathBuf> {
    if let Ok(root) = std::env::var("HEADLESS_SIEM_ROOT") {
        let p = PathBuf::from(&root);
        if p.join("config").join("sources.toml").exists() {
            return Some(p);
        }
    }

    let mut current = std::env::current_dir().ok()?;
    loop {
        if current.join("config").join("sources.toml").exists() {
            return Some(current);
        }
        if !current.pop() {
            break;
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        let mut p = exe;
        for _ in 0..4 {
            p.pop();
        }
        if p.join("config").join("sources.toml").exists() {
            return Some(p);
        }
    }

    None
}

fn main() {
    // ── Initialize structured logging ────────────────────────────────
    // Default to INFO when RUST_LOG is unset so the operator sees scan
    // progress; respect RUST_LOG when it is set (e.g. RUST_LOG=debug for
    // per-file detail, RUST_LOG=warn for quiet).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // ── Parse command-line arguments ─────────────────────────────────
    let mut data_dir = PathBuf::from("data");
    let mut config_path: Option<String> = None;
    let mut clear = false;
    let mut reindex_all = false;
    let mut reindex_new = false;
    let mut no_watch = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data-dir" => {
                if let Some(dir) = args.next() {
                    data_dir = PathBuf::from(dir);
                }
            }
            "--config" => {
                if let Some(path) = args.next() {
                    config_path = Some(path);
                }
            }
            "--clear" => clear = true,
            "--reindex-all" => reindex_all = true,
            "--reindex-new" => reindex_new = true,
            "--no-watch" => no_watch = true,
            "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                error!("unknown flag: {}", other);
                error!("use --help for usage");
                std::process::exit(1);
            }
        }
    }

    // ── Handle one-shot commands (--clear, --reindex-all) ───────────────
    if clear {
        match clear_indexes(&data_dir) {
            Ok(count) => {
                info!("cleared {} index file(s)", count);
                std::process::exit(0);
            }
            Err(e) => {
                error!("failed to clear indexes: {}", e);
                std::process::exit(1);
            }
        }
    }

    if reindex_all {
        info!("re-indexing all logs (this may take a while)...");
        match clear_indexes(&data_dir) {
            Ok(count) => {
                info!("cleared {} index file(s)", count);
            }
            Err(e) => {
                error!("failed to clear indexes: {}", e);
                std::process::exit(1);
            }
        }
        // Continue to load config and re-index all; note: don't return yet
    }

    // ── Load config ──────────────────────────────────────────────────
    let config_path = config_path.unwrap_or_else(|| {
        let root = find_project_root().unwrap_or_else(|| {
            error!("could not find project root (config/sources.toml)");
            error!("set HEADLESS_SIEM_ROOT or use --config");
            std::process::exit(1);
        });
        root.join("config").join("sources.toml")
            .to_str()
            .unwrap()
            .to_string()
    });

    let siem_config = config::Config::load(&config_path).unwrap_or_else(|e| {
        error!("failed to load config {}: {}", config_path, e);
        std::process::exit(1);
    });

    let index_fields = siem_config.all_index_fields();
    info!(
        "loaded config with {} index fields: {:?}",
        index_fields.len(),
        index_fields
    );

    let raw_dir = data_dir.join("raw");

    // ── Signal handling ──────────────────────────────────────────────
    // signal_hook::flag::register stores `true` into the AtomicBool on signal delivery,
    // so we use a `shutdown` flag (false = keep running, true = stop).
    let shutdown = Arc::new(AtomicBool::new(false));
    if let Err(e) = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown)) {
        warn!("failed to register SIGTERM handler: {}", e);
    }
    if let Err(e) = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown)) {
        warn!("failed to register SIGINT handler: {}", e);
    }

    // ── Ensure raw directory exists ──────────────────────────────────
    if !raw_dir.exists() {
        warn!("raw directory does not exist: {}", raw_dir.display());
        info!("waiting for normalized to create it...");
    }

    // ── Initialize inotify ───────────────────────────────────────────
    let mut inotify = Inotify::init().unwrap_or_else(|e| {
        error!("failed to initialize inotify: {}", e);
        std::process::exit(1);
    });

    // ── Initialize index database manager ────────────────────────────
    let index_db = db::IndexDb::new(&data_dir, &index_fields);

    // ── Handle --reindex-new ─────────────────────────────────────────
    if reindex_new {
        let index_dir = data_dir.join("index");
        let newest = if index_dir.is_dir() { newest_indexed_bucket(&index_dir) } else { None };

        match newest {
            None => {
                // No index yet — full scan, same as --reindex-all
                info!("no existing index found — scanning all raw logs");
                let mut progress = ScanProgress::new();
                scan_existing(&index_db, &raw_dir, &data_dir, &shutdown, &mut progress);
                progress.finish();
            }
            Some(ref bucket) => {
                info!("newest indexed bucket: {} — scanning from there", bucket);
                let hour_dirs = collect_hour_dirs(&raw_dir);
                let eligible: Vec<_> = hour_dirs
                    .iter()
                    .filter(|(b, _)| b.as_str() >= bucket.as_str())
                    .collect();

                if eligible.is_empty() {
                    info!("nothing new to index");
                } else {
                    // Only clear the boundary bucket if its raw hour dir still exists.
                    // Skipping the clear when raw files are gone avoids wiping index
                    // data that can no longer be reconstructed (e.g. post-retention).
                    let boundary_has_raw = eligible.iter().any(|(b, _)| b == bucket);
                    if boundary_has_raw {
                        if let Err(e) = clear_bucket(&index_dir, bucket) {
                            error!("failed to clear boundary bucket {}: {}", bucket, e);
                            std::process::exit(1);
                        }
                        info!("cleared boundary bucket {} for clean re-index", bucket);
                    }
                    let mut progress = ScanProgress::new();
                    for (b, dir) in &eligible {
                        if shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                        info!("indexing hour: {}", b);
                        scan_existing(&index_db, dir, &data_dir, &shutdown, &mut progress);
                    }
                    progress.finish();
                    info!("reindex-new: processed {} hour bucket(s)", eligible.len());
                }
            }
        }

        index_db.close_all();
        info!("reindex-new complete");
        std::process::exit(0);
    }

    let watch_mask = WatchMask::CLOSE_WRITE | WatchMask::CREATE | WatchMask::MOVED_TO;

    if raw_dir.exists() {
        add_recursive_watches(&mut inotify, &raw_dir, watch_mask);
    } else if data_dir.exists() {
        inotify.watches().add(&data_dir, WatchMask::CREATE).unwrap_or_else(|e| {
            error!("failed to watch {}: {}", data_dir.display(), e);
            std::process::exit(1);
        });
    }

    // ── Initial scan ──────────────────────────────────────────────────
    info!("scanning existing files in {}", raw_dir.display());
    let mut progress = ScanProgress::new();
    scan_existing(&index_db, &raw_dir, &data_dir, &shutdown, &mut progress);
    progress.finish();

    // ── Exit after scan for one-shot flags ──────────────────────────
    if reindex_all {
        index_db.close_all();
        info!("re-indexing complete");
        std::process::exit(0);
    }
    if no_watch {
        index_db.close_all();
        info!("initial indexing complete");
        std::process::exit(0);
    }

    // A signal during the initial scan stops it early; exit instead of
    // dropping into the watch loop.
    if shutdown.load(Ordering::Relaxed) {
        info!("shutdown requested during initial scan — exiting");
        index_db.close_all();
        std::process::exit(0);
    }

    info!("watching {} for new .jsonl files", raw_dir.display());
    info!("send SIGTERM or SIGINT to stop");

    // ── Buffer for inotify events ────────────────────────────────────
    let mut buffer = [0u8; 4096];
    let inotify_fd = inotify.as_raw_fd();

    // ── Main event loop ──────────────────────────────────────────────
    while !shutdown.load(Ordering::Relaxed) {
        let events = match inotify.read_events(&mut buffer) {
            Ok(events) => events,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Block until the inotify fd is readable or a signal arrives.
                // signal-hook does not set SA_RESTART, so SIGINT/SIGTERM interrupt
                // poll immediately — unlike std::thread::sleep which retries on EINTR
                // and doesn't re-check `running` until the full sleep completes.
                let mut pfd = libc::pollfd {
                    fd: inotify_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                unsafe { libc::poll(&mut pfd, 1, 200) };
                continue;
            }
            Err(e) => {
                error!("inotify read error: {}", e);
                break;
            }
        };

        for event in events {
            if event.mask.contains(EventMask::CREATE) && event.mask.contains(EventMask::ISDIR) {
                if let Some(name) = event.name {
                    let new_dir = raw_dir.join(name);
                    if new_dir.exists() {
                        add_recursive_watches(&mut inotify, &new_dir, watch_mask);
                        info!("watching new directory: {}", new_dir.display());
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        let mut progress = ScanProgress::new();
                        scan_existing(&index_db, &new_dir, &data_dir, &shutdown, &mut progress);
                    }
                }
                continue;
            }

            if event.mask.contains(EventMask::CLOSE_WRITE)
                || event.mask.contains(EventMask::MOVED_TO)
            {
                if let Some(name) = event.name {
                    let path_str = name.to_string_lossy();
                    if path_str.ends_with(".jsonl") {
                        let full_path = reconstruct_path(&raw_dir, &event, name);
                        info!("indexing: {}", full_path.display());
                        match parser::index_file(&index_db, &full_path, &data_dir, 100) {
                            Ok((indexed, skipped)) => {
                                info!(
                                    "indexed {} events, skipped {} lines",
                                    indexed, skipped
                                );
                            }
                            Err(e) => {
                                error!(
                                    "failed to index {}: {}",
                                    full_path.display(),
                                    e
                                );
                            }
                        }
                        let _ = io::stdout().flush();
                    }
                }
            }
        }
    }

    info!("shutting down gracefully");
    index_db.close_all();
}

/// Scan a directory tree for existing .jsonl files and index them.
///
/// Checks `shutdown` before each directory and each file so a SIGINT/SIGTERM
/// during a long initial scan takes effect promptly instead of waiting for the
/// whole tree to finish. Per-file detail is logged at `debug` (use
/// `RUST_LOG=debug`); aggregate progress is logged via `progress`.
fn scan_existing(
    index_db: &db::IndexDb,
    dir: &Path,
    data_dir: &Path,
    shutdown: &AtomicBool,
    progress: &mut ScanProgress,
) {
    if shutdown.load(Ordering::Relaxed) {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            let path = entry.path();
            if path.is_dir() {
                scan_existing(index_db, &path, data_dir, shutdown, progress);
            } else if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
                debug!("indexing existing: {}", path.display());
                match parser::index_file(index_db, &path, data_dir, 100) {
                    Ok((indexed, skipped)) => {
                        debug!("indexed {} events, skipped {} lines", indexed, skipped);
                        progress.record(indexed, skipped);
                    }
                    Err(e) => {
                        error!("failed to index {}: {}", path.display(), e);
                    }
                }
            }
        }
    }
}

/// Add recursive inotify watches for a directory tree.
fn add_recursive_watches(inotify: &mut Inotify, dir: &Path, mask: WatchMask) {
    if let Err(e) = inotify.watches().add(dir, mask) {
        warn!("failed to watch {}: {}", dir.display(), e);
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                add_recursive_watches(inotify, &path, mask);
            }
        }
    }
}

/// Reconstruct the full filesystem path from an inotify event.
fn reconstruct_path(
    raw_dir: &Path,
    _event: &inotify::Event<&std::ffi::OsStr>,
    name: &std::ffi::OsStr,
) -> PathBuf {
    let direct = raw_dir.join(name);
    if direct.exists() {
        return direct;
    }

    fn search_dir(dir: &Path, name: &std::ffi::OsStr) -> Option<PathBuf> {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let candidate = path.join(name);
                    if candidate.exists() {
                        return Some(candidate);
                    }
                    if let Some(found) = search_dir(&path, name) {
                        return Some(found);
                    }
                }
            }
        }
        None
    }

    if let Some(found) = search_dir(raw_dir, name) {
        return found;
    }
    direct
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use rusqlite;

    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let n = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
            let dir = std::env::temp_dir()
                .join(format!("hsiem_indexd_main_test_{}_{}", std::process::id(), n));
            fs::create_dir_all(&dir).unwrap();
            TempDir { path: dir }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn test_reconstruct_path_direct() {
        let raw = Path::new("/data/raw");
        let name = std::ffi::OsStr::new("sshd.jsonl");
        let result = raw.join(name);
        assert_eq!(result, PathBuf::from("/data/raw/sshd.jsonl"));
    }

    #[test]
    fn test_reconstruct_path_nested() {
        let raw = Path::new("/data/raw");
        let name = std::ffi::OsStr::new("sshd.jsonl");
        let expected = raw.join("2026").join("06").join("22").join(name);
        assert_eq!(expected, PathBuf::from("/data/raw/2026/06/22/sshd.jsonl"));
    }

    #[test]
    fn test_clear_indexes_empty_dir() {
        let tmp = TempDir::new();
        let count = clear_indexes(&tmp.path).unwrap();
        assert_eq!(count, 0, "empty index dir should return 0");
    }

    #[test]
    fn test_clear_indexes_missing_dir() {
        let tmp = TempDir::new();
        let missing = tmp.path.join("nonexistent");
        let count = clear_indexes(&missing).unwrap();
        assert_eq!(count, 0, "missing index dir should return 0");
    }

    #[test]
    fn test_clear_indexes_deletes_db_files() {
        let tmp = TempDir::new();
        let index_dir = tmp.path.join("index");
        fs::create_dir(&index_dir).unwrap();

        // Create some test index files
        fs::write(index_dir.join("2026-06-22-08.db"), "fake db").unwrap();
        fs::write(index_dir.join("2026-06-22-08.db-wal"), "fake wal").unwrap();
        fs::write(index_dir.join("2026-06-22-08.db-shm"), "fake shm").unwrap();
        fs::write(index_dir.join("2026-06-22-09.db"), "fake db").unwrap();
        fs::write(index_dir.join("other.txt"), "should not delete").unwrap();

        let count = clear_indexes(&tmp.path).unwrap();
        assert_eq!(count, 4, "should delete 4 db files (2 .db, 1 .db-wal, 1 .db-shm)");

        // Verify deletion
        assert!(!index_dir.join("2026-06-22-08.db").exists());
        assert!(!index_dir.join("2026-06-22-08.db-wal").exists());
        assert!(!index_dir.join("2026-06-22-08.db-shm").exists());
        assert!(!index_dir.join("2026-06-22-09.db").exists());
        assert!(index_dir.join("other.txt").exists(), "non-index files should remain");
    }

    #[test]
    fn test_clear_indexes_idempotent() {
        let tmp = TempDir::new();
        let index_dir = tmp.path.join("index");
        fs::create_dir(&index_dir).unwrap();
        fs::write(index_dir.join("test.db"), "data").unwrap();

        let count1 = clear_indexes(&tmp.path).unwrap();
        assert_eq!(count1, 1);

        let count2 = clear_indexes(&tmp.path).unwrap();
        assert_eq!(count2, 0, "second clear should find nothing");
    }

    // ── newest_indexed_bucket ─────────────────────────────────────────────

    #[test]
    fn test_newest_indexed_bucket_picks_max() {
        let tmp = TempDir::new();
        let index_dir = tmp.path.join("index");
        fs::create_dir(&index_dir).unwrap();
        fs::write(index_dir.join("2026-06-22-08.db"), "").unwrap();
        fs::write(index_dir.join("2026-06-22-10.db"), "").unwrap();
        fs::write(index_dir.join("2026-06-22-09.db"), "").unwrap();

        let newest = newest_indexed_bucket(&index_dir);
        assert_eq!(newest.as_deref(), Some("2026-06-22-10"));
    }

    #[test]
    fn test_newest_indexed_bucket_ignores_non_db_files() {
        let tmp = TempDir::new();
        let index_dir = tmp.path.join("index");
        fs::create_dir(&index_dir).unwrap();
        fs::write(index_dir.join("2026-06-22-08.db"), "").unwrap();
        fs::write(index_dir.join("2026-06-22-08.db-wal"), "").unwrap(); // sidecar
        fs::write(index_dir.join("README.txt"), "").unwrap();

        let newest = newest_indexed_bucket(&index_dir);
        assert_eq!(newest.as_deref(), Some("2026-06-22-08"));
    }

    #[test]
    fn test_newest_indexed_bucket_empty_dir() {
        let tmp = TempDir::new();
        let index_dir = tmp.path.join("index");
        fs::create_dir(&index_dir).unwrap();
        assert!(newest_indexed_bucket(&index_dir).is_none());
    }

    #[test]
    fn test_newest_indexed_bucket_missing_dir() {
        let tmp = TempDir::new();
        let missing = tmp.path.join("index");
        assert!(newest_indexed_bucket(&missing).is_none());
    }

    // ── collect_hour_dirs ────────────────────────────────────────────────

    #[test]
    fn test_collect_hour_dirs_basic() {
        let tmp = TempDir::new();
        let raw = tmp.path.join("raw");
        fs::create_dir_all(raw.join("2026/06/22/08")).unwrap();
        fs::create_dir_all(raw.join("2026/06/22/09")).unwrap();
        fs::create_dir_all(raw.join("2026/06/23/00")).unwrap();

        let dirs = collect_hour_dirs(&raw);
        let buckets: Vec<&str> = dirs.iter().map(|(b, _)| b.as_str()).collect();
        assert_eq!(buckets, &["2026-06-22-08", "2026-06-22-09", "2026-06-23-00"]);
    }

    #[test]
    fn test_collect_hour_dirs_empty() {
        let tmp = TempDir::new();
        let raw = tmp.path.join("raw");
        fs::create_dir_all(&raw).unwrap();
        assert!(collect_hour_dirs(&raw).is_empty());
    }

    #[test]
    fn test_collect_hour_dirs_missing() {
        let tmp = TempDir::new();
        let raw = tmp.path.join("raw");
        assert!(collect_hour_dirs(&raw).is_empty());
    }

    // ── clear_bucket ─────────────────────────────────────────────────────

    #[test]
    fn test_clear_bucket_removes_db_and_sidecars() {
        let tmp = TempDir::new();
        let index_dir = tmp.path.join("index");
        fs::create_dir(&index_dir).unwrap();
        fs::write(index_dir.join("2026-06-22-08.db"), "db").unwrap();
        fs::write(index_dir.join("2026-06-22-08.db-wal"), "wal").unwrap();
        fs::write(index_dir.join("2026-06-22-08.db-shm"), "shm").unwrap();
        fs::write(index_dir.join("2026-06-22-09.db"), "other").unwrap();

        clear_bucket(&index_dir, "2026-06-22-08").unwrap();

        assert!(!index_dir.join("2026-06-22-08.db").exists());
        assert!(!index_dir.join("2026-06-22-08.db-wal").exists());
        assert!(!index_dir.join("2026-06-22-08.db-shm").exists());
        assert!(index_dir.join("2026-06-22-09.db").exists(), "other bucket untouched");
    }

    #[test]
    fn test_clear_bucket_idempotent() {
        let tmp = TempDir::new();
        let index_dir = tmp.path.join("index");
        fs::create_dir(&index_dir).unwrap();
        fs::write(index_dir.join("2026-06-22-08.db"), "db").unwrap();

        clear_bucket(&index_dir, "2026-06-22-08").unwrap();
        clear_bucket(&index_dir, "2026-06-22-08").unwrap(); // second call: no error
    }

    // ── reindex-new integration ───────────────────────────────────────────

    #[test]
    fn test_reindex_new_no_duplicates() {
        let tmp = TempDir::new();
        let fields = vec![
            "timestamp".to_string(), "source".to_string(),
            "src_ip".to_string(), "byte_offset".to_string(), "raw_file".to_string(),
        ];

        // Create two hour directories with JSONL files
        let hour08 = tmp.path.join("raw/2026/06/28/08/55/03");
        let hour09 = tmp.path.join("raw/2026/06/28/09/00/00");
        fs::create_dir_all(&hour08).unwrap();
        fs::create_dir_all(&hour09).unwrap();

        let f08 = hour08.join("sshd.jsonl");
        fs::write(&f08, concat!(
            "{\"timestamp\":\"Jun 28 08:55:01\",\"src_ip\":\"10.0.0.1\",\"_source_type\":\"sshd\"}\n",
            "{\"timestamp\":\"Jun 28 08:55:02\",\"src_ip\":\"10.0.0.2\",\"_source_type\":\"sshd\"}\n",
        )).unwrap();

        let f09 = hour09.join("sshd.jsonl");
        fs::write(&f09, "{\"timestamp\":\"Jun 28 09:00:00\",\"src_ip\":\"10.0.0.3\",\"_source_type\":\"sshd\"}\n").unwrap();

        // Phase 1: index only hour 08 (simulates state before --reindex-new)
        {
            let db = db::IndexDb::new(&tmp.path, &fields);
            parser::index_file(&db, &f08, &tmp.path, 100).unwrap();
            db.close_all();
        }

        // derive_bucket returns "YYYY/MM/DD/HH" (slashes); open_bucket converts
        // to "YYYY-MM-DD-HH" (dashes) for the filename.  newest_indexed_bucket
        // reads the filename stem directly, so it also uses dashes.
        let index_dir = tmp.path.join("index");
        let stem_08 = db::IndexDb::derive_bucket(&f08).unwrap().replace('/', "-");
        let stem_09 = db::IndexDb::derive_bucket(&f09).unwrap().replace('/', "-");
        assert_eq!(newest_indexed_bucket(&index_dir).as_deref(), Some(stem_08.as_str()));
        assert!(!index_dir.join(format!("{}.db", stem_09)).exists());

        // Phase 2: simulate --reindex-new
        {
            let raw_dir = tmp.path.join("raw");
            let newest = newest_indexed_bucket(&index_dir).unwrap();
            let hour_dirs = collect_hour_dirs(&raw_dir);
            let eligible: Vec<_> = hour_dirs.iter()
                .filter(|(b, _)| b.as_str() >= newest.as_str())
                .collect();
            assert_eq!(eligible.len(), 2, "both hours should be eligible");

            // Clear boundary bucket
            clear_bucket(&index_dir, &newest).unwrap();
            assert!(!index_dir.join(format!("{}.db", newest)).exists(), "boundary db should be gone");

            let db = db::IndexDb::new(&tmp.path, &fields);
            let shutdown = AtomicBool::new(false);
            let mut progress = ScanProgress::new();
            for (_, dir) in &eligible {
                scan_existing(&db, dir, &tmp.path, &shutdown, &mut progress);
            }
            db.close_all();
        }

        // Verify: hour 08 has exactly 2 rows (re-indexed, not doubled), hour 09 has 1
        let db_08 = index_dir.join(format!("{}.db", stem_08));
        let db_09 = index_dir.join(format!("{}.db", stem_09));

        let conn_08 = rusqlite::Connection::open_with_flags(
            &db_08, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).unwrap();
        let count_08: i64 = conn_08
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count_08, 2, "hour 08 should have exactly 2 rows (no duplicates)");

        let conn_09 = rusqlite::Connection::open_with_flags(
            &db_09, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).unwrap();
        let count_09: i64 = conn_09
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count_09, 1, "hour 09 should have 1 row");
    }

    #[test]
    fn test_reindex_new_nothing_new() {
        let tmp = TempDir::new();
        let index_dir = tmp.path.join("index");
        fs::create_dir(&index_dir).unwrap();
        // Index has bucket for an hour that has no corresponding raw dir
        fs::write(index_dir.join("2026-06-28-10.db"), "").unwrap();

        let raw_dir = tmp.path.join("raw");
        fs::create_dir_all(&raw_dir).unwrap();

        let newest = newest_indexed_bucket(&index_dir).unwrap();
        let hour_dirs = collect_hour_dirs(&raw_dir);
        let eligible: Vec<_> = hour_dirs.iter()
            .filter(|(b, _)| b.as_str() >= newest.as_str())
            .collect();

        assert!(eligible.is_empty(), "no raw dirs → nothing to index");
    }
}

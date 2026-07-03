mod config;
mod db;
mod parser;

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use std::collections::HashMap;
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How often the initial scan logs an aggregate progress line.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(2);

/// How often the main loop checks for idle bucket connections to evict.
/// Piggybacks on the existing inotify poll timeout, so this is a lower
/// bound, not a guarantee — fine, since eviction timing only needs to be
/// coarse (see `IndexDb::evict_idle`).
const IDLE_EVICT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// How often the main loop re-scans raw files with a recent mtime, as a
/// safety net against missed inotify events.
///
/// Recursive inotify watching has an inherent TOCTOU race for a brand-new,
/// multi-level-deep directory chain created in one burst (`fs::create_dir_all`
/// completes several `mkdir`s well inside a microsecond — potentially before
/// this process even wakes from `poll()` to react to the *first* level's
/// CREATE event and install a watch on it, at which point any child created
/// in between is never observed by the kernel at all — nothing to catch up
/// on later, the event simply never existed). The reactive
/// watch-then-synchronously-scan handling in the main loop closes most of
/// this window already, but not all of it, and there's no way to prove a
/// negative from the event stream alone. This sweep is the actual fix:
/// periodically re-scan anything touched recently by *wall-clock mtime*
/// (deliberately not by the event-time bucket the file happens to be named
/// after — a bucket can carry an out-of-order or future event timestamp,
/// same root cause as the race above, and still have a very recent mtime).
/// `scan_existing`'s `INSERT OR IGNORE` on `(raw_file, byte_offset)` makes
/// re-scanning already-indexed files a cheap no-op, so this costs
/// approximately nothing on a quiet system.
const RECENT_FILE_SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// How far back (by mtime) the recent-file sweep looks. Comfortably longer
/// than the sweep interval itself so a file can't fall through a gap
/// between two sweeps, and longer than any plausible reactive-watch
/// catch-up delay.
const RECENT_FILE_SWEEP_LOOKBACK: Duration = Duration::from_secs(900);

/// How long a bucket connection can go without a write before eviction
/// reclaims its WAL. An hour bucket goes quiet forever once its hour
/// passes, so this just needs to be comfortably longer than any expected
/// gap in live traffic — 15 minutes.
const IDLE_EVICT_AFTER: Duration = Duration::from_secs(15 * 60);

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
            eprintln!(
                "[indexd] progress: {} files, {} events indexed, {} skipped ({:.0}s elapsed)",
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
        eprintln!(
            "[indexd] scan complete: {} files, {} events indexed, {} skipped in {:.1}s",
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
    eprintln!("  --backfill <bucket> Clear and re-index one hour bucket (\"YYYY-MM-DD-HH\"),");
    eprintln!("                      then exit. Unlike --reindex-new (which only covers the");
    eprintln!("                      tail from the newest indexed bucket onward), this repairs");
    eprintln!("                      a gap anywhere in the range — e.g. a bucket `siemctl");
    eprintln!("                      digest`'s completeness check flagged as incomplete. Repeat");
    eprintln!("                      the flag to backfill multiple buckets in one run.");
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

/// Parse a `"YYYY-MM-DD-HH"` bucket string into its four zero-padded
/// components, for building a `raw/YYYY/MM/DD/HH` path. Returns `None` for
/// anything that isn't exactly 4/2/2/2 ASCII digits in that shape — the
/// same strictness `--backfill` needs to avoid silently no-op'ing on a typo.
fn parse_bucket(s: &str) -> Option<(String, String, String, String)> {
    let parts: Vec<&str> = s.split('-').collect();
    let [y, mo, d, h] = parts.as_slice() else { return None };
    let widths_ok = y.len() == 4 && mo.len() == 2 && d.len() == 2 && h.len() == 2;
    let digits_ok = [*y, *mo, *d, *h].iter().all(|p| p.chars().all(|c| c.is_ascii_digit()));
    if widths_ok && digits_ok {
        Some((y.to_string(), mo.to_string(), d.to_string(), h.to_string()))
    } else {
        None
    }
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
    // ── Parse command-line arguments ─────────────────────────────────
    let mut data_dir = PathBuf::from("data");
    let mut config_path: Option<String> = None;
    let mut clear = false;
    let mut reindex_all = false;
    let mut reindex_new = false;
    let mut no_watch = false;
    let mut backfill_buckets: Vec<String> = Vec::new();
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
            "--backfill" => {
                if let Some(bucket) = args.next() {
                    backfill_buckets.push(bucket);
                } else {
                    eprintln!("[indexd] --backfill requires a bucket argument (\"YYYY-MM-DD-HH\")");
                    std::process::exit(1);
                }
            }
            "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                eprintln!("[indexd] unknown flag: {}", other);
                eprintln!("[indexd] use --help for usage");
                std::process::exit(1);
            }
        }
    }

    // ── Handle one-shot commands (--clear, --reindex-all) ───────────────
    if clear {
        match clear_indexes(&data_dir) {
            Ok(count) => {
                eprintln!("[indexd] cleared {} index file(s)", count);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("[indexd] failed to clear indexes: {}", e);
                std::process::exit(1);
            }
        }
    }

    if reindex_all {
        eprintln!("[indexd] re-indexing all logs (this may take a while)...");
        match clear_indexes(&data_dir) {
            Ok(count) => {
                eprintln!("[indexd] cleared {} index file(s)", count);
            }
            Err(e) => {
                eprintln!("[indexd] failed to clear indexes: {}", e);
                std::process::exit(1);
            }
        }
        // Continue to load config and re-index all; note: don't return yet
    }

    // ── Load config ──────────────────────────────────────────────────
    let config_path = config_path.unwrap_or_else(|| {
        let root = find_project_root().unwrap_or_else(|| {
            eprintln!("[indexd] could not find project root (config/sources.toml)");
            eprintln!("[indexd] set HEADLESS_SIEM_ROOT or use --config");
            std::process::exit(1);
        });
        root.join("config").join("sources.toml")
            .to_str()
            .unwrap()
            .to_string()
    });

    let siem_config = config::Config::load(&config_path).unwrap_or_else(|e| {
        eprintln!("[indexd] failed to load config {}: {}", config_path, e);
        std::process::exit(1);
    });

    let index_fields = siem_config.all_index_fields();
    eprintln!(
        "[indexd] loaded config with {} index fields: {:?}",
        index_fields.len(),
        index_fields
    );

    let raw_dir = data_dir.join("raw");

    // ── Signal handling ──────────────────────────────────────────────
    // signal_hook::flag::register stores `true` into the AtomicBool on signal delivery,
    // so we use a `shutdown` flag (false = keep running, true = stop).
    let shutdown = Arc::new(AtomicBool::new(false));
    if let Err(e) = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown)) {
        eprintln!("[indexd] failed to register SIGTERM handler: {}", e);
    }
    if let Err(e) = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown)) {
        eprintln!("[indexd] failed to register SIGINT handler: {}", e);
    }

    // ── Ensure raw directory exists ──────────────────────────────────
    if !raw_dir.exists() {
        eprintln!("[indexd] raw directory does not exist: {}", raw_dir.display());
        eprintln!("[indexd] waiting for normalized to create it...");
    }

    // ── Initialize inotify ───────────────────────────────────────────
    let mut inotify = Inotify::init().unwrap_or_else(|e| {
        eprintln!("[indexd] failed to initialize inotify: {}", e);
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
                eprintln!("[indexd] no existing index found — scanning all raw logs");
                let mut progress = ScanProgress::new();
                scan_existing(&index_db, &raw_dir, &data_dir, &shutdown, &mut progress);
                progress.finish();
            }
            Some(ref bucket) => {
                eprintln!("[indexd] newest indexed bucket: {} — scanning from there", bucket);
                let hour_dirs = collect_hour_dirs(&raw_dir);
                let eligible: Vec<_> = hour_dirs
                    .iter()
                    .filter(|(b, _)| b.as_str() >= bucket.as_str())
                    .collect();

                if eligible.is_empty() {
                    eprintln!("[indexd] nothing new to index");
                } else {
                    // Only clear the boundary bucket if its raw hour dir still exists.
                    // Skipping the clear when raw files are gone avoids wiping index
                    // data that can no longer be reconstructed (e.g. post-retention).
                    let boundary_has_raw = eligible.iter().any(|(b, _)| b == bucket);
                    if boundary_has_raw {
                        if let Err(e) = clear_bucket(&index_dir, bucket) {
                            eprintln!("[indexd] failed to clear boundary bucket {}: {}", bucket, e);
                            std::process::exit(1);
                        }
                        eprintln!("[indexd] cleared boundary bucket {} for clean re-index", bucket);
                    }
                    let mut progress = ScanProgress::new();
                    for (b, dir) in &eligible {
                        if shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                        eprintln!("[indexd] indexing hour: {}", b);
                        scan_existing(&index_db, dir, &data_dir, &shutdown, &mut progress);
                    }
                    progress.finish();
                    eprintln!("[indexd] reindex-new: processed {} hour bucket(s)", eligible.len());
                }
            }
        }

        index_db.close_all();
        eprintln!("[indexd] reindex-new complete");
        std::process::exit(0);
    }

    // ── Handle --backfill ────────────────────────────────────────────
    // Repairs a gap anywhere in the range (unlike --reindex-new, which only
    // covers the tail from the newest indexed bucket onward). Typical
    // trigger: `siemctl digest`'s completeness check flags a specific
    // "YYYY-MM-DD-HH" bucket as short of what's on disk in raw.
    if !backfill_buckets.is_empty() {
        let index_dir = data_dir.join("index");
        let mut ok = true;
        for bucket in &backfill_buckets {
            let Some((y, mo, d, h)) = parse_bucket(bucket) else {
                eprintln!(
                    "[indexd] --backfill: invalid bucket '{}' (expected \"YYYY-MM-DD-HH\")",
                    bucket
                );
                ok = false;
                continue;
            };
            let hour_dir = raw_dir.join(&y).join(&mo).join(&d).join(&h);
            if !hour_dir.is_dir() {
                eprintln!(
                    "[indexd] --backfill {}: no raw directory at {} — nothing to backfill \
                     (data may be past retention)",
                    bucket,
                    hour_dir.display()
                );
                continue;
            }
            if let Err(e) = clear_bucket(&index_dir, bucket) {
                eprintln!("[indexd] --backfill {}: failed to clear existing index: {}", bucket, e);
                ok = false;
                continue;
            }
            eprintln!("[indexd] backfilling bucket {} from {}", bucket, hour_dir.display());
            let mut progress = ScanProgress::new();
            scan_existing(&index_db, &hour_dir, &data_dir, &shutdown, &mut progress);
            progress.finish();
        }
        index_db.close_all();
        if ok {
            eprintln!("[indexd] backfill complete ({} bucket(s))", backfill_buckets.len());
            std::process::exit(0);
        } else {
            eprintln!("[indexd] backfill completed with errors");
            std::process::exit(1);
        }
    }

    let watch_mask = WatchMask::CLOSE_WRITE | WatchMask::CREATE | WatchMask::MOVED_TO;

    // Maps every watch descriptor to the directory path it watches.
    // Event handlers use this to reconstruct the full path of a new
    // file or directory without needing to search the filesystem.
    let mut watch_paths: HashMap<WatchDescriptor, PathBuf> = HashMap::new();

    if raw_dir.exists() {
        add_recursive_watches(&mut inotify, &raw_dir, watch_mask, &mut watch_paths);
    } else if data_dir.exists() {
        // raw/ doesn't exist yet — watch data/ until normalized creates it.
        match inotify.watches().add(&data_dir, WatchMask::CREATE) {
            Ok(wd) => { watch_paths.insert(wd, data_dir.clone()); }
            Err(e) => {
                eprintln!("[indexd] failed to watch {}: {}", data_dir.display(), e);
                std::process::exit(1);
            }
        }
    }

    // ── Initial scan ──────────────────────────────────────────────────
    eprintln!("[indexd] scanning existing files in {}", raw_dir.display());
    let mut progress = ScanProgress::new();
    scan_existing(&index_db, &raw_dir, &data_dir, &shutdown, &mut progress);
    progress.finish();

    // ── Exit after scan for one-shot flags ──────────────────────────
    if reindex_all {
        index_db.close_all();
        eprintln!("[indexd] re-indexing complete");
        std::process::exit(0);
    }
    if no_watch {
        index_db.close_all();
        eprintln!("[indexd] initial indexing complete");
        std::process::exit(0);
    }

    // A signal during the initial scan stops it early; exit instead of
    // dropping into the watch loop.
    if shutdown.load(Ordering::Relaxed) {
        eprintln!("[indexd] shutdown requested during initial scan — exiting");
        index_db.close_all();
        std::process::exit(0);
    }

    eprintln!("[indexd] watching {} for new .jsonl files", raw_dir.display());
    eprintln!("[indexd] send SIGTERM or SIGINT to stop");

    // ── Buffer for inotify events ────────────────────────────────────
    let mut buffer = [0u8; 4096];
    let inotify_fd = inotify.as_raw_fd();
    let mut last_evict_sweep = Instant::now();
    let mut last_recent_sweep = Instant::now();

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

                // Idle bucket eviction rides the same poll timeout — this
                // branch is where the loop actually sits most of the time
                // for a homelab-volume SIEM, which is exactly when quiet
                // hour buckets need their WAL reclaimed.
                if last_evict_sweep.elapsed() >= IDLE_EVICT_SWEEP_INTERVAL {
                    let evicted = index_db.evict_idle(IDLE_EVICT_AFTER);
                    if !evicted.is_empty() {
                        eprintln!(
                            "[indexd] evicted {} idle bucket connection(s) (WAL checkpointed): {:?}",
                            evicted.len(),
                            evicted
                        );
                    }
                    last_evict_sweep = Instant::now();
                }

                // Recent-file reconciliation sweep — see RECENT_FILE_SWEEP_INTERVAL's
                // doc comment for why this exists (inotify recursive-watch races on
                // freshly created deep directory chains are unrecoverable at the
                // event-stream level; this is the actual fix).
                if last_recent_sweep.elapsed() >= RECENT_FILE_SWEEP_INTERVAL {
                    let (files, events) = scan_recent(
                        &index_db,
                        &raw_dir,
                        &data_dir,
                        &shutdown,
                        RECENT_FILE_SWEEP_LOOKBACK,
                    );
                    if files > 0 {
                        eprintln!(
                            "[indexd] recent-file sweep: checked {} file(s) modified in the last {}s, {} event(s) indexed (already-indexed lines are no-ops)",
                            files,
                            RECENT_FILE_SWEEP_LOOKBACK.as_secs(),
                            events
                        );
                    }
                    last_recent_sweep = Instant::now();
                }
                continue;
            }
            Err(e) => {
                eprintln!("[indexd] inotify read error: {}", e);
                break;
            }
        };

        for event in events {
            if event.mask.contains(EventMask::CREATE) && event.mask.contains(EventMask::ISDIR) {
                if let Some(name) = event.name {
                    // Use the watch descriptor to find the exact parent directory.
                    // Previously this always joined to raw_dir, which broke for any
                    // directory level below data/raw/ (e.g. the month "06" dir was
                    // joined to data/raw/ producing data/raw/06 instead of
                    // data/raw/2026/06).
                    let parent = watch_paths.get(&event.wd)
                        .cloned()
                        .unwrap_or_else(|| raw_dir.clone());
                    let new_dir = parent.join(name);
                    if new_dir.exists() {
                        add_recursive_watches(&mut inotify, &new_dir, watch_mask, &mut watch_paths);
                        eprintln!("[indexd] watching new directory: {}", new_dir.display());
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
                        // Resolve the full path via the watch descriptor map; fall
                        // back to the old filesystem search only if the wd is unknown.
                        let full_path = watch_paths.get(&event.wd)
                            .map(|parent| parent.join(name))
                            .unwrap_or_else(|| reconstruct_path(&raw_dir, &event, name));
                        eprintln!("[indexd] indexing: {}", full_path.display());
                        match parser::index_file(&index_db, &full_path, &data_dir, 100) {
                            Ok((indexed, skipped)) => {
                                eprintln!(
                                    "[indexd] indexed {} events, skipped {} lines",
                                    indexed, skipped
                                );
                            }
                            Err(e) => {
                                eprintln!(
                                    "[indexd] failed to index {}: {}",
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

    eprintln!("[indexd] shutting down gracefully");
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
                match parser::index_file(index_db, &path, data_dir, 100) {
                    Ok((indexed, skipped)) => {
                        progress.record(indexed, skipped);
                    }
                    Err(e) => {
                        eprintln!("[indexd] failed to index {}: {}", path.display(), e);
                    }
                }
            }
        }
    }
}

/// Re-scan `.jsonl` files under `dir` whose mtime is within `lookback` of
/// now, indexing any lines not already present. Returns
/// `(files_checked, events_indexed)`.
///
/// This is the periodic safety net described on [`RECENT_FILE_SWEEP_INTERVAL`]:
/// scoped by *wall-clock mtime*, not by the event-time bucket a file is
/// named after, so it still catches a file sitting in an out-of-order or
/// future-dated bucket that the reactive inotify watcher missed. Cheap on a
/// quiet system — `index_file`'s `INSERT OR IGNORE` on `(raw_file,
/// byte_offset)` makes re-scanning an already-fully-indexed file a fast
/// no-op, and this only walks files touched in the lookback window, not the
/// whole raw tree.
fn scan_recent(
    index_db: &db::IndexDb,
    dir: &Path,
    data_dir: &Path,
    shutdown: &AtomicBool,
    lookback: Duration,
) -> (usize, usize) {
    let Some(cutoff) = std::time::SystemTime::now().checked_sub(lookback) else {
        return (0, 0);
    };
    let mut files_checked = 0usize;
    let mut events_indexed = 0usize;
    walk_recent(index_db, dir, data_dir, shutdown, cutoff, &mut files_checked, &mut events_indexed);
    (files_checked, events_indexed)
}

fn walk_recent(
    index_db: &db::IndexDb,
    dir: &Path,
    data_dir: &Path,
    shutdown: &AtomicBool,
    cutoff: std::time::SystemTime,
    files_checked: &mut usize,
    events_indexed: &mut usize,
) {
    if shutdown.load(Ordering::Relaxed) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };

        if path.is_dir() {
            // A directory's mtime updates whenever an entry is added inside
            // it — so a subtree with no *directory-level* changes since
            // `cutoff` cannot contain a file created since `cutoff` either,
            // and is safe to skip without descending. This is what keeps
            // the sweep cheap as the raw tree grows over months: old
            // year/month/day branches get pruned in O(1) per branch instead
            // of walked in full, and only the handful of directories on the
            // "hot" path (wherever normalized is actively writing) get
            // descended into.
            if meta.modified().map(|m| m >= cutoff).unwrap_or(true) {
                walk_recent(index_db, &path, data_dir, shutdown, cutoff, files_checked, events_indexed);
            }
            continue;
        }

        if !path.extension().map(|e| e == "jsonl").unwrap_or(false) {
            continue;
        }
        let Ok(mtime) = meta.modified() else { continue };
        if mtime < cutoff {
            continue;
        }
        *files_checked += 1;
        if let Ok((indexed, _skipped)) = parser::index_file(index_db, &path, data_dir, 100) {
            *events_indexed += indexed;
        }
    }
}

/// Add recursive inotify watches for a directory tree.
/// Records every (WatchDescriptor → path) pair in `watch_paths` so that
/// event handlers can resolve the full path of a newly created file or
/// directory without guessing.
fn add_recursive_watches(
    inotify: &mut Inotify,
    dir: &Path,
    mask: WatchMask,
    watch_paths: &mut HashMap<WatchDescriptor, PathBuf>,
) {
    match inotify.watches().add(dir, mask) {
        Ok(wd) => { watch_paths.insert(wd, dir.to_path_buf()); }
        Err(e) => {
            eprintln!("[indexd] failed to watch {}: {}", dir.display(), e);
            return;
        }
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                add_recursive_watches(inotify, &path, mask, watch_paths);
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

    // ── parse_bucket ─────────────────────────────────────────────────────

    #[test]
    fn parse_bucket_valid() {
        assert_eq!(
            parse_bucket("2026-07-01-00"),
            Some(("2026".to_string(), "07".to_string(), "01".to_string(), "00".to_string()))
        );
    }

    #[test]
    fn parse_bucket_rejects_wrong_width() {
        assert_eq!(parse_bucket("26-07-01-00"), None);
        assert_eq!(parse_bucket("2026-7-01-00"), None);
        assert_eq!(parse_bucket("2026-07-01-0"), None);
    }

    #[test]
    fn parse_bucket_rejects_non_digits() {
        assert_eq!(parse_bucket("2026-07-01-XX"), None);
    }

    #[test]
    fn parse_bucket_rejects_wrong_shape() {
        assert_eq!(parse_bucket("2026-07-01"), None);
        assert_eq!(parse_bucket("2026-07-01-00-00"), None);
        assert_eq!(parse_bucket(""), None);
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

    // ── backfill (clear_bucket + scan_existing on one hour dir) ────────────

    #[test]
    fn backfill_indexes_a_bucket_with_no_prior_index() {
        let tmp = TempDir::new();
        let fields = vec![
            "timestamp".to_string(), "source".to_string(),
            "src_ip".to_string(), "byte_offset".to_string(), "raw_file".to_string(),
        ];

        // Simulates the real gap: raw events exist for an hour that was
        // never indexed at all (no .db file for it). `leaf_dir` is the
        // minute/second-level directory a raw file actually lives in;
        // `--backfill` operates on the coarser YYYY/MM/DD/HH hour dir and
        // relies on scan_existing's own recursion to reach files this deep.
        let leaf_dir = tmp.path.join("raw/2026/07/01/00/00/00");
        fs::create_dir_all(&leaf_dir).unwrap();
        fs::write(
            leaf_dir.join("sshd.jsonl"),
            concat!(
                "{\"timestamp\":\"2026-07-01T00:00:00Z\",\"src_ip\":\"10.0.0.1\",\"_source_type\":\"sshd\"}\n",
                "{\"timestamp\":\"2026-07-01T00:00:01Z\",\"src_ip\":\"10.0.0.2\",\"_source_type\":\"sshd\"}\n",
            ),
        )
        .unwrap();

        let index_dir = tmp.path.join("index");
        assert!(!index_dir.join("2026-07-01-00.db").exists());

        // What `--backfill 2026-07-01-00` does, inline (main() exits the
        // process, so the logic under test is exercised directly here).
        let (y, mo, d, h) = parse_bucket("2026-07-01-00").unwrap();
        let target = tmp.path.join("raw").join(&y).join(&mo).join(&d).join(&h);
        assert!(leaf_dir.starts_with(&target), "leaf dir must live under the hour dir");

        clear_bucket(&index_dir, "2026-07-01-00").unwrap(); // no-op, nothing to clear
        let db = db::IndexDb::new(&tmp.path, &fields);
        let shutdown = AtomicBool::new(false);
        let mut progress = ScanProgress::new();
        scan_existing(&db, &target, &tmp.path, &shutdown, &mut progress);
        db.close_all();

        let conn = rusqlite::Connection::open_with_flags(
            index_dir.join("2026-07-01-00.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 2, "both raw lines backfilled");
    }

    #[test]
    fn backfill_is_idempotent_no_duplicate_rows() {
        let tmp = TempDir::new();
        let fields = vec![
            "timestamp".to_string(), "source".to_string(),
            "src_ip".to_string(), "byte_offset".to_string(), "raw_file".to_string(),
        ];
        let hour_dir = tmp.path.join("raw/2026/07/01/00/00/00");
        fs::create_dir_all(&hour_dir).unwrap();
        fs::write(
            hour_dir.join("sshd.jsonl"),
            "{\"timestamp\":\"2026-07-01T00:00:00Z\",\"src_ip\":\"10.0.0.1\",\"_source_type\":\"sshd\"}\n",
        )
        .unwrap();
        let index_dir = tmp.path.join("index");

        // Run the backfill sequence twice — clear_bucket + scan_existing —
        // as would happen if an operator re-ran --backfill on a bucket that
        // was already fixed.
        for _ in 0..2 {
            clear_bucket(&index_dir, "2026-07-01-00").unwrap();
            let db = db::IndexDb::new(&tmp.path, &fields);
            let shutdown = AtomicBool::new(false);
            let mut progress = ScanProgress::new();
            scan_existing(&db, &hour_dir, &tmp.path, &shutdown, &mut progress);
            db.close_all();
        }

        let conn = rusqlite::Connection::open_with_flags(
            index_dir.join("2026-07-01-00.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1, "re-running backfill must not duplicate rows");
    }

    // ── scan_recent ──────────────────────────────────────────────────────

    #[test]
    fn scan_recent_indexes_files_within_lookback() {
        let tmp = TempDir::new();
        let fields = vec![
            "timestamp".to_string(), "source".to_string(),
            "src_ip".to_string(), "byte_offset".to_string(), "raw_file".to_string(),
        ];
        let raw = tmp.path.join("raw/2099/01/01/00/00/00");
        fs::create_dir_all(&raw).unwrap();
        fs::write(
            raw.join("sshd.jsonl"),
            "{\"timestamp\":\"2099-01-01T00:00:00Z\",\"src_ip\":\"10.0.0.1\",\"_source_type\":\"sshd\"}\n",
        )
        .unwrap();

        let db = db::IndexDb::new(&tmp.path, &fields);
        let shutdown = AtomicBool::new(false);
        let (files, events) =
            scan_recent(&db, &tmp.path.join("raw"), &tmp.path, &shutdown, Duration::from_secs(3600));
        db.close_all();

        assert_eq!(files, 1, "the freshly written file is within the lookback window");
        assert_eq!(events, 1);
    }

    #[test]
    fn scan_recent_skips_files_older_than_lookback() {
        let tmp = TempDir::new();
        let fields = vec![
            "timestamp".to_string(), "source".to_string(),
            "src_ip".to_string(), "byte_offset".to_string(), "raw_file".to_string(),
        ];
        let raw = tmp.path.join("raw/2020/01/01/00/00/00");
        fs::create_dir_all(&raw).unwrap();
        let path = raw.join("sshd.jsonl");
        fs::write(
            &path,
            "{\"timestamp\":\"2020-01-01T00:00:00Z\",\"src_ip\":\"10.0.0.1\",\"_source_type\":\"sshd\"}\n",
        )
        .unwrap();
        // Back-date mtime well outside any lookback window this test uses.
        let old = std::time::SystemTime::now() - Duration::from_secs(999_999);
        filetime_set(&path, old);

        let db = db::IndexDb::new(&tmp.path, &fields);
        let shutdown = AtomicBool::new(false);
        let (files, events) =
            scan_recent(&db, &tmp.path.join("raw"), &tmp.path, &shutdown, Duration::from_secs(60));
        db.close_all();

        assert_eq!(files, 0, "an old-mtime file must be pruned before it's even opened");
        assert_eq!(events, 0);
    }

    /// Minimal mtime-setter so the pruning test doesn't need a `filetime`
    /// crate dependency just for one test — `utimensat` via `libc`, already
    /// a dependency of this crate for the inotify poll loop.
    fn filetime_set(path: &Path, t: std::time::SystemTime) {
        let dur = t.duration_since(std::time::UNIX_EPOCH).unwrap();
        let spec = libc::timespec {
            tv_sec: dur.as_secs() as libc::time_t,
            tv_nsec: dur.subsec_nanos() as _,
        };
        let times = [spec, spec];
        let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        unsafe {
            libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0);
        }
    }
}

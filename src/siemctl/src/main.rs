mod alerts;
mod db;
mod digest;
mod digest_config;
mod digest_query;
mod digest_render;
mod normconfig;
mod query;
mod render;
mod sources;
mod time;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs,
    io::{self, BufRead, BufReader, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const DEFAULT_DATA_DIR: &str = "./data";
const PROD_DATA_DIR: &str = "/var/lib/headless-siem";

/// `./data` for the dev tree; falls back to the production data dir (see
/// config/systemd/install.sh) if that's not present, so siemctl works from
/// any cwd on an installed host without requiring --data-dir every time.
fn default_data_dir() -> PathBuf {
    let dev = PathBuf::from(DEFAULT_DATA_DIR);
    if dev.is_dir() {
        return dev;
    }
    let prod = PathBuf::from(PROD_DATA_DIR);
    if prod.is_dir() {
        return prod;
    }
    dev
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_top_help();
        std::process::exit(0);
    }

    let cmd = &args[0];
    let rest = &args[1..];

    let valid_fields = sources::find_sources_toml()
        .map(|p| sources::load_valid_fields(&p))
        .unwrap_or_default();

    let rc = match cmd.as_str() {
        "status" => run(cmd_status(rest)),
        "stats" => run(cmd_stats(rest)),
        "search" => run(cmd_search(rest, &valid_fields)),
        "alerts" => run(cmd_alerts(rest)),
        "digest" => run(cmd_digest(rest)),
        "tail" => run(cmd_tail(rest)),
        "retention" => run(cmd_retention(rest)),
        "dry-run" => run(cmd_dryrun(rest)),
        "validate" => run(cmd_validate(rest)),
        other => {
            eprintln!("siemctl: unknown command '{other}'. Try 'siemctl --help'.");
            1
        }
    };
    std::process::exit(rc);
}

fn run(r: Result<i32>) -> i32 {
    match r {
        Ok(rc) => rc,
        Err(e) => {
            eprintln!("siemctl: {e}");
            1
        }
    }
}

fn print_top_help() {
    println!(
        "siemctl — Headless SIEM management CLI\n\
         \n\
         USAGE:\n\
         \x20 siemctl <command> [options]\n\
         \n\
         COMMANDS:\n\
         \x20 status      Show data directory size, file counts, index coverage\n\
         \x20 stats       Event counts per source, field coverage (use --source for breakdown)\n\
         \x20 search      Search indexed buckets or raw JSONL (field, full-text, time-range)\n\
         \x20 alerts      Query ruled/correlated alerts under data/alerts/\n\
         \x20 digest      Anomaly-oriented shift-briefing summary over a time window\n\
         \x20 tail        Stream live events from raw JSONL files\n\
         \x20 retention   Delete raw data older than N days\n\
         \x20 dry-run     Test normalization + rule matching against a fixture file\n\
         \x20 validate    Validate sources.toml and Sigma rule files\n\
         \n\
         Run 'siemctl <command> --help' for per-command options."
    );
}

// ── helpers ────────────────────────────────────────────────────────────────

fn next_arg<'a>(it: &mut impl Iterator<Item = &'a str>, flag: &str) -> Result<&'a str> {
    it.next()
        .ok_or_else(|| format!("{flag} requires an argument").into())
}

fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB", "EB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Locate a SIEM pipeline binary relative to siemctl's own path, then PATH.
fn find_binary(name: &str) -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.as_path();
        for _ in 0..6 {
            for profile in &["debug", "release"] {
                let c = dir.join("src").join(name).join("target").join(profile).join(name);
                if c.is_file() {
                    return c;
                }
            }
            match dir.parent() {
                Some(p) => dir = p,
                None => break,
            }
        }
    }
    PathBuf::from(name)
}

/// Walk `dir` recursively, calling `f` on every `.jsonl` file.
pub(crate) fn walk_jsonl(dir: &Path, f: &mut impl FnMut(&Path)) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let p = entry.path();
        if p.is_dir() {
            walk_jsonl(&p, f);
        } else if p.extension().map(|e| e == "jsonl").unwrap_or(false) {
            f(&p);
        }
    }
}

/// Collect `.jsonl` files under `data_dir/raw/`, optionally filtered by
/// source stem, and optionally limited to an hour-bucket time range.
fn collect_raw_files(
    data_dir: &Path,
    source: Option<&str>,
    after: Option<time::HourBucket>,
    before: Option<time::HourBucket>,
) -> Vec<PathBuf> {
    let raw_dir = data_dir.join("raw");

    if after.is_some() || before.is_some() {
        let a = after.unwrap_or(time::HourBucket { year: 2000, month: 1, day: 1, hour: 0 });
        let b = before.unwrap_or(time::HourBucket { year: 2099, month: 12, day: 31, hour: 23 });
        let mut files = Vec::new();
        for dir in time::hour_dirs_in_range(data_dir, a, b) {
            let Ok(es) = fs::read_dir(&dir) else { continue };
            let mut names: Vec<_> = es.flatten().collect();
            names.sort_by_key(|e| e.file_name());
            for entry in names {
                let p = entry.path();
                if p.extension().map(|e| e == "jsonl").unwrap_or(false)
                    && stem_matches(&p, source)
                {
                    files.push(p);
                }
            }
        }
        return files;
    }

    let mut files = Vec::new();
    walk_jsonl(&raw_dir, &mut |p| {
        if stem_matches(p, source) {
            files.push(p.to_owned());
        }
    });
    files
}

fn stem_matches(path: &Path, source: Option<&str>) -> bool {
    match source {
        None => true,
        Some(src) => path.file_stem().and_then(|s| s.to_str()) == Some(src),
    }
}

// ── cmd: status ────────────────────────────────────────────────────────────

fn cmd_status(args: &[String]) -> Result<i32> {
    let mut data_dir = default_data_dir();
    let mut verbose = false;

    let mut it = args.iter().map(String::as_str);
    while let Some(arg) = it.next() {
        match arg {
            "--data-dir" | "-d" => data_dir = PathBuf::from(next_arg(&mut it, arg)?),
            "--verbose" | "-v" => verbose = true,
            "--help" | "-h" => {
                println!(
                    "Usage: siemctl status [--verbose] [--data-dir DIR]\n\n\
                     Show SIEM data directory size, source file counts, and index coverage.\n\n\
                     Options:\n\
                     \x20 --verbose    Also show sources.toml, normalized.toml field inventory,\n\
                     \x20              and the actual column set of the latest index bucket.\n\
                     \x20 --data-dir   Data directory (default: ./data)"
                );
                return Ok(0);
            }
            other => {
                eprintln!("siemctl: unknown flag: {other}");
                return Ok(1);
            }
        }
    }

    if !data_dir.is_dir() {
        return Err(format!("data directory not found: {}", data_dir.display()).into());
    }

    println!("SIEM Status — {}", data_dir.display());
    println!("{}", "─".repeat(48));

    // Total size (walk and sum)
    let mut total_bytes = 0u64;
    walk_jsonl(&data_dir, &mut |p| {
        if let Ok(m) = p.metadata() {
            total_bytes += m.len();
        }
    });
    // Also count non-jsonl (index dbs, etc.)
    let mut total_all = 0u64;
    count_dir_size(&data_dir, &mut total_all);
    println!("  Total size:        {}", human_bytes(total_all));

    // File counts and last-modified per source
    let raw_dir = data_dir.join("raw");
    if raw_dir.is_dir() {
        let mut counts: std::collections::BTreeMap<String, (usize, std::time::SystemTime)> =
            std::collections::BTreeMap::new();
        walk_jsonl(&raw_dir, &mut |p| {
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("?");
            let mtime = p.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
            let e = counts.entry(stem.to_string()).or_insert((0, std::time::UNIX_EPOCH));
            e.0 += 1;
            if mtime > e.1 {
                e.1 = mtime;
            }
        });
        if !counts.is_empty() {
            println!("  Source file counts:");
            for (src, (cnt, mtime)) in &counts {
                let secs = mtime
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                println!("    {:<20} {:>5} files  last={}", src, cnt, secs);
            }
        }
    }

    // Index coverage
    let idx_dir = data_dir.join("index");
    if idx_dir.is_dir() {
        let mut dbs: Vec<String> = fs::read_dir(&idx_dir)
            .map(|it| {
                it.flatten()
                    .filter(|e| e.path().extension().map(|x| x == "db").unwrap_or(false))
                    .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        dbs.sort();
        println!("  Indexed buckets ({}):", dbs.len());
        for db in &dbs {
            println!("    {db}");
        }
    } else {
        println!("  Index: (no index/ directory)");
    }

    if verbose {
        print_verbose_status(&data_dir);
    }

    Ok(0)
}

// ── cmd: status --verbose helpers ──────────────────────────────────────────

fn wrap_field_list(fields: &[&str], indent: usize, width: usize) -> String {
    let pad = " ".repeat(indent);
    let mut out = pad.clone();
    let mut line_len = indent;
    for (i, f) in fields.iter().enumerate() {
        let sep = if i + 1 < fields.len() { ", " } else { "" };
        let chunk = format!("{f}{sep}");
        if line_len + chunk.len() > width && line_len > indent {
            out.push('\n');
            out.push_str(&pad);
            line_len = indent;
        }
        out.push_str(&chunk);
        line_len += chunk.len();
    }
    out
}

fn print_verbose_status(data_dir: &Path) {
    // ── sources.toml section ──────────────────────────────────────────────
    let sources_path = sources::find_sources_toml();
    let per_source = sources_path
        .as_ref()
        .map(|p| sources::load_per_source_fields(p))
        .unwrap_or_default();

    println!("\n── sources.toml — indexed fields {}", "─".repeat(17));
    if per_source.is_empty() {
        println!("  (sources.toml not found or empty)");
    } else {
        println!("  Envelope (all sources — from the syslog transport layer):");
        println!("    source_addr  — sender IP (UDP source address, or \"stdin\")");
        println!("    hostname     — syslog header hostname");
        println!("    app_name     — syslog process name before override rules rewrite _source_type");

        // Core derived fields
        let core: Vec<String> = {
            let mut v = sources::core_fields();
            v.sort();
            v
        };
        println!();
        println!("  Core (all sources, normalization pipeline):");
        println!("    {}", core.join(", "));

        println!();
        println!("  Per-source indexed fields (from sources.toml):");
        for (src, fields) in &per_source {
            if fields.is_empty() {
                println!("  {src:<20} (no indexed fields)");
            } else {
                let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
                let prefix = format!("    {src:<20} ");
                let indent = prefix.len();
                println!("{}{}", prefix, wrap_field_list(&refs, indent, 76)[indent..].trim_start());
            }
        }
    }

    // ── normalized.toml section ───────────────────────────────────────────
    let norm_path = normconfig::find_normalized_toml();
    let norm_per = norm_path
        .as_ref()
        .map(|p| normconfig::load_per_source(p))
        .unwrap_or_default();

    if !norm_per.is_empty() {
        println!("\n── normalized.toml — fields by app_name {}", "─".repeat(10));
        println!(
            "  (override rules may relabel app_name to a different source in sources.toml)\n"
        );

        // Build full set of indexed fields for cross-reference.
        let all_indexed: HashSet<String> = {
            let mut s = sources::always_valid();
            for fields in per_source.values() {
                s.extend(fields.iter().cloned());
            }
            s
        };

        for (app, fields) in &norm_per {
            let flist: Vec<&str> = fields.iter().map(String::as_str).collect();
            let prefix = format!("  {app:<20} ");
            let indent = prefix.len();
            println!("{}{}", prefix, wrap_field_list(&flist, indent, 76)[indent..].trim_start());

            let not_indexed: Vec<&str> = flist
                .iter()
                .copied()
                .filter(|f| !all_indexed.contains(*f))
                .collect();
            if !not_indexed.is_empty() {
                let arrow = " ".repeat(indent - 4);
                println!(
                    "{arrow}  → not indexed: {}",
                    wrap_field_list(&not_indexed, indent + 2, 76)
                        .trim_start()
                        .to_string()
                );
            }
        }
    } else if norm_path.is_some() {
        println!("\n── normalized.toml — fields by app_name {}", "─".repeat(10));
        println!("  (no extract rules with app_name found)");
    }

    // ── Index schema — latest bucket ──────────────────────────────────────
    let idx_dir = data_dir.join("index");
    if idx_dir.is_dir() {
        let mut db_files: Vec<PathBuf> = fs::read_dir(&idx_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().extension().map(|x| x == "db").unwrap_or(false))
            .map(|e| e.path())
            .collect();
        db_files.sort();

        if let Some(latest) = db_files.last() {
            let name = latest.file_name().and_then(|n| n.to_str()).unwrap_or("?");
            println!("\n── Index schema (latest bucket) {}", "─".repeat(19));
            match db::open_bucket_conn(latest, data_dir) {
                Ok(conn) => {
                    let cols = db::bucket_columns(&conn);
                    let refs: Vec<&str> = cols.iter().map(String::as_str).collect();
                    println!("  {name}  — {} columns:", cols.len());
                    println!("{}", wrap_field_list(&refs, 4, 76));
                }
                Err(e) => {
                    println!("  {name}  — (could not open: {e})");
                }
            }
        }
    }
}

/// Format a u64 with comma thousands separators: 1234567 → "1,234,567".
pub(crate) fn fmt_n(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn count_dir_size(dir: &Path, total: &mut u64) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            count_dir_size(&p, total);
        } else if let Ok(m) = p.metadata() {
            *total += m.len();
        }
    }
}

// ── cmd: stats ─────────────────────────────────────────────────────────────

fn cmd_stats(args: &[String]) -> Result<i32> {
    let mut data_dir = default_data_dir();
    let mut source: Option<String> = None;
    let mut after: Option<time::HourBucket> = None;
    let mut before: Option<time::HourBucket> = None;
    let mut interval: Option<chrono::Duration> = None;
    let mut last: Option<chrono::Duration> = None;

    let mut it = args.iter().map(String::as_str);
    while let Some(arg) = it.next() {
        match arg {
            "--data-dir" | "-d" => data_dir = PathBuf::from(next_arg(&mut it, arg)?),
            "--source" | "-s" => source = Some(next_arg(&mut it, arg)?.to_string()),
            "--after" | "-a" => {
                let s = next_arg(&mut it, arg)?;
                after = Some(
                    time::HourBucket::parse(s)
                        .ok_or_else(|| format!("invalid --after '{s}' (YYYY-MM-DDTHH)"))?,
                );
            }
            "--before" | "-b" => {
                let s = next_arg(&mut it, arg)?;
                before = Some(
                    time::HourBucket::parse(s)
                        .ok_or_else(|| format!("invalid --before '{s}' (YYYY-MM-DDTHH)"))?,
                );
            }
            "--interval" => {
                let s = next_arg(&mut it, arg)?;
                let d = time::parse_duration(s)?;
                if d.num_hours() < 1 || d != chrono::Duration::hours(d.num_hours()) {
                    return Err(format!(
                        "--interval must be a whole number of hours (got '{s}') — \
                         the index is bucketed per clock-hour, so sub-hour trend \
                         columns aren't available here (see 'siemctl digest' for \
                         sub-hour sparklines)"
                    )
                    .into());
                }
                interval = Some(d);
            }
            "--last" => {
                let s = next_arg(&mut it, arg)?;
                last = Some(time::parse_duration(s)?);
            }
            "--help" | "-h" => {
                println!(
                    "Usage: siemctl stats [--source SRC] [--after YYYY-MM-DDTHH] \
                     [--before YYYY-MM-DDTHH] [--data-dir DIR]\n       \
                     siemctl stats --interval Nh (--last Nh | --after ... --before ...) \
                     [--source SRC] [--data-dir DIR]\n\n\
                     Show event counts and field coverage from the index.\n\n\
                     Without --source: event counts per source, then overall field coverage.\n\
                     With --source SRC: event type breakdown for that source, then per-field\n\
                     coverage scoped to that source.\n\n\
                     With --interval: instead of one aggregate total, print a volume-trend\n\
                     table — one column per interval-sized time bucket, one row per source\n\
                     (or per event type, with --source). Needs an overall range, given via\n\
                     --last (relative to now) or an explicit --after/--before pair.\n\n\
                     Options:\n\
                     \x20 --source SRC       Restrict to one source label\n\
                     \x20 --after  YYYY-MM-DDTHH  Start of time range\n\
                     \x20 --before YYYY-MM-DDTHH  End of time range\n\
                     \x20 --interval Nh      Trend table bucket width, whole hours (e.g. 1h, 3h)\n\
                     \x20 --last Nh/Nd       Overall range: the last N hours/days, ending now\n\
                     \x20 --data-dir DIR     Data directory (default: ./data)"
                );
                return Ok(0);
            }
            other => {
                eprintln!("siemctl: unknown flag: {other}");
                return Ok(1);
            }
        }
    }

    if let Some(d) = last {
        if after.is_some() || before.is_some() {
            return Err("--last cannot be combined with --after/--before".into());
        }
        let now = chrono::Utc::now();
        after = Some(time::HourBucket::from_datetime(now - d));
        before = Some(time::HourBucket::from_datetime(now));
    }

    if let Some(interval) = interval {
        let after = after.ok_or("--interval requires --last or --after/--before to set the overall range")?;
        let before = before.ok_or("--interval requires --last or --after/--before to set the overall range")?;
        return cmd_stats_trend(&data_dir, source.as_deref(), after, before, interval);
    }

    // Load indexed fields for field coverage query.
    let sources_path = sources::find_sources_toml();
    let all_indexed_fields: Vec<String> = {
        let mut set: BTreeSet<String> = sources::always_valid().into_iter().collect();
        if let Some(ref p) = sources_path {
            for fields in sources::load_per_source_fields(p).into_values() {
                set.extend(fields);
            }
        }
        set.into_iter().collect()
    };

    let dbs = match query::index_buckets(&data_dir) {
        Ok(v) => v,
        Err(_) => {
            // No index yet — fall back to counting events from raw JSONL files.
            return stats_from_raw(&data_dir, source.as_deref(), after, before);
        }
    };

    // Accumulate across all in-range buckets.
    let mut source_counts: BTreeMap<Vec<String>, u64> = BTreeMap::new();
    let mut type_counts: BTreeMap<Vec<String>, u64> = BTreeMap::new();
    let mut total_events: u64 = 0;
    let mut field_sums: HashMap<String, u64> = HashMap::new();

    for db_path in &dbs {
        // Time-range pruning by bucket filename. Bucket filenames are
        // dash-separated ("2026-06-22-08.db"); HourBucket::parse expects the
        // CLI's "T"-separated form ("2026-06-22T08") and returns None for
        // this shape, silently skipping the filter entirely — from_filename
        // is the one that actually matches what's on disk here.
        if let Some(name) = db_path.file_name().and_then(|n| n.to_str()) {
            if let Some(bkt) = time::HourBucket::from_filename(name) {
                if after.map(|a| bkt < a).unwrap_or(false) { continue; }
                if before.map(|b| bkt > b).unwrap_or(false) { continue; }
            }
        }

        let conn = match db::open_bucket_conn(db_path, &data_dir) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if source.is_none() {
            // GROUP BY _source_type to get per-source counts.
            let _ = db::fold_group_sql(
                &conn,
                "SELECT _source_type, COUNT(*) FROM events GROUP BY _source_type",
                &[],
                1,
                &mut source_counts,
            );
        } else {
            // GROUP BY event_type for the given source.
            let src = source.as_ref().unwrap().clone();
            let _ = db::fold_group_sql(
                &conn,
                "SELECT event_type, COUNT(*) FROM events WHERE _source_type = ? \
                 GROUP BY event_type ORDER BY COUNT(*) DESC",
                &[src],
                1,
                &mut type_counts,
            );
        }

        // Field coverage.
        if let Ok((total, counts)) = db::field_coverage(&conn, &all_indexed_fields, source.as_deref()) {
            total_events += total;
            for (f, c) in counts {
                *field_sums.entry(f).or_default() += c;
            }
        }
    }

    if source.is_none() {
        println!("── Event counts by source {}", "─".repeat(25));
        if source_counts.is_empty() {
            println!("  (no data)");
        } else {
            let grand_total: u64 = source_counts.values().sum();
            // Sort by count descending for easier reading.
            let mut sorted: Vec<_> = source_counts.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            for (key, count) in &sorted {
                let src = key.first().map(String::as_str).unwrap_or("?");
                println!("  {:<24}  {:>10}", src, fmt_n(**count));
            }
            println!("  {}", "─".repeat(37));
            println!("  {:<24}  {:>10}", "total", fmt_n(grand_total));
        }
    } else {
        let src = source.as_deref().unwrap_or("?");
        println!("── {} — event types {}", src, "─".repeat(30usize.saturating_sub(src.len())));
        if type_counts.is_empty() {
            println!("  (no data for source '{src}')");
        } else {
            let mut sorted: Vec<_> = type_counts.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            for (key, count) in &sorted {
                let et = key.first().map(String::as_str).unwrap_or("(none)");
                println!("  {:<30}  {:>10}", et, fmt_n(**count));
            }
            println!("  {}", "─".repeat(43));
            println!("  {:<30}  {:>10}", format!("total ({})", src), fmt_n(total_events));
        }
    }

    if total_events == 0 {
        return Ok(if source_counts.is_empty() && type_counts.is_empty() { 1 } else { 0 });
    }

    let section = match &source {
        Some(s) => format!("{s} — field coverage"),
        None => "Field coverage".to_string(),
    };
    println!("\n── {} {}", section, "─".repeat(40usize.saturating_sub(section.len())));
    println!("  {:<24}  {:>10}  {:>8}", "Field", "Events", "Coverage");
    println!("  {}", "─".repeat(47));

    // Print fields sorted by coverage descending, then name.
    let mut cov_rows: Vec<(&str, u64)> = all_indexed_fields
        .iter()
        .map(|f| (f.as_str(), *field_sums.get(f).unwrap_or(&0)))
        .collect();
    cov_rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));

    for (field, count) in cov_rows {
        let pct = if total_events > 0 {
            format!("{:>6.1}%", count as f64 / total_events as f64 * 100.0)
        } else {
            "     —".to_string()
        };
        println!("  {:<24}  {:>10}  {}", field, fmt_n(count), pct);
    }

    Ok(0)
}

/// `siemctl stats --interval` — a volume-trend table (roadmap item 5):
/// one column per `interval`-sized time bucket, one row per source (or per
/// event type, with `source` given), from `after` to `before` inclusive.
/// Reuses the same per-hour-bucket index files the aggregate path above
/// does; `interval` just groups adjacent hour buckets into wider columns.
fn cmd_stats_trend(
    data_dir: &Path,
    source: Option<&str>,
    after: time::HourBucket,
    before: time::HourBucket,
    interval: chrono::Duration,
) -> Result<i32> {
    if before < after {
        return Err("--before must not be earlier than --after".into());
    }
    let interval_hours = interval.num_hours().max(1) as u32;

    // One entry per trend-table column, in order.
    let mut group_starts: Vec<time::HourBucket> = Vec::new();
    let mut cur = after;
    loop {
        group_starts.push(cur);
        if cur >= before {
            break;
        }
        cur = cur.advance_by(interval_hours);
    }

    let dbs = query::index_buckets(data_dir)?;

    let (sql, param_list): (&str, Vec<String>) = match source {
        None => ("SELECT _source_type, COUNT(*) FROM events GROUP BY _source_type", vec![]),
        Some(s) => (
            "SELECT event_type, COUNT(*) FROM events WHERE _source_type = ? GROUP BY event_type",
            vec![s.to_string()],
        ),
    };

    let mut group_data: Vec<BTreeMap<String, u64>> = vec![BTreeMap::new(); group_starts.len()];
    let mut row_totals: BTreeMap<String, u64> = BTreeMap::new();
    // Rows whose group-by key (event_type) came back empty aren't shown as
    // their own row (an unlabeled row would be meaningless), but their
    // events are still real — tracked separately so a source with no
    // dedicated parser (every event_type empty) doesn't get reported as
    // having no data at all when it actually has plenty, just none of it
    // groupable this way.
    let mut ungrouped_group_totals: Vec<u64> = vec![0; group_starts.len()];
    let mut ungrouped_total: u64 = 0;

    for db_path in &dbs {
        let Some(name) = db_path.file_name().and_then(|n| n.to_str()) else { continue };
        let Some(bkt) = time::HourBucket::from_filename(name) else { continue };
        if bkt < after || bkt > before {
            continue;
        }
        let hours_since_start = (bkt.to_datetime() - after.to_datetime()).num_hours().max(0) as u32;
        let group_idx = (hours_since_start / interval_hours) as usize;
        let Some(group_bucket) = group_data.get_mut(group_idx) else { continue };

        let Ok(conn) = db::open_bucket_conn(db_path, data_dir) else { continue };
        let mut acc: BTreeMap<Vec<String>, u64> = BTreeMap::new();
        let _ = db::fold_group_sql(&conn, sql, &param_list, 1, &mut acc);
        for (key, count) in acc {
            let row_key = key.into_iter().next().unwrap_or_default();
            if row_key.is_empty() {
                ungrouped_group_totals[group_idx] += count;
                ungrouped_total += count;
                continue;
            }
            *group_bucket.entry(row_key.clone()).or_default() += count;
            *row_totals.entry(row_key).or_default() += count;
        }
    }

    if row_totals.is_empty() {
        if source.is_some() && ungrouped_total > 0 {
            // Every event for this source has an empty event_type (no
            // dedicated parser) — fall back to one undifferentiated
            // "total" row instead of claiming there's no data at all.
            println!(
                "note: '{}' events have no populated event_type (no dedicated \
                 parser) — showing total volume per bucket instead of a \
                 per-type breakdown",
                source.unwrap()
            );
            let synthetic = "(total, ungrouped)".to_string();
            row_totals.insert(synthetic.clone(), ungrouped_total);
            for (gd, count) in group_data.iter_mut().zip(ungrouped_group_totals.iter()) {
                gd.insert(synthetic.clone(), *count);
            }
        } else {
            println!("(no data in range)");
            return Ok(1);
        }
    }

    let mut rows: Vec<String> = row_totals.keys().cloned().collect();
    rows.sort_by(|a, b| {
        row_totals.get(b).cmp(&row_totals.get(a)).then_with(|| a.cmp(b))
    });

    let row_header = if source.is_some() { "event_type" } else { "source" };
    let row_width = rows.iter().map(|r| r.len()).max().unwrap_or(0).max(row_header.len());
    const COL_WIDTH: usize = 11; // "MM-DD HH:00" is 11 chars

    print!("{:<width$}", row_header, width = row_width);
    for g in &group_starts {
        print!("  {:>width$}", g.label(), width = COL_WIDTH);
    }
    println!();

    for row in &rows {
        print!("{:<width$}", row, width = row_width);
        for gd in &group_data {
            let count = gd.get(row).copied().unwrap_or(0);
            print!("  {:>width$}", fmt_n(count), width = COL_WIDTH);
        }
        println!();
    }

    Ok(0)
}

/// Fallback for `siemctl stats` when no index exists yet.
/// Counts events by reading raw JSONL files directly. Field coverage is
/// skipped (that requires indexed columns); a note is printed instead.
fn stats_from_raw(
    data_dir: &Path,
    source: Option<&str>,
    after: Option<time::HourBucket>,
    before: Option<time::HourBucket>,
) -> Result<i32> {
    eprintln!(
        "siemctl: no index found — counting events from raw JSONL files\n\
         \x20        (field coverage requires the index; run 'indexd' to build it)"
    );

    let files = collect_raw_files(data_dir, source, after, before);
    if files.is_empty() {
        eprintln!("siemctl: no raw JSONL files found under {}", data_dir.display());
        return Ok(1);
    }

    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for path in &files {
        let src = path.file_stem().and_then(|s| s.to_str()).unwrap_or("?");
        let Ok(f) = fs::File::open(path) else { continue };
        let n = BufReader::new(f).lines().count() as u64;
        *counts.entry(src.to_string()).or_default() += n;
    }

    if let Some(src) = source {
        let total: u64 = counts.values().sum();
        println!("\n── {} — event count (raw files) {}", src, "─".repeat(18usize.saturating_sub(src.len())));
        println!("  {:<24}  {:>10}", src, fmt_n(total));
    } else {
        println!("\n── Event counts by source (raw files) {}", "─".repeat(13));
        let mut sorted: Vec<_> = counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        let grand_total: u64 = sorted.iter().map(|(_, c)| *c).sum();
        for (src, count) in &sorted {
            println!("  {:<24}  {:>10}", src, fmt_n(**count));
        }
        println!("  {}", "─".repeat(37));
        println!("  {:<24}  {:>10}", "total", fmt_n(grand_total));
    }

    Ok(0)
}

// ── cmd: search ────────────────────────────────────────────────────────────

fn cmd_search(args: &[String], valid_fields: &HashSet<String>) -> Result<i32> {
    let mut data_dir = default_data_dir();
    let mut dsl: Option<String> = None;
    let mut raw: Option<Option<String>> = None; // Some(None)=--raw no arg; Some(Some(s))=--raw SUBSTRING
    let mut after: Option<time::HourBucket> = None;
    let mut before: Option<time::HourBucket> = None;
    let mut window: Option<String> = None;
    let mut format = render::Format::Json;
    let mut no_limit = false;

    let mut it = args.iter().map(String::as_str).peekable();
    while let Some(arg) = it.next() {
        match arg {
            "--data-dir" | "-d" => data_dir = PathBuf::from(next_arg(&mut it, arg)?),
            "--query" | "-q" => dsl = Some(next_arg(&mut it, arg)?.to_string()),
            "--no-limit" => no_limit = true,
            "--raw" => {
                // Optional substring argument: consume the next token unless it
                // is another flag.
                let sub = match it.peek() {
                    Some(s) if !s.starts_with('-') => Some(it.next().unwrap().to_string()),
                    _ => None,
                };
                raw = Some(sub);
            }
            "--format" => format = render::Format::parse(next_arg(&mut it, arg)?)?,
            "--after" | "-a" => {
                let s = next_arg(&mut it, arg)?;
                after = Some(
                    time::HourBucket::parse(s)
                        .ok_or_else(|| format!("invalid --after '{s}' (YYYY-MM-DDTHH)"))?,
                );
            }
            "--before" | "-b" => {
                let s = next_arg(&mut it, arg)?;
                before = Some(
                    time::HourBucket::parse(s)
                        .ok_or_else(|| format!("invalid --before '{s}' (YYYY-MM-DDTHH)"))?,
                );
            }
            "--window" | "-w" => window = Some(next_arg(&mut it, arg)?.to_string()),
            "--help" | "-h" => {
                print_search_help();
                return Ok(0);
            }
            other => {
                eprintln!("siemctl: unknown flag: {other}");
                return Ok(1);
            }
        }
    }

    if let Some(w) = window {
        if after.is_some() || before.is_some() {
            return Err("--window cannot be combined with --after/--before".into());
        }
        let win = time::parse_window(&w, chrono::Utc::now())?;
        after = Some(time::HourBucket::from_datetime(win.start));
        before = Some(time::HourBucket::from_datetime(win.end));
    }

    if !data_dir.is_dir() {
        return Err(format!("data directory not found: {}", data_dir.display()).into());
    }

    // --raw: bypass the index, scan raw files directly (legacy grep/dump). The
    // argument, if any, is a literal substring — never parsed as DSL.
    if let Some(sub) = raw {
        if dsl.is_some() {
            return Err("--raw and --query are mutually exclusive (--raw takes a literal \
                        substring, not a DSL expression)"
                .into());
        }
        let mut renderer =
            render::Renderer::new(format, None, io::BufWriter::new(io::stdout()), None);
        let rc = match sub {
            Some(needle) => search_by_grep(&data_dir, &needle, None, after, before, &mut renderer),
            None => search_dump(&data_dir, None, after, before, &mut renderer),
        };
        renderer.flush().ok();
        return rc;
    }

    // Index-driven path: parse the DSL (empty/absent => match-all) into a Query,
    // attach the time-range bounds, and execute.
    let mut q = query::Query::parse(dsl.as_deref().unwrap_or(""), valid_fields)
        .map_err(|e| -> Box<dyn std::error::Error> { format!("invalid --query: {e}").into() })?;
    q.after = after;
    q.before = before;

    // An explicit LIMIT in the query always wins; --no-limit opts out of the
    // default entirely. Otherwise fall back to DEFAULT_ROW_CAP so a query with
    // neither a narrow SELECT nor a LIMIT can't dump an unbounded number of
    // rows into the caller's context — see query::DEFAULT_ROW_CAP's doc
    // comment.
    let default_applied = q.limit.is_none() && !no_limit;
    if default_applied {
        q.limit = Some(query::DEFAULT_ROW_CAP);
    }

    let mut renderer =
        render::Renderer::new(format, q.select.clone(), io::BufWriter::new(io::stdout()), q.limit);
    let rc = query::run_query(&data_dir, &q, &mut renderer);
    // Truncation notice goes to stderr, never stdout — several canned queries
    // pipe stdout straight into `jq`, and a stray non-JSON line would break that.
    if default_applied && renderer.emitted() >= query::DEFAULT_ROW_CAP {
        eprintln!(
            "siemctl: showing first {} matches (default row cap reached) — add an explicit \
             LIMIT to your --query or pass --no-limit to see more",
            renderer.emitted()
        );
    }
    renderer.flush().ok();
    rc
}

fn print_search_help() {
    println!(
        "Usage: siemctl search [--query \"<dsl>\"] [OPTIONS]\n\
         \n\
         Searches the SQLite index. The entire predicate, grouping and limit is a\n\
         single SQL-ish expression passed to --query. Quotes are optional and\n\
         keywords are case-insensitive.\n\
         \n\
         Options:\n\
         \x20 --query \"<dsl>\"        Predicate / GROUP BY / LIMIT expression (see DSL below)\n\
         \x20 --raw [SUBSTRING]      Bypass the index; substring/range scan over raw files.\n\
         \x20                        Escape hatch when the index is missing/stale or you need\n\
         \x20                        the very latest, not-yet-indexed events. No DSL parsing.\n\
         \x20 --after  YYYY-MM-DDTHH Start of time range (bucket pruning)\n\
         \x20 --before YYYY-MM-DDTHH End of time range (bucket pruning)\n\
         \x20 --window W             Time range as a relative duration ending now\n\
         \x20                        ('10m','6h','24h','2d') or an explicit\n\
         \x20                        'start..end' range (same format as --after/\n\
         \x20                        --before). Same bucket-pruning precision as\n\
         \x20                        --after/--before, just less typing. Mutually\n\
         \x20                        exclusive with --after/--before.\n\
         \x20 --format FMT           Output format: json (default), tsv, tsv-noheader\n\
         \x20 --data-dir DIR         Data directory (default: ./data)\n\
         \x20 --no-limit             Disable the default row cap below (an explicit\n\
         \x20                        LIMIT in --query always applies regardless)\n\
         \x20 --help                 Show this help\n\
         \n\
         A query with no explicit LIMIT is capped at 150 rows by default (a\n\
         warning is printed to stderr if the cap is reached) so an unbounded\n\
         --query can't dump unbounded output; pass --no-limit to disable this.\n\
         \n\
         DSL grammar:\n\
         \x20 query   := [SELECT f1,f2,...] [WHERE] [expr] [GROUP BY f1,f2,...] [LIMIT n]\n\
         \x20 expr    := AND / OR / NOT / ( ) over comparisons and functions\n\
         \x20 compare := field (== | = | != | <>) value\n\
         \x20 funcs   := startswith(f,'v')  endswith(f,'v')  contains(f,'v')\n\
         \x20            any(f)  cidr_match(f,'a.b.c.d/n')  raw_contains('needle')\n\
         \x20 AND binds tighter than OR; use parentheses to override.\n\
         \n\
         Examples:\n\
         \x20 siemctl search --query \"SELECT timestamp,src_ip,username WHERE src_ip == 10.0.0.5\"\n\
         \x20 siemctl search --query \"SELECT src_ip,count GROUP BY src_ip LIMIT 20\"\n\
         \x20 siemctl search --query \"src_ip == 10.0.0.5\"\n\
         \x20 siemctl search --query \"any(username)\" --format tsv\n\
         \x20 siemctl search --query \"cidr_match(src_ip,'10.0.0.0/24')\"\n\
         \x20 siemctl search --query \"startswith(event_type,'ssh')\"\n\
         \x20 siemctl search --query \"_source_type == sshd AND raw_contains('Failed password')\"\n\
         \x20 siemctl search --query \"_source_type == sshd GROUP BY src_ip\"\n\
         \x20 siemctl search --query \"GROUP BY src_ip,dst_ip\" --after 2026-06-22T08\n\
         \x20 siemctl search --raw 'Failed password' --after 2026-06-22T08\n\
         \x20 siemctl search --after 2026-06-22T08 --before 2026-06-22T10"
    );
}

// ── cmd: alerts ──────────────────────────────────────────────────────────────

fn cmd_alerts(args: &[String]) -> Result<i32> {
    if args.first().map(String::as_str) == Some("ack") {
        return cmd_alerts_ack(&args[1..]);
    }

    let mut data_dir = default_data_dir();
    let mut dsl: Option<String> = None;
    let mut after: Option<time::HourBucket> = None;
    let mut before: Option<time::HourBucket> = None;
    let mut window: Option<String> = None;
    let mut format = render::Format::Json;
    let mut correlated_only = false;
    let mut show_all = false;

    let mut it = args.iter().map(String::as_str);
    while let Some(arg) = it.next() {
        match arg {
            "--data-dir" | "-d" => data_dir = PathBuf::from(next_arg(&mut it, arg)?),
            "--query" | "-q" => dsl = Some(next_arg(&mut it, arg)?.to_string()),
            "--correlated" => correlated_only = true,
            "--all" => show_all = true,
            "--format" => format = render::Format::parse(next_arg(&mut it, arg)?)?,
            "--after" | "-a" => {
                let s = next_arg(&mut it, arg)?;
                after = Some(
                    time::HourBucket::parse(s)
                        .ok_or_else(|| format!("invalid --after '{s}' (YYYY-MM-DDTHH)"))?,
                );
            }
            "--before" | "-b" => {
                let s = next_arg(&mut it, arg)?;
                before = Some(
                    time::HourBucket::parse(s)
                        .ok_or_else(|| format!("invalid --before '{s}' (YYYY-MM-DDTHH)"))?,
                );
            }
            "--window" | "-w" => window = Some(next_arg(&mut it, arg)?.to_string()),
            "--help" | "-h" => {
                print_alerts_help();
                return Ok(0);
            }
            other => {
                eprintln!("siemctl: unknown flag: {other}");
                return Ok(1);
            }
        }
    }

    if let Some(w) = window {
        if after.is_some() || before.is_some() {
            return Err("--window cannot be combined with --after/--before".into());
        }
        let win = time::parse_window(&w, chrono::Utc::now())?;
        after = Some(time::HourBucket::from_datetime(win.start));
        before = Some(time::HourBucket::from_datetime(win.end));
    }

    if !data_dir.is_dir() {
        return Err(format!("data directory not found: {}", data_dir.display()).into());
    }

    // Alert fields aren't a fixed indexed schema (unlike `search`'s columns) —
    // an empty `valid` set makes `Query::parse` accept any field name.
    let q = query::Query::parse(dsl.as_deref().unwrap_or(""), &HashSet::new())
        .map_err(|e| -> Box<dyn std::error::Error> { format!("invalid --query: {e}").into() })?;

    let mut records = alerts::load_alerts(&data_dir, after, before);
    if correlated_only {
        records.retain(|r| r.get("type").and_then(|v| v.as_str()) == Some("correlated"));
    }
    if !show_all {
        let watermarks = alerts::load_ack_watermarks(&data_dir);
        alerts::filter_acked(&mut records, &watermarks);
    }

    let mut renderer =
        render::Renderer::new(format, q.select.clone(), io::BufWriter::new(io::stdout()), q.limit);
    let rc = alerts::run_query(&records, &q, &mut renderer);
    renderer.flush().ok();
    rc
}

fn cmd_alerts_ack(args: &[String]) -> Result<i32> {
    let mut data_dir = default_data_dir();
    let mut note: Option<String> = None;
    let mut rule_id: Option<String> = None;

    let mut it = args.iter().map(String::as_str);
    while let Some(arg) = it.next() {
        match arg {
            "--data-dir" | "-d" => data_dir = PathBuf::from(next_arg(&mut it, arg)?),
            "--note" => note = Some(next_arg(&mut it, arg)?.to_string()),
            "--help" | "-h" => {
                println!(
                    "Usage: siemctl alerts ack <rule_id> [--note \"text\"] [--data-dir DIR]\n\n\
                     Marks every alert for <rule_id> up to right now as acknowledged — a\n\
                     watermark, not a global switch. `siemctl alerts`' default output hides\n\
                     alerts for <rule_id> at or before this moment; a NEW alert for the same\n\
                     rule_id firing afterward still shows up normally next time. `--all`\n\
                     bypasses this filter entirely (acked or not).\n\n\
                     Options:\n\
                     \x20 --note \"text\"    Optional free-text note, stored alongside the ack\n\
                     \x20 --data-dir DIR   Data directory (default: ./data)\n\n\
                     Example:\n\
                     \x20 siemctl alerts ack 1007-haproxy-tls-probe --note \"known CDN probe pattern\""
                );
                return Ok(0);
            }
            other if !other.starts_with('-') && rule_id.is_none() => rule_id = Some(other.to_string()),
            other => {
                eprintln!("siemctl: unknown flag: {other}");
                return Ok(1);
            }
        }
    }

    let rule_id = rule_id.ok_or("siemctl alerts ack: <rule_id> is required")?;
    if !data_dir.is_dir() {
        return Err(format!("data directory not found: {}", data_dir.display()).into());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    alerts::ack(&data_dir, &rule_id, now, note.as_deref())?;
    println!(
        "acked '{rule_id}' up to now — matching alerts up to this point are hidden by default \
         (siemctl alerts --all shows them); a new alert for this rule will still show up."
    );
    Ok(0)
}

fn print_alerts_help() {
    println!(
        "Usage: siemctl alerts [--query \"<dsl>\"] [OPTIONS]\n\
         \x20      siemctl alerts ack <rule_id> [--note \"text\"]\n\
         \n\
         Queries ruled alerts (data/alerts/) and correlated alerts\n\
         (data/alerts/correlated/) — both are flat JSONL, not indexed, so\n\
         --query uses the same DSL as `search` but is evaluated directly\n\
         against each record rather than compiled to SQL. WHERE and SELECT\n\
         both resolve fields via: the alert's own top-level keys, then its\n\
         embedded event (a ruled alert's `event` object), then its first\n\
         sample event (a correlated alert's `sample_events[0]`) — so\n\
         `src_ip`, `event_type`, etc. work the same way regardless of which\n\
         alert shape they come from.\n\
         \n\
         Every record carries a synthetic `type` field (\"ruled\" or\n\
         \"correlated\") so a query can distinguish them; correlated alerts\n\
         have no `level` field at all (they carry no severity).\n\
         \n\
         `siemctl alerts ack <rule_id>` marks alerts for that rule_id up to\n\
         right now as acknowledged (a watermark, not a global switch — a new\n\
         alert for the same rule firing later still shows up). Acked alerts\n\
         are hidden from the default view; --all shows everything regardless.\n\
         Run 'siemctl alerts ack --help' for details.\n\
         \n\
         Options:\n\
         \x20 --query \"<dsl>\"        Predicate / SELECT / GROUP BY / LIMIT expression\n\
         \x20 --correlated           Only correlated alerts (equivalent to adding\n\
         \x20                        \"type == correlated\" to --query yourself)\n\
         \x20 --all                  Include acked alerts too (default: hidden)\n\
         \x20 --after  YYYY-MM-DDTHH Start of time range (bucket pruning)\n\
         \x20 --before YYYY-MM-DDTHH End of time range (bucket pruning)\n\
         \x20 --window W             Time range as a relative duration ending now\n\
         \x20                        ('10m','6h','24h','2d') or an explicit\n\
         \x20                        'start..end' range (same format as --after/\n\
         \x20                        --before). Same bucket-pruning precision as\n\
         \x20                        --after/--before, just less typing. Mutually\n\
         \x20                        exclusive with --after/--before.\n\
         \x20 --format FMT           Output format: json (default), tsv, tsv-noheader\n\
         \x20 --data-dir DIR         Data directory (default: ./data)\n\
         \x20 --help                 Show this help\n\
         \n\
         Examples:\n\
         \x20 siemctl alerts --query \"level == high OR level == critical\" --after 2026-06-29T19\n\
         \x20 siemctl alerts --query \"SELECT rule_title,timestamp WHERE src_ip == 10.10.50.11\"\n\
         \x20 siemctl alerts --query \"GROUP BY rule_id,rule_title LIMIT 20\"\n\
         \x20 siemctl alerts --correlated --after 2026-06-29T00\n\
         \x20 siemctl alerts --query \"type == correlated GROUP BY correlation_id\"\n\
         \x20 siemctl alerts ack 1007-haproxy-tls-probe --note \"known CDN probe pattern\"\n\
         \x20 siemctl alerts --all --query \"GROUP BY rule_id\""
    );
}

/// True if `s` is a safe bare SQL identifier (letters/digits/underscore, not
/// starting with a digit). Used to guard field/group identifiers that are
/// interpolated into the compiled SQL rather than bound as parameters.
pub(crate) fn is_sql_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Pure-Rust full-text substring search across raw JSONL files.
fn search_by_grep<W: io::Write>(
    data_dir: &Path,
    query: &str,
    source: Option<&str>,
    after: Option<time::HourBucket>,
    before: Option<time::HourBucket>,
    renderer: &mut render::Renderer<W>,
) -> Result<i32> {
    let files = collect_raw_files(data_dir, source, after, before);
    if files.is_empty() {
        eprintln!("siemctl: no raw files found");
        return Ok(1);
    }

    let mut found = false;
    'outer: for path in &files {
        let Ok(f) = fs::File::open(path) else { continue };
        for line in BufReader::new(f).lines().map_while(|r| r.ok()) {
            if line.contains(query) {
                let _ = renderer.emit_raw_line(&line);
                found = true;
                if renderer.is_done() { break 'outer; }
            }
        }
    }

    Ok(if found { 0 } else { 1 })
}

/// Dump all events in a time range (no filtering by content).
fn search_dump<W: io::Write>(
    data_dir: &Path,
    source: Option<&str>,
    after: Option<time::HourBucket>,
    before: Option<time::HourBucket>,
    renderer: &mut render::Renderer<W>,
) -> Result<i32> {
    let files = collect_raw_files(data_dir, source, after, before);
    if files.is_empty() {
        eprintln!("siemctl: no files found in range");
        return Ok(1);
    }

    'outer: for path in &files {
        let Ok(f) = fs::File::open(path) else { continue };
        for line in BufReader::new(f).lines().map_while(|r| r.ok()) {
            let _ = renderer.emit_raw_line(&line);
            if renderer.is_done() { break 'outer; }
        }
    }
    Ok(0)
}

// ── cmd: digest ──────────────────────────────────────────────────────────────

fn cmd_digest(args: &[String]) -> Result<i32> {
    let mut data_dir = default_data_dir();
    let mut window_arg = "6h".to_string();
    let mut interval_arg = "10m".to_string();
    let mut format = "text".to_string();

    let mut it = args.iter().map(String::as_str);
    while let Some(arg) = it.next() {
        match arg {
            "--data-dir" | "-d" => data_dir = PathBuf::from(next_arg(&mut it, arg)?),
            "--window" => window_arg = next_arg(&mut it, arg)?.to_string(),
            "--interval" => interval_arg = next_arg(&mut it, arg)?.to_string(),
            "--format" => format = next_arg(&mut it, arg)?.to_string(),
            "--help" | "-h" => {
                println!(
                    "Usage: siemctl digest [--window DURATION] [--interval DURATION] \
                     [--data-dir DIR] [--format text|json]\n\n\
                     Anomaly-oriented shift-briefing summary: coverage/health, volume\n\
                     deltas vs. the immediately-preceding baseline, network trends,\n\
                     auth activity, alerts, and notable low-volume events.\n\n\
                     Options:\n\
                     \x20 --window   DURATION  Analysis period ending now (default: 6h)\n\
                     \x20                      Examples: 1h, 6h, 24h, 2026-06-29T18..2026-06-29T20\n\
                     \x20 --interval DURATION  Trending bucket size (default: 10m)\n\
                     \x20 --data-dir DIR       Data directory (default: ./data)\n\
                     \x20 --format   FMT       text (default) | json\n\n\
                     Thresholds (spike %, unparsed-event minimum, ...) are read from\n\
                     config/digest.toml if present; see that file for defaults."
                );
                return Ok(0);
            }
            other => {
                eprintln!("siemctl: unknown flag: {other}");
                return Ok(1);
            }
        }
    }

    // Lag "now" behind real wall-clock time so a relative --window (and its
    // baseline, which derives from it) never reads back data from the last
    // few minutes indexd might still be catching up on — see
    // digest::NOW_LAG_SECONDS's doc comment.
    let now = chrono::Utc::now() - chrono::Duration::seconds(digest::NOW_LAG_SECONDS);
    let win = time::parse_window(&window_arg, now)
        .map_err(|e| format!("invalid --window: {e}"))?;
    let interval = time::parse_duration(&interval_arg)
        .map_err(|e| format!("invalid --interval: {e}"))?;

    let cfg = digest_config::load_or_default();
    let report = digest::build_report(&data_dir, &win, &cfg, interval)?;

    match format.as_str() {
        "text" => {
            print!("{}", digest_render::render_text(&report, &cfg, interval));
        }
        "json" => {
            println!("{}", digest_render::render_json(&report)?);
        }
        other => {
            eprintln!("siemctl: invalid --format '{other}' (expected: text, json)");
            return Ok(1);
        }
    }
    Ok(0)
}

// ── cmd: tail ──────────────────────────────────────────────────────────────

fn cmd_tail(args: &[String]) -> Result<i32> {
    let mut data_dir = default_data_dir();
    let mut source: Option<String> = None;
    let mut follow = true;

    let mut it = args.iter().map(String::as_str);
    while let Some(arg) = it.next() {
        match arg {
            "--data-dir" | "-d" => data_dir = PathBuf::from(next_arg(&mut it, arg)?),
            "--source" | "-s" => source = Some(next_arg(&mut it, arg)?.to_string()),
            "--follow" | "-f" => follow = true,
            "--no-follow" | "-F" => follow = false,
            "--help" | "-h" => {
                println!(
                    "Usage: siemctl tail [--data-dir DIR] [--source SRC] [--no-follow]\n\n\
                     Stream events from raw JSONL files.\n\n\
                     Options:\n\
                     \x20 --data-dir DIR   Data directory (default: ./data)\n\
                     \x20 --source SRC     Restrict to this source name\n\
                     \x20 --follow         Keep reading as new events arrive (default)\n\
                     \x20 --no-follow      Read current files and exit"
                );
                return Ok(0);
            }
            other => {
                eprintln!("siemctl: unknown flag: {other}");
                return Ok(1);
            }
        }
    }

    if !data_dir.is_dir() {
        return Err(format!("data directory not found: {}", data_dir.display()).into());
    }

    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    if !follow {
        let files = collect_raw_files(&data_dir, source.as_deref(), None, None);
        if files.is_empty() {
            eprintln!("siemctl: no JSONL files found");
            return Ok(1);
        }
        for path in &files {
            let Ok(f) = fs::File::open(path) else { continue };
            for line in BufReader::new(f).lines().map_while(|r| r.ok()) {
                let _ = writeln!(out, "{line}");
            }
        }
        return Ok(0);
    }

    // Follow mode: polling loop with per-file byte-offset tracking.
    //
    // The previous implementation spawned `tail -F` on a fixed file list captured
    // at startup. This broke immediately because normalized writes to a new path
    // every second (data/raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl), so the file
    // list was stale within one second and tail kept watching empty old files.
    //
    // This loop re-scans for new files every 200 ms and tracks the byte offset of
    // the last complete line read from each file. Partial lines at EOF (write in
    // progress) are left in place and retried on the next poll.

    // Seed with existing files, starting at EOF so we only show new events
    // (matching `tail -n 0 -F` behaviour).
    let mut tracked: HashMap<PathBuf, u64> = HashMap::new();
    for path in collect_raw_files(&data_dir, source.as_deref(), None, None) {
        let eof = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        tracked.insert(path, eof);
    }

    loop {
        // Discover files created since the last scan; start from offset 0 for new ones.
        for path in collect_raw_files(&data_dir, source.as_deref(), None, None) {
            tracked.entry(path).or_insert(0);
        }

        // Emit new complete lines from every tracked file in chronological order.
        let mut paths: Vec<PathBuf> = tracked.keys().cloned().collect();
        paths.sort();

        for path in &paths {
            let offset = *tracked.get(path).unwrap_or(&0);
            let Ok(mut f) = fs::File::open(path) else { continue };
            if f.seek(SeekFrom::Start(offset)).is_err() { continue }

            let mut reader = BufReader::new(&mut f);
            let mut pos = offset;
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,   // EOF — no more data right now
                    Ok(n) => {
                        if line.ends_with('\n') {
                            // Complete line: emit it (strip trailing newline/CR).
                            let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
                            let _ = writeln!(out, "{trimmed}");
                            pos += n as u64;
                        } else {
                            // Partial line: writer hasn't flushed yet; retry next poll.
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = out.flush();
            tracked.insert(path.clone(), pos);
        }

        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

// ── cmd: retention ─────────────────────────────────────────────────────────

fn cmd_retention(args: &[String]) -> Result<i32> {
    let mut data_dir = default_data_dir();
    let mut days: Option<u32> = None;
    let mut dry_run = false;
    let mut assume_yes = false;

    let mut it = args.iter().map(String::as_str);
    while let Some(arg) = it.next() {
        match arg {
            "--data-dir" | "-d" => data_dir = PathBuf::from(next_arg(&mut it, arg)?),
            "--days" | "-n" => {
                let s = next_arg(&mut it, arg)?;
                days = Some(s.parse::<u32>().map_err(|_| format!("--days: invalid number '{s}'"))?);
            }
            "--dry-run" | "-D" => dry_run = true,
            "--yes" | "--force" | "-y" => assume_yes = true,
            "--help" | "-h" => {
                println!(
                    "Usage: siemctl retention --days N [--dry-run] [--yes] [--data-dir DIR]\n\n\
                     Delete data files older than N days (raw logs, index DBs, alert JSONL).\n\
                     Also compacts data/alerts/ack.jsonl, dropping ack lines older than N\n\
                     days — that file is append-only and never ages out on its own mtime\n\
                     the way whole files do, since it's touched on every ack.\n\n\
                     --days 0 deletes ALL data — raw logs and indexes. Because that is\n\
                     irreversible it must be confirmed: answer the interactive prompt, or\n\
                     pass --yes for non-interactive (cron) use.\n\n\
                     Options:\n\
                     \x20 --days N       Retention period in days (0 = wipe everything)\n\
                     \x20 --dry-run      Print what would be deleted, without deleting\n\
                     \x20 --yes, --force Skip the confirmation prompt (required for --days 0\n\
                     \x20                when stdin is not a TTY)\n\
                     \x20 --data-dir DIR Data directory (default: ./data)"
                );
                return Ok(0);
            }
            other => {
                eprintln!("siemctl: unknown flag: {other}");
                return Ok(1);
            }
        }
    }

    let days = days.ok_or("--days N is required")?;
    if !data_dir.is_dir() {
        return Err(format!("data directory not found: {}", data_dir.display()).into());
    }

    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(u64::from(days) * 86_400))
        .unwrap_or(std::time::UNIX_EPOCH);
    let cutoff_epoch =
        cutoff.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);

    let mut old: Vec<(PathBuf, u64)> = Vec::new();
    collect_old_files(&data_dir, cutoff, &mut old);

    // `ack.jsonl` is a single continuously-appended file (see
    // docs/roadmap-soc-improvements.md item 2) — its own mtime is always
    // recent regardless of how old individual lines are, so the mtime-based
    // sweep above can never clean it. Age its *lines* out separately.
    let ack_path = data_dir.join("alerts").join("ack.jsonl");
    let stale_ack_lines = alerts::compact_ack_log(&ack_path, cutoff_epoch, true).unwrap_or(0);

    if old.is_empty() && stale_ack_lines == 0 {
        if days == 0 {
            println!("No data to delete under {}.", data_dir.display());
        } else {
            println!("No files older than {days} days found.");
        }
        return Ok(0);
    }

    let total_bytes: u64 = old.iter().map(|(_, sz)| sz).sum();

    if dry_run {
        if !old.is_empty() {
            println!("DRY RUN — would delete {} file(s), {} total:", old.len(), human_bytes(total_bytes));
            for (p, sz) in &old {
                println!("  {:>10}  {}", human_bytes(*sz), p.display());
            }
        }
        if stale_ack_lines > 0 {
            println!(
                "DRY RUN — would drop {stale_ack_lines} stale ack line(s) from {}",
                ack_path.display()
            );
        }
        return Ok(0);
    }

    // --days 0 wipes everything (raw logs + index DBs). Require confirmation
    // since it is irreversible: an interactive "yes", or --yes for cron use.
    if days == 0 && !assume_yes {
        use std::io::IsTerminal;
        if !io::stdin().is_terminal() {
            return Err(
                "refusing to wipe all data non-interactively — re-run with --yes to confirm, \
                 or --dry-run to preview"
                    .into(),
            );
        }
        print!(
            "This will permanently delete ALL {} file(s) ({}) under {} — raw logs AND indexes.\n\
             Type 'yes' to continue: ",
            old.len(),
            human_bytes(total_bytes),
            data_dir.display()
        );
        io::stdout().flush().ok();
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        if !line.trim().eq_ignore_ascii_case("yes") {
            println!("Aborted — nothing deleted.");
            return Ok(0);
        }
    }

    let mut deleted = 0usize;
    for (p, _) in &old {
        if let Err(e) = fs::remove_file(p) {
            eprintln!("siemctl: remove {}: {e}", p.display());
        } else {
            deleted += 1;
        }
    }

    let ack_dropped = alerts::compact_ack_log(&ack_path, cutoff_epoch, false).unwrap_or(0);

    // Remove now-empty directories (multiple passes until nothing changes)
    let mut dirs_removed = 0usize;
    loop {
        let n = prune_empty_dirs(&data_dir);
        dirs_removed += n;
        if n == 0 {
            break;
        }
    }

    let ack_note =
        if ack_dropped > 0 { format!(", {ack_dropped} stale ack line(s) compacted") } else { String::new() };
    println!(
        "Retention complete: {deleted} file(s) deleted, {}, {dirs_removed} empty dir(s) removed{ack_note}.",
        human_bytes(total_bytes)
    );
    Ok(0)
}

fn collect_old_files(dir: &Path, cutoff: std::time::SystemTime, out: &mut Vec<(PathBuf, u64)>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_old_files(&p, cutoff, out);
        } else if let Ok(meta) = p.metadata() {
            if meta.modified().map(|m| m < cutoff).unwrap_or(false) {
                out.push((p, meta.len()));
            }
        }
    }
}

fn prune_empty_dirs(dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else { return 0 };
    let mut count = 0;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            count += prune_empty_dirs(&p);
            if fs::remove_dir(&p).is_ok() {
                count += 1;
            }
        }
    }
    count
}

// ── cmd: dry-run ───────────────────────────────────────────────────────────

fn cmd_dryrun(args: &[String]) -> Result<i32> {
    let mut file: Option<PathBuf> = None;
    let mut source: Option<String> = None;
    let mut config: Option<PathBuf> = None;
    let mut rules: Option<PathBuf> = None;

    let mut it = args.iter().map(String::as_str);
    while let Some(arg) = it.next() {
        match arg {
            "--file" | "-f" => file = Some(PathBuf::from(next_arg(&mut it, arg)?)),
            "--source" | "-s" => source = Some(next_arg(&mut it, arg)?.to_string()),
            "--config" | "-c" => config = Some(PathBuf::from(next_arg(&mut it, arg)?)),
            "--rules" | "-r" => rules = Some(PathBuf::from(next_arg(&mut it, arg)?)),
            "--help" | "-h" => {
                println!(
                    "Usage: siemctl dry-run --file FILE [--source SRC] [--config CFG] [--rules DIR]\n\n\
                     Run a fixture file through normalized (and optionally ruled) in dry-run mode.\n\n\
                     Options:\n\
                     \x20 --file FILE     Input log file (required)\n\
                     \x20 --source SRC    Override source label passed to normalized\n\
                     \x20 --config CFG    Path to normalized.toml\n\
                     \x20 --rules DIR     If set, also pipe output through ruled"
                );
                return Ok(0);
            }
            other => {
                eprintln!("siemctl: unknown flag: {other}");
                return Ok(1);
            }
        }
    }

    let file = file.ok_or("--file FILE is required")?;
    if !file.is_file() {
        return Err(format!("file not found: {}", file.display()).into());
    }

    let norm_bin = find_binary("normalized");
    let mut norm_cmd = Command::new(&norm_bin);
    norm_cmd.arg("--stdin").arg("--dry-run");
    if let Some(src) = &source {
        norm_cmd.args(["--source", src]);
    }
    if let Some(cfg) = &config {
        norm_cmd.args(["--config", cfg.to_str().unwrap_or("")]);
    }

    let norm_out = norm_cmd
        .stdin(Stdio::from(fs::File::open(&file)?))
        .output()
        .map_err(|e| format!("failed to run '{}': {e}", norm_bin.display()))?;

    let norm_stdout = String::from_utf8_lossy(&norm_out.stdout);
    let total = norm_stdout.lines().count();
    let matched = norm_stdout.matches("\"_normalized\":true").count();
    let rate = if total > 0 { matched as f64 / total as f64 * 100.0 } else { 0.0 };

    println!("=== Normalization ===");
    println!("  Lines processed: {total}");
    println!("  Matched:         {matched}  ({rate:.1}%)");
    println!("  Unmatched:       {}", total - matched);

    if let Some(rules_dir) = &rules {
        if !rules_dir.is_dir() {
            return Err(format!("rules directory not found: {}", rules_dir.display()).into());
        }

        // Re-run normalized to pipe into ruled (can't re-use the first run's stdout)
        let mut norm2 = Command::new(&norm_bin);
        norm2.arg("--stdin").arg("--dry-run");
        if let Some(src) = &source {
            norm2.args(["--source", src]);
        }
        if let Some(cfg) = &config {
            norm2.args(["--config", cfg.to_str().unwrap_or("")]);
        }
        let norm2_child = norm2
            .stdin(Stdio::from(fs::File::open(&file)?))
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to run '{}': {e}", norm_bin.display()))?;

        let ruled_bin = find_binary("ruled");
        let ruled_out = Command::new(&ruled_bin)
            .args(["--rules", rules_dir.to_str().unwrap_or("")])
            .stdin(Stdio::from(norm2_child.stdout.unwrap()))
            .output()
            .map_err(|e| format!("failed to run '{}': {e}", ruled_bin.display()))?;

        let ruled_stdout = String::from_utf8_lossy(&ruled_out.stdout);
        let alert_count = ruled_stdout.lines().count();
        let mut rule_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for line in ruled_stdout.lines() {
            if let Some(i) = line.find("\"rule_id\":\"") {
                let rest = &line[i + 11..];
                if let Some(j) = rest.find('"') {
                    rule_ids.insert(&rest[..j]);
                }
            }
        }

        println!("\n=== Rule Evaluation ===");
        println!("  Alerts generated: {alert_count}");
        println!("  Rules triggered:  {}", rule_ids.len());
        for id in rule_ids {
            println!("    {id}");
        }
    }

    Ok(0)
}

// ── cmd: validate ──────────────────────────────────────────────────────────

fn cmd_validate(args: &[String]) -> Result<i32> {
    let mut sources_path: Option<PathBuf> = None;
    let mut rules_dir: Option<PathBuf> = None;
    let mut normalized_path: Option<PathBuf> = None;

    let mut it = args.iter().map(String::as_str);
    while let Some(arg) = it.next() {
        match arg {
            "--config" | "-c" => sources_path = Some(PathBuf::from(next_arg(&mut it, arg)?)),
            "--rules" | "-r" => rules_dir = Some(PathBuf::from(next_arg(&mut it, arg)?)),
            "--normalized-config" | "-N" => {
                normalized_path = Some(PathBuf::from(next_arg(&mut it, arg)?))
            }
            "--help" | "-h" => {
                println!(
                    "Usage: siemctl validate --config sources.toml --rules DIR \
                     [--normalized-config normalized.toml]\n\n\
                     Validate sources.toml field definitions and Sigma rule files.\n\
                     With --normalized-config, also cross-check that the fields\n\
                     normalized extracts line up with the fields sources.toml indexes.\n\n\
                     Options:\n\
                     \x20 --config FILE             Path to sources.toml (required)\n\
                     \x20 --rules DIR               Directory containing Sigma .yml files (required)\n\
                     \x20 --normalized-config FILE  Path to normalized.toml (optional; enables\n\
                     \x20                           the field cross-check, advisory only)"
                );
                return Ok(0);
            }
            other => {
                eprintln!("siemctl: unknown flag: {other}");
                return Ok(1);
            }
        }
    }

    let sources_path = sources_path.ok_or("--config FILE is required")?;
    let rules_dir = rules_dir.ok_or("--rules DIR is required")?;
    if !sources_path.is_file() {
        return Err(format!("not found: {}", sources_path.display()).into());
    }
    if !rules_dir.is_dir() {
        return Err(format!("not found: {}", rules_dir.display()).into());
    }
    if let Some(np) = &normalized_path {
        if !np.is_file() {
            return Err(format!("not found: {}", np.display()).into());
        }
    }

    let mut errors = 0usize;
    let mut warnings = 0usize;

    // ── sources.toml ──────────────────────────────────────────────────
    println!("=== sources.toml: {} ===", sources_path.display());
    let content = fs::read_to_string(&sources_path)?;
    let mut cur_source: Option<String> = None;
    let mut cur_fields: Vec<String> = Vec::new();
    let mut source_count = 0usize;

    let flush = |name: &Option<String>, fields: &[String], cnt: &mut usize, errs: &mut usize| {
        if let Some(n) = name {
            *cnt += 1;
            if fields.is_empty() {
                eprintln!("  WARN [{n}] no index_fields defined");
            } else {
                println!("  OK   [{n}] index_fields: [{}]", fields.join(", "));
                *errs += 0; // keep signature consistent
            }
        }
    };

    for line in content.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        if let Some(rest) = t.strip_prefix("[source.") {
            flush(&cur_source, &cur_fields, &mut source_count, &mut errors);
            cur_source = rest.strip_suffix(']').map(|s| s.to_string());
            cur_fields.clear();
        } else if t.starts_with("index_fields") {
            // Grab all quoted strings on this and potentially continued lines
            let mut in_array = true;
            let work = t.to_string();
            while in_array {
                let mut rest = work.as_str();
                while let Some(i) = rest.find('"') {
                    rest = &rest[i + 1..];
                    if let Some(j) = rest.find('"') {
                        let f = &rest[..j];
                        if !f.is_empty() {
                            cur_fields.push(f.to_string());
                        }
                        rest = &rest[j + 1..];
                    } else {
                        break;
                    }
                }
                if work.contains(']') {
                    in_array = false;
                } else {
                    break; // single-line only for now
                }
            }
        }
    }
    flush(&cur_source, &cur_fields, &mut source_count, &mut errors);

    if source_count == 0 {
        eprintln!("  ERROR: no [source.*] entries found");
        errors += 1;
    } else {
        println!("  Total: {source_count} source(s)");
    }

    // ── Sigma rules ───────────────────────────────────────────────────
    println!("\n=== Sigma rules: {} ===", rules_dir.display());
    let mut rule_files: Vec<PathBuf> = fs::read_dir(&rules_dir)?
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "yml" || x == "yaml").unwrap_or(false))
        .map(|e| e.path())
        .collect();
    rule_files.sort();

    if rule_files.is_empty() {
        println!("  No .yml files found.");
    }

    for rf in &rule_files {
        let name = rf.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        let content = match fs::read_to_string(rf) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  ERROR [{name}] cannot read: {e}");
                errors += 1;
                continue;
            }
        };

        let issues = validate_sigma_rule(&content);
        let deprecated = is_sigma_deprecated(&content);

        if issues.is_empty() {
            if deprecated {
                println!("  SKIP [{name}] deprecated");
                warnings += 1;
            } else {
                println!("  OK   [{name}]");
            }
        } else {
            for issue in &issues {
                eprintln!("  ERROR [{name}] {issue}");
                errors += 1;
            }
        }
    }

    // ── Cross-check: normalized.toml ↔ sources.toml (advisory) ────────
    if let Some(np) = &normalized_path {
        validate_config_crosscheck(np, &sources_path);
    }

    println!();
    println!(
        "Validation complete: {} rule file(s), {} error(s), {} warning(s).",
        rule_files.len(),
        errors,
        warnings
    );
    Ok(if errors > 0 { 1 } else { 0 })
}

/// Advisory cross-check between what `normalized` extracts and what
/// `sources.toml` indexes. Prints findings only; never affects the exit code,
/// because a config scan can't see fields produced by the zero-config format
/// chain (CEF/LEEF/JSON/…), so both directions can have false positives.
fn validate_config_crosscheck(normalized_path: &Path, sources_path: &Path) {
    println!(
        "\n=== config cross-check: {} ↔ {} ===",
        normalized_path.display(),
        sources_path.display()
    );

    let prod = match normconfig::load(normalized_path) {
        Some(p) => p,
        None => {
            eprintln!("  WARN: could not read {}", normalized_path.display());
            return;
        }
    };
    let declared = sources::load_index_fields(sources_path);
    let core = sources::always_valid();

    println!("  declared index_fields (union): {}", declared.len());
    println!("  producible output fields:      {}", prod.output_fields.len());

    // Direction 1: produced by normalized but indexed by no source → not searchable.
    let mut gap: Vec<&String> = prod
        .output_fields
        .iter()
        .filter(|f| !declared.contains(*f) && !core.contains(*f))
        .collect();
    gap.sort();
    if gap.is_empty() {
        println!("  OK   every producible output field is indexed (or is a core field)");
    } else {
        println!("  WARN produced but indexed by no source ({}):", gap.len());
        println!("         {}", join_refs(&gap));
        println!("       → add to a source's index_fields in sources.toml to search/group on them");
    }

    // Direction 2: declared index_field that no rule produces → typo or
    // structured-format-only field.
    let mut dead: Vec<&String> = declared
        .iter()
        .filter(|f| !prod.all_fields.contains(*f) && !core.contains(*f))
        .collect();
    dead.sort();
    if dead.is_empty() {
        println!("  OK   every declared index_field is produced by a rule (or is a core field)");
    } else {
        println!("  WARN index_fields not produced by any normalized.toml rule ({}):", dead.len());
        println!("         {}", join_refs(&dead));
        println!("       → check for a typo, or a field supplied by a structured-format");
        println!("         parser (CEF/LEEF/JSON) that this config scan can't see");
    }

    println!("  (advisory — these findings do not affect the exit code)");
}

fn join_refs(v: &[&String]) -> String {
    v.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
}

fn validate_sigma_rule(content: &str) -> Vec<String> {
    let mut issues = Vec::new();

    let has_id = content.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("id:") && t.len() > 3 && !t[3..].trim().is_empty()
    });
    if !has_id {
        issues.push("missing 'id' field".to_string());
    }

    let has_title = content.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("title:") && t.len() > 6 && !t[6..].trim().is_empty()
    });
    if !has_title {
        issues.push("missing 'title' field".to_string());
    }

    if !content.contains("detection:") {
        issues.push("missing 'detection' block".to_string());
    } else {
        let has_cond = content.lines().any(|l| {
            let stripped = l.trim_start();
            // condition must be indented (inside detection block)
            l.starts_with(' ') || l.starts_with('\t') && stripped.starts_with("condition:")
        });
        // Simpler check: just look for "condition:" anywhere indented
        let has_cond2 = content.lines().any(|l| {
            (l.starts_with("  ") || l.starts_with('\t'))
                && l.trim_start().starts_with("condition:")
        });
        if !has_cond2 {
            issues.push("missing 'condition' inside detection block".to_string());
        }
        let _ = has_cond;
    }

    issues
}

fn is_sigma_deprecated(content: &str) -> bool {
    content.lines().any(|l| {
        let t = l.trim();
        t.starts_with("status:") && t.contains("deprecated")
    })
}

#[cfg(test)]
mod retention_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        fn new() -> Self {
            let n = CTR.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir()
                .join(format!("siemctl_ret_test_{}_{}", std::process::id(), n));
            fs::create_dir_all(&p).unwrap();
            TempDir { path: p }
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// `--days 0` computes a cutoff of "now", so every already-written file is
    /// older and gets collected — including index DBs and their WAL/SHM
    /// sidecars, not just raw logs. (Cutoff is taken in the future here to keep
    /// the assertion robust against filesystem mtime granularity.)
    #[test]
    fn collect_old_files_zero_day_cutoff_catches_raw_and_index() {
        let tmp = TempDir::new();
        let raw = tmp.path.join("raw/2026/06/27/22/13/22");
        let idx = tmp.path.join("index");
        fs::create_dir_all(&raw).unwrap();
        fs::create_dir_all(&idx).unwrap();
        fs::write(raw.join("sshd.jsonl"), b"{}\n").unwrap();
        fs::write(idx.join("2026-06-27-22.db"), b"x").unwrap();
        fs::write(idx.join("2026-06-27-22.db-wal"), b"x").unwrap();

        let cutoff = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        let mut old = Vec::new();
        collect_old_files(&tmp.path, cutoff, &mut old);

        let names: Vec<String> = old
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(old.len(), 3, "expected raw + 2 index files, got: {names:?}");
        assert!(names.iter().any(|n| n == "sshd.jsonl"), "raw log missing: {names:?}");
        assert!(names.iter().any(|n| n == "2026-06-27-22.db"), "index db missing: {names:?}");
        assert!(names.iter().any(|n| n == "2026-06-27-22.db-wal"), "wal sidecar missing: {names:?}");
    }
}

#[cfg(test)]
mod human_bytes_tests {
    use super::*;

    #[test]
    fn sub_tb_values_unchanged() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
        assert_eq!(human_bytes(7 * 1024_u64.pow(4)), "7.0 TB");
    }

    #[test]
    fn petabyte_and_exabyte_scale_rolls_over_past_tb() {
        // 2048 TB should roll over to 2.0 PB, not stay pinned at the last unit.
        assert_eq!(human_bytes(2048 * 1024_u64.pow(4)), "2.0 PB");
        assert_eq!(human_bytes(3 * 1024_u64.pow(6)), "3.0 EB");
    }
}

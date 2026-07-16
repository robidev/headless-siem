//! Section builders for `siemctl digest` — see `main.rs`'s `cmd_digest` for
//! the CLI, `digest_render.rs` for text/JSON rendering, and `digest_config.rs`
//! for `config/digest.toml` loading (`docs/design-digest-command.md` has the
//! full Implementation Plan).
//!
//! Each `build_*` function computes one section of the spec's output and
//! returns a plain, `Serialize`-able struct. Both the eventual text and JSON
//! renderers consume the same structs — all the "what counts as an anomaly"
//! logic lives here, once, not duplicated per output format.
//!
//! Threshold parameters (spike %, unparsed-event minimum, etc.) are passed
//! in rather than hardcoded, so the config-loading batch can plumb
//! `config/digest.toml` values straight through; the constants in this file
//! are only the spec's documented defaults, used by tests and as fallbacks.
//!
//! Scoping decisions made while implementing this batch (so a fresh session
//! doesn't have to re-derive them):
//!
//! - **Auth failures are unified by `src_ip` only for sources that actually
//!   carry one.** `sudo_auth_failure` (sudo) and `local_auth_failure`
//!   (unix_chkpwd) are local-origin checks with no network component — the
//!   indexed schema has no `src_ip` for either (see `config/sources.toml`).
//!   They're excluded from [`AuthFailureRow`] rather than silently grouped
//!   under an empty-string IP. A username-keyed "local auth failures" view
//!   would be a reasonable follow-up but is out of scope here.
//! - **`config/sources.toml`'s `[source.sudo]` gained `target_user`,
//!   `command`, `tty`** — needed for the privilege-escalation list and not
//!   previously indexed. This is the normal/expected way to extend the
//!   index (`CLAUDE.md`'s own "Adding a New Log Parser" guidance); existing
//!   un-reindexed hour buckets simply lack the column and are skipped per
//!   the tolerant `is_benign` handling already in `digest_query.rs`, not an
//!   error.
//! - **The digest's alerts section covers `ruled` alerts only, not
//!   correlated alerts** (`data/alerts/correlated/`). The design doc's own
//!   mockup only shows rule-style rows; correlated-alert query support is
//!   `siemctl alerts`' job (a separate, unbuilt roadmap item), not this
//!   command's.
//! - **Top-blocked / inbound-allowed rows are grouped by their full key
//!   tuple** (`src_ip, protocol` / `src_ip, dst_ip, dst_port`), not by
//!   `src_ip` alone with an ad-hoc "dominant protocol" pick — simpler, and
//!   the mockup's single-protocol-per-IP appearance is just what typically
//!   happens for its example IPs, not a hard requirement.
//! - **"Critical/emergency" notable events list `_source_type`/`event_type`/
//!   `severity`/timestamp only**, not the resolved raw message text — those
//!   fields aren't indexed (see `sources.toml`) and full-line resolution
//!   would need `byte_offset` plumbed through too. Low-volume-by-design
//!   section, but full-message resolution is a reasonable future addition.

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::digest_query;
use crate::time::Window;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// ── Documented defaults (config/digest.toml overrides these) ───────────────

pub const DEFAULT_SPIKE_THRESHOLD_PCT: f64 = 50.0;
pub const DEFAULT_UNPARSED_MIN_EVENTS: u64 = 50;
pub const DEFAULT_CONCENTRATION_THRESHOLD_PCT: f64 = 80.0;
pub const DEFAULT_WAN_INTERFACE: &str = "re1";
pub const DEFAULT_TOP_BLOCKED_LIMIT: usize = 20;

/// How far behind real wall-clock `now` the digest's shared window/baseline
/// anchor is deliberately held back, so neither the digest window nor its
/// baseline ever depends on the last few minutes of data `indexd` may not
/// have caught up on yet (see `main.rs`'s `cmd_digest`, which subtracts this
/// before calling `time::parse_window`). A lagging index read back
/// near-zero counts for an actively-logging source, producing a spurious
/// `flag=new baseline=0` on the very next digest run after real data starts
/// flowing — see
/// `ticketing-system/tuner-dev/20260716T163247.000_digest-baseline-zero-index-lag-suspected.md`.
/// 300s matches `indexd`'s own documented worst-case catch-up bound
/// (`RECENT_FILE_SWEEP_INTERVAL` in `src/indexd/src/main.rs` — the periodic
/// safety-net re-scan interval backstopping a missed inotify event); the
/// reactive inotify path is normally near-instant, so this is a worst-case
/// margin, not a typical delay. Only affects a relative `--window` (e.g.
/// `"6h"`); an explicit `start..end` range ignores `now` entirely and is
/// unaffected (`time::parse_window`).
pub const NOW_LAG_SECONDS: i64 = 300;
/// Default lookback for the coverage section's `new_sources`/`gone_silent`
/// check — long enough to absorb the slowest named noisy sources'
/// reporting jitter (`corosync`/`pmxcfs`, sub-daily but not hourly) without
/// making a genuinely-decommissioned source take unreasonably long to flag
/// (worst case ~2x lookback). See `build_coverage`'s doc comment.
pub const DEFAULT_COVERAGE_LOOKBACK_HOURS: u64 = 24;

/// Minimum fraction of the baseline window that must actually have data on
/// disk before it's trusted as a real comparison baseline — see
/// `build_report`'s cold-start doc comment. Deliberately a majority-of-window
/// bar, not a low bar like 10%: a baseline with only a few scattered hours
/// of real data out of a multi-day window may still miss whole daily-rhythm
/// sources (a `cron` job that only runs at 03:00, say), so "some data
/// exists" isn't the same as "this is a trustworthy comparison point."
const COLD_START_COVERAGE_FLOOR: f64 = 0.50;

/// Auth-failure `event_type`s that carry a `src_ip` — see the module doc
/// comment for why `sudo_auth_failure`/`local_auth_failure` are excluded.
const AUTH_FAILURE_EVENT_TYPES: &[&str] =
    &["ssh_auth_failure", "ssh_auth_timeout", "vpn_auth_failure", "vpn_tls_error"];

const SUCCESS_EVENT_TYPES: &[&str] = &["ssh_auth_success"];

const SERVICE_TRANSITION_EVENT_TYPES: &[&str] =
    &["unit_started", "unit_stopped", "unit_stopping", "unit_failed"];

/// Unit transitions whose `first_seen` timestamps land within this many
/// seconds of each other are considered part of the same boot/shutdown
/// storm rather than independent restarts — see [`collapse_boot_storms`].
pub const BOOT_STORM_GAP_SECONDS: i64 = 300;

/// Minimum distinct units clustered within [`BOOT_STORM_GAP_SECONDS`] to be
/// collapsed into one boot-storm summary instead of listed individually.
/// A genuine reboot produces dozens; a couple of unrelated units restarting
/// minutes apart (a config reload, a crash-restart) is normal noise and
/// should stay visible per-unit.
const BOOT_STORM_MIN_UNITS: usize = 5;

// ── Top-level report ────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DigestReport {
    pub window: WindowInfo,
    pub coverage: CoverageSection,
    pub volume: Vec<VolumeRow>,
    pub network: NetworkSection,
    pub auth: AuthSection,
    pub alerts: AlertsSection,
    pub notable: NotableSection,
}

#[derive(Debug, Serialize)]
pub struct WindowInfo {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub baseline_start: DateTime<Utc>,
    pub baseline_end: DateTime<Utc>,
}

/// Thresholds for the digest's anomaly flags — the runtime form of
/// `config/digest.toml` (loaded by `digest_config.rs`; `Default` gives the
/// spec's documented defaults).
#[derive(Debug, Clone)]
pub struct DigestConfig {
    pub spike_threshold_pct: f64,
    pub new_source_always_flag: bool,
    pub unparsed_min_events: u64,
    pub coverage_lookback_hours: u64,
    pub concentration_threshold_pct: f64,
    pub wan_interface: String,
    pub top_blocked_limit: usize,
    pub new_destination_always_flag: bool,
}

impl Default for DigestConfig {
    fn default() -> Self {
        DigestConfig {
            spike_threshold_pct: DEFAULT_SPIKE_THRESHOLD_PCT,
            new_source_always_flag: true,
            unparsed_min_events: DEFAULT_UNPARSED_MIN_EVENTS,
            coverage_lookback_hours: DEFAULT_COVERAGE_LOOKBACK_HOURS,
            concentration_threshold_pct: DEFAULT_CONCENTRATION_THRESHOLD_PCT,
            wan_interface: DEFAULT_WAN_INTERFACE.to_string(),
            top_blocked_limit: DEFAULT_TOP_BLOCKED_LIMIT,
            new_destination_always_flag: true,
        }
    }
}

/// Compute every section of the digest for `win`. `interval` is the
/// sparkline bucket width (the CLI's `--interval`, "10m" by default).
pub fn build_report(
    data_dir: &Path,
    win: &Window,
    cfg: &DigestConfig,
    interval: Duration,
) -> Result<DigestReport> {
    let baseline = win.baseline();
    let cold_start = cold_start_for_baseline(data_dir, &baseline);

    // The coverage section's new_sources/gone_silent check needs its own,
    // much longer lookback (independent of `win`'s own duration) so a
    // sub-daily source doesn't flap between "new"/"gone silent" every time
    // a short digest window happens to miss it — see `build_coverage`'s
    // doc comment. It gets its own cold-start check against its own
    // baseline, not `cold_start` above: reusing the short-window bool here
    // would under/over-suppress `new_sources` for the first
    // `coverage_lookback_hours` after SIEM startup (that window's own
    // baseline is a different — and much longer — span than `win`'s).
    let coverage_window = win.lookback(Duration::hours(cfg.coverage_lookback_hours as i64));
    let coverage_cold_start = cold_start_for_baseline(data_dir, &coverage_window.baseline());

    Ok(DigestReport {
        window: WindowInfo {
            start: win.start,
            end: win.end,
            baseline_start: baseline.start,
            baseline_end: baseline.end,
        },
        coverage: build_coverage(data_dir, win, &coverage_window, cfg, cold_start, coverage_cold_start)?,
        volume: build_volume(data_dir, win, cfg, cold_start)?,
        network: build_network_with_interval(data_dir, win, cfg, interval)?,
        auth: build_auth(data_dir, win)?,
        alerts: build_alerts(data_dir, win, cfg)?,
        notable: build_notable(data_dir, win)?,
    })
}

/// Whether `baseline` predates real data collection enough that it can't be
/// trusted as a comparison point — every source in the compared window
/// would otherwise look "new"/"gone silent" not because of a real change,
/// but because the SIEM itself hasn't been collecting long enough to have a
/// genuine prior period to compare against.
///
/// Two simpler approaches were tried and rejected:
/// - Comparing `baseline.start` against the earliest raw event on disk:
///   false-positives on almost every real baseline, since actual event
///   timestamps essentially never land exactly on the window's nominal
///   start (seen live: a baseline "starting" 10 minutes into its hour
///   still has 50 real minutes of coverage — not a cold start).
/// - Comparing total baseline event *count* against the window's count:
///   false-positives on a genuine volume spike (window count \u{226b}
///   baseline count is also what a real attack/anomaly looks like, not
///   just "not enough history yet").
///
/// The time-coverage-fraction below avoids both: it only cares how much of
/// `baseline`, by wall-clock duration, falls after data collection began —
/// immune to rate differences between the two periods, and tolerant of a
/// baseline that starts a little before the first real event.
///
/// Shared by `build_report`'s short-window check (`win.baseline()`, feeds
/// `build_volume`'s "new"-flag suppression) and its long-lookback check
/// (`coverage_window.baseline()`, feeds `build_coverage`'s `new_sources`
/// suppression) — each call is against that check's own baseline, never a
/// bool shared across the two windows.
fn cold_start_for_baseline(data_dir: &Path, baseline: &Window) -> bool {
    digest_query::earliest_raw_event_time(data_dir)
        .map(|earliest| {
            let baseline_seconds = (baseline.end - baseline.start).num_seconds().max(1) as f64;
            let covered_start = earliest.max(baseline.start);
            let covered_seconds = (baseline.end - covered_start).num_seconds().max(0) as f64;
            covered_seconds < baseline_seconds * COLD_START_COVERAGE_FLOOR
        })
        .unwrap_or(false)
}

// ── 1. Coverage / health ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct UnparsedSource {
    pub app_name: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct IncompleteBucket {
    pub bucket: String,
    pub raw_count: u64,
    pub indexed_count: u64,
}

#[derive(Debug, Serialize)]
pub struct CoverageSection {
    pub sources_reporting: usize,
    pub gone_silent: Vec<String>,
    pub new_sources: Vec<String>,
    pub unparsed_high_volume: Vec<UnparsedSource>,
    pub latest_raw: Option<DateTime<Utc>>,
    pub latest_indexed: Option<DateTime<Utc>>,
    pub index_lag_seconds: Option<i64>,
    /// Hour buckets in this window where the index is short of what's on
    /// disk in raw — a completeness gap that `index_lag_seconds` (which
    /// only compares the newest timestamp on each side) cannot see. See
    /// `digest_query::completeness_in_range`'s doc comment.
    pub incomplete_buckets: Vec<IncompleteBucket>,
    /// True when `win`'s own short baseline (`win.baseline()`) starts
    /// before the earliest raw event on disk — there's no real prior
    /// period to compare against yet. Gates `build_volume`'s "new" flag
    /// and `digest_render.rs`'s baseline-count-is-zero explanation; see
    /// `build_report`'s doc comment. Distinct from `coverage_cold_start`
    /// below, which gates this section's own `new_sources`/`gone_silent`.
    pub cold_start: bool,
    /// True when the coverage lookback window's own baseline
    /// (`coverage_window.baseline()` — see [`crate::time::Window::lookback`]
    /// and `config/digest.toml`'s `coverage_lookback_hours`) starts before
    /// the earliest raw event on disk. Gates `new_sources` (left empty
    /// rather than flooding with every currently-reporting source) —
    /// computed against the long lookback window, not `win`'s own short
    /// baseline, so the first `coverage_lookback_hours` after SIEM startup
    /// doesn't under/over-suppress using the wrong window's coverage.
    pub coverage_cold_start: bool,
}

/// `coverage_window` (`win.lookback(coverage_lookback_hours)` — see
/// [`crate::time::Window::lookback`]) drives `new_sources`/`gone_silent`,
/// compared against `coverage_window.baseline()`, **not** `win`/
/// `win.baseline()`. A sub-daily source (e.g. `corosync`/`pmxcfs`) can
/// easily miss `win` itself (a short `--window`) without having actually
/// gone away — comparing over a multi-hour lookback instead absorbs that
/// reporting jitter. `sources_reporting` and everything else in this
/// section still describe `win` itself, unchanged.
pub fn build_coverage(
    data_dir: &Path,
    win: &Window,
    coverage_window: &Window,
    cfg: &DigestConfig,
    cold_start: bool,
    coverage_cold_start: bool,
) -> Result<CoverageSection> {
    let window_counts = digest_query::group_count_in_range(data_dir, win, &["_source_type"], None, &[])?;
    let window_sources: BTreeSet<String> =
        window_counts.keys().filter_map(|k| k.first()).filter(|s| !s.is_empty()).cloned().collect();

    let coverage_window_counts =
        digest_query::group_count_in_range(data_dir, coverage_window, &["_source_type"], None, &[])?;
    let coverage_baseline_counts = digest_query::group_count_in_range(
        data_dir,
        &coverage_window.baseline(),
        &["_source_type"],
        None,
        &[],
    )?;

    let coverage_window_sources: BTreeSet<String> = coverage_window_counts
        .keys()
        .filter_map(|k| k.first())
        .filter(|s| !s.is_empty())
        .cloned()
        .collect();
    let coverage_baseline_sources: BTreeSet<String> = coverage_baseline_counts
        .keys()
        .filter_map(|k| k.first())
        .filter(|s| !s.is_empty())
        .cloned()
        .collect();

    let gone_silent: Vec<String> =
        coverage_baseline_sources.difference(&coverage_window_sources).cloned().collect();
    let new_sources: Vec<String> = if coverage_cold_start {
        Vec::new()
    } else {
        coverage_window_sources.difference(&coverage_baseline_sources).cloned().collect()
    };

    let unparsed_high_volume = unparsed_high_volume_sources(data_dir, win, cfg.unparsed_min_events);

    let latest_raw = digest_query::latest_raw_event_time(data_dir);
    let latest_indexed = digest_query::newest_indexed_event_time(data_dir);
    let index_lag_seconds = match (latest_raw, latest_indexed) {
        (Some(r), Some(i)) => Some((r - i).num_seconds()),
        _ => None,
    };

    let incomplete_buckets = digest_query::completeness_in_range(data_dir, win)
        .into_iter()
        .map(|b| IncompleteBucket {
            bucket: b.bucket,
            raw_count: b.raw_count,
            indexed_count: b.indexed_count,
        })
        .collect();

    Ok(CoverageSection {
        sources_reporting: window_sources.len(),
        gone_silent,
        new_sources,
        unparsed_high_volume,
        latest_raw,
        latest_indexed,
        index_lag_seconds,
        incomplete_buckets,
        cold_start,
        coverage_cold_start,
    })
}

/// Scans raw JSONL directly (not the index — unparsed events were never
/// indexed) for `_normalized: false` lines, grouped by `app_name`.
fn unparsed_high_volume_sources(data_dir: &Path, win: &Window, min_events: u64) -> Vec<UnparsedSource> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for path in digest_query::raw_files_in_range(data_dir, win) {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        for line in content.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            let normalized = v.get("_normalized").and_then(|x| x.as_bool()).unwrap_or(true);
            if normalized {
                continue;
            }
            let app = v.get("app_name").and_then(|x| x.as_str()).unwrap_or("(unknown)");
            *counts.entry(app.to_string()).or_default() += 1;
        }
    }
    let mut out: Vec<UnparsedSource> = counts
        .into_iter()
        .filter(|(_, c)| *c > min_events)
        .map(|(app_name, count)| UnparsedSource { app_name, count })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then(a.app_name.cmp(&b.app_name)));
    out
}

// ── 2. Volume anomalies ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct VolumeRow {
    pub source: String,
    pub count: u64,
    pub baseline: u64,
    pub delta_pct: Option<f64>,
    /// `"new"` (zero baseline), `"spike"` (increase beyond the configured
    /// threshold), or `"drop"` (decrease beyond the threshold, including a
    /// baseline source going silent — a -100% delta is a silence, not a
    /// spike, so it gets its own label); `None` for a normal row.
    pub flag: Option<String>,
}

pub fn build_volume(
    data_dir: &Path,
    win: &Window,
    cfg: &DigestConfig,
    cold_start: bool,
) -> Result<Vec<VolumeRow>> {
    let window_counts = digest_query::group_count_in_range(data_dir, win, &["_source_type"], None, &[])?;
    let baseline_counts =
        digest_query::group_count_in_range(data_dir, &win.baseline(), &["_source_type"], None, &[])?;

    let mut sources: BTreeSet<String> = BTreeSet::new();
    for k in window_counts.keys().chain(baseline_counts.keys()) {
        if let Some(s) = k.first() {
            if !s.is_empty() {
                sources.insert(s.clone());
            }
        }
    }

    let mut rows: Vec<VolumeRow> = sources
        .into_iter()
        .map(|source| {
            let key = vec![source.clone()];
            let count = *window_counts.get(&key).unwrap_or(&0);
            let baseline = *baseline_counts.get(&key).unwrap_or(&0);
            let (delta_pct, flag) = if baseline == 0 {
                // Cold start: baseline is empty because there's no history
                // yet, not because this source is actually new — never
                // flag, regardless of new_source_always_flag.
                let flag =
                    (!cold_start && cfg.new_source_always_flag && count > 0).then(|| "new".to_string());
                (None, flag)
            } else {
                let pct = ((count as f64 - baseline as f64) / baseline as f64) * 100.0;
                let flag = if pct > cfg.spike_threshold_pct {
                    Some("spike".to_string())
                } else if pct < -cfg.spike_threshold_pct {
                    Some("drop".to_string())
                } else {
                    None
                };
                (Some(pct), flag)
            };
            VolumeRow { source, count, baseline, delta_pct, flag }
        })
        .collect();

    rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.source.cmp(&b.source)));
    Ok(rows)
}

// ── 3. Network (filterlog) ───────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct TopBlocked {
    pub src_ip: String,
    pub protocol: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct InboundAllowed {
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct NewDestination {
    pub dst_ip: String,
    pub dst_port: String,
    pub count: u64,
    pub first_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct NetworkSection {
    pub block_trend: Vec<u64>,
    pub top_blocked: Vec<TopBlocked>,
    pub inbound: Vec<InboundAllowed>,
    pub new_destinations: Vec<NewDestination>,
}

/// `interval` is the sparkline bucket width — the CLI's `--interval`
/// ("10m" by default, see `main.rs`'s `cmd_digest`).
pub fn build_network_with_interval(
    data_dir: &Path,
    win: &Window,
    cfg: &DigestConfig,
    interval: Duration,
) -> Result<NetworkSection> {
    let block_minutes = digest_query::minute_counts_in_range(
        data_dir,
        win,
        Some("_source_type = ? AND action = ?"),
        &["filterlog".to_string(), "BLOCK".to_string()],
    )?;
    let block_trend = digest_query::bucket_series(&block_minutes, win, interval);

    let top_blocked = top_blocked_sources(data_dir, win, cfg.top_blocked_limit)?;
    let inbound = inbound_allowed(data_dir, win, &cfg.wan_interface)?;
    let new_destinations = if cfg.new_destination_always_flag {
        new_outbound_destinations(data_dir, win)?
    } else {
        Vec::new()
    };

    Ok(NetworkSection { block_trend, top_blocked, inbound, new_destinations })
}

fn top_blocked_sources(data_dir: &Path, win: &Window, limit: usize) -> Result<Vec<TopBlocked>> {
    let counts = digest_query::group_count_in_range(
        data_dir,
        win,
        &["src_ip", "protocol"],
        Some("_source_type = ? AND action = ?"),
        &["filterlog".to_string(), "BLOCK".to_string()],
    )?;
    let mut rows: Vec<TopBlocked> = counts
        .into_iter()
        .filter(|(k, _)| !k[0].is_empty())
        .map(|(k, count)| TopBlocked {
            src_ip: k[0].clone(),
            protocol: k.get(1).cloned().unwrap_or_default(),
            count,
        })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count));
    rows.truncate(limit);
    Ok(rows)
}

fn inbound_allowed(data_dir: &Path, win: &Window, wan_interface: &str) -> Result<Vec<InboundAllowed>> {
    let counts = digest_query::group_count_in_range(
        data_dir,
        win,
        &["src_ip", "dst_ip", "dst_port"],
        Some("_source_type = ? AND action = ? AND interface = ?"),
        &["filterlog".to_string(), "ALLOW".to_string(), wan_interface.to_string()],
    )?;
    let mut rows: Vec<InboundAllowed> = counts
        .into_iter()
        .filter(|(k, _)| !k[0].is_empty())
        .map(|(k, count)| InboundAllowed {
            src_ip: k[0].clone(),
            dst_ip: k.get(1).cloned().unwrap_or_default(),
            dst_port: k.get(2).cloned().unwrap_or_default(),
            count,
        })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count));
    Ok(rows)
}

fn new_outbound_destinations(data_dir: &Path, win: &Window) -> Result<Vec<NewDestination>> {
    let window_counts = digest_query::group_count_in_range(
        data_dir,
        win,
        &["dst_ip", "dst_port"],
        Some("_source_type = ? AND direction = ?"),
        &["filterlog".to_string(), "out".to_string()],
    )?;
    let baseline_dst_ips: BTreeSet<String> = digest_query::group_count_in_range(
        data_dir,
        &win.baseline(),
        &["dst_ip"],
        Some("_source_type = ? AND direction = ?"),
        &["filterlog".to_string(), "out".to_string()],
    )?
    .into_keys()
    .filter_map(|k| k.into_iter().next())
    .collect();

    let mut rows = Vec::new();
    for (key, count) in window_counts {
        let dst_ip = key[0].clone();
        if dst_ip.is_empty() || baseline_dst_ips.contains(&dst_ip) {
            continue;
        }
        let dst_port = key.get(1).cloned().unwrap_or_default();
        let first_seen = digest_query::first_seen_in_range(
            data_dir,
            win,
            "_source_type = ? AND direction = ? AND dst_ip = ?",
            &["filterlog".to_string(), "out".to_string(), dst_ip.clone()],
        )?;
        rows.push(NewDestination { dst_ip, dst_port, count, first_seen });
    }
    rows.sort_by(|a, b| b.count.cmp(&a.count));
    Ok(rows)
}

// ── 4. Authentication and access ─────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AuthFailureBySource {
    pub source: String,
    pub event_type: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct AuthFailureRow {
    pub src_ip: String,
    pub count: u64,
    pub by_source: Vec<AuthFailureBySource>,
}

#[derive(Debug, Serialize)]
pub struct AccessEvent {
    pub timestamp: Option<DateTime<Utc>>,
    pub src_ip: String,
    pub username: String,
    pub source: String,
}

#[derive(Debug, Serialize)]
pub struct SudoEvent {
    pub timestamp: Option<DateTime<Utc>>,
    pub username: String,
    pub target_user: String,
    pub command: String,
}

#[derive(Debug, Serialize)]
pub struct AuthSection {
    pub failures: Vec<AuthFailureRow>,
    pub successes: Vec<AccessEvent>,
    pub sudo: Vec<SudoEvent>,
}

pub fn build_auth(data_dir: &Path, win: &Window) -> Result<AuthSection> {
    Ok(AuthSection {
        failures: auth_failures(data_dir, win)?,
        successes: successful_access(data_dir, win)?,
        sudo: sudo_events(data_dir, win)?,
    })
}

fn auth_failures(data_dir: &Path, win: &Window) -> Result<Vec<AuthFailureRow>> {
    let placeholders = AUTH_FAILURE_EVENT_TYPES.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let where_clause = format!("event_type IN ({placeholders})");
    let params: Vec<String> = AUTH_FAILURE_EVENT_TYPES.iter().map(|s| s.to_string()).collect();

    let counts = digest_query::group_count_in_range(
        data_dir,
        win,
        &["src_ip", "_source_type", "event_type"],
        Some(&where_clause),
        &params,
    )?;

    let mut by_ip: BTreeMap<String, Vec<AuthFailureBySource>> = BTreeMap::new();
    for (key, count) in counts {
        let src_ip = key[0].clone();
        if src_ip.is_empty() {
            continue;
        }
        by_ip.entry(src_ip).or_default().push(AuthFailureBySource {
            source: key.get(1).cloned().unwrap_or_default(),
            event_type: key.get(2).cloned().unwrap_or_default(),
            count,
        });
    }

    let mut rows: Vec<AuthFailureRow> = by_ip
        .into_iter()
        .map(|(src_ip, by_source)| {
            let count = by_source.iter().map(|b| b.count).sum();
            AuthFailureRow { src_ip, count, by_source }
        })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count));
    Ok(rows)
}

fn successful_access(data_dir: &Path, win: &Window) -> Result<Vec<AccessEvent>> {
    let placeholders = SUCCESS_EVENT_TYPES.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let where_clause = format!("event_type IN ({placeholders})");
    let params: Vec<String> = SUCCESS_EVENT_TYPES.iter().map(|s| s.to_string()).collect();

    let rows = digest_query::select_rows_in_range(
        data_dir,
        win,
        &["raw_file", "src_ip", "username", "_source_type"],
        Some(&where_clause),
        &params,
    )?;

    let mut out: Vec<AccessEvent> = rows
        .into_iter()
        .map(|r| AccessEvent {
            timestamp: crate::time::parse_raw_file_time(&r[0]),
            src_ip: r[1].clone(),
            username: r[2].clone(),
            source: r[3].clone(),
        })
        .collect();
    out.sort_by_key(|e| e.timestamp);
    Ok(out)
}

fn sudo_events(data_dir: &Path, win: &Window) -> Result<Vec<SudoEvent>> {
    let rows = digest_query::select_rows_in_range(
        data_dir,
        win,
        &["raw_file", "username", "target_user", "command"],
        Some("_source_type = ? AND event_type = ?"),
        &["sudo".to_string(), "sudo_command".to_string()],
    )?;

    let mut out: Vec<SudoEvent> = rows
        .into_iter()
        .map(|r| SudoEvent {
            timestamp: crate::time::parse_raw_file_time(&r[0]),
            username: r[1].clone(),
            target_user: r[2].clone(),
            command: r[3].clone(),
        })
        .collect();
    out.sort_by_key(|e| e.timestamp);
    Ok(out)
}

// ── 5. Alerts ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AlertRuleCount {
    pub rule_id: String,
    pub rule_title: String,
    pub level: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct AlertsSection {
    pub total: u64,
    pub by_rule: Vec<AlertRuleCount>,
    pub first_time_rules: Vec<String>,
    pub concentration_warning: Option<String>,
}

/// Single pass over every `ruled` alert file ever written
/// (`data/alerts/**/*.jsonl`, excluding `data/alerts/correlated/` — see the
/// module doc comment): rows before `win.start` build the "seen before"
/// rule set, rows inside `win` build the counts. Cheap because alert volume
/// is inherently low (see `docs/design-digest-command.md`'s Implementation
/// Plan notes).
fn build_alerts(data_dir: &Path, win: &Window, cfg: &DigestConfig) -> Result<AlertsSection> {
    let alerts_root = data_dir.join("alerts");
    let start_ts = win.start.timestamp();
    let end_ts = win.end.timestamp();

    let mut by_rule: BTreeMap<String, AlertRuleCount> = BTreeMap::new();
    let mut total: u64 = 0;
    let mut rules_before_window: BTreeSet<String> = BTreeSet::new();

    for path in walk_alert_files(&alerts_root) {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        for line in content.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            let Some(rule_id) = v.get("rule_id").and_then(|x| x.as_str()) else { continue };
            let ts = v.get("timestamp").and_then(|x| x.as_i64()).unwrap_or(0);

            if ts < start_ts {
                rules_before_window.insert(rule_id.to_string());
                continue;
            }
            if ts >= end_ts {
                continue;
            }

            total += 1;
            let entry = by_rule.entry(rule_id.to_string()).or_insert_with(|| AlertRuleCount {
                rule_id: rule_id.to_string(),
                rule_title: v.get("rule_title").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                level: v.get("level").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                count: 0,
            });
            entry.count += 1;
        }
    }

    let mut rows: Vec<AlertRuleCount> = by_rule.into_values().collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.rule_id.cmp(&b.rule_id)));

    let first_time_rules: Vec<String> =
        rows.iter().map(|r| r.rule_id.clone()).filter(|id| !rules_before_window.contains(id)).collect();

    let concentration_warning = rows.first().and_then(|top| {
        if total == 0 {
            return None;
        }
        let pct = (top.count as f64 / total as f64) * 100.0;
        (pct > cfg.concentration_threshold_pct).then(|| {
            format!("rule '{}' accounts for {:.0}% of alerts this window", top.rule_id, pct)
        })
    });

    Ok(AlertsSection { total, by_rule: rows, first_time_rules, concentration_warning })
}

/// Every `*.jsonl` under `alerts_root`, excluding the `correlated/` subtree.
fn walk_alert_files(alerts_root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().map(|n| n == "correlated").unwrap_or(false) {
                    continue;
                }
                walk(&path, out);
            } else if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(alerts_root, &mut out);
    out
}

// ── 6. Notable events ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ConfigChange {
    pub timestamp: Option<DateTime<Utc>>,
    pub admin_user: String,
    pub src_ip: String,
    pub page: String,
}

#[derive(Debug, Serialize)]
pub struct ServiceRestart {
    pub unit: String,
    pub count: u64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// A cluster of `BOOT_STORM_MIN_UNITS`+ distinct units transitioning within
/// `BOOT_STORM_GAP_SECONDS` of each other — almost always one desktop
/// reboot/shutdown, not `unit_count` independent restarts worth separately
/// escalating. See [`collapse_boot_storms`].
#[derive(Debug, Serialize)]
pub struct BootStorm {
    pub unit_count: usize,
    pub units: Vec<String>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct CriticalEvent {
    pub timestamp: Option<DateTime<Utc>>,
    pub source: String,
    pub event_type: String,
    pub severity: String,
}

#[derive(Debug, Serialize)]
pub struct NotableSection {
    pub config_changes: Vec<ConfigChange>,
    /// Individual unit transitions *not* absorbed into a `boot_storms` entry.
    pub service_restarts: Vec<ServiceRestart>,
    /// Boot/shutdown storms collapsed out of `service_restarts` — see
    /// [`collapse_boot_storms`]. A Tier-1 agent should treat one storm as
    /// one event (a reboot), not `unit_count` events.
    pub boot_storms: Vec<BootStorm>,
    pub critical_events: Vec<CriticalEvent>,
}

pub fn build_notable(data_dir: &Path, win: &Window) -> Result<NotableSection> {
    let (service_restarts, boot_storms) = collapse_boot_storms(service_restarts(data_dir, win)?);
    Ok(NotableSection {
        config_changes: config_changes(data_dir, win)?,
        service_restarts,
        boot_storms,
        critical_events: critical_events(data_dir, win)?,
    })
}

/// Cluster `ServiceRestart` rows by `first_seen` proximity
/// (`BOOT_STORM_GAP_SECONDS`) and pull out any cluster of
/// `BOOT_STORM_MIN_UNITS`+ distinct units as a [`BootStorm`], leaving
/// everything else as individual rows.
///
/// Without this, one desktop reboot (dozens of units each transitioning
/// once — every row reads `"1x transition(s)"`, hence the name) floods the
/// Notable Events section with one line per unit, which a Tier-1 agent has
/// no way to distinguish from dozens of *independent* restarts worth
/// individually investigating.
fn collapse_boot_storms(mut rows: Vec<ServiceRestart>) -> (Vec<ServiceRestart>, Vec<BootStorm>) {
    // Rows without a first_seen can't be clustered — never entered a storm.
    let (mut clusterable, unclustered): (Vec<ServiceRestart>, Vec<ServiceRestart>) =
        rows.drain(..).partition(|r| r.first_seen.is_some());
    clusterable.sort_by_key(|r| r.first_seen);

    let mut kept = unclustered;
    let mut storms = Vec::new();
    let mut cluster: Vec<ServiceRestart> = Vec::new();

    let flush = |cluster: &mut Vec<ServiceRestart>, kept: &mut Vec<ServiceRestart>, storms: &mut Vec<BootStorm>| {
        if cluster.len() >= BOOT_STORM_MIN_UNITS {
            let first_seen = cluster.iter().filter_map(|r| r.first_seen).min();
            let last_seen = cluster.iter().filter_map(|r| r.last_seen).max();
            let mut units: Vec<String> = cluster.iter().map(|r| r.unit.clone()).collect();
            units.sort();
            storms.push(BootStorm { unit_count: cluster.len(), units, first_seen, last_seen });
        } else {
            kept.extend(cluster.drain(..));
        }
        cluster.clear();
    };

    for row in clusterable {
        if let Some(last) = cluster.last() {
            let gap = (row.first_seen.unwrap() - last.first_seen.unwrap()).num_seconds();
            if gap > BOOT_STORM_GAP_SECONDS {
                flush(&mut cluster, &mut kept, &mut storms);
            }
        }
        cluster.push(row);
    }
    flush(&mut cluster, &mut kept, &mut storms);

    kept.sort_by(|a, b| b.count.cmp(&a.count).then(a.unit.cmp(&b.unit)));
    storms.sort_by_key(|s| s.first_seen);
    (kept, storms)
}

fn config_changes(data_dir: &Path, win: &Window) -> Result<Vec<ConfigChange>> {
    let rows = digest_query::select_rows_in_range(
        data_dir,
        win,
        &["raw_file", "admin_user", "src_ip", "pfsense_page"],
        Some("event_type = ?"),
        &["pfsense_config_change".to_string()],
    )?;
    let mut out: Vec<ConfigChange> = rows
        .into_iter()
        .map(|r| ConfigChange {
            timestamp: crate::time::parse_raw_file_time(&r[0]),
            admin_user: r[1].clone(),
            src_ip: r[2].clone(),
            page: r[3].clone(),
        })
        .collect();
    out.sort_by_key(|c| c.timestamp);
    Ok(out)
}

fn service_restarts(data_dir: &Path, win: &Window) -> Result<Vec<ServiceRestart>> {
    let placeholders = SERVICE_TRANSITION_EVENT_TYPES.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let where_clause = format!("_source_type = ? AND event_type IN ({placeholders})");
    let mut params = vec!["systemd".to_string()];
    params.extend(SERVICE_TRANSITION_EVENT_TYPES.iter().map(|s| s.to_string()));

    let counts = digest_query::group_count_in_range(data_dir, win, &["unit"], Some(&where_clause), &params)?;

    let mut rows = Vec::new();
    for (key, count) in counts {
        let unit = key[0].clone();
        if unit.is_empty() {
            continue;
        }
        let unit_where = format!("{where_clause} AND unit = ?");
        let mut unit_params = params.clone();
        unit_params.push(unit.clone());
        let first_seen = digest_query::first_seen_in_range(data_dir, win, &unit_where, &unit_params)?;
        let last_seen = digest_query::last_seen_in_range(data_dir, win, &unit_where, &unit_params)?;
        rows.push(ServiceRestart { unit, count, first_seen, last_seen });
    }
    rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.unit.cmp(&b.unit)));
    Ok(rows)
}

fn critical_events(data_dir: &Path, win: &Window) -> Result<Vec<CriticalEvent>> {
    let rows = digest_query::select_rows_in_range(
        data_dir,
        win,
        &["raw_file", "_source_type", "event_type", "severity"],
        Some("severity = ? OR severity = ?"),
        &["critical".to_string(), "emergency".to_string()],
    )?;
    let mut out: Vec<CriticalEvent> = rows
        .into_iter()
        .map(|r| CriticalEvent {
            timestamp: crate::time::parse_raw_file_time(&r[0]),
            source: r[1].clone(),
            event_type: r[2].clone(),
            severity: r[3].clone(),
        })
        .collect();
    out.sort_by_key(|c| c.timestamp);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use rusqlite::Connection;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_CTR: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let n = TMP_CTR.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("hsiem_digest_test_{}_{}", std::process::id(), n));
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

    /// One bucket ("2026-06-29-14.db", the tests' window hour) with a
    /// representative row for every section this test module exercises,
    /// plus a lighter baseline bucket ("2026-06-29-08.db") for delta/gone-
    /// silent checks against `window_with_matching_baseline()` below.
    fn seed_fixture(data_dir: &Path) {
        let idx = data_dir.join("index");
        std::fs::create_dir_all(&idx).unwrap();

        let window_db = idx.join("2026-06-29-14.db");
        let conn = Connection::open(&window_db).unwrap();
        conn.execute_batch(
            "CREATE TABLE events (
                raw_file TEXT, _source_type TEXT, src_ip TEXT, src_port TEXT,
                protocol TEXT, action TEXT, interface TEXT, direction TEXT,
                dst_ip TEXT, dst_port TEXT, event_type TEXT, username TEXT,
                target_user TEXT, command TEXT, unit TEXT, admin_user TEXT,
                pfsense_page TEXT, severity TEXT
            );",
        )
        .unwrap();

        let insert = "INSERT INTO events (
            raw_file, _source_type, src_ip, protocol, action, interface, direction,
            dst_ip, dst_port, event_type, username, target_user, command, unit,
            admin_user, pfsense_page, severity
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)";

        let rows: &[[&str; 17]] = &[
            // sshd auth failure, two events from the same src_ip
            ["raw/2026/06/29/14/05/00/sshd.jsonl", "sshd", "203.0.113.5", "", "", "", "",
             "", "", "ssh_auth_failure", "", "", "", "", "", "", "warning"],
            ["raw/2026/06/29/14/06/00/sshd.jsonl", "sshd", "203.0.113.5", "", "", "", "",
             "", "", "ssh_auth_failure", "", "", "", "", "", "", "warning"],
            // openvpn: tls_error + auth_failure, same src_ip as an sshd failure to
            // exercise cross-source unification
            ["raw/2026/06/29/14/07/00/openvpn.jsonl", "openvpn", "203.0.113.5", "", "", "", "",
             "", "", "vpn_tls_error", "", "", "", "", "", "", "warning"],
            ["raw/2026/06/29/14/08/00/openvpn.jsonl", "openvpn", "203.0.113.5", "", "", "", "",
             "", "", "vpn_auth_failure", "", "", "", "", "", "", "warning"],
            // ssh success
            ["raw/2026/06/29/14/09/00/sshd.jsonl", "sshd", "192.168.1.50", "", "", "", "",
             "", "", "ssh_auth_success", "robin", "", "", "", "", "", "informational"],
            // filterlog: BLOCK from a noisy scanner, ALLOW inbound on WAN, new
            // outbound destination
            ["raw/2026/06/29/14/10/00/filterlog.jsonl", "filterlog", "198.51.100.9", "TCP", "BLOCK", "re1", "",
             "", "", "firewall_block", "", "", "", "", "", "", "informational"],
            ["raw/2026/06/29/14/11/00/filterlog.jsonl", "filterlog", "198.51.100.9", "TCP", "BLOCK", "re1", "",
             "", "", "firewall_block", "", "", "", "", "", "", "informational"],
            ["raw/2026/06/29/14/12/00/filterlog.jsonl", "filterlog", "217.103.119.242", "TCP", "ALLOW", "re1", "",
             "192.168.178.12", "8006", "firewall_allow", "", "", "", "", "", "", "informational"],
            ["raw/2026/06/29/14/13/00/filterlog.jsonl", "filterlog", "192.168.178.12", "TCP", "ALLOW", "lan", "out",
             "172.66.152.176", "80", "firewall_allow", "", "", "", "", "", "", "informational"],
            // systemd: sshguard unit restarted (stop then start)
            ["raw/2026/06/29/14/14/00/systemd.jsonl", "systemd", "", "", "", "", "",
             "", "", "unit_stopped", "", "", "", "sshguard.service", "", "", "informational"],
            ["raw/2026/06/29/14/14/30/systemd.jsonl", "systemd", "", "", "", "", "",
             "", "", "unit_started", "", "", "", "sshguard.service", "", "", "informational"],
            // sudo privilege escalation
            ["raw/2026/06/29/14/15/00/sudo.jsonl", "sudo", "", "", "", "", "",
             "", "", "sudo_command", "robin", "root", "nano /etc/x", "", "", "", "notice"],
            // pfsense config change
            ["raw/2026/06/29/14/16/00/php-fpm.jsonl", "php-fpm", "192.168.178.75", "", "", "", "",
             "", "", "pfsense_config_change", "", "", "", "", "admin", "/firewall_rules.php", "informational"],
            // a critical event
            ["raw/2026/06/29/14/17/00/haproxy.jsonl", "haproxy", "", "", "", "", "",
             "", "", "some_failure", "", "", "", "", "", "", "critical"],
        ];

        for r in rows {
            conn.execute(insert, rusqlite::params_from_iter(r.iter())).unwrap();
        }
        drop(conn);

        // Lighter baseline bucket: sshd present (so it's not "new"), openvpn
        // absent (so it's "new" in the window), filterlog present at a much
        // lower BLOCK volume, and a `suricata` source that goes silent in
        // the window.
        let baseline_db = idx.join("2026-06-29-08.db");
        let conn = Connection::open(&baseline_db).unwrap();
        conn.execute_batch(
            "CREATE TABLE events (
                raw_file TEXT, _source_type TEXT, src_ip TEXT, protocol TEXT,
                action TEXT, interface TEXT, direction TEXT, dst_ip TEXT, dst_port TEXT,
                event_type TEXT
            );",
        )
        .unwrap();
        let insert = "INSERT INTO events (
            raw_file, _source_type, src_ip, protocol, action, interface, direction, dst_ip, dst_port, event_type
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)";
        let baseline_rows: &[[&str; 10]] = &[
            ["raw/2026/06/29/08/05/00/sshd.jsonl", "sshd", "10.0.0.1", "", "", "", "", "", "", "ssh_auth_success"],
            ["raw/2026/06/29/08/06/00/filterlog.jsonl", "filterlog", "1.2.3.4", "TCP", "BLOCK", "re1", "", "", "", "firewall_block"],
            ["raw/2026/06/29/08/07/00/suricata.jsonl", "suricata", "", "", "", "", "", "", "", "alert"],
            // dst_ip that's also hit in the window -> not "new"
            ["raw/2026/06/29/08/08/00/filterlog.jsonl", "filterlog", "192.168.178.12", "TCP", "ALLOW", "lan", "out", "172.66.152.176", "80", "firewall_allow"],
        ];
        for r in baseline_rows {
            conn.execute(insert, rusqlite::params_from_iter(r.iter())).unwrap();
        }
    }

    fn window() -> Window {
        Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 15, 0, 0) }
    }

    // `build_*` functions derive their baseline via `win.baseline()`
    // (the window's own duration immediately preceding it), not an
    // independently-chosen bucket. This window's derived baseline
    // (08:00-09:00) lands exactly on the fixture's baseline bucket.
    fn window_with_matching_baseline() -> Window {
        Window { start: ymdhms(2026, 6, 29, 9, 0, 0), end: ymdhms(2026, 6, 29, 10, 0, 0) }
    }

    // ── coverage ─────────────────────────────────────────────────────────

    #[test]
    fn coverage_gone_silent_against_real_baseline() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);

        // window_with_matching_baseline() itself has no data, so every
        // source that reported in its baseline (08:00-09:00) is gone silent.
        let cov = build_coverage(
            &tmp.path,
            &window_with_matching_baseline(),
            &window_with_matching_baseline(),
            &DigestConfig::default(),
            false,
            false,
        )
        .unwrap();
        assert_eq!(cov.sources_reporting, 0);
        assert!(cov.gone_silent.contains(&"suricata".to_string()));
        assert!(cov.gone_silent.contains(&"sshd".to_string()));
        assert!(cov.gone_silent.contains(&"filterlog".to_string()));
        assert!(cov.new_sources.is_empty());
    }

    #[test]
    fn coverage_new_source_detected_against_adjacent_baseline() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);

        // window()'s derived baseline (13:00-14:00) is empty, so every
        // source present in the window bucket counts as "new".
        let cov = build_coverage(&tmp.path, &window(), &window(), &DigestConfig::default(), false, false).unwrap();
        assert!(cov.new_sources.contains(&"openvpn".to_string()));
        assert!(cov.new_sources.contains(&"sshd".to_string()));
        assert_eq!(cov.sources_reporting, cov.new_sources.len());
    }

    #[test]
    fn coverage_unparsed_high_volume_sources_from_raw_scan() {
        let tmp = TempDir::new();
        let win = window();

        // 51 unparsed lines from gnome-shell (over the default threshold of
        // 50), 3 from rtkit-daemon (under threshold, so excluded).
        let dir = tmp.path.join("raw/2026/06/29/14/20/00");
        std::fs::create_dir_all(&dir).unwrap();
        let gnome_lines: String = (0..51)
            .map(|_| r#"{"_normalized":false,"app_name":"gnome-shell","_raw":"x"}"#.to_string() + "\n")
            .collect();
        std::fs::write(dir.join("gnome-shell.jsonl"), gnome_lines).unwrap();
        let rtkit_lines: String = (0..3)
            .map(|_| r#"{"_normalized":false,"app_name":"rtkit-daemon","_raw":"x"}"#.to_string() + "\n")
            .collect();
        std::fs::write(dir.join("rtkit-daemon.jsonl"), rtkit_lines).unwrap();
        // A normalized event for a different app shouldn't count.
        std::fs::write(
            dir.join("sshd.jsonl"),
            "{\"_normalized\":true,\"app_name\":\"sshd\",\"event_type\":\"ssh_auth_success\"}\n",
        )
        .unwrap();

        let cov = build_coverage(&tmp.path, &win, &win, &DigestConfig::default(), false, false).unwrap();
        assert_eq!(cov.unparsed_high_volume.len(), 1);
        assert_eq!(cov.unparsed_high_volume[0].app_name, "gnome-shell");
        assert_eq!(cov.unparsed_high_volume[0].count, 51);
    }

    #[test]
    fn coverage_index_lag_computed_from_latest_raw_vs_indexed() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);
        // Latest indexed event (from seed_fixture) is 14:17:00. Add a raw
        // file 10 minutes later that hasn't been indexed yet.
        let dir = tmp.path.join("raw/2026/06/29/14/27/00");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sshd.jsonl"), "{}\n").unwrap();

        let cov = build_coverage(&tmp.path, &window(), &window(), &DigestConfig::default(), false, false).unwrap();
        assert_eq!(cov.latest_raw, Some(ymdhms(2026, 6, 29, 14, 27, 0)));
        assert_eq!(cov.latest_indexed, Some(ymdhms(2026, 6, 29, 14, 17, 0)));
        assert_eq!(cov.index_lag_seconds, Some(600));
    }

    #[test]
    fn coverage_flags_incomplete_bucket_lag_check_alone_would_miss() {
        let tmp = TempDir::new();
        // No index/ dir at all — deliberately not using seed_fixture here:
        // its rows are inserted directly into the DB with no matching raw
        // files, and completeness compares per-bucket *totals*, so those
        // phantom rows would mask the very gap this test wants to prove is
        // caught. latest_raw/latest_indexed (the existing lag check) would
        // report "no index yet" here — proving completeness is a genuinely
        // independent signal, not a side effect of the lag check, since it
        // still needs to name the exact bucket and counts.
        let dir = tmp.path.join("raw/2026/06/29/14/50/00");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sshd.jsonl"), "{}\n{}\n{}\n").unwrap();

        let cov = build_coverage(&tmp.path, &window(), &window(), &DigestConfig::default(), false, false).unwrap();
        assert_eq!(cov.incomplete_buckets.len(), 1);
        assert_eq!(cov.incomplete_buckets[0].bucket, "2026-06-29-14");
        assert_eq!(cov.incomplete_buckets[0].raw_count, 3);
        assert_eq!(cov.incomplete_buckets[0].indexed_count, 0);
    }

    #[test]
    fn coverage_completeness_empty_when_nothing_written_to_raw() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);
        // seed_fixture only writes index rows, no raw files — completeness
        // has nothing to compare against, so it must not false-positive.
        let cov = build_coverage(&tmp.path, &window(), &window(), &DigestConfig::default(), false, false).unwrap();
        assert!(cov.incomplete_buckets.is_empty());
    }

    #[test]
    fn coverage_cold_start_suppresses_new_sources_but_reports_it() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);
        // Passing coverage_cold_start=true directly (the flag build_report
        // would compute when the coverage lookback window's own baseline
        // predates the earliest raw event) — every source in the window
        // would otherwise show up in new_sources per
        // coverage_new_source_detected_against_adjacent_baseline.
        let cov = build_coverage(&tmp.path, &window(), &window(), &DigestConfig::default(), false, true).unwrap();
        assert!(cov.coverage_cold_start);
        assert!(cov.new_sources.is_empty(), "cold start must suppress new_sources, not flood it");
    }

    #[test]
    fn coverage_long_lookback_absorbs_a_sub_daily_source_missing_the_short_window() {
        // The live bug this feature exists for: a source that only logs
        // once a day (corosync/pmxcfs) fires outside `win` itself but well
        // within a 24h coverage lookback ending at `win.end` — it must show
        // up in neither `gone_silent` nor `new_sources`, even though `win`
        // alone (14:00-15:00) never sees it and `sources_reporting` (which
        // still describes `win` alone) stays 0.
        let tmp = TempDir::new();
        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();

        let today = idx.join("2026-06-29-03.db");
        let conn = Connection::open(&today).unwrap();
        conn.execute_batch("CREATE TABLE events (raw_file TEXT, _source_type TEXT);").unwrap();
        conn.execute(
            "INSERT INTO events VALUES ('raw/2026/06/29/03/00/00/corosync.jsonl', 'corosync')",
            [],
        )
        .unwrap();
        drop(conn);
        // Also present the day before, so it's not "new" in the coverage
        // window either — a genuinely steady sub-daily source, not a
        // one-off.
        let yesterday = idx.join("2026-06-28-03.db");
        let conn = Connection::open(&yesterday).unwrap();
        conn.execute_batch("CREATE TABLE events (raw_file TEXT, _source_type TEXT);").unwrap();
        conn.execute(
            "INSERT INTO events VALUES ('raw/2026/06/28/03/00/00/corosync.jsonl', 'corosync')",
            [],
        )
        .unwrap();
        drop(conn);

        let win = window();
        let coverage_window = win.lookback(Duration::hours(24));
        let cov =
            build_coverage(&tmp.path, &win, &coverage_window, &DigestConfig::default(), false, false)
                .unwrap();

        assert_eq!(cov.sources_reporting, 0, "win alone never sees corosync's 03:00 event");
        assert!(
            !cov.gone_silent.contains(&"corosync".to_string()),
            "a sub-daily source within the lookback must not flap as gone-silent"
        );
        assert!(
            !cov.new_sources.contains(&"corosync".to_string()),
            "a source seen in the coverage baseline too must not be flagged new"
        );
    }

    #[test]
    fn build_report_coverage_cold_start_is_independent_of_the_short_window_cold_start() {
        let tmp = TempDir::new();
        // Earliest data at 12:00 comfortably covers window()'s short
        // baseline (13:00-14:00) — the short `cold_start` is false. But the
        // coverage lookback's own baseline (the 24h immediately before the
        // 24h coverage window, i.e. 06-27T15:00-06-28T15:00) is entirely
        // before this data — `coverage_cold_start` must independently
        // still be true. Proves the two checks use their own baseline, not
        // one bool shared across windows (see `build_report`'s doc
        // comment on `cold_start_for_baseline`).
        std::fs::create_dir_all(tmp.path.join("raw/2026/06/29/12/00/00")).unwrap();
        std::fs::write(
            tmp.path.join("raw/2026/06/29/12/00/00/sshd.jsonl"),
            "{\"timestamp\":\"2026-06-29T12:00:00Z\",\"_source_type\":\"sshd\"}\n",
        )
        .unwrap();

        let report =
            build_report(&tmp.path, &window(), &DigestConfig::default(), Duration::minutes(10)).unwrap();
        assert!(!report.coverage.cold_start, "short window baseline is well covered");
        assert!(report.coverage.coverage_cold_start, "24h lookback baseline predates any real data");
    }

    #[test]
    fn build_report_detects_cold_start_from_earliest_raw_event() {
        let tmp = TempDir::new();
        // Exercises the short-window check (`report.coverage.cold_start`,
        // against `win.baseline()`) — see
        // `build_report_coverage_cold_start_is_independent_of_the_short_window_cold_start`
        // below for the long-lookback equivalent (`coverage_cold_start`).
        //
        // Earliest data on disk starts at 14:00 on the window's own day —
        // window()'s baseline (13:00-14:00) predates that, so this is a
        // genuine cold start: there's no real prior period on disk yet.
        std::fs::create_dir_all(tmp.path.join("raw/2026/06/29/14/00/00")).unwrap();
        std::fs::write(
            tmp.path.join("raw/2026/06/29/14/00/00/sshd.jsonl"),
            "{\"timestamp\":\"2026-06-29T14:00:00Z\",\"_source_type\":\"sshd\"}\n",
        )
        .unwrap();

        let report =
            build_report(&tmp.path, &window(), &DigestConfig::default(), Duration::minutes(10))
                .unwrap();
        assert!(report.coverage.cold_start);
    }

    #[test]
    fn build_report_not_cold_start_once_history_covers_the_baseline() {
        let tmp = TempDir::new();
        // Earliest data predates the baseline window entirely — a real,
        // fully-populated prior period exists.
        std::fs::create_dir_all(tmp.path.join("raw/2026/06/20/00/00/00")).unwrap();
        std::fs::write(
            tmp.path.join("raw/2026/06/20/00/00/00/sshd.jsonl"),
            "{\"timestamp\":\"2026-06-20T00:00:00Z\",\"_source_type\":\"sshd\"}\n",
        )
        .unwrap();

        let report =
            build_report(&tmp.path, &window(), &DigestConfig::default(), Duration::minutes(10))
                .unwrap();
        assert!(!report.coverage.cold_start);
    }

    #[test]
    fn build_report_not_cold_start_with_partial_but_substantial_baseline_coverage() {
        // Regression case: window()'s baseline is 13:00-14:00 (1h). Data
        // starts at 13:10, i.e. the baseline window is missing its first 10
        // minutes but has 50 real minutes (83% coverage) — nowhere near
        // cold-start territory, even though the naive "does data exist
        // exactly at baseline.start" check used to false-positive on
        // exactly this shape (see test-siemctl-digest.sh's fixture, which
        // starts baseline data at 13:10 for the same reason).
        let tmp = TempDir::new();
        std::fs::create_dir_all(tmp.path.join("raw/2026/06/29/13/10/00")).unwrap();
        std::fs::write(
            tmp.path.join("raw/2026/06/29/13/10/00/sshd.jsonl"),
            "{\"timestamp\":\"2026-06-29T13:10:00Z\",\"_source_type\":\"sshd\"}\n",
        )
        .unwrap();

        let report =
            build_report(&tmp.path, &window(), &DigestConfig::default(), Duration::minutes(10))
                .unwrap();
        assert!(!report.coverage.cold_start);
    }

    #[test]
    fn build_report_cold_start_with_only_a_sliver_of_baseline_coverage() {
        // The live bug this whole feature exists for: earliest data lands
        // in just the last few minutes of a much longer baseline window
        // (a 72h digest run 3 days into collection) — under the coverage
        // floor (50%), so still a cold start despite *some* overlap.
        let tmp = TempDir::new();
        std::fs::create_dir_all(tmp.path.join("raw/2026/06/29/13/55/00")).unwrap();
        std::fs::write(
            tmp.path.join("raw/2026/06/29/13/55/00/sshd.jsonl"),
            "{\"timestamp\":\"2026-06-29T13:55:00Z\",\"_source_type\":\"sshd\"}\n",
        )
        .unwrap();

        // Only the last 5 of 60 baseline minutes (~8%) have any data —
        // under the coverage floor.
        let report =
            build_report(&tmp.path, &window(), &DigestConfig::default(), Duration::minutes(10))
                .unwrap();
        assert!(report.coverage.cold_start);
    }

    // ── volume ───────────────────────────────────────────────────────────

    #[test]
    fn volume_flags_new_source_and_computes_delta() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);

        let rows = build_volume(&tmp.path, &window(), &DigestConfig::default(), false).unwrap();
        let sshd = rows.iter().find(|r| r.source == "sshd").unwrap();
        assert_eq!(sshd.baseline, 0);
        assert_eq!(sshd.flag.as_deref(), Some("new"));
        assert_eq!(sshd.delta_pct, None);
    }

    #[test]
    fn volume_cold_start_suppresses_new_flag() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);

        let rows = build_volume(&tmp.path, &window(), &DigestConfig::default(), true).unwrap();
        let sshd = rows.iter().find(|r| r.source == "sshd").unwrap();
        assert_eq!(sshd.baseline, 0);
        assert_eq!(sshd.flag, None, "cold start must suppress the 'new' flag even though baseline is 0");
    }

    #[test]
    fn volume_new_source_flag_suppressed_when_disabled() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);

        let cfg = DigestConfig { new_source_always_flag: false, ..DigestConfig::default() };
        let rows = build_volume(&tmp.path, &window(), &cfg, false).unwrap();
        let sshd = rows.iter().find(|r| r.source == "sshd").unwrap();
        assert_eq!(sshd.baseline, 0);
        assert_eq!(sshd.flag, None);
    }

    #[test]
    fn network_new_destination_flag_suppressed_when_disabled() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);

        let cfg = DigestConfig { new_destination_always_flag: false, ..DigestConfig::default() };
        let net = build_network_with_interval(&tmp.path, &window(), &cfg, Duration::minutes(10)).unwrap();
        assert!(net.new_destinations.is_empty());
    }

    #[test]
    fn volume_flags_spike_over_threshold() {
        let tmp = TempDir::new();
        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();

        let win_db = idx.join("2026-06-29-20.db");
        let conn = Connection::open(&win_db).unwrap();
        conn.execute_batch("CREATE TABLE events (raw_file TEXT, _source_type TEXT);").unwrap();
        for i in 0..9 {
            conn.execute(
                "INSERT INTO events VALUES (?1, 'openvpn')",
                [format!("raw/2026/06/29/20/{:02}/00/openvpn.jsonl", i)],
            )
            .unwrap();
        }
        drop(conn);
        let base_db = idx.join("2026-06-29-19.db");
        let conn = Connection::open(&base_db).unwrap();
        conn.execute_batch("CREATE TABLE events (raw_file TEXT, _source_type TEXT);").unwrap();
        conn.execute(
            "INSERT INTO events VALUES ('raw/2026/06/29/19/05/00/openvpn.jsonl', 'openvpn')",
            [],
        )
        .unwrap();
        drop(conn);

        let win = Window { start: ymdhms(2026, 6, 29, 20, 0, 0), end: ymdhms(2026, 6, 29, 21, 0, 0) };
        let rows = build_volume(&tmp.path, &win, &DigestConfig::default(), false).unwrap();
        let openvpn = rows.iter().find(|r| r.source == "openvpn").unwrap();
        assert_eq!(openvpn.count, 9);
        assert_eq!(openvpn.baseline, 1);
        assert_eq!(openvpn.delta_pct, Some(800.0));
        assert_eq!(openvpn.flag.as_deref(), Some("spike"));
    }

    #[test]
    fn volume_flags_drop_not_spike_when_source_goes_silent() {
        let tmp = TempDir::new();
        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();

        // Window has zero events for this source; baseline had some — a
        // total silence, not a volume increase, so it must not be labeled
        // "spike" (see ticket tuner-dev/20260711T175421.845).
        let win_db = idx.join("2026-06-29-20.db");
        let conn = Connection::open(&win_db).unwrap();
        conn.execute_batch("CREATE TABLE events (raw_file TEXT, _source_type TEXT);").unwrap();
        drop(conn);
        let base_db = idx.join("2026-06-29-19.db");
        let conn = Connection::open(&base_db).unwrap();
        conn.execute_batch("CREATE TABLE events (raw_file TEXT, _source_type TEXT);").unwrap();
        for i in 0..2 {
            conn.execute(
                "INSERT INTO events VALUES (?1, 'anacron')",
                [format!("raw/2026/06/29/19/{:02}/00/anacron.jsonl", i)],
            )
            .unwrap();
        }
        drop(conn);

        let win = Window { start: ymdhms(2026, 6, 29, 20, 0, 0), end: ymdhms(2026, 6, 29, 21, 0, 0) };
        let rows = build_volume(&tmp.path, &win, &DigestConfig::default(), false).unwrap();
        let anacron = rows.iter().find(|r| r.source == "anacron").unwrap();
        assert_eq!(anacron.count, 0);
        assert_eq!(anacron.baseline, 2);
        assert_eq!(anacron.delta_pct, Some(-100.0));
        assert_eq!(anacron.flag.as_deref(), Some("drop"));
    }

    // ── network ──────────────────────────────────────────────────────────

    #[test]
    fn network_top_blocked_and_inbound_and_new_destination() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);

        let net = build_network_with_interval(&tmp.path, &window(), &DigestConfig::default(), Duration::minutes(10)).unwrap();

        assert_eq!(net.top_blocked.len(), 1);
        assert_eq!(net.top_blocked[0].src_ip, "198.51.100.9");
        assert_eq!(net.top_blocked[0].count, 2);

        assert_eq!(net.inbound.len(), 1);
        assert_eq!(net.inbound[0].src_ip, "217.103.119.242");
        assert_eq!(net.inbound[0].dst_ip, "192.168.178.12");
        assert_eq!(net.inbound[0].dst_port, "8006");

        // window()'s derived baseline (13:00-14:00) is empty, so
        // 172.66.152.176 shows as new here even though it also appears in
        // the fixture's *other* baseline bucket (08:00) — see the next test
        // for the case where the baseline actually reaches that bucket.
        assert_eq!(net.new_destinations.len(), 1);
        assert_eq!(net.new_destinations[0].dst_ip, "172.66.152.176");
        assert_eq!(net.new_destinations[0].first_seen, Some(ymdhms(2026, 6, 29, 14, 13, 0)));
    }

    #[test]
    fn network_new_destination_excluded_when_seen_in_baseline() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);

        // window_with_matching_baseline()'s derived baseline is the
        // fixture's real 08:00-09:00 bucket, which already contains
        // 172.66.152.176. The window itself has no filterlog rows, so
        // new_destinations must be empty (nothing to report, not
        // "everything is new").
        let net =
            build_network_with_interval(&tmp.path, &window_with_matching_baseline(), &DigestConfig::default(), Duration::minutes(10)).unwrap();
        assert!(net.new_destinations.is_empty());
    }

    #[test]
    fn network_block_trend_sums_to_total_blocks() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);

        let net = build_network_with_interval(&tmp.path, &window(), &DigestConfig::default(), Duration::minutes(10)).unwrap();
        let total: u64 = net.block_trend.iter().sum();
        assert_eq!(total, 2); // the two 198.51.100.9 BLOCK rows
    }

    // ── auth ─────────────────────────────────────────────────────────────

    #[test]
    fn auth_failures_unified_across_sources_by_src_ip() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);

        let auth = build_auth(&tmp.path, &window()).unwrap();
        assert_eq!(auth.failures.len(), 1);
        let row = &auth.failures[0];
        assert_eq!(row.src_ip, "203.0.113.5");
        assert_eq!(row.count, 4); // 2 sshd + 1 tls_error + 1 auth_failure
        // Grouped by (source, event_type), not just source — the doc's own
        // example ("openvpn (tls_error x123, auth_failure x145)") shows two
        // separate counts for the same source, so ssh_auth_failure (x2),
        // vpn_tls_error (x1), vpn_auth_failure (x1) are three distinct rows.
        assert_eq!(row.by_source.len(), 3);
        let sshd_failures: u64 =
            row.by_source.iter().filter(|b| b.source == "sshd").map(|b| b.count).sum();
        let openvpn_failures: u64 =
            row.by_source.iter().filter(|b| b.source == "openvpn").map(|b| b.count).sum();
        assert_eq!(sshd_failures, 2);
        assert_eq!(openvpn_failures, 2);
    }

    #[test]
    fn auth_successes_and_sudo_events_carry_timestamps() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);

        let auth = build_auth(&tmp.path, &window()).unwrap();
        assert_eq!(auth.successes.len(), 1);
        assert_eq!(auth.successes[0].username, "robin");
        assert_eq!(auth.successes[0].timestamp, Some(ymdhms(2026, 6, 29, 14, 9, 0)));

        assert_eq!(auth.sudo.len(), 1);
        assert_eq!(auth.sudo[0].command, "nano /etc/x");
        assert_eq!(auth.sudo[0].target_user, "root");
        assert_eq!(auth.sudo[0].timestamp, Some(ymdhms(2026, 6, 29, 14, 15, 0)));
    }

    // ── notable ──────────────────────────────────────────────────────────

    #[test]
    fn notable_config_change_and_critical_event_and_restart() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);

        let notable = build_notable(&tmp.path, &window()).unwrap();

        assert_eq!(notable.config_changes.len(), 1);
        assert_eq!(notable.config_changes[0].admin_user, "admin");
        assert_eq!(notable.config_changes[0].page, "/firewall_rules.php");

        assert_eq!(notable.critical_events.len(), 1);
        assert_eq!(notable.critical_events[0].source, "haproxy");
        assert_eq!(notable.critical_events[0].severity, "critical");

        assert_eq!(notable.service_restarts.len(), 1);
        let restart = &notable.service_restarts[0];
        assert_eq!(restart.unit, "sshguard.service");
        assert_eq!(restart.count, 2);
        assert_eq!(restart.first_seen, Some(ymdhms(2026, 6, 29, 14, 14, 0)));
        assert_eq!(restart.last_seen, Some(ymdhms(2026, 6, 29, 14, 14, 30)));
    }

    // ── boot storm collapsing ───────────────────────────────────────────────

    fn restart_row(unit: &str, seen: DateTime<Utc>) -> ServiceRestart {
        ServiceRestart { unit: unit.to_string(), count: 1, first_seen: Some(seen), last_seen: Some(seen) }
    }

    #[test]
    fn collapse_boot_storms_leaves_a_few_units_uncollapsed() {
        // Below BOOT_STORM_MIN_UNITS (5) — a couple of units restarting
        // close together is normal noise, not a reboot.
        let rows = vec![
            restart_row("sshguard.service", ymdhms(2026, 6, 29, 3, 0, 0)),
            restart_row("cron.service", ymdhms(2026, 6, 29, 3, 0, 5)),
            restart_row("dbus.service", ymdhms(2026, 6, 29, 3, 0, 9)),
        ];
        let (kept, storms) = collapse_boot_storms(rows);
        assert_eq!(kept.len(), 3);
        assert!(storms.is_empty());
    }

    #[test]
    fn collapse_boot_storms_collapses_a_tight_burst() {
        // >= BOOT_STORM_MIN_UNITS transitioning within BOOT_STORM_GAP_SECONDS
        // of each other — a reboot, per the live 03:00 shakedown finding.
        let units = ["NetworkManager", "sshd", "cron", "dbus", "systemd-logind", "cups"];
        let rows: Vec<ServiceRestart> = units
            .iter()
            .enumerate()
            .map(|(i, u)| restart_row(u, ymdhms(2026, 6, 29, 3, 0, i as u32 * 3)))
            .collect();

        let (kept, storms) = collapse_boot_storms(rows);
        assert!(kept.is_empty(), "all 6 units should be absorbed into the storm");
        assert_eq!(storms.len(), 1);
        assert_eq!(storms[0].unit_count, 6);
        assert_eq!(storms[0].first_seen, Some(ymdhms(2026, 6, 29, 3, 0, 0)));
        assert_eq!(storms[0].last_seen, Some(ymdhms(2026, 6, 29, 3, 0, 15)));
        for u in units {
            assert!(storms[0].units.contains(&u.to_string()));
        }
    }

    #[test]
    fn collapse_boot_storms_does_not_merge_across_a_large_gap() {
        // Two separate 5-unit bursts 20 minutes apart (e.g. a reboot, then
        // later a batch config-reload) — two storms, not one spanning both.
        let mut rows: Vec<ServiceRestart> = (0..5)
            .map(|i| restart_row(&format!("a{i}"), ymdhms(2026, 6, 29, 3, 0, i * 2)))
            .collect();
        rows.extend((0..5).map(|i| restart_row(&format!("b{i}"), ymdhms(2026, 6, 29, 3, 20, i * 2))));

        let (kept, storms) = collapse_boot_storms(rows);
        assert!(kept.is_empty());
        assert_eq!(storms.len(), 2, "a 20-minute gap must not merge into one storm");
    }

    #[test]
    fn collapse_boot_storms_mixed_leaves_non_storm_units_individually_listed() {
        // A 5-unit reboot burst at 03:00, plus one unrelated unit restart
        // at 09:00 — the storm collapses, the lone restart stays visible.
        let mut rows: Vec<ServiceRestart> = (0..5)
            .map(|i| restart_row(&format!("boot{i}"), ymdhms(2026, 6, 29, 3, 0, i * 2)))
            .collect();
        rows.push(restart_row("haproxy.service", ymdhms(2026, 6, 29, 9, 0, 0)));

        let (kept, storms) = collapse_boot_storms(rows);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].unit, "haproxy.service");
        assert_eq!(storms.len(), 1);
        assert_eq!(storms[0].unit_count, 5);
    }

    #[test]
    fn collapse_boot_storms_rows_without_first_seen_are_never_clustered() {
        let rows = vec![ServiceRestart {
            unit: "mystery.service".to_string(),
            count: 1,
            first_seen: None,
            last_seen: None,
        }];
        let (kept, storms) = collapse_boot_storms(rows);
        assert_eq!(kept.len(), 1);
        assert!(storms.is_empty());
    }

    #[test]
    fn build_notable_surfaces_boot_storm_from_real_events() {
        let tmp = TempDir::new();
        let idx = tmp.path.join("index");
        std::fs::create_dir_all(&idx).unwrap();
        let db = idx.join("2026-06-29-03.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE events (raw_file TEXT, _source_type TEXT, event_type TEXT, unit TEXT);",
        )
        .unwrap();
        let insert =
            "INSERT INTO events (raw_file, _source_type, event_type, unit) VALUES (?1,?2,?3,?4)";
        let units = ["a.service", "b.service", "c.service", "d.service", "e.service", "f.service"];
        for (i, u) in units.iter().enumerate() {
            conn.execute(
                insert,
                rusqlite::params![
                    format!("raw/2026/06/29/03/00/{:02}/systemd.jsonl", i),
                    "systemd",
                    "unit_started",
                    u,
                ],
            )
            .unwrap();
        }
        drop(conn);

        let win = Window { start: ymdhms(2026, 6, 29, 3, 0, 0), end: ymdhms(2026, 6, 29, 4, 0, 0) };
        let notable = build_notable(&tmp.path, &win).unwrap();
        assert_eq!(notable.boot_storms.len(), 1);
        assert_eq!(notable.boot_storms[0].unit_count, 6);
        assert!(notable.service_restarts.is_empty());
    }

    // ── alerts ───────────────────────────────────────────────────────────

    fn write_alert(dir: &Path, filename: &str, rule_id: &str, level: &str, ts: i64) {
        std::fs::create_dir_all(dir).unwrap();
        let line = serde_json::json!({
            "_ruled": true,
            "rule_id": rule_id,
            "rule_title": format!("Title for {rule_id}"),
            "level": level,
            "event": {},
            "timestamp": ts,
        });
        std::fs::write(dir.join(filename), format!("{}\n", line)).unwrap();
    }

    #[test]
    fn alerts_counts_first_time_rule_and_concentration() {
        let tmp = TempDir::new();
        let win = window();
        let start_ts = win.start.timestamp();

        // Before the window: "known-rule" has fired before.
        write_alert(
            &tmp.path.join("alerts/2026/06/29/08"),
            "alerts.jsonl",
            "known-rule",
            "low",
            start_ts - 3600,
        );

        // In the window: "known-rule" fires once, "new-rule" fires 9 times
        // (concentration: 9/10 = 90%, comfortably over the 80% default).
        let alert_dir = tmp.path.join("alerts/2026/06/29/14");
        std::fs::create_dir_all(&alert_dir).unwrap();
        let mut lines = String::new();
        lines += &format!(
            "{}\n",
            serde_json::json!({"rule_id":"known-rule","rule_title":"Known","level":"low","event":{},"timestamp":start_ts+60})
        );
        for i in 0..9 {
            lines += &format!(
                "{}\n",
                serde_json::json!({"rule_id":"new-rule","rule_title":"New","level":"medium","event":{},"timestamp":start_ts+120+i})
            );
        }
        std::fs::write(alert_dir.join("alerts.jsonl"), lines).unwrap();

        // An alert under alerts/correlated/ must be ignored entirely.
        write_alert(
            &tmp.path.join("alerts/correlated/2026/06/29/14"),
            "correlated.jsonl",
            "should-be-ignored",
            "high",
            start_ts + 60,
        );

        let alerts = build_alerts(&tmp.path, &win, &DigestConfig::default()).unwrap();
        assert_eq!(alerts.total, 10);
        assert_eq!(alerts.by_rule.len(), 2);
        assert_eq!(alerts.first_time_rules, vec!["new-rule".to_string()]);
        assert!(alerts.concentration_warning.is_some());
        assert!(alerts.concentration_warning.as_ref().unwrap().contains("new-rule"));
    }

    #[test]
    fn alerts_empty_when_no_alert_files() {
        let tmp = TempDir::new();
        let alerts = build_alerts(&tmp.path, &window(), &DigestConfig::default()).unwrap();
        assert_eq!(alerts.total, 0);
        assert!(alerts.by_rule.is_empty());
        assert!(alerts.first_time_rules.is_empty());
        assert!(alerts.concentration_warning.is_none());
    }

    // ── build_report ─────────────────────────────────────────────────────

    #[test]
    fn build_report_assembles_all_sections_with_baseline_window_info() {
        let tmp = TempDir::new();
        seed_fixture(&tmp.path);

        let report =
            build_report(&tmp.path, &window(), &DigestConfig::default(), Duration::minutes(10)).unwrap();
        assert_eq!(report.window.start, ymdhms(2026, 6, 29, 14, 0, 0));
        assert_eq!(report.window.end, ymdhms(2026, 6, 29, 15, 0, 0));
        assert_eq!(report.window.baseline_start, ymdhms(2026, 6, 29, 13, 0, 0));
        assert_eq!(report.window.baseline_end, ymdhms(2026, 6, 29, 14, 0, 0));
        assert!(!report.volume.is_empty());
        assert!(!report.auth.failures.is_empty());
    }
}

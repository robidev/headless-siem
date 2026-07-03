//! Text and JSON rendering for `siemctl digest`. Both consume the same
//! [`crate::digest::DigestReport`] built by `digest.rs` — no formatting
//! decision duplicated between the two.
//!
//! `render_json` is close to free: `DigestReport` and everything under it
//! already `#[derive(Serialize)]` with field names matching the design
//! doc's documented JSON schema, so this is a direct serialization, not a
//! hand-built structure.
//!
//! `render_text` reproduces the design doc's section mockups closely but
//! not literally byte-for-byte — a few of the doc's illustrative lines
//! imply cross-referencing data this command doesn't have:
//! - "Config changes" shows a human label ("— Suricata configuration") where
//!   this renders the raw `pfsense_page` path instead; no page → label
//!   mapping exists.
//! - "Service restarts" shows `rsyslog restarted (user via sudo)`, which
//!   would mean correlating a `sudo` command's text against a systemd
//!   event — a second correlation this command doesn't attempt. Only actual
//!   systemd unit start/stop/fail transitions are rendered.
//! - "Alert concentration"'s gap-detection aside ("suricata has 1,651 raw
//!   events — check suppression config") needs a rule_id → source mapping
//!   that isn't available from alert records alone (that lives in each
//!   Sigma rule's `logsource`, a `ruled`-side concept) — not implemented.

use chrono::{DateTime, Duration, Utc};

use crate::digest::*;
use crate::fmt_n;

const SPARK_CHARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

pub fn render_json(report: &DigestReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

pub fn render_text(report: &DigestReport, cfg: &DigestConfig, interval: Duration) -> String {
    let mut out = String::new();
    render_coverage(&mut out, report);
    render_volume(&mut out, report);
    render_network(&mut out, report, cfg, interval);
    render_auth(&mut out, report);
    render_alerts(&mut out, report);
    render_notable(&mut out, report);
    out
}

fn fmt_hm(t: DateTime<Utc>) -> String {
    t.format("%H:%M").to_string()
}

fn fmt_hms(t: DateTime<Utc>) -> String {
    t.format("%H:%M:%S").to_string()
}

fn fmt_opt_hm(t: Option<DateTime<Utc>>) -> String {
    t.map(fmt_hm).unwrap_or_else(|| "?".to_string())
}

fn fmt_opt_hms(t: Option<DateTime<Utc>>) -> String {
    t.map(fmt_hms).unwrap_or_else(|| "?".to_string())
}

/// Human label for a `chrono::Duration` used only as a bucket-size caption
/// (e.g. `10min`, `1h`) — mirrors `time::parse_duration`'s units, largest
/// unit that divides evenly wins so "1h" reads better than "60min".
fn fmt_duration_label(d: Duration) -> String {
    let secs = d.num_seconds();
    if secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 {
        format!("{}min", secs / 60)
    } else {
        format!("{secs}s")
    }
}

fn list_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "\u{2014} (none)".to_string()
    } else {
        items.join(", ")
    }
}

// ── 1. Coverage ──────────────────────────────────────────────────────────

fn render_coverage(out: &mut String, report: &DigestReport) {
    let w = &report.window;
    let cov = &report.coverage;
    out.push_str(&format!("=== COVERAGE ({} \u{2013} {}) ===\n\n", fmt_hm(w.start), fmt_hm(w.end)));
    out.push_str(&format!("Sources reporting:     {}\n", cov.sources_reporting));
    out.push_str(&format!("Sources gone silent:   {}\n", list_or_none(&cov.gone_silent)));
    if cov.new_sources.is_empty() {
        out.push_str("New sources:           \u{2014} (none)\n");
    } else {
        out.push_str(&format!(
            "New sources:           {}  (first seen this window)\n",
            cov.new_sources.join(", ")
        ));
    }
    out.push('\n');

    out.push_str("Unparsed high-volume sources (>threshold events, _normalized: false):\n");
    if cov.unparsed_high_volume.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for u in &cov.unparsed_high_volume {
            out.push_str(&format!("  {:<15} {:>5} events\n", u.app_name, u.count));
        }
    }
    out.push('\n');

    let coverage_state = match (cov.latest_raw, cov.index_lag_seconds) {
        (Some(_), Some(lag)) if lag <= 300 => "current".to_string(),
        (Some(_), Some(lag)) => format!("LAGGING by {}s", lag),
        (Some(_), None) => "unknown (no index yet)".to_string(),
        (None, _) => "unknown (no raw data)".to_string(),
    };
    out.push_str(&format!(
        "Index coverage:        {} (latest raw: {}, latest bucket: {})\n",
        coverage_state,
        fmt_opt_hm(cov.latest_raw),
        fmt_opt_hm(cov.latest_indexed),
    ));

    // "current" above only compares the newest timestamp on each side — it
    // cannot see a gap in the middle of the range. This is that check:
    // per-bucket raw-line-count vs indexed-row-count, independent of lag.
    if cov.incomplete_buckets.is_empty() {
        out.push_str("Index completeness:    complete (raw line counts match indexed row counts)\n\n");
    } else {
        out.push_str("Index completeness:    INCOMPLETE — raw events exist that were never indexed:\n");
        for b in &cov.incomplete_buckets {
            let missing = b.raw_count.saturating_sub(b.indexed_count);
            out.push_str(&format!(
                "  {}   {} raw, {} indexed ({} missing) — try: indexd --backfill {}\n",
                b.bucket, b.raw_count, b.indexed_count, missing, b.bucket
            ));
        }
        out.push('\n');
    }
}

// ── 2. Volume ────────────────────────────────────────────────────────────

fn render_volume(out: &mut String, report: &DigestReport) {
    let w = &report.window;
    out.push_str(&format!(
        "=== VOLUME ({} \u{2013} {} vs {} \u{2013} {}) ===\n\n",
        fmt_hm(w.start),
        fmt_hm(w.end),
        fmt_hm(w.baseline_start),
        fmt_hm(w.baseline_end),
    ));
    out.push_str(&format!("{:<14}{:>12}  {:>8}   delta\n", "source", "this window", "baseline"));
    for row in &report.volume {
        let delta = match (&row.flag, row.delta_pct) {
            (Some(f), _) if f == "new" => "NEW".to_string(),
            (_, Some(pct)) => format!("{:+.0}%", pct),
            _ => "0%".to_string(),
        };
        let arrow = if row.flag.is_some() { " \u{2190}" } else { "" };
        out.push_str(&format!(
            "{:<14}{:>12}  {:>8}   {}{}\n",
            row.source,
            fmt_n(row.count),
            fmt_n(row.baseline),
            delta,
            arrow
        ));
    }
    out.push('\n');
}

// ── 3. Network ───────────────────────────────────────────────────────────

fn render_network(out: &mut String, report: &DigestReport, cfg: &DigestConfig, interval: Duration) {
    let w = &report.window;
    let net = &report.network;
    let label = fmt_duration_label(interval);

    out.push_str(&format!("=== FIREWALL TRENDS (BLOCK / {label}) ===\n\n"));
    render_sparkline(out, &net.block_trend, w.start, w.end, cfg.spike_threshold_pct, &label);
    out.push('\n');

    out.push_str("=== TOP BLOCKED SOURCE IPs ===\n\n");
    if net.top_blocked.is_empty() {
        out.push_str("  (none)\n");
    } else {
        out.push_str(&format!("{:<18}{:>7}  protocol\n", "src_ip", "count"));
        for row in &net.top_blocked {
            out.push_str(&format!("{:<18}{:>7}  {}\n", row.src_ip, fmt_n(row.count), row.protocol));
        }
    }
    out.push('\n');

    out.push_str(&format!("=== INBOUND ALLOWED ({}) ===\n\n", cfg.wan_interface));
    if net.inbound.is_empty() {
        out.push_str("  (none)\n");
    } else {
        out.push_str(&format!("{:<18}{:<24}{:>7}\n", "src_ip", "dst", "count"));
        for row in &net.inbound {
            let dst = format!("{}:{}", row.dst_ip, row.dst_port);
            out.push_str(&format!("{:<18}{:<24}{:>7}\n", row.src_ip, dst, fmt_n(row.count)));
        }
    }
    out.push('\n');

    out.push_str("=== NEW OUTBOUND DESTINATIONS (vs baseline) ===\n\n");
    if net.new_destinations.is_empty() {
        out.push_str("  (none)\n");
    } else {
        out.push_str(&format!("{:<18}{:<10}{:>7}  first seen\n", "dst_ip", "dst_port", "count"));
        for row in &net.new_destinations {
            out.push_str(&format!(
                "{:<18}{:<10}{:>7}  {}\n",
                row.dst_ip,
                row.dst_port,
                fmt_n(row.count),
                fmt_opt_hms(row.first_seen),
            ));
        }
    }
    out.push('\n');
}

/// Renders the block-character sparkline when the series has a meaningful
/// peak (>`spike_threshold_pct` above its own average — reusing the same
/// threshold the volume section uses, rather than a second magic number),
/// otherwise the flat single-line summary the spec calls for.
fn render_sparkline(
    out: &mut String,
    series: &[u64],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    spike_threshold_pct: f64,
    label: &str,
) {
    if series.is_empty() {
        out.push_str("  (no data)\n");
        return;
    }
    let max = *series.iter().max().unwrap_or(&0);
    let sum: u64 = series.iter().sum();
    let avg = sum as f64 / series.len() as f64;
    let has_spike = avg > 0.0 && (max as f64 - avg) / avg * 100.0 > spike_threshold_pct;

    if !has_spike {
        out.push_str(&format!("BLOCK rate stable: avg {:.0}/{label}, max {max}/{label}\n", avg));
        return;
    }

    let line: String = series
        .iter()
        .map(|&v| {
            if max == 0 {
                SPARK_CHARS[0]
            } else {
                let level = ((v as f64 / max as f64) * (SPARK_CHARS.len() - 1) as f64).round() as usize;
                SPARK_CHARS[level.min(SPARK_CHARS.len() - 1)]
            }
        })
        .collect();
    out.push_str(&line);
    out.push('\n');
    let pad = line.chars().count().saturating_sub(fmt_hm(start).len() + fmt_hm(end).len());
    out.push_str(&format!("{}{}{}\n", fmt_hm(start), " ".repeat(pad), fmt_hm(end)));
}

// ── 4. Auth ──────────────────────────────────────────────────────────────

fn render_auth(out: &mut String, report: &DigestReport) {
    let auth = &report.auth;

    out.push_str("=== AUTHENTICATION FAILURES (all sources) ===\n\n");
    if auth.failures.is_empty() {
        out.push_str("  (none in window)\n");
    } else {
        out.push_str(&format!("{:<18}{:>7}  sources\n", "src_ip", "count"));
        for row in &auth.failures {
            out.push_str(&format!(
                "{:<18}{:>7}  {}\n",
                row.src_ip,
                fmt_n(row.count),
                format_auth_breakdown(&row.by_source),
            ));
        }
    }
    out.push_str("\n=== SUCCESSFUL LOGINS / ACCESS ===\n\n");
    if auth.successes.is_empty() {
        out.push_str("  (none in window)\n");
    } else {
        for e in &auth.successes {
            out.push_str(&format!(
                "  {}  {} @ {} ({})\n",
                fmt_opt_hms(e.timestamp),
                e.username,
                e.src_ip,
                e.source
            ));
        }
    }
    out.push_str("\n=== PRIVILEGE ESCALATION (sudo) ===\n\n");
    if auth.sudo.is_empty() {
        out.push_str("  (none in window)\n");
    } else {
        render_sudo_events(out, &auth.sudo);
    }
    out.push('\n');
}

/// Groups `by_source` entries by their `source` (a `src_ip` can have
/// multiple event types per source, e.g. openvpn's `tls_error`+
/// `auth_failure`), formatting each group as `source (type xN, type xM)`.
fn format_auth_breakdown(by_source: &[AuthFailureBySource]) -> String {
    let mut sources: Vec<&str> = by_source.iter().map(|b| b.source.as_str()).collect();
    sources.sort();
    sources.dedup();

    sources
        .into_iter()
        .map(|source| {
            let types: Vec<String> = by_source
                .iter()
                .filter(|b| b.source == source)
                .map(|b| format!("{} x{}", b.event_type, b.count))
                .collect();
            format!("{source} ({})", types.join(", "))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Groups sudo events by `(username, target_user)`, matching the spec's
/// "user → root  N events" header — using the actual invoking username
/// rather than the literal word "user", since that's more useful and the
/// doc doesn't explain why it wouldn't be the real name.
fn render_sudo_events(out: &mut String, events: &[SudoEvent]) {
    let mut groups: Vec<(String, String, Vec<&SudoEvent>)> = Vec::new();
    for e in events {
        match groups.iter_mut().find(|(u, t, _)| *u == e.username && *t == e.target_user) {
            Some((_, _, evts)) => evts.push(e),
            None => groups.push((e.username.clone(), e.target_user.clone(), vec![e])),
        }
    }
    for (username, target_user, evts) in groups {
        let noun = if evts.len() == 1 { "event" } else { "events" };
        out.push_str(&format!("{username} \u{2192} {target_user}  {} {noun}\n", evts.len()));
        for e in evts {
            out.push_str(&format!("  {}  {}\n", fmt_opt_hms(e.timestamp), e.command));
        }
    }
}

// ── 5. Alerts ────────────────────────────────────────────────────────────

fn render_alerts(out: &mut String, report: &DigestReport) {
    let alerts = &report.alerts;
    out.push_str("=== ALERTS ===\n\n");
    out.push_str(&format!(
        "total alerts:   {} events, {} rules\n\n",
        fmt_n(alerts.total),
        alerts.by_rule.len()
    ));

    if !alerts.by_rule.is_empty() {
        out.push_str(&format!("{:<26}{:<8}count\n", "rule", "level"));
        for r in &alerts.by_rule {
            out.push_str(&format!("{:<26}{:<8}{:>5}\n", r.rule_id, r.level, fmt_n(r.count)));
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "Rules firing for the first time this window:  {}\n",
        list_or_none(&alerts.first_time_rules)
    ));

    let high_critical: Vec<String> = alerts
        .by_rule
        .iter()
        .filter(|r| r.level == "high" || r.level == "critical")
        .map(|r| r.rule_id.clone())
        .collect();
    out.push_str(&format!(
        "High/critical alerts:                         {}\n",
        if high_critical.is_empty() { "none".to_string() } else { high_critical.join(", ") }
    ));

    if let Some(warning) = &alerts.concentration_warning {
        out.push_str(&format!("\nAlert concentration: {warning}\n"));
    }
    out.push('\n');
}

// ── 6. Notable events ────────────────────────────────────────────────────

fn render_notable(out: &mut String, report: &DigestReport) {
    let notable = &report.notable;
    out.push_str("=== NOTABLE EVENTS ===\n\n");

    out.push_str("Config changes (pfsense):\n");
    if notable.config_changes.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for c in &notable.config_changes {
            out.push_str(&format!(
                "  {}  {} @ {} \u{2014} {}\n",
                fmt_opt_hm(c.timestamp),
                c.admin_user,
                c.src_ip,
                c.page
            ));
        }
    }

    out.push_str("\nService restarts (systemd):\n");
    if notable.service_restarts.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for r in &notable.service_restarts {
            out.push_str(&format!(
                "  {}  {}: {}x transition(s) (first {}, last {})\n",
                fmt_opt_hm(r.first_seen),
                r.unit,
                r.count,
                fmt_opt_hm(r.first_seen),
                fmt_opt_hm(r.last_seen),
            ));
        }
    }

    if notable.critical_events.is_empty() {
        out.push_str("\nSeverity critical/emergency:  none\n");
    } else {
        out.push_str("\nSeverity critical/emergency:\n");
        for e in &notable.critical_events {
            out.push_str(&format!(
                "  {}  {} ({}) [{}]\n",
                fmt_opt_hms(e.timestamp),
                e.source,
                e.event_type,
                e.severity
            ));
        }
    }
}

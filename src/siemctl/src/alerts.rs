//! `siemctl alerts` — query interface over `data/alerts/` (`ruled` alerts)
//! and `data/alerts/correlated/` (correlation alerts). CLI wiring is a later
//! batch (see `docs/roadmap-soc-improvements.md`'s Implementation Plan);
//! this module is the loading + execution engine underneath it.
//!
//! Neither alert tree is indexed in SQLite — alerts are flat JSONL, and
//! volume is low enough that scanning them directly is cheap (the same
//! reasoning `digest.rs`'s alerts section already relies on). So this reuses
//! `query::Query::parse`'s DSL grammar completely unchanged (an empty
//! `valid` field set bypasses its field-membership check, since alert/event
//! fields aren't a fixed schema — see `query.rs::validate_field`) but
//! evaluates each parsed predicate directly against loaded JSON records via
//! `Expr::eval_json`/`Condition::eval_json`, instead of compiling to SQL.
//! [`run_query`] mirrors `query::run_query`'s two modes (row / `GROUP BY`)
//! and its `Renderer` output contract exactly, so the CLI batch can call it
//! the same way `cmd_search` calls `query::run_query`.
//!
//! `ruled` alerts and correlated alerts have genuinely different JSON
//! shapes (`rule_id`/`event`/`level` vs. `correlation_id`/`sample_events`,
//! no `level` at all) — see `query.rs`'s `resolve_json_field` doc comment
//! for the field-resolution order that papers over this without aliasing
//! field names. Every loaded record is tagged with a synthetic `type` field
//! (`"ruled"` or `"correlated"`) so a query can distinguish them
//! (`type == correlated`) instead of guessing from field presence.
//!
//! `ack`/`load_ack_watermarks`/`filter_acked`/`compact_ack_log` are alert
//! *state* management (`siemctl alerts ack <rule_id>`) — see the "Ack"
//! section below for the watermark design.

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

use crate::query::{self, Query};
use crate::render::{json_to_val, Record, Renderer, Val};
use crate::time::{self, HourBucket};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Load every alert record whose hour bucket falls in `[after, before]`
/// (inclusive; `None` on either side means unbounded in that direction —
/// the same semantics `search`'s own `--after`/`--before` use). Every
/// record is tagged with a synthetic `"type"` field: `"ruled"` for
/// `data/alerts/YYYY/MM/DD/HH/alerts.jsonl`, `"correlated"` for
/// `data/alerts/correlated/YYYY/MM/DD/HH/correlated.jsonl`. Malformed lines
/// and unreadable files are skipped, not fatal.
pub fn load_alerts(data_dir: &Path, after: Option<HourBucket>, before: Option<HourBucket>) -> Vec<Value> {
    let mut out = Vec::new();
    load_tree(&data_dir.join("alerts"), "alerts.jsonl", "ruled", after, before, &mut out);
    load_tree(
        &data_dir.join("alerts").join("correlated"),
        "correlated.jsonl",
        "correlated",
        after,
        before,
        &mut out,
    );
    out
}

fn load_tree(
    root: &Path,
    filename: &str,
    type_tag: &str,
    after: Option<HourBucket>,
    before: Option<HourBucket>,
    out: &mut Vec<Value>,
) {
    let mut files = Vec::new();
    if after.is_some() || before.is_some() {
        // Sentinel bounds on the open side, same convention as
        // `main.rs::collect_raw_files` for unbounded `--after`/`--before`.
        let a = after.unwrap_or(HourBucket { year: 2000, month: 1, day: 1, hour: 0 });
        let b = before.unwrap_or(HourBucket { year: 2099, month: 12, day: 31, hour: 23 });
        for dir in time::dirs_in_range_under(root, a, b) {
            let path = dir.join(filename);
            if path.is_file() {
                files.push(path);
            }
        }
    } else {
        crate::walk_jsonl(root, &mut |p| {
            if p.file_name().and_then(|n| n.to_str()) == Some(filename) {
                files.push(p.to_owned());
            }
        });
    }

    for path in files {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }
            let Ok(mut record) = serde_json::from_str::<Value>(line) else { continue };
            if let Some(obj) = record.as_object_mut() {
                obj.insert("type".to_string(), Value::String(type_tag.to_string()));
            }
            out.push(record);
        }
    }
}

// ── Ack (alert state management) ────────────────────────────────────────
//
// `data/alerts/ack.jsonl` — one append-only file, one line per ack action:
// `{"rule_id","timestamp","note"}`. `timestamp` is a *watermark*: acking a
// rule_id hides every alert for it up to that moment, but a new alert for
// the same rule_id firing afterward is unaffected (see
// docs/roadmap-soc-improvements.md item 2's "Resolved" note for why this
// isn't a global on/off switch, and why there's no `state`/`analyst` field
// the original sketch proposed). Correlated alerts have no `rule_id` (they
// key on `correlation_id` instead) and are never filtered by this.

/// Append one ack watermark for `rule_id` at `timestamp` (epoch seconds) to
/// `data/alerts/ack.jsonl`, creating the file (and `data/alerts/`, though
/// that should already exist if there are any alerts to ack) if needed.
pub fn ack(data_dir: &Path, rule_id: &str, timestamp: i64, note: Option<&str>) -> Result<()> {
    use std::io::Write;

    let path = data_dir.join("alerts").join("ack.jsonl");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut obj = serde_json::Map::new();
    obj.insert("rule_id".to_string(), Value::String(rule_id.to_string()));
    obj.insert("timestamp".to_string(), Value::Number(timestamp.into()));
    if let Some(n) = note {
        obj.insert("note".to_string(), Value::String(n.to_string()));
    }
    let line = serde_json::to_string(&Value::Object(obj))?;

    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(f, "{line}")?;
    Ok(())
}

/// The latest ack watermark (epoch seconds) per `rule_id`, from
/// `data/alerts/ack.jsonl`. A missing file, or a malformed line, is not an
/// error — it just contributes no watermark.
pub fn load_ack_watermarks(data_dir: &Path) -> std::collections::HashMap<String, i64> {
    let path = data_dir.join("alerts").join("ack.jsonl");
    let mut watermarks = std::collections::HashMap::new();
    let Ok(content) = std::fs::read_to_string(&path) else { return watermarks };
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        let Some(rule_id) = v.get("rule_id").and_then(|x| x.as_str()) else { continue };
        let Some(ts) = v.get("timestamp").and_then(|x| x.as_i64()) else { continue };
        watermarks.entry(rule_id.to_string()).and_modify(|w: &mut i64| *w = (*w).max(ts)).or_insert(ts);
    }
    watermarks
}

/// Drop ruled alerts whose `timestamp` is `<=` the latest ack watermark for
/// their `rule_id`. An alert with no `rule_id` (correlated), no matching
/// watermark (never acked), or no `timestamp` (can't compare — fail open,
/// don't hide it) is always kept.
pub fn filter_acked(records: &mut Vec<Value>, watermarks: &std::collections::HashMap<String, i64>) {
    records.retain(|r| {
        let Some(rule_id) = r.get("rule_id").and_then(|v| v.as_str()) else { return true };
        let Some(watermark) = watermarks.get(rule_id) else { return true };
        let Some(ts) = r.get("timestamp").and_then(|v| v.as_i64()) else { return true };
        ts > *watermark
    });
}

/// Compact `data/alerts/ack.jsonl` (used by `siemctl retention`): drop lines
/// whose `timestamp` is older than `cutoff_epoch` (epoch seconds). Returns
/// how many lines were (or, if `dry_run`, would be) dropped. A line with an
/// unparseable or missing `timestamp` is always kept — never silently lose
/// an ack because of a field we don't understand. Removes the file entirely
/// if nothing survives; a missing file is `Ok(0)`, not an error.
pub fn compact_ack_log(path: &Path, cutoff_epoch: i64, dry_run: bool) -> std::io::Result<usize> {
    let Ok(content) = std::fs::read_to_string(path) else { return Ok(0) };

    let mut survivors = Vec::new();
    let mut dropped = 0usize;
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        let keep = serde_json::from_str::<Value>(line)
            .ok()
            .and_then(|v| v.get("timestamp").and_then(|t| t.as_i64()))
            .map(|ts| ts >= cutoff_epoch)
            .unwrap_or(true);
        if keep {
            survivors.push(line.to_string());
        } else {
            dropped += 1;
        }
    }

    if dropped > 0 && !dry_run {
        if survivors.is_empty() {
            std::fs::remove_file(path)?;
        } else {
            std::fs::write(path, survivors.join("\n") + "\n")?;
        }
    }
    Ok(dropped)
}

/// Execute `query` against already-loaded alert records and render the
/// result. Returns the process exit code (0 = hits, 1 = no matches) — same
/// contract as `query::run_query`.
pub fn run_query<W: std::io::Write>(
    records: &[Value],
    query: &Query,
    renderer: &mut Renderer<W>,
) -> Result<i32> {
    let matched: Vec<&Value> = match &query.expr {
        Some(expr) => records.iter().filter(|r| expr.eval_json(r)).collect(),
        None => records.iter().collect(),
    };

    match &query.group_by {
        Some(fields) => run_group(&matched, fields, renderer),
        None => run_rows(&matched, query, renderer),
    }
}

fn run_rows<W: std::io::Write>(
    matched: &[&Value],
    query: &Query,
    renderer: &mut Renderer<W>,
) -> Result<i32> {
    let mut total = 0usize;
    for record in matched {
        if renderer.is_done() {
            break;
        }
        match &query.select {
            // Projected fields use the same top-level → event → sample_events
            // resolution as WHERE-clause matching, so `SELECT src_ip` works
            // on a `ruled` alert the same way `WHERE src_ip == ...` does —
            // unlike a plain `emit_raw_line` + flat-object parse, which would
            // only ever see the alert's own top-level keys.
            Some(fields) => {
                let rec: Record = fields
                    .iter()
                    .map(|f| {
                        let val =
                            query::resolve_json_field(record, f).map(json_to_val).unwrap_or(Val::Null);
                        (f.clone(), val)
                    })
                    .collect();
                let _ = renderer.emit_record(&rec);
            }
            None => {
                let line = serde_json::to_string(record).unwrap_or_default();
                let _ = renderer.emit_raw_line(&line);
            }
        }
        total += 1;
    }
    if total == 0 {
        eprintln!("siemctl: no matches found");
        return Ok(1);
    }
    Ok(0)
}

fn run_group<W: std::io::Write>(
    matched: &[&Value],
    fields: &[String],
    renderer: &mut Renderer<W>,
) -> Result<i32> {
    let mut acc: BTreeMap<Vec<String>, u64> = BTreeMap::new();
    for record in matched {
        let key: Vec<String> = fields
            .iter()
            .map(|f| {
                query::resolve_json_field(record, f).and_then(query::json_scalar_to_string).unwrap_or_default()
            })
            .collect();
        *acc.entry(key).or_insert(0) += 1;
    }

    if acc.is_empty() {
        eprintln!("siemctl: no matches found");
        return Ok(1);
    }

    // Sort by count descending, ties broken by the group key ascending —
    // matching query.rs's SQL-backed group mode exactly.
    let mut entries: Vec<(Vec<String>, u64)> = acc.into_iter().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    for (keyvals, count) in entries {
        let mut rec: Record = Vec::with_capacity(fields.len() + 1);
        for (f, v) in fields.iter().zip(keyvals.iter()) {
            rec.push((f.clone(), Val::Str(v.clone())));
        }
        rec.push(("count".to_string(), Val::Int(count as i64)));
        let _ = renderer.emit_record(&rec);
        if renderer.is_done() {
            break;
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Format;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_CTR: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let n = TMP_CTR.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("hsiem_alerts_test_{}_{}", std::process::id(), n));
            std::fs::create_dir_all(&p).unwrap();
            TempDir { path: p }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn write_ruled_alert(dir: &std::path::Path, rule_id: &str, level: &str, src_ip: &str) {
        std::fs::create_dir_all(dir).unwrap();
        let line = serde_json::json!({
            "_ruled": true,
            "rule_id": rule_id,
            "rule_title": format!("Title for {rule_id}"),
            "level": level,
            "timestamp": 1783026390,
            "event": { "src_ip": src_ip, "_source_type": "sshd" },
        });
        let path = dir.join("alerts.jsonl");
        let mut existing = std::fs::read_to_string(&path).unwrap_or_default();
        existing.push_str(&line.to_string());
        existing.push('\n');
        std::fs::write(path, existing).unwrap();
    }

    fn write_correlated_alert(dir: &std::path::Path, correlation_id: &str, src_ip: &str) {
        std::fs::create_dir_all(dir).unwrap();
        let line = serde_json::json!({
            "_correlated": true,
            "correlation_id": correlation_id,
            "correlation_title": "Test correlation",
            "join_field": "src_ip",
            "join_value": src_ip,
            "chain_start": 100,
            "chain_end": 200,
            "step_counts": [2, 1],
            "sample_events": [{ "src_ip": src_ip }],
        });
        let path = dir.join("correlated.jsonl");
        let mut existing = std::fs::read_to_string(&path).unwrap_or_default();
        existing.push_str(&line.to_string());
        existing.push('\n');
        std::fs::write(path, existing).unwrap();
    }

    fn parse(dsl: &str) -> Query {
        Query::parse(dsl, &HashSet::new()).unwrap()
    }

    fn render(records: &[Value], query: &Query) -> (i32, String) {
        let mut buf: Vec<u8> = Vec::new();
        let rc = {
            let mut r = Renderer::new(Format::Json, query.select.clone(), &mut buf, query.limit);
            run_query(records, query, &mut r).unwrap()
        };
        (rc, String::from_utf8(buf).unwrap())
    }

    // ── load_alerts ──────────────────────────────────────────────────────

    #[test]
    fn load_alerts_tags_ruled_and_correlated_distinctly() {
        let tmp = TempDir::new();
        write_ruled_alert(&tmp.path.join("alerts/2026/07/01/14"), "sudo-execution", "low", "10.0.0.1");
        write_correlated_alert(&tmp.path.join("alerts/correlated/2026/07/01/14"), "cred-guess", "10.0.0.1");

        let records = load_alerts(&tmp.path, None, None);
        assert_eq!(records.len(), 2);
        let types: Vec<&str> = records.iter().map(|r| r["type"].as_str().unwrap()).collect();
        assert!(types.contains(&"ruled"));
        assert!(types.contains(&"correlated"));
    }

    #[test]
    fn load_alerts_respects_after_before_bucket_range() {
        let tmp = TempDir::new();
        write_ruled_alert(&tmp.path.join("alerts/2026/07/01/08"), "before-window", "low", "10.0.0.1");
        write_ruled_alert(&tmp.path.join("alerts/2026/07/01/14"), "in-window", "low", "10.0.0.1");
        write_ruled_alert(&tmp.path.join("alerts/2026/07/01/20"), "after-window", "low", "10.0.0.1");

        let after = HourBucket::parse("2026-07-01T10").unwrap();
        let before = HourBucket::parse("2026-07-01T18").unwrap();
        let records = load_alerts(&tmp.path, Some(after), Some(before));

        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["rule_id"], "in-window");
    }

    #[test]
    fn load_alerts_skips_malformed_lines_without_failing() {
        let tmp = TempDir::new();
        let dir = tmp.path.join("alerts/2026/07/01/14");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("alerts.jsonl"), "not json\n{\"rule_id\":\"ok\",\"level\":\"low\"}\n").unwrap();

        let records = load_alerts(&tmp.path, None, None);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["rule_id"], "ok");
    }

    #[test]
    fn load_alerts_empty_when_no_alerts_dir() {
        let tmp = TempDir::new();
        assert!(load_alerts(&tmp.path, None, None).is_empty());
    }

    // ── run_query: row mode ──────────────────────────────────────────────

    #[test]
    fn run_query_default_emits_whole_record_as_json() {
        let records = vec![serde_json::json!({"rule_id": "r1", "level": "low", "event": {"src_ip": "1.2.3.4"}})];
        let query = parse("rule_id == r1");
        let (rc, out) = render(&records, &query);
        assert_eq!(rc, 0);
        assert!(out.contains("\"src_ip\":\"1.2.3.4\""), "got: {out}");
    }

    #[test]
    fn run_query_select_projects_nested_fields() {
        let records =
            vec![serde_json::json!({"rule_id": "r1", "level": "low", "event": {"src_ip": "1.2.3.4"}})];
        let query = parse("SELECT rule_id,src_ip WHERE rule_id == r1");
        let (rc, out) = render(&records, &query);
        assert_eq!(rc, 0);
        assert!(out.contains("\"rule_id\":\"r1\""));
        assert!(out.contains("\"src_ip\":\"1.2.3.4\""), "got: {out}");
    }

    #[test]
    fn run_query_no_match_returns_1() {
        let records = vec![serde_json::json!({"rule_id": "r1", "level": "low"})];
        let query = parse("rule_id == nonexistent");
        let (rc, out) = render(&records, &query);
        assert_eq!(rc, 1);
        assert!(out.is_empty());
    }

    #[test]
    fn run_query_limit_caps_row_output() {
        let records: Vec<Value> = (0..5).map(|i| serde_json::json!({"rule_id": format!("r{i}")})).collect();
        let query = parse("LIMIT 2");
        let (rc, out) = render(&records, &query);
        assert_eq!(rc, 0);
        assert_eq!(out.lines().count(), 2);
    }

    // ── run_query: group mode ────────────────────────────────────────────

    #[test]
    fn run_query_group_by_counts_per_rule() {
        let records = vec![
            serde_json::json!({"rule_id": "r1"}),
            serde_json::json!({"rule_id": "r1"}),
            serde_json::json!({"rule_id": "r2"}),
        ];
        let query = parse("GROUP BY rule_id");
        let (rc, out) = render(&records, &query);
        assert_eq!(rc, 0);
        assert!(out.contains(r#"{"rule_id":"r1","count":2}"#), "got: {out}");
        assert!(out.contains(r#"{"rule_id":"r2","count":1}"#), "got: {out}");
    }

    #[test]
    fn run_query_type_correlated_filters_to_correlated_alerts_only() {
        let tmp = TempDir::new();
        write_ruled_alert(&tmp.path.join("alerts/2026/07/01/14"), "sudo-execution", "low", "10.0.0.1");
        write_correlated_alert(&tmp.path.join("alerts/correlated/2026/07/01/14"), "cred-guess", "10.0.0.1");
        let records = load_alerts(&tmp.path, None, None);

        let query = parse("type == correlated");
        let (rc, out) = render(&records, &query);
        assert_eq!(rc, 0);
        assert!(out.contains("cred-guess"));
        assert!(!out.contains("sudo-execution"), "got: {out}");
    }

    #[test]
    fn run_query_group_by_type_separates_shapes() {
        let tmp = TempDir::new();
        write_ruled_alert(&tmp.path.join("alerts/2026/07/01/14"), "r1", "low", "10.0.0.1");
        write_ruled_alert(&tmp.path.join("alerts/2026/07/01/14"), "r2", "low", "10.0.0.1");
        write_correlated_alert(&tmp.path.join("alerts/correlated/2026/07/01/14"), "c1", "10.0.0.1");
        let records = load_alerts(&tmp.path, None, None);

        let query = parse("GROUP BY type");
        let (rc, out) = render(&records, &query);
        assert_eq!(rc, 0);
        assert!(out.contains(r#"{"type":"ruled","count":2}"#), "got: {out}");
        assert!(out.contains(r#"{"type":"correlated","count":1}"#), "got: {out}");
    }

    // ── ack / load_ack_watermarks / filter_acked ────────────────────────

    #[test]
    fn ack_appends_and_creates_the_alerts_dir() {
        let tmp = TempDir::new();
        ack(&tmp.path, "1001-ssh-brute-force", 1000, Some("known pattern")).unwrap();
        ack(&tmp.path, "1004-suspicious-ssh", 2000, None).unwrap();

        let content = std::fs::read_to_string(tmp.path.join("alerts/ack.jsonl")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["rule_id"], "1001-ssh-brute-force");
        assert_eq!(first["timestamp"], 1000);
        assert_eq!(first["note"], "known pattern");
        let second: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["rule_id"], "1004-suspicious-ssh");
        assert!(second.get("note").is_none());
    }

    #[test]
    fn load_ack_watermarks_uses_the_latest_timestamp_per_rule() {
        let tmp = TempDir::new();
        ack(&tmp.path, "r1", 1000, None).unwrap();
        ack(&tmp.path, "r1", 3000, None).unwrap(); // later ack for the same rule
        ack(&tmp.path, "r1", 2000, None).unwrap(); // out-of-order, still older than 3000
        ack(&tmp.path, "r2", 500, None).unwrap();

        let watermarks = load_ack_watermarks(&tmp.path);
        assert_eq!(watermarks.get("r1"), Some(&3000));
        assert_eq!(watermarks.get("r2"), Some(&500));
        assert_eq!(watermarks.get("r3"), None);
    }

    #[test]
    fn load_ack_watermarks_missing_file_is_empty() {
        let tmp = TempDir::new();
        assert!(load_ack_watermarks(&tmp.path).is_empty());
    }

    #[test]
    fn filter_acked_hides_at_or_before_watermark_shows_after() {
        let mut records = vec![
            serde_json::json!({"rule_id": "r1", "timestamp": 1000}), // exactly at watermark -> hidden
            serde_json::json!({"rule_id": "r1", "timestamp": 999}),  // before -> hidden
            serde_json::json!({"rule_id": "r1", "timestamp": 1001}), // after -> shown
            serde_json::json!({"rule_id": "r2", "timestamp": 1}),    // never acked -> shown
        ];
        let mut watermarks = std::collections::HashMap::new();
        watermarks.insert("r1".to_string(), 1000i64);

        filter_acked(&mut records, &watermarks);

        let remaining: Vec<i64> = records.iter().map(|r| r["timestamp"].as_i64().unwrap()).collect();
        assert_eq!(remaining, vec![1001, 1]);
    }

    #[test]
    fn filter_acked_never_touches_correlated_alerts() {
        let mut records = vec![serde_json::json!({
            "correlation_id": "c1",
            "chain_end": 1,
            "sample_events": [{"src_ip": "10.0.0.1"}],
        })];
        let mut watermarks = std::collections::HashMap::new();
        watermarks.insert("c1".to_string(), i64::MAX); // even a huge watermark under the wrong key
        filter_acked(&mut records, &watermarks);
        assert_eq!(records.len(), 1); // no rule_id field at all -> always kept
    }

    #[test]
    fn ack_then_filter_round_trip_via_load_alerts() {
        let tmp = TempDir::new();
        write_ruled_alert(&tmp.path.join("alerts/2026/07/01/14"), "r1", "low", "10.0.0.1");
        // write_ruled_alert hardcodes timestamp 1783026390 — ack just after it.
        ack(&tmp.path, "r1", 1783026390, None).unwrap();

        let mut records = load_alerts(&tmp.path, None, None);
        let watermarks = load_ack_watermarks(&tmp.path);
        filter_acked(&mut records, &watermarks);
        assert!(records.is_empty(), "acked alert should be hidden by default");

        // --all bypasses the filter entirely.
        let unfiltered = load_alerts(&tmp.path, None, None);
        assert_eq!(unfiltered.len(), 1);
    }

    // ── compact_ack_log ──────────────────────────────────────────────────

    fn write_ack_lines(path: &std::path::Path, lines: &[(&str, i64)]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let content: String = lines
            .iter()
            .map(|(rule_id, ts)| format!(r#"{{"rule_id":"{rule_id}","timestamp":{ts}}}"#) + "\n")
            .collect();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn compact_ack_log_drops_only_stale_lines() {
        let tmp = TempDir::new();
        let path = tmp.path.join("ack.jsonl");
        write_ack_lines(&path, &[("r1", 100), ("r2", 5000), ("r3", 200)]);

        let dropped = compact_ack_log(&path, 1000, false).unwrap();
        assert_eq!(dropped, 2);

        let remaining = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = remaining.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"r2\""));
    }

    #[test]
    fn compact_ack_log_dry_run_reports_but_does_not_rewrite() {
        let tmp = TempDir::new();
        let path = tmp.path.join("ack.jsonl");
        write_ack_lines(&path, &[("r1", 100), ("r2", 5000)]);
        let original = std::fs::read_to_string(&path).unwrap();

        let dropped = compact_ack_log(&path, 1000, true).unwrap();
        assert_eq!(dropped, 1);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original, "dry run must not modify the file");
    }

    #[test]
    fn compact_ack_log_removes_the_file_when_nothing_survives() {
        let tmp = TempDir::new();
        let path = tmp.path.join("ack.jsonl");
        write_ack_lines(&path, &[("r1", 100), ("r2", 200)]);

        let dropped = compact_ack_log(&path, 1000, false).unwrap();
        assert_eq!(dropped, 2);
        assert!(!path.exists());
    }

    #[test]
    fn compact_ack_log_missing_file_is_a_no_op() {
        let tmp = TempDir::new();
        let path = tmp.path.join("nonexistent.jsonl");
        assert_eq!(compact_ack_log(&path, 1000, false).unwrap(), 0);
    }

    #[test]
    fn compact_ack_log_keeps_lines_with_unparseable_or_missing_timestamp() {
        let tmp = TempDir::new();
        let path = tmp.path.join("ack.jsonl");
        std::fs::write(&path, "not json\n{\"rule_id\":\"r1\"}\n{\"rule_id\":\"r2\",\"timestamp\":100}\n")
            .unwrap();

        let dropped = compact_ack_log(&path, 1000, false).unwrap();
        assert_eq!(dropped, 1); // only the r2 line (timestamp 100 < 1000) is stale
        let remaining = std::fs::read_to_string(&path).unwrap();
        assert_eq!(remaining.lines().count(), 2);
    }
}

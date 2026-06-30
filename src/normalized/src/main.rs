//! normalized — Headless SIEM log normalizer.
//!
//! Ingests logs from stdin, UDP, or TCP; runs each line through a
//! deterministic parser chain (RFC5424/3164, JSON, CEF, LEEF, logfmt, CSV,
//! XML, YAML, plain); and writes flat, downstream-compatible JSON records to
//! both stdout and the time-bucketed filesystem store
//! (`<data_dir>/raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl` + `.tsv`).
//!
//! Sole external dependency: chrono (timestamp parsing + bucket paths).

mod config;
mod envelope;
mod event;
mod extract;
mod output;
mod parsers;

use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use config::{Config, OverrideRule};
use event::serialize_flat;
use output::{BucketTime, OutputRouter};

/// Shared, immutable processing context used by every input source.
struct Processor {
    rules: Vec<OverrideRule>,
    extract: Vec<extract::ExtractRule>,
    force_source: Option<String>,
    basis: BucketTime,
    router: Option<OutputRouter>,
    /// Inclusive lower/upper bounds on event time; events outside are dropped.
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    /// When a time range is set, also drop events whose timestamp can't be
    /// parsed. Default false: undated events pass through (preserves the
    /// "never drops" invariant unless the operator opts in).
    drop_undated: bool,
    /// Serializes stdout + filesystem writes across listener threads.
    out: Mutex<io::Stdout>,
}

impl Processor {
    /// Normalize one raw line from `source_addr` and emit it.
    fn handle(&self, raw: &[u8], source_addr: &str) {
        let now = Utc::now();
        let received_iso = now.to_rfc3339();

        // Unwrap the rsyslog/fixture `_raw` envelope if present; otherwise
        // parse the line as-is. The chain runs on the inner log line.
        let env = envelope::unwrap(raw);
        let inner: Vec<u8> = match &env {
            Some(e) => e.raw.clone().into_bytes(),
            None => raw.to_vec(),
        };

        let outcome = parsers::parse(&inner, source_addr, &self.rules);
        let mut event = outcome.event;

        if let Some(canon) = event.app_name.as_deref().and_then(canonical_app_name) {
            event.app_name = Some(canon.to_string());
        }

        // Fold envelope metadata into any fields the inner parse didn't supply.
        if let Some(e) = &env {
            if event.timestamp.is_none() {
                event.timestamp = e.timestamp.clone();
            }
            if event.hostname.is_none() {
                event.hostname = e.hostname.clone();
            }
            if event.severity.is_none() {
                event.severity = e.severity.as_deref().and_then(envelope::severity_from_word);
            }
        }

        // Source precedence: CLI --source > override rule > envelope tag.
        let env_source = env.as_ref().and_then(|e| e.source.clone());
        let override_source = self
            .force_source
            .as_deref()
            .or(outcome.source.as_deref())
            .or(env_source.as_deref());
        let source = event.derive_source(override_source);

        // Config-driven field extraction (runs against the parsed event).
        extract::apply(&self.extract, &mut event, &source);

        // Normalization-time filter: skip events outside [since, until].
        // Filter on the event's *own* timestamp (not the receive-time fallback
        // that flatten would substitute), so undated events are governed by
        // --drop-undated rather than silently filtered by receive time.
        let own_time = event
            .timestamp
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .and_then(output::parse_event_timestamp);
        if !self.in_time_range(own_time) {
            return;
        }

        let map = event.flatten(&source, &received_iso);
        let json = serialize_flat(&map);

        let mut stdout = self.out.lock().unwrap();
        if let Err(e) = writeln!(stdout, "{}", json) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                std::process::exit(0);
            }
            eprintln!("[normalized] stdout write error: {}", e);
        }
        if let Some(router) = &self.router {
            if let Err(e) = router.write(&json, &source, &map, now, self.basis) {
                eprintln!("[normalized] storage write error: {}", e);
            }
        }
    }

    /// Whether an event falls within the configured `[since, until]` window.
    /// With no bounds set, always true (the common case). `own_time` is the
    /// event's own parsed timestamp, or `None` if it had none/unparseable —
    /// undated events pass unless `--drop-undated` was given.
    fn in_time_range(&self, own_time: Option<DateTime<Utc>>) -> bool {
        if self.since.is_none() && self.until.is_none() {
            return true;
        }
        match own_time {
            Some(dt) => {
                if self.since.map(|s| dt < s).unwrap_or(false) {
                    return false;
                }
                if self.until.map(|u| dt > u).unwrap_or(false) {
                    return false;
                }
                true
            }
            None => !self.drop_undated,
        }
    }
}

struct Args {
    stdin: bool,
    dry_run: bool,
    data_dir: Option<String>,
    config: Option<String>,
    config_dir: Option<String>,
    force_source: Option<String>,
    basis: BucketTime,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    drop_undated: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        stdin: false,
        dry_run: false,
        data_dir: None,
        config: None,
        config_dir: None,
        force_source: None,
        basis: BucketTime::Event,
        since: None,
        until: None,
        drop_undated: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--stdin" => a.stdin = true,
            "--dry-run" => a.dry_run = true,
            "--data-dir" => a.data_dir = Some(it.next().ok_or("--data-dir needs a value")?),
            "--config" => a.config = Some(it.next().ok_or("--config needs a value")?),
            "--config-dir" => a.config_dir = Some(it.next().ok_or("--config-dir needs a value")?),
            "--source" => a.force_source = Some(it.next().ok_or("--source needs a value")?),
            "--since" => {
                let s = it.next().ok_or("--since needs a value")?;
                a.since = Some(
                    output::parse_time_bound(&s)
                        .ok_or_else(|| format!("--since: unrecognized timestamp '{}'", s))?,
                );
            }
            "--until" => {
                let s = it.next().ok_or("--until needs a value")?;
                a.until = Some(
                    output::parse_time_bound(&s)
                        .ok_or_else(|| format!("--until: unrecognized timestamp '{}'", s))?,
                );
            }
            "--drop-undated" => a.drop_undated = true,
            "--bucket-time" => {
                a.basis = match it.next().as_deref() {
                    Some("event") => BucketTime::Event,
                    Some("receive") => BucketTime::Receive,
                    other => {
                        return Err(format!(
                            "--bucket-time expects 'event' or 'receive', got {:?}",
                            other
                        ))
                    }
                };
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag: {}", other)),
        }
    }
    Ok(a)
}

fn print_help() {
    eprintln!("normalized — Headless SIEM log normalizer");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  normalized [FLAGS]");
    eprintln!();
    eprintln!("INPUT (choose one mode):");
    eprintln!("  --stdin               Read newline-delimited logs from stdin");
    eprintln!("                        (cat /var/log/syslog | normalized --stdin)");
    eprintln!("  (default)             Listen on UDP+TCP per --config (default :514)");
    eprintln!();
    eprintln!("FLAGS:");
    eprintln!("  --data-dir <path>     Bucket root for raw storage (default: ./data)");
    eprintln!("  --dry-run             Write to stdout only; no filesystem storage");
    eprintln!("  --bucket-time <mode>  'event' (default) or 'receive' — clock used");
    eprintln!("                        to choose the YYYY/MM/DD/HH/MM/SS bucket");
    eprintln!("  --source <name>       Force the source label for every record");
    eprintln!("  --since <ts>          Drop events before <ts> (inclusive). Accepts");
    eprintln!("                        RFC3339, 'YYYY-MM-DD HH:MM:SS', or 'YYYY-MM-DD'");
    eprintln!("                        (= midnight UTC). Filters on event time.");
    eprintln!("  --until <ts>          Drop events after <ts> (inclusive). Same formats.");
    eprintln!("  --drop-undated        With --since/--until, also drop events whose");
    eprintln!("                        timestamp can't be parsed (default: pass through)");
    eprintln!("  --config <file>       Config file (listen ports, override rules, data_dir)");
    eprintln!("  --config-dir <dir>    Directory of *.toml config files, merged in");
    eprintln!("                        filename order. --config-dir loads first;");
    eprintln!("                        --config (if also given) is merged after.");
    eprintln!("  --help                Print this help");
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[normalized] {}", e);
            eprintln!("[normalized] use --help for usage");
            std::process::exit(1);
        }
    };

    if let (Some(s), Some(u)) = (args.since, args.until) {
        if s > u {
            eprintln!("[normalized] --since ({}) must be <= --until ({})", s, u);
            std::process::exit(1);
        }
    }

    // ── Load config (optional) ──────────────────────────────────────────────
    // Load order: --config-dir first (sorted filenames), then --config on top.
    let mut cfg = match &args.config_dir {
        Some(dir) => match Config::from_dir(dir) {
            Ok(c) => {
                eprintln!("[normalized] loaded config dir {}", dir);
                c
            }
            Err(e) => {
                eprintln!("[normalized] could not read config dir {}: {}", dir, e);
                std::process::exit(1);
            }
        },
        None => Config::default(),
    };
    if let Some(path) = &args.config {
        match Config::from_file(path) {
            Ok(c) => {
                eprintln!("[normalized] loaded config from {}", path);
                cfg.merge(c);
            }
            Err(e) => {
                eprintln!("[normalized] could not read config {}: {}", path, e);
                std::process::exit(1);
            }
        }
    }

    // ── Resolve storage: CLI > config > default ./data; --dry-run disables ──
    let router = if args.dry_run {
        None
    } else {
        let dir = args
            .data_dir
            .clone()
            .or_else(|| cfg.storage.data_dir.clone())
            .unwrap_or_else(|| "data".to_string());
        eprintln!("[normalized] storing buckets under {}/raw", dir);
        Some(OutputRouter::new(&PathBuf::from(dir)))
    };

    let processor = Arc::new(Processor {
        rules: cfg.rules.clone(),
        extract: extract::build(&cfg.extract),
        force_source: args.force_source.clone(),
        basis: args.basis,
        router,
        since: args.since,
        until: args.until,
        drop_undated: args.drop_undated,
        out: Mutex::new(io::stdout()),
    });

    if args.stdin {
        run_stdin(&processor);
    } else {
        run_listeners(&processor, &cfg);
    }
}

/// Read newline-delimited logs from stdin (cat / tail / journalctl | …).
fn run_stdin(processor: &Arc<Processor>) {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        match line {
            Ok(l) if !l.is_empty() => processor.handle(l.as_bytes(), "stdin"),
            Ok(_) => {}
            Err(e) => {
                eprintln!("[normalized] stdin read error: {}", e);
                continue; // tolerate bad UTF-8 / read hiccups
            }
        }
    }
}

/// Start UDP + TCP syslog listeners from config.
fn run_listeners(processor: &Arc<Processor>, cfg: &Config) {
    let bind = cfg.listen.bind.clone();
    let udp_addr = format!("{}:{}", bind, cfg.listen.udp_port);
    let tcp_addr = format!("{}:{}", bind, cfg.listen.tcp_port);

    {
        let processor = Arc::clone(processor);
        std::thread::Builder::new()
            .name("udp-listener".into())
            .spawn(move || run_udp(&udp_addr, &processor))
            .expect("failed to spawn UDP thread");
    }

    run_tcp(&tcp_addr, processor);
}

fn run_udp(addr: &str, processor: &Arc<Processor>) {
    let socket = match UdpSocket::bind(addr) {
        Ok(s) => {
            eprintln!("[normalized] UDP listening on {}", addr);
            s
        }
        Err(e) => {
            eprintln!("[normalized] UDP bind error on {}: {}", addr, e);
            return;
        }
    };
    let mut buf = vec![0u8; 65535];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => processor.handle(&buf[..n], &peer.ip().to_string()),
            Err(e) => eprintln!("[normalized] UDP recv error: {}", e),
        }
    }
}

fn run_tcp(addr: &str, processor: &Arc<Processor>) {
    let listener = match TcpListener::bind(addr) {
        Ok(l) => {
            eprintln!("[normalized] TCP listening on {}", addr);
            l
        }
        Err(e) => {
            eprintln!("[normalized] TCP bind error on {}: {}", addr, e);
            return;
        }
    };
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let processor = Arc::clone(processor);
                let peer = s
                    .peer_addr()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
                std::thread::Builder::new()
                    .name(format!("tcp-{}", peer))
                    .spawn(move || handle_tcp(s, &peer, &processor))
                    .ok();
            }
            Err(e) => eprintln!("[normalized] TCP accept error: {}", e),
        }
    }
}

fn handle_tcp(stream: TcpStream, peer: &str, processor: &Arc<Processor>) {
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        match line {
            Ok(l) if !l.is_empty() => processor.handle(strip_octet_count(&l), peer),
            Ok(_) => {}
            Err(e) => {
                eprintln!("[normalized] TCP read error from {}: {}", peer, e);
                break;
            }
        }
    }
}

/// Strip an RFC 6587 octet-count framing prefix (`"N "`) if present.
fn strip_octet_count(s: &str) -> &[u8] {
    let bytes = s.as_bytes();
    if bytes.first().map(|b| b.is_ascii_digit()).unwrap_or(false) {
        if let Some(sp) = bytes.iter().position(|&b| b == b' ') {
            if bytes[..sp].iter().all(|b| b.is_ascii_digit()) {
                return &bytes[sp + 1..];
            }
        }
    }
    bytes
}

/// Canonicalize a program/app name to a stable, lowercase source label.
///
/// Two cases are folded:
///   - OpenSSH 9.8+ privilege-separation subprocesses (`sshd-session`,
///     `sshd-auth`) → `sshd`, so auth events log under one label across
///     OpenSSH versions.
///   - Debian cron's uppercase `CRON` program name → `cron`, so the source
///     label matches the lowercase convention used by every other source
///     (the Sigma logsource match in `ruled` is case-sensitive).
///
/// The original program name remains visible in `_raw`. Returns
/// `Some(canonical)` only when a rewrite is needed, so callers can skip the
/// allocation otherwise.
fn canonical_app_name(app: &str) -> Option<&'static str> {
    match app {
        "sshd-session" | "sshd-auth" => Some("sshd"),
        "CRON" => Some("cron"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Format;

    fn outcome(raw: &str, rules: &[OverrideRule]) -> parsers::ParseOutcome {
        parsers::parse(raw.as_bytes(), "127.0.0.1", rules)
    }

    fn flat_json(raw: &str, rules: &[OverrideRule], force: Option<&str>) -> String {
        let o = outcome(raw, rules);
        let ov = force.or(o.source.as_deref());
        let source = o.event.derive_source(ov);
        serialize_flat(&o.event.flatten(&source, "2026-06-27T00:00:00+00:00"))
    }

    #[test]
    fn rfc3164_line_buckets_to_app_name_source() {
        let o = outcome("<13>Jan 15 12:34:56 router sshd[1234]: Accepted publickey", &[]);
        assert_eq!(o.event.format, Format::Rfc3164);
        assert_eq!(o.event.derive_source(None), "sshd");
    }

    #[test]
    fn json_input_is_flattened_with_compat_keys() {
        let json = flat_json(
            r#"{"timestamp":"2024-01-01T00:00:00Z","host":"web1","message":"ok","status":"200"}"#,
            &[],
            None,
        );
        assert!(json.contains(r#""_format":"json""#));
        assert!(json.contains(r#""_normalized":true"#));
        assert!(json.contains(r#""timestamp":"2024-01-01T00:00:00Z""#));
        // every record carries _source_type and _received for the pipeline
        assert!(json.contains(r#""_source_type":"#));
        assert!(json.contains(r#""_received":"2026-06-27T00:00:00+00:00""#));
    }

    #[test]
    fn cef_src_dst_canonicalized_to_ip_fields() {
        let json = flat_json(
            "CEF:0|V|P|1.0|100|Login|5|src=10.0.0.1 dst=10.0.0.2 msg=test",
            &[],
            None,
        );
        assert!(json.contains(r#""src_ip":"10.0.0.1""#));
        assert!(json.contains(r#""dst_ip":"10.0.0.2""#));
    }

    #[test]
    fn override_rule_assigns_source_and_format() {
        let rules = vec![OverrideRule {
            contains: Some("filterlog".into()),
            source: Some("pfsense".into()),
            force_format: Some("plain".into()),
            ..Default::default()
        }];
        let o = outcome("filterlog: 1,2,3 something", &rules);
        assert_eq!(o.event.format, Format::Plain);
        assert_eq!(o.source.as_deref(), Some("pfsense"));
        assert_eq!(o.event.derive_source(o.source.as_deref()), "pfsense");
    }

    #[test]
    fn cli_force_source_beats_rule_and_app_name() {
        let json = flat_json(
            "<13>Jan 15 12:34:56 router sshd[1234]: hi",
            &[],
            Some("audit"),
        );
        assert!(json.contains(r#""_source_type":"audit""#));
    }

    #[test]
    fn cef_wrapped_in_syslog_is_reparsed() {
        let o = outcome(
            "<134>Nov 23 21:58:05 tap54 JATP: CEF:0|JATP|Cortex|3.6|http|TROJAN|8|src=10.0.0.1 dst=10.0.0.2",
            &[],
        );
        // payload format wins; transport recorded; syslog host preserved
        assert_eq!(o.event.format, Format::Cef);
        assert_eq!(o.event.hostname.as_deref(), Some("tap54"));
        let json = serialize_flat(&o.event.flatten("jatp", "2026-06-27T00:00:00Z"));
        assert!(json.contains(r#""_transport":"rfc3164""#));
        assert!(json.contains(r#""src_ip":"10.0.0.1""#));
        assert!(json.contains(r#""dst_ip":"10.0.0.2""#));
    }

    #[test]
    fn leef_without_app_tag_is_reparsed_via_raw_marker() {
        // No "app:" before LEEF: — the syslog tag parser eats "LEEF" as the tag,
        // so the marker is found in the raw line instead.
        let o = outcome(
            "<134>Sep 24 16:23:36 ovf-core LEEF:1.0|Cyphort|Cortex|5.0|http|src=172.16.1.101\tdst=172.16.1.105\tsev=10",
            &[],
        );
        assert_eq!(o.event.format, Format::Leef);
        assert_eq!(o.event.hostname.as_deref(), Some("ovf-core"));
        let json = serialize_flat(&o.event.flatten("leef", "2026-06-27T00:00:00Z"));
        assert!(json.contains(r#""src_ip":"172.16.1.101""#));
        assert!(json.contains(r#""dst_ip":"172.16.1.105""#));
    }

    #[test]
    fn prose_mentioning_cef_is_not_falsely_reparsed() {
        // "CEF:" in prose has no valid header → inner parser rejects it.
        let o = outcome("Jun 22 08:55:03 h app: deploying CEF: pipeline now", &[]);
        assert_eq!(o.event.format, Format::Rfc3164);
    }

    #[test]
    fn plain_syslog_message_is_not_reparsed() {
        // No CEF/LEEF/JSON prefix → stays rfc3164, message intact.
        let o = outcome("Jun 22 08:55:03 h sshd[1]: user=root action=login", &[]);
        assert_eq!(o.event.format, Format::Rfc3164);
    }

    #[test]
    fn plain_line_is_never_dropped() {
        let json = flat_json("totally unstructured line", &[], None);
        assert!(json.contains(r#""_normalized":false"#));
        assert!(json.contains(r#""_raw":"totally unstructured line""#));
    }

    #[test]
    fn app_names_are_canonicalized() {
        assert_eq!(canonical_app_name("sshd-session"), Some("sshd"));
        assert_eq!(canonical_app_name("sshd-auth"), Some("sshd"));
        // Debian's uppercase CRON folds to the lowercase convention.
        assert_eq!(canonical_app_name("CRON"), Some("cron"));
        // Already-canonical and unrelated names are left untouched.
        assert_eq!(canonical_app_name("sshd"), None);
        assert_eq!(canonical_app_name("cron"), None);
        assert_eq!(canonical_app_name("sudo"), None);
        assert_eq!(canonical_app_name("sshd-foo"), None);
    }

    #[test]
    fn strip_octet_count_handles_framing() {
        assert_eq!(strip_octet_count("12 hello world"), b"hello world");
        assert_eq!(strip_octet_count("no-count here"), b"no-count here");
    }

    // ── --since/--until time-range filter ─────────────────────────────────

    fn proc_window(
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
        drop_undated: bool,
    ) -> Processor {
        Processor {
            rules: vec![],
            extract: vec![],
            force_source: None,
            basis: BucketTime::Event,
            router: None,
            since,
            until,
            drop_undated,
            out: Mutex::new(io::stdout()),
        }
    }

    fn t(s: &str) -> Option<DateTime<Utc>> {
        output::parse_event_timestamp(s)
    }

    #[test]
    fn time_range_filters_by_event_time() {
        let since = output::parse_time_bound("2026-06-27T00:00:00Z");
        let until = output::parse_time_bound("2026-06-27T23:59:59Z");
        let p = proc_window(since, until, false);
        assert!(p.in_time_range(t("2026-06-27T12:00:00Z")), "in range");
        assert!(!p.in_time_range(t("2026-06-26T23:00:00Z")), "before since");
        assert!(!p.in_time_range(t("2026-06-28T00:00:01Z")), "after until");
    }

    #[test]
    fn no_bounds_passes_everything() {
        let p = proc_window(None, None, true);
        assert!(p.in_time_range(t("2026-06-27T12:00:00Z")));
        assert!(p.in_time_range(None));
    }

    #[test]
    fn undated_passes_by_default_drops_with_flag() {
        let since = output::parse_time_bound("2026-06-27T00:00:00Z");
        assert!(proc_window(since, None, false).in_time_range(None), "default: pass");
        assert!(!proc_window(since, None, true).in_time_range(None), "--drop-undated: drop");
    }
}

use output::AlertRouter;
use serde_json::Value;
use signal_hook::{consts::SIGTERM, consts::SIGINT, iterator::Signals};
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tracing::{error, info, warn};

mod output;
mod rules;

const USAGE: &str = "\
USAGE: ruled --rules <path> [--output <path>] [--dedup-window <secs>] [--help]

  --rules <path>          Directory containing Sigma YAML rule files
  --output <path>         Optional output directory for filesystem alerts
  --dedup-window <secs>   Suppress repeat alerts for the same (rule, key) within
                          this many seconds (default 5). 0 disables dedup —
                          use for batch/historical replay and to feed
                          count-based correlation without losing volume.
  --help                  Print this help

DESCRIPTION:
  Reads JSONL events from stdin, evaluates them against loaded Sigma rules,
  and writes alert JSONL to stdout. Non-matching events are silently consumed.

  Each alert is a JSON object with:
    - _ruled: true
    - rule_id: the Sigma rule id
    - rule_title: the Sigma rule title
    - level: the rule severity level
    - event: the original event that triggered the rule
    - timestamp: epoch seconds when the alert was generated

SIGNALS:
  SIGTERM / SIGINT — flush pending output and exit cleanly.
";

fn main() {
    // ── Initialize structured logging ────────────────────────────────
    // Default to INFO when RUST_LOG is unset so the operator sees the
    // "loaded N rules" / shutdown lines; respect RUST_LOG when set
    // (RUST_LOG=warn to quiet it, RUST_LOG=debug for more detail).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let mut rules_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut dedup_window_secs: u64 = 5;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            "--rules" => {
                rules_path = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    error!("--rules requires a path argument");
                    std::process::exit(1);
                })));
            }
            "--output" => {
                output_path = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    error!("--output requires a path argument");
                    std::process::exit(1);
                })));
            }
            "--dedup-window" => {
                let raw = args.next().unwrap_or_else(|| {
                    error!("--dedup-window requires a value in seconds");
                    std::process::exit(1);
                });
                dedup_window_secs = raw.parse().unwrap_or_else(|_| {
                    error!("--dedup-window: invalid number of seconds: {}", raw);
                    std::process::exit(1);
                });
            }
            other => {
                error!("unknown flag: {}", other);
                error!("use --help for usage");
                std::process::exit(1);
            }
        }
    }

    let rules_path = rules_path.unwrap_or_else(|| {
        error!("--rules <path> is required");
        error!("use --help for usage");
        std::process::exit(1);
    });

    if !rules_path.is_dir() {
        error!(
            "rules path does not exist or is not a directory: {}",
            rules_path.display()
        );
        std::process::exit(1);
    }

    // Load rules
    let rule_set = match rules::load_rules(&rules_path) {
        Ok(rs) => {
            info!(
                "loaded {} rules from {}",
                rs.len(),
                rules_path.display()
            );
            rs
        }
        Err(e) => {
            error!("failed to load rules: {}", e);
            std::process::exit(1);
        }
    };

    // Alert router
    let mut router = AlertRouter::new(output_path, dedup_window_secs);

    // Signal handling
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let mut signals = Signals::new([SIGTERM, SIGINT]).expect("ruled: failed to register signal handler");
    std::thread::spawn(move || {
        if signals.forever().next().is_some() {
            r.store(false, Ordering::SeqCst);
        }
    });

    // Main loop: read JSONL from stdin, evaluate rules, write alerts to stdout
    let stdin = io::stdin();
    let reader = BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line_result in reader.lines() {
        if !running.load(Ordering::SeqCst) {
            info!("received signal, shutting down");
            break;
        }

        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                warn!("read error: {}", e);
                break;
            }
        };

        if line.is_empty() {
            continue;
        }

        let event: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                warn!("skipping malformed JSON: {}", e);
                continue;
            }
        };

        // Evaluate all rules against this event
        for rule in &rule_set.rules {
            if rule.matches(&event) {
                let _ = router.emit(
                    &rule.id,
                    &rule.title,
                    &rule.level,
                    &event,
                    &mut out,
                );
            }
        }
    }

    router.flush();
    info!("shutdown complete");
}

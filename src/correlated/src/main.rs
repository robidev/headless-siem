use correlation::CrossRuleEngine;
use output::OutputRouter;
use serde_json::Value;
use signal_hook::{consts::SIGINT, consts::SIGTERM, iterator::Signals};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

mod config;
mod correlation;
mod output;

const USAGE: &str = "\
USAGE: correlated [--config <path>] [--output <path>] [--help]

  --config <path>   Path to correlations.toml defining correlation rules
  --output <path>   Optional output directory for filesystem correlation alerts
  --help            Print this help

DESCRIPTION:
  Reads alert JSONL from stdin (produced by ruled), evaluates each alert
  against cross-rule correlation patterns defined in correlations.toml,
  and emits a correlation alert whenever all steps of a rule are satisfied
  within the configured window.

  Each correlation alert is a JSON object with:
    - _correlated: true
    - correlation_id: the rule id from correlations.toml
    - correlation_title: the rule title
    - join_field: the field used to link alerts across steps (e.g. src_ip)
    - join_value: the actual field value (e.g. \"10.0.0.1\")
    - window_seconds: the configured window
    - chain_start / chain_end: epoch seconds of first and last matched alert
    - step_counts: how many times each step fired
    - sample_events: up to 5 representative events from the chain

  All input alerts are passed through to stdout unchanged; correlation alerts
  are emitted immediately before the alert that completed the chain.

  If --output is specified, correlation alerts are also written to
  <output>/YYYY/MM/DD/HH/correlated.jsonl.

  If --config is omitted, no correlations are evaluated and all alerts pass
  through unmodified.

SIGNALS:
  SIGTERM / SIGINT — flush pending output and exit cleanly.
";

fn main() {
    let mut config_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            "--config" => {
                config_path = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("[correlated] --config requires a path argument");
                    std::process::exit(1);
                })));
            }
            "--output" => {
                output_path = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("[correlated] --output requires a path argument");
                    std::process::exit(1);
                })));
            }
            other => {
                eprintln!("[correlated] unknown flag: {}", other);
                eprintln!("[correlated] use --help for usage");
                std::process::exit(1);
            }
        }
    }

    let corr_config = match config_path {
        Some(ref path) => {
            config::CorrelationConfig::load(path).unwrap_or_else(|e| {
                eprintln!("[correlated] failed to load correlation config {}: {}", path.display(), e);
                std::process::exit(1);
            })
        }
        None => {
            eprintln!("[correlated] no --config provided; running in passthrough mode (no correlations evaluated)");
            config::CorrelationConfig::empty()
        }
    };

    eprintln!(
        "[correlated] loaded {} correlation rule(s)",
        corr_config.rules.len()
    );
    for rule in &corr_config.rules {
        eprintln!(
            "[correlated]   rule '{}': {} step(s), join_field={}, window={}s, ordered={}",
            rule.id,
            rule.steps.len(),
            rule.join_field,
            rule.window_seconds,
            rule.ordered,
        );
    }

    let mut engine = CrossRuleEngine::new(corr_config.rules);
    let router = OutputRouter::new(output_path);

    // Signal handling via signal_hook::iterator (self-pipe trick).
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let mut signals =
        Signals::new([SIGTERM, SIGINT]).expect("[correlated] failed to register signal handlers");
    std::thread::spawn(move || {
        if signals.forever().next().is_some() {
            r.store(false, Ordering::SeqCst);
        }
    });

    let stdin = io::stdin();
    let reader = BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line_result in reader.lines() {
        if !running.load(Ordering::SeqCst) {
            eprintln!("[correlated] received signal, shutting down");
            break;
        }

        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[correlated] read error: {}", e);
                break;
            }
        };

        if line.is_empty() {
            continue;
        }

        let alert: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[correlated] skipping malformed JSON: {}", e);
                continue;
            }
        };

        // Evaluate correlation rules and emit any triggered alerts first.
        for corr in engine.feed(&alert) {
            let corr_line = serde_json::to_string(&corr).unwrap();
            if let Err(e) = router.emit(&corr_line, &mut out) {
                eprintln!("[correlated] output error: {}", e);
                break;
            }
        }

        // Pass the original alert through to stdout.
        if let Err(e) = writeln!(out, "{}", line) {
            eprintln!("[correlated] stdout write error: {}", e);
            break;
        }
    }

    eprintln!("[correlated] shutdown complete");
}

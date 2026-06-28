#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use tempfile::NamedTempFile;

    fn run_correlated(input: &str, args: &[&str]) -> Vec<String> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_correlated"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn correlated");

        {
            let stdin = child.stdin.as_mut().unwrap();
            stdin.write_all(input.as_bytes()).unwrap();
        }

        let output = child.wait_with_output().unwrap();
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|s| s.to_string())
            .collect()
    }

    /// Build a ruled-format alert with nested event fields.
    fn make_alert(rule_id: &str, src_ip: &str) -> String {
        format!(
            r#"{{"_ruled":true,"rule_id":"{}","rule_title":"Test","level":"medium","event":{{"src_ip":"{}"}},"timestamp":0}}"#,
            rule_id, src_ip
        )
    }

    fn make_alert_user(rule_id: &str, username: &str) -> String {
        format!(
            r#"{{"_ruled":true,"rule_id":"{}","rule_title":"Test","level":"medium","event":{{"username":"{}"}},"timestamp":0}}"#,
            rule_id, username
        )
    }

    /// Write a TOML config to a temp file; caller must keep the handle alive.
    fn write_config(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn single_step_cfg(rule_id: &str, min_count: usize, window: u64) -> String {
        format!(
            r#"
[[rule]]
id           = "test-rule"
title        = "Test Rule"
join_field   = "src_ip"
window_seconds = {window}
ordered      = false

  [[rule.step]]
  rule_id   = "{rule_id}"
  min_count = {min_count}
"#
        )
    }

    // ── passthrough behaviour ─────────────────────────────────────────────

    #[test]
    fn test_passthrough_no_config() {
        let mut input = String::new();
        for _ in 0..3 {
            input.push_str(&make_alert("rule-1", "10.0.0.1"));
            input.push('\n');
        }
        let lines = run_correlated(&input, &[]);
        assert_eq!(lines.len(), 3, "all alerts pass through in no-config mode");
        assert!(!lines.iter().any(|l| l.contains("_correlated")));
    }

    #[test]
    fn test_empty_input() {
        let lines = run_correlated("", &[]);
        assert!(lines.is_empty(), "empty input → no output");
    }

    #[test]
    fn test_blank_lines_ignored() {
        let lines = run_correlated("\n\n\n", &[]);
        assert!(lines.is_empty(), "blank lines are skipped");
    }

    #[test]
    fn test_malformed_json_skipped() {
        // "not json" is skipped; the valid JSON object passes through
        let input = "not json\n{\"rule_id\":\"foo\",\"_ruled\":true}\n";
        let lines = run_correlated(input, &[]);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("rule_id"));
    }

    // ── single-step threshold rules ───────────────────────────────────────

    #[test]
    fn test_below_threshold_no_correlation() {
        let cfg = write_config(&single_step_cfg("rule-1", 5, 300));
        let mut input = String::new();
        for _ in 0..4 {
            input.push_str(&make_alert("rule-1", "10.0.0.1"));
            input.push('\n');
        }
        let lines = run_correlated(&input, &["--config", cfg.path().to_str().unwrap()]);
        assert_eq!(lines.len(), 4, "all 4 alerts pass through, none trigger correlation");
        assert!(!lines.iter().any(|l| l.contains("_correlated")));
    }

    #[test]
    fn test_threshold_triggers_correlation() {
        let cfg = write_config(&single_step_cfg("rule-1", 3, 300));
        let mut input = String::new();
        for _ in 0..5 {
            input.push_str(&make_alert("rule-1", "10.0.0.1"));
            input.push('\n');
        }
        let lines = run_correlated(&input, &["--config", cfg.path().to_str().unwrap()]);
        // 5 passthrough + 1 correlation (fires at alert 3; alerts 4-5 restart a new chain)
        assert_eq!(lines.len(), 6, "5 alerts + 1 correlation");
        let corr = lines.iter().find(|l| l.contains("_correlated")).unwrap();
        assert!(corr.contains("\"correlation_id\":\"test-rule\""));
        assert!(corr.contains("\"step_counts\":[3]"));
        assert!(corr.contains("\"join_value\":\"10.0.0.1\""));
    }

    #[test]
    fn test_window_seconds_in_output() {
        let cfg = write_config(&single_step_cfg("rule-1", 3, 60));
        let mut input = String::new();
        for _ in 0..3 {
            input.push_str(&make_alert("rule-1", "10.0.0.1"));
            input.push('\n');
        }
        let lines = run_correlated(&input, &["--config", cfg.path().to_str().unwrap()]);
        let corr = lines.iter().find(|l| l.contains("_correlated")).unwrap();
        assert!(corr.contains("\"window_seconds\":60"));
    }

    #[test]
    fn test_rapid_fire_resets_and_fires_multiple_times() {
        let cfg = write_config(&single_step_cfg("rule-1", 3, 300));
        let mut input = String::new();
        for _ in 0..9 {
            input.push_str(&make_alert("rule-1", "10.0.0.1"));
            input.push('\n');
        }
        let lines = run_correlated(&input, &["--config", cfg.path().to_str().unwrap()]);
        let corr_count = lines.iter().filter(|l| l.contains("_correlated")).count();
        // chain resets on each fire: fires at alert 3, 6, 9 → 3 correlations
        assert_eq!(corr_count, 3, "fires and resets at each multiple of min_count");
        assert_eq!(lines.len(), 12, "9 passthrough + 3 correlations");
    }

    #[test]
    fn test_different_ips_tracked_independently() {
        let cfg = write_config(&single_step_cfg("rule-1", 2, 300));
        let mut input = String::new();
        // 1 alert from each of 5 different IPs — none should correlate
        for i in 1..=5 {
            input.push_str(&make_alert("rule-1", &format!("10.0.0.{}", i)));
            input.push('\n');
        }
        let lines = run_correlated(&input, &["--config", cfg.path().to_str().unwrap()]);
        assert!(!lines.iter().any(|l| l.contains("_correlated")));
        // 2 alerts from IP 10.0.0.1 → should correlate
        let mut extra = String::new();
        extra.push_str(&make_alert("rule-1", "10.0.0.1"));
        extra.push('\n');
        extra.push_str(&make_alert("rule-1", "10.0.0.1"));
        extra.push('\n');
        let lines2 = run_correlated(&extra, &["--config", cfg.path().to_str().unwrap()]);
        assert_eq!(lines2.iter().filter(|l| l.contains("_correlated")).count(), 1);
    }

    // ── ordered two-step chain ────────────────────────────────────────────

    #[test]
    fn test_ordered_two_step_fires() {
        let cfg_str = r#"
[[rule]]
id           = "cred-guess"
title        = "Credential Guessing Success"
join_field   = "src_ip"
window_seconds = 300
ordered      = true

  [[rule.step]]
  rule_id   = "ssh-fail"
  min_count = 2

  [[rule.step]]
  rule_id   = "ssh-ok"
  min_count = 1
"#;
        let cfg = write_config(cfg_str);
        let mut input = String::new();
        input.push_str(&make_alert("ssh-fail", "10.0.0.1"));
        input.push('\n');
        input.push_str(&make_alert("ssh-fail", "10.0.0.1"));
        input.push('\n');
        input.push_str(&make_alert("ssh-ok", "10.0.0.1"));
        input.push('\n');
        let lines = run_correlated(&input, &["--config", cfg.path().to_str().unwrap()]);
        assert_eq!(lines.iter().filter(|l| l.contains("_correlated")).count(), 1);
        let corr = lines.iter().find(|l| l.contains("_correlated")).unwrap();
        assert!(corr.contains("\"correlation_id\":\"cred-guess\""));
        assert!(corr.contains("\"step_counts\":[2,1]"));
    }

    #[test]
    fn test_ordered_wrong_order_no_fire() {
        let cfg_str = r#"
[[rule]]
id = "cred-guess"
title = "Test"
join_field = "src_ip"
window_seconds = 300
ordered = true

  [[rule.step]]
  rule_id = "ssh-fail"
  min_count = 2

  [[rule.step]]
  rule_id = "ssh-ok"
  min_count = 1
"#;
        let cfg = write_config(cfg_str);
        // Success before failures — ordered=true, so ok doesn't count for step 1 yet
        let mut input = String::new();
        input.push_str(&make_alert("ssh-ok", "10.0.0.1"));
        input.push('\n');
        input.push_str(&make_alert("ssh-fail", "10.0.0.1"));
        input.push('\n');
        input.push_str(&make_alert("ssh-fail", "10.0.0.1"));
        input.push('\n');
        let lines = run_correlated(&input, &["--config", cfg.path().to_str().unwrap()]);
        assert!(!lines.iter().any(|l| l.contains("_correlated")),
            "success before failures should not trigger ordered rule");
    }

    #[test]
    fn test_join_field_username() {
        let cfg_str = r#"
[[rule]]
id = "priv-esc"
title = "Privilege Escalation"
join_field = "username"
window_seconds = 60
ordered = true

  [[rule.step]]
  rule_id = "user-created"
  min_count = 1

  [[rule.step]]
  rule_id = "sudo-exec"
  min_count = 1
"#;
        let cfg = write_config(cfg_str);
        let mut input = String::new();
        input.push_str(&make_alert_user("user-created", "alice"));
        input.push('\n');
        input.push_str(&make_alert_user("sudo-exec", "alice"));
        input.push('\n');
        // Different user should not correlate
        input.push_str(&make_alert_user("user-created", "bob"));
        input.push('\n');
        let lines = run_correlated(&input, &["--config", cfg.path().to_str().unwrap()]);
        let corr_count = lines.iter().filter(|l| l.contains("_correlated")).count();
        assert_eq!(corr_count, 1);
        let corr = lines.iter().find(|l| l.contains("_correlated")).unwrap();
        assert!(corr.contains("\"join_value\":\"alice\""));
    }

    // ── flags ─────────────────────────────────────────────────────────────

    #[test]
    fn test_help_flag() {
        let output = Command::new(env!("CARGO_BIN_EXE_correlated"))
            .arg("--help")
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("USAGE:"));
        assert!(stdout.contains("--config"));
        assert!(stdout.contains("--output"));
    }

    #[test]
    fn test_unknown_flag() {
        let output = Command::new(env!("CARGO_BIN_EXE_correlated"))
            .arg("--bogus")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("unknown flag"));
    }

    #[test]
    fn test_bad_config_path_exits_nonzero() {
        let output = Command::new(env!("CARGO_BIN_EXE_correlated"))
            .args(["--config", "/nonexistent/path/correlations.toml"])
            .stdin(Stdio::piped())
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
}

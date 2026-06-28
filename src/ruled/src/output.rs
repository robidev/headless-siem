use serde_json::Value;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Routes alerts to stdout and optionally to the filesystem.
pub struct AlertRouter {
    /// Optional output directory for filesystem alerts.
    output_dir: Option<PathBuf>,
    /// Deduplication cache: (rule_id, dedup_key) → last_seen_timestamp
    dedup_cache: HashMap<(String, String), u64>,
    /// Deduplication window in seconds.
    dedup_window_secs: u64,
}

impl AlertRouter {
    /// Create a new AlertRouter.
    ///
    /// If `output_dir` is Some, alerts are also written to
    /// `<output_dir>/YYYY/MM/DD/HH/alerts.jsonl`.
    pub fn new(output_dir: Option<PathBuf>) -> Self {
        AlertRouter {
            output_dir,
            dedup_cache: HashMap::new(),
            dedup_window_secs: 5,
        }
    }

    /// Write an alert to stdout and optionally to the filesystem.
    ///
    /// Returns true if the alert was emitted (not deduplicated).
    pub fn emit(
        &mut self,
        rule_id: &str,
        rule_title: &str,
        level: &str,
        event: &Value,
        out: &mut dyn Write,
    ) -> io::Result<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Build dedup key from event's key fields
        let dedup_key = build_dedup_key(event);

        // Check dedup cache
        if let Some(&last_seen) = self.dedup_cache.get(&(rule_id.to_string(), dedup_key.clone())) {
            if now - last_seen < self.dedup_window_secs {
                return Ok(false); // suppressed
            }
        }

        // Update cache
        self.dedup_cache
            .insert((rule_id.to_string(), dedup_key), now);

        // Build alert JSON
        let alert = serde_json::json!({
            "_ruled": true,
            "rule_id": rule_id,
            "rule_title": rule_title,
            "level": level,
            "event": event,
            "timestamp": now,
        });

        let alert_line = serde_json::to_string(&alert).unwrap();

        // Write to stdout
        writeln!(out, "{}", alert_line)?;

        // Write to filesystem if configured
        if let Some(ref dir) = self.output_dir {
            self.write_to_filesystem(dir, &alert_line, now)?;
        }

        Ok(true)
    }

    /// Write an alert line to the filesystem hierarchy.
    fn write_to_filesystem(&self, base_dir: &Path, line: &str, now_secs: u64) -> io::Result<()> {
        let (y, m, d, h) = bucket_from_epoch(now_secs);
        let bucket_dir = base_dir
            .join(format!("{:04}", y))
            .join(format!("{:02}", m))
            .join(format!("{:02}", d))
            .join(format!("{:02}", h));

        fs::create_dir_all(&bucket_dir)?;

        let alert_path = bucket_dir.join("alerts.jsonl");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&alert_path)?;

        writeln!(file, "{}", line)?;
        Ok(())
    }

    /// Flush the dedup cache (e.g., on shutdown).
    pub fn flush(&mut self) {
        self.dedup_cache.clear();
    }
}

/// Build a deduplication key from an event's identifying fields.
///
/// Uses src_ip + event_type if available, otherwise falls back to
/// a hash of the event's string representation.
fn build_dedup_key(event: &Value) -> String {
    let src_ip = event
        .get("src_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let event_type = event
        .get("event_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if !src_ip.is_empty() || !event_type.is_empty() {
        format!("{}|{}", src_ip, event_type)
    } else {
        // Fallback: use first 64 chars of event string
        let raw = serde_json::to_string(event).unwrap_or_default();
        raw.chars().take(64).collect()
    }
}

/// Convert epoch seconds to (year, month, day, hour).
fn bucket_from_epoch(secs: u64) -> (u64, u64, u64, u64) {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;

    let (y, m, d) = days_to_date(days);
    (y, m, d, hour)
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_date(days: u64) -> (u64, u64, u64) {
    let mut remaining = days;
    let mut year = 1970u64;

    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }

    let month_days = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u64;
    for &md in &month_days {
        if remaining < md {
            break;
        }
        remaining -= md;
        month += 1;
    }

    (year, month, remaining + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dedup_key_with_fields() {
        let event = serde_json::json!({
            "src_ip": "10.0.0.5",
            "event_type": "SSH_FAILED_PASSWORD"
        });
        assert_eq!(build_dedup_key(&event), "10.0.0.5|SSH_FAILED_PASSWORD");
    }

    #[test]
    fn test_build_dedup_key_empty() {
        let event = serde_json::json!({"message": "test"});
        let key = build_dedup_key(&event);
        assert!(!key.is_empty());
    }

    #[test]
    fn test_dedup_suppresses_duplicate() {
        let mut router = AlertRouter::new(None);
        let event = serde_json::json!({
            "src_ip": "10.0.0.5",
            "event_type": "SSH_FAILED_PASSWORD"
        });

        let mut buf: Vec<u8> = Vec::new();

        // First emit should succeed
        let emitted = router
            .emit("rule-1", "Test Rule", "medium", &event, &mut buf)
            .unwrap();
        assert!(emitted);
        assert!(!buf.is_empty());

        // Second emit within 5s should be suppressed
        buf.clear();
        let emitted2 = router
            .emit("rule-1", "Test Rule", "medium", &event, &mut buf)
            .unwrap();
        assert!(!emitted2);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_dedup_different_rules_not_suppressed() {
        let mut router = AlertRouter::new(None);
        let event = serde_json::json!({
            "src_ip": "10.0.0.5",
            "event_type": "SSH_FAILED_PASSWORD"
        });

        let mut buf: Vec<u8> = Vec::new();

        router
            .emit("rule-1", "Rule 1", "medium", &event, &mut buf)
            .unwrap();
        buf.clear();
        let emitted = router
            .emit("rule-2", "Rule 2", "high", &event, &mut buf)
            .unwrap();
        assert!(emitted);
    }

    #[test]
    fn test_dedup_different_events_not_suppressed() {
        let mut router = AlertRouter::new(None);
        let event1 = serde_json::json!({
            "src_ip": "10.0.0.5",
            "event_type": "SSH_FAILED_PASSWORD"
        });
        let event2 = serde_json::json!({
            "src_ip": "10.0.0.6",
            "event_type": "SSH_FAILED_PASSWORD"
        });

        let mut buf: Vec<u8> = Vec::new();

        router
            .emit("rule-1", "Rule 1", "medium", &event1, &mut buf)
            .unwrap();
        buf.clear();
        let emitted = router
            .emit("rule-1", "Rule 1", "medium", &event2, &mut buf)
            .unwrap();
        assert!(emitted);
    }

    #[test]
    fn test_filesystem_output() {
        let tmp = tempfile::tempdir().unwrap();
        let mut router = AlertRouter::new(Some(tmp.path().to_path_buf()));
        let event = serde_json::json!({
            "src_ip": "10.0.0.5",
            "event_type": "SSH_FAILED_PASSWORD"
        });

        let mut buf: Vec<u8> = Vec::new();
        router
            .emit("rule-1", "Test Rule", "medium", &event, &mut buf)
            .unwrap();

        // Should have created the alerts directory structure
        let alerts_dir = tmp.path().join("2026");
        assert!(alerts_dir.exists(), "alerts dir should exist");

        // Find the alerts.jsonl file somewhere under the tree
        let mut found = false;
        for entry in walkdir::WalkDir::new(tmp.path()) {
            let entry = entry.unwrap();
            if entry.file_name() == "alerts.jsonl" {
                found = true;
                let content = std::fs::read_to_string(entry.path()).unwrap();
                assert!(content.contains("rule-1"));
                assert!(content.contains("Test Rule"));
                break;
            }
        }
        assert!(found, "alerts.jsonl should exist");
    }

    #[test]
    fn test_bucket_from_epoch() {
        // 2026-06-22 11:00 UTC ≈ secs 1782126000
        let (y, m, d, h) = bucket_from_epoch(1782126000);
        assert_eq!(y, 2026);
        assert_eq!(m, 6);
        assert_eq!(d, 22);
        assert_eq!(h, 11);
    }
}

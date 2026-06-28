use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Routes correlation alerts to stdout and optionally to the filesystem.
pub struct OutputRouter {
    /// Optional output directory for filesystem correlation alerts.
    output_dir: Option<PathBuf>,
}

impl OutputRouter {
    /// Create a new OutputRouter.
    ///
    /// If `output_dir` is Some, correlation alerts are also written to
    /// `<output_dir>/YYYY/MM/DD/HH/correlated.jsonl`.
    pub fn new(output_dir: Option<PathBuf>) -> Self {
        OutputRouter { output_dir }
    }

    /// Write a correlation alert line to stdout and optionally to the filesystem.
    pub fn emit(&self, line: &str, out: &mut dyn Write) -> io::Result<()> {
        // Write to stdout
        writeln!(out, "{}", line)?;

        // Write to filesystem if configured
        if let Some(ref dir) = self.output_dir {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.write_to_filesystem(dir, line, now)?;
        }

        Ok(())
    }

    /// Write a line to the filesystem hierarchy.
    fn write_to_filesystem(&self, base_dir: &Path, line: &str, now_secs: u64) -> io::Result<()> {
        let (y, m, d, h) = bucket_from_epoch(now_secs);
        let bucket_dir = base_dir
            .join(format!("{:04}", y))
            .join(format!("{:02}", m))
            .join(format!("{:02}", d))
            .join(format!("{:02}", h));

        fs::create_dir_all(&bucket_dir)?;

        let alert_path = bucket_dir.join("correlated.jsonl");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&alert_path)?;

        writeln!(file, "{}", line)?;
        Ok(())
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
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_from_epoch() {
        // 2026-06-22 11:00 UTC ≈ secs 1782126000
        let (y, m, d, h) = bucket_from_epoch(1782126000);
        assert_eq!(y, 2026);
        assert_eq!(m, 6);
        assert_eq!(d, 22);
        assert_eq!(h, 11);
    }

    #[test]
    fn test_filesystem_output() {
        let tmp = tempfile::tempdir().unwrap();
        let router = OutputRouter::new(Some(tmp.path().to_path_buf()));

        let mut buf: Vec<u8> = Vec::new();
        router
            .emit(
                r#"{"_correlated":true,"rule_id":"rule-1","rule_title":"Test","count":5}"#,
                &mut buf,
            )
            .unwrap();

        // Should have written to stdout
        assert!(!buf.is_empty());

        // Should have created the correlated directory structure
        let mut found = false;
        for entry in walkdir::WalkDir::new(tmp.path()) {
            let entry = entry.unwrap();
            if entry.file_name() == "correlated.jsonl" {
                found = true;
                let content = std::fs::read_to_string(entry.path()).unwrap();
                assert!(content.contains("rule-1"));
                assert!(content.contains("_correlated"));
                break;
            }
        }
        assert!(found, "correlated.jsonl should exist");
    }

    #[test]
    fn test_stdout_only() {
        let router = OutputRouter::new(None);
        let mut buf: Vec<u8> = Vec::new();
        router
            .emit(r#"{"_correlated":true}"#, &mut buf)
            .unwrap();
        assert!(buf.starts_with(b"{"));
    }
}

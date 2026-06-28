/// Time-bucketed filesystem storage.
///
/// Preserves the on-disk layout of the original `normalized`:
///   <data_dir>/raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl   (one JSON object per line)
///   <data_dir>/raw/YYYY/MM/DD/HH/MM/SS/<source>.tsv     (6-column grep sidecar)
///
/// The first write to a bucket file is atomic (temp file + rename); subsequent
/// writes append (atomic for small writes on POSIX). Buckets are keyed either
/// by the event's own timestamp or by receive time (see `BucketTime`).
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, TimeZone, Utc};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::event::FlatVal;

/// Which clock drives the bucket directory path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketTime {
    /// Use the event's own timestamp, falling back to receive time.
    Event,
    /// Always use wall-clock receive time.
    Receive,
}

pub struct OutputRouter {
    data_dir: PathBuf,
}

impl OutputRouter {
    pub fn new(data_dir: &Path) -> Self {
        OutputRouter {
            data_dir: data_dir.to_path_buf(),
        }
    }

    /// Write one normalized record to its time bucket (JSONL + TSV sidecar).
    ///
    /// `json_line` is the already-serialized flat JSON (no trailing newline).
    /// `source` is the derived source label (already sanitized).
    /// `fields` is the flattened map, used to extract TSV columns and the
    /// event timestamp for `BucketTime::Event`.
    pub fn write(
        &self,
        json_line: &str,
        source: &str,
        fields: &BTreeMap<String, FlatVal>,
        received: DateTime<Utc>,
        basis: BucketTime,
    ) -> io::Result<()> {
        let bucket_dt = match basis {
            BucketTime::Receive => received,
            BucketTime::Event => event_time(fields).unwrap_or(received),
        };

        let rel_path = format!(
            "raw/{}/{}/{}/{}/{}/{}/{}.jsonl",
            bucket_dt.format("%Y"),
            bucket_dt.format("%m"),
            bucket_dt.format("%d"),
            bucket_dt.format("%H"),
            bucket_dt.format("%M"),
            bucket_dt.format("%S"),
            source,
        );
        let full_path = self.data_dir.join(&rel_path);

        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)?;
        }

        append_or_create(&full_path, json_line)?;
        self.write_tsv_sidecar(&full_path, source, fields)?;
        Ok(())
    }

    /// Write the 6-column TSV sidecar: timestamp, src_ip, dst_ip, event_type,
    /// severity, source. First write includes the header (atomic); later
    /// writes append a single data row.
    fn write_tsv_sidecar(
        &self,
        jsonl_path: &Path,
        source: &str,
        fields: &BTreeMap<String, FlatVal>,
    ) -> io::Result<()> {
        let tsv_path = jsonl_path.with_extension("tsv");
        let is_new = !tsv_path.exists();

        let row = format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            str_field(fields, "timestamp").unwrap_or(""),
            str_field(fields, "src_ip").unwrap_or(""),
            str_field(fields, "dst_ip").unwrap_or(""),
            str_field(fields, "event_type").unwrap_or(""),
            str_field(fields, "severity").unwrap_or(""),
            source,
        );

        if is_new {
            let tmp = tsv_path.with_extension("tsv.tmp");
            {
                let mut f = fs::File::create(&tmp)?;
                writeln!(f, "timestamp\tsrc_ip\tdst_ip\tevent_type\tseverity\tsource")?;
                writeln!(f, "{}", row)?;
            }
            fs::rename(&tmp, &tsv_path)?;
        } else {
            let mut f = fs::OpenOptions::new().append(true).open(&tsv_path)?;
            writeln!(f, "{}", row)?;
        }
        Ok(())
    }
}

/// Append `line` to `path`, or atomically create the file via temp + rename.
fn append_or_create(path: &Path, line: &str) -> io::Result<()> {
    if path.exists() {
        let mut f = fs::OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(f, "{}", line)?;
    } else {
        let tmp = path.with_extension("jsonl.tmp");
        {
            let mut f = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp)?;
            writeln!(f, "{}", line)?;
        }
        fs::rename(&tmp, path)?;
    }
    Ok(())
}

/// Parse the event's own `timestamp` field into UTC, if present and parseable.
/// Shared by the bucketer and the `--since/--until` normalization-time filter
/// so both agree on what an event's time is.
pub fn event_time(fields: &BTreeMap<String, FlatVal>) -> Option<DateTime<Utc>> {
    str_field(fields, "timestamp").and_then(parse_event_timestamp)
}

/// Parse a `--since` / `--until` CLI value into UTC. Accepts everything
/// [`parse_event_timestamp`] does (RFC 3339, ISO without zone, BSD syslog) plus
/// a bare `YYYY-MM-DD` date, interpreted as midnight UTC (start of that day).
pub fn parse_time_bound(s: &str) -> Option<DateTime<Utc>> {
    if let Some(dt) = parse_event_timestamp(s) {
        return Some(dt);
    }
    let d = NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").ok()?;
    Some(Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0)?))
}

fn str_field<'a>(fields: &'a BTreeMap<String, FlatVal>, key: &str) -> Option<&'a str> {
    match fields.get(key) {
        Some(FlatVal::Str(s)) => Some(s.as_str()),
        _ => None,
    }
}

/// Best-effort parse of an event timestamp into UTC, covering the formats the
/// parser chain emits (RFC 3339, ISO without zone, BSD syslog). Returns `None`
/// if none match, so the caller can fall back to receive time.
pub fn parse_event_timestamp(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();

    // RFC 3339 / ISO 8601 with timezone (rfc5424, JSON, logfmt).
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }

    // ISO without timezone — assume UTC.
    for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&naive));
        }
    }

    // BSD syslog "Mon DD HH:MM:SS" — no year, assume the current one.
    let year = Utc::now().year();
    for fmt in ["%b %e %H:%M:%S", "%b %d %H:%M:%S"] {
        if let Ok(naive) =
            NaiveDateTime::parse_from_str(&format!("{} {}", year, s), &format!("%Y {}", fmt))
        {
            return Some(Utc.from_utc_datetime(&naive));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("hsiem_norm_out_{}_{}", std::process::id(), n));
            fs::create_dir_all(&p).unwrap();
            TempDir { path: p }
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn fields_with(ts: &str, src: &str) -> BTreeMap<String, FlatVal> {
        let mut m = BTreeMap::new();
        m.insert("timestamp".into(), FlatVal::Str(ts.into()));
        m.insert("src_ip".into(), FlatVal::Str(src.into()));
        m
    }

    #[test]
    fn parse_rfc3339_and_syslog_and_iso() {
        assert!(parse_event_timestamp("2026-06-27T08:55:03Z").is_some());
        assert!(parse_event_timestamp("2026-06-27 08:55:03").is_some());
        let bsd = parse_event_timestamp("Jun 27 08:55:03").unwrap();
        assert_eq!(bsd.hour(), 8);
        assert_eq!(bsd.minute(), 55);
        assert!(parse_event_timestamp("totally not a timestamp").is_none());
    }

    #[test]
    fn parse_time_bound_accepts_rfc3339_iso_and_date_only() {
        assert!(parse_time_bound("2026-06-27T08:55:03Z").is_some());
        assert!(parse_time_bound("2026-06-27 08:55:03").is_some());
        // Bare date → midnight UTC.
        let d = parse_time_bound("2026-06-27").unwrap();
        assert_eq!(d.hour(), 0);
        assert_eq!(d.minute(), 0);
        assert_eq!(d.second(), 0);
        assert!(parse_time_bound("not a date").is_none());
    }

    #[test]
    fn event_time_reads_timestamp_field() {
        let mut m = BTreeMap::new();
        m.insert("timestamp".to_string(), FlatVal::Str("2026-06-27T08:55:03Z".into()));
        assert!(event_time(&m).is_some());

        let mut none = BTreeMap::new();
        none.insert("timestamp".to_string(), FlatVal::Str("garbage".into()));
        assert!(event_time(&none).is_none());
        assert!(event_time(&BTreeMap::new()).is_none());
    }

    #[test]
    fn write_event_basis_uses_event_timestamp() {
        let tmp = TempDir::new();
        let r = OutputRouter::new(&tmp.path);
        let fields = fields_with("2026-06-27T08:55:03Z", "10.0.0.5");
        let received = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();

        r.write(r#"{"x":1}"#, "sshd", &fields, received, BucketTime::Event)
            .unwrap();

        let jsonl = tmp
            .path
            .join("raw/2026/06/27/08/55/03/sshd.jsonl");
        let tsv = tmp.path.join("raw/2026/06/27/08/55/03/sshd.tsv");
        assert!(jsonl.exists(), "expected {:?}", jsonl);
        assert!(tsv.exists());
        let tsv_body = fs::read_to_string(&tsv).unwrap();
        assert!(tsv_body.lines().next().unwrap().starts_with("timestamp\t"));
        assert!(tsv_body.contains("10.0.0.5"));
    }

    #[test]
    fn write_receive_basis_uses_received_time() {
        let tmp = TempDir::new();
        let r = OutputRouter::new(&tmp.path);
        let fields = fields_with("2026-06-27T08:55:03Z", "10.0.0.5");
        let received = Utc.with_ymd_and_hms(2030, 1, 2, 3, 4, 5).unwrap();

        r.write(r#"{"x":1}"#, "sshd", &fields, received, BucketTime::Receive)
            .unwrap();

        assert!(tmp.path.join("raw/2030/01/02/03/04/05/sshd.jsonl").exists());
    }

    #[test]
    fn append_adds_second_line_same_bucket() {
        let tmp = TempDir::new();
        let r = OutputRouter::new(&tmp.path);
        let fields = fields_with("2026-06-27T08:55:03Z", "10.0.0.5");
        let received = Utc::now();
        r.write(r#"{"n":1}"#, "sshd", &fields, received, BucketTime::Event).unwrap();
        r.write(r#"{"n":2}"#, "sshd", &fields, received, BucketTime::Event).unwrap();

        let jsonl = tmp.path.join("raw/2026/06/27/08/55/03/sshd.jsonl");
        let body = fs::read_to_string(&jsonl).unwrap();
        assert_eq!(body.lines().count(), 2);
        assert!(!tmp.path.join("raw/2026/06/27/08/55/03/sshd.jsonl.tmp").exists());
    }

    #[test]
    fn falls_back_to_received_when_event_ts_unparseable() {
        let tmp = TempDir::new();
        let r = OutputRouter::new(&tmp.path);
        let fields = fields_with("garbage", "10.0.0.5");
        let received = Utc.with_ymd_and_hms(2031, 5, 6, 7, 8, 9).unwrap();
        r.write(r#"{"x":1}"#, "sshd", &fields, received, BucketTime::Event).unwrap();
        assert!(tmp.path.join("raw/2031/05/06/07/08/09/sshd.jsonl").exists());
    }
}

use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc};
use std::path::{Path, PathBuf};

/// An hour-precision time bucket matching the data directory layout
/// `data/raw/YYYY/MM/DD/HH/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HourBucket {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
}

impl HourBucket {
    /// Parse `YYYY-MM-DDTHH` (or `YYYY-MM-DDTHH:MM:SS…`).
    pub fn parse(s: &str) -> Option<Self> {
        let (date, time) = s.split_once('T')?;
        let mut d = date.split('-');
        let year: i32 = d.next()?.parse().ok()?;
        let month: u8 = d.next()?.parse().ok()?;
        let day: u8 = d.next()?.parse().ok()?;
        let hour: u8 = time.split(':').next()?.parse().ok()?;
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 {
            return None;
        }
        Some(Self { year, month, day, hour })
    }

    /// Parse from a bucket filename like `2026-06-22-08.db` (indexd writes the
    /// `YYYY/MM/DD/HH` bucket key with slashes replaced by dashes).
    pub fn from_filename(name: &str) -> Option<Self> {
        let base = name.strip_suffix(".db").unwrap_or(name);
        let mut p = base.split('-');
        let year: i32 = p.next()?.parse().ok()?;
        let month: u8 = p.next()?.parse().ok()?;
        let day: u8 = p.next()?.parse().ok()?;
        let hour: u8 = p.next()?.parse().ok()?;
        if p.next().is_some() {
            return None;
        }
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 {
            return None;
        }
        Some(Self { year, month, day, hour })
    }

    /// Returns `base/YYYY/MM/DD/HH` — the same hour-bucket directory layout
    /// used under `data/raw/`, `data/alerts/`, and `data/alerts/correlated/`.
    pub fn dir_under(&self, base: &Path) -> PathBuf {
        base.join(format!("{:04}", self.year))
            .join(format!("{:02}", self.month))
            .join(format!("{:02}", self.day))
            .join(format!("{:02}", self.hour))
    }

    /// Truncate a `DateTime<Utc>` down to its hour bucket.
    pub fn from_datetime(dt: DateTime<Utc>) -> Self {
        Self { year: dt.year(), month: dt.month() as u8, day: dt.day() as u8, hour: dt.hour() as u8 }
    }

    /// This bucket's start instant.
    pub fn to_datetime(self) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(self.year, self.month as u32, self.day as u32, self.hour as u32, 0, 0)
            .single()
            .expect("HourBucket always holds a valid calendar hour")
    }

    /// The next hour bucket after this one.
    pub fn advance(self) -> Self {
        let mut h = self.hour + 1;
        let mut d = self.day;
        let mut m = self.month;
        let mut y = self.year;
        if h > 23 {
            h = 0;
            d += 1;
            if d > days_in_month(m, y) {
                d = 1;
                m += 1;
                if m > 12 {
                    m = 1;
                    y += 1;
                }
            }
        }
        Self { year: y, month: m, day: d, hour: h }
    }

    /// Advance by `n` hours (`n == 0` returns `self` unchanged).
    pub fn advance_by(self, n: u32) -> Self {
        let mut cur = self;
        for _ in 0..n {
            cur = cur.advance();
        }
        cur
    }

    /// Compact, unambiguous label for a trend-table column header:
    /// `"MM-DD HH:00"`. Always date-qualified (unlike the digest's
    /// same-day-collapsing `fmt_header_times`) since `stats --interval` is
    /// an investigation tool a specialist reads closely, not a Tier-1
    /// agent's every-run summary — clarity wins over compactness here.
    pub fn label(&self) -> String {
        format!("{:02}-{:02} {:02}:00", self.month, self.day, self.hour)
    }
}

fn days_in_month(m: u8, y: i32) -> u8 {
    match m {
        4 | 6 | 9 | 11 => 30,
        2 => {
            if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => 31,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_filename_parses_dashed_bucket() {
        let b = HourBucket::from_filename("2026-06-22-08.db").unwrap();
        assert_eq!(b, HourBucket { year: 2026, month: 6, day: 22, hour: 8 });
    }

    #[test]
    fn from_filename_without_suffix() {
        let b = HourBucket::from_filename("2026-12-31-23").unwrap();
        assert_eq!(b, HourBucket { year: 2026, month: 12, day: 31, hour: 23 });
    }

    #[test]
    fn from_filename_rejects_garbage() {
        assert!(HourBucket::from_filename("not-a-bucket.db").is_none());
        assert!(HourBucket::from_filename("2026-13-01-00.db").is_none()); // bad month
        assert!(HourBucket::from_filename("2026-06-22-08-09.db").is_none()); // extra field
    }

    #[test]
    fn dir_under_builds_year_month_day_hour_path() {
        let b = HourBucket { year: 2026, month: 6, day: 22, hour: 8 };
        assert_eq!(b.dir_under(Path::new("data/alerts")), Path::new("data/alerts/2026/06/22/08"));
        assert_eq!(
            b.dir_under(Path::new("data/alerts/correlated")),
            Path::new("data/alerts/correlated/2026/06/22/08")
        );
    }

    #[test]
    fn from_filename_ordering_matches_parse() {
        let a = HourBucket::from_filename("2026-06-22-08.db").unwrap();
        let b = HourBucket::parse("2026-06-22T09").unwrap();
        assert!(a < b);
    }

    #[test]
    fn from_datetime_truncates_to_the_hour() {
        let dt = Utc.with_ymd_and_hms(2026, 6, 22, 8, 42, 17).unwrap();
        assert_eq!(HourBucket::from_datetime(dt), HourBucket { year: 2026, month: 6, day: 22, hour: 8 });
    }

    #[test]
    fn to_datetime_round_trips_from_datetime() {
        let dt = Utc.with_ymd_and_hms(2026, 6, 22, 8, 0, 0).unwrap();
        assert_eq!(HourBucket::from_datetime(dt).to_datetime(), dt);
    }

    #[test]
    fn advance_by_crosses_day_month_year_boundaries() {
        let b = HourBucket { year: 2026, month: 6, day: 22, hour: 22 };
        assert_eq!(b.advance_by(0), b);
        assert_eq!(b.advance_by(2), HourBucket { year: 2026, month: 6, day: 23, hour: 0 });
        let ny = HourBucket { year: 2026, month: 12, day: 31, hour: 23 };
        assert_eq!(ny.advance_by(1), HourBucket { year: 2027, month: 1, day: 1, hour: 0 });
    }

    #[test]
    fn label_is_month_day_hour() {
        let b = HourBucket { year: 2026, month: 6, day: 22, hour: 8 };
        assert_eq!(b.label(), "06-22 08:00");
    }

    // ── dirs_in_range_under ──────────────────────────────────────────────

    #[test]
    fn dirs_in_range_under_finds_dirs_beyond_the_old_one_year_cap() {
        // Regression test: a fixed `366 * 24 + 1`-iteration cap used to
        // silently truncate any [from, to] span over ~1 year, which is
        // exactly what `siemctl alerts --before <cutoff>` (no `--after`)
        // hits — it defaults the missing lower bound to a year-2000
        // sentinel, so the range to any real cutoff is decades long.
        let n = std::sync::atomic::AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "hsiem_time_test_{}_{}",
            std::process::id(),
            n.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&base);
        let real = HourBucket { year: 2026, month: 7, day: 20, hour: 2 };
        std::fs::create_dir_all(real.dir_under(&base)).unwrap();

        // ~2.5 years / ~21,900 hours — well past the old 8,785-hour cap.
        let from = HourBucket { year: 2024, month: 1, day: 1, hour: 0 };
        let to = HourBucket { year: 2026, month: 7, day: 20, hour: 23 };
        let dirs = dirs_in_range_under(&base, from, to);

        std::fs::remove_dir_all(&base).ok();
        assert_eq!(dirs, vec![real.dir_under(&base)]);
    }

    #[test]
    fn dirs_in_range_under_from_after_to_is_empty() {
        let base = Path::new("/nonexistent/base");
        let from = HourBucket { year: 2026, month: 7, day: 20, hour: 5 };
        let to = HourBucket { year: 2026, month: 7, day: 20, hour: 4 };
        assert!(dirs_in_range_under(base, from, to).is_empty());
    }
}

/// Yield existing `raw/` hour directories in [`from`, `to`] (inclusive).
pub fn hour_dirs_in_range(data_dir: &Path, from: HourBucket, to: HourBucket) -> Vec<PathBuf> {
    dirs_in_range_under(&data_dir.join("raw"), from, to)
}

/// Yield existing hour-bucket directories `base/YYYY/MM/DD/HH` in
/// `[from, to]` (inclusive) — the same walk as [`hour_dirs_in_range`], under
/// an arbitrary base (e.g. `data_dir/alerts` or `data_dir/alerts/correlated`
/// for `siemctl alerts`, not just `data_dir/raw`).
pub fn dirs_in_range_under(base: &Path, from: HourBucket, to: HourBucket) -> Vec<PathBuf> {
    let mut result = Vec::new();
    if from > to {
        return result;
    }
    // Iterate exactly the number of hour buckets in [from, to] — a fixed
    // `366 * 24 + 1` cap here previously silently truncated any range over
    // ~1 year (e.g. `--before` alone, which defaults the missing `--after`
    // to a year-2000 sentinel: a ~26-year span that exhausted the old cap
    // while still stuck in 2000-2001, before ever reaching real data).
    let hours = (to.to_datetime() - from.to_datetime()).num_hours();
    let mut cur = from;
    for _ in 0..=hours {
        let dir = cur.dir_under(base);
        if dir.is_dir() {
            result.push(dir);
        }
        cur = cur.advance();
    }
    result
}

// ── Digest window math ───────────────────────────────────────────────────────
//
// `siemctl digest` needs second-precision time arithmetic (window/baseline
// boundaries that don't align to hour boundaries, N-minute sparkline
// buckets), which the hand-rolled `HourBucket` above isn't built for. Rather
// than extend `HourBucket`'s hand-rolled calendar math (`advance`,
// `days_in_month`) to sub-hour precision, this section uses `chrono` — the
// same crate `normalized` already relies on for exactly this kind of
// concern, and everything under `data/raw/` is bucketed by UTC (see
// `src/normalized/src/main.rs`/`output.rs`, both `chrono::Utc`), so `Utc` is
// the correct clock to compute "now" against here too.
//
/// An analysis window: `[start, end)` in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl Window {
    pub fn duration(&self) -> Duration {
        self.end - self.start
    }

    /// The baseline window: the same duration immediately preceding `self`.
    pub fn baseline(&self) -> Window {
        let dur = self.duration();
        Window { start: self.start - dur, end: self.start }
    }

    /// A window of exactly `dur`, ending at `self.end` — independent of
    /// `self`'s own duration, unlike [`Window::baseline`]. Used where a
    /// comparison needs a duration decoupled from `--window` itself (e.g.
    /// the digest's coverage section, which wants a multi-day lookback
    /// regardless of how short the digest's own window is).
    pub fn lookback(&self, dur: Duration) -> Window {
        Window { start: self.end - dur, end: self.end }
    }
}

/// Parse a relative duration like `"10m"`, `"6h"`, `"24h"`, `"2d"`, `"45s"`.
/// The unit is a single trailing letter (`s`/`m`/`h`/`d`); the magnitude must
/// be a positive integer.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.len() < 2 {
        return Err(format!("invalid duration '{s}' (expected e.g. '10m', '6h', '24h')"));
    }
    let (num_part, unit) = s.split_at(s.len() - 1);
    let n: i64 = num_part
        .parse()
        .map_err(|_| format!("invalid duration '{s}' (expected e.g. '10m', '6h', '24h')"))?;
    if n <= 0 {
        return Err(format!("duration must be positive: '{s}'"));
    }
    match unit {
        "s" => Ok(Duration::seconds(n)),
        "m" => Ok(Duration::minutes(n)),
        "h" => Ok(Duration::hours(n)),
        "d" => Ok(Duration::days(n)),
        _ => Err(format!("invalid duration unit in '{s}' (expected one of s/m/h/d)")),
    }
}

/// Parse a `--window` value: either a relative duration ending at `now`
/// (`"6h"`) or an explicit `start..end` range
/// (`"2026-06-29T18..2026-06-29T20"`). Each side of an explicit range accepts
/// `YYYY-MM-DDTHH[:MM[:SS]]`, with missing minute/second defaulting to 0.
pub fn parse_window(s: &str, now: DateTime<Utc>) -> Result<Window, String> {
    if let Some((lo, hi)) = s.split_once("..") {
        let start = parse_explicit_timestamp(lo.trim())?;
        let end = parse_explicit_timestamp(hi.trim())?;
        if end <= start {
            return Err(format!("--window range end must be after start: '{s}'"));
        }
        return Ok(Window { start, end });
    }
    let dur = parse_duration(s)?;
    Ok(Window { start: now - dur, end: now })
}

/// Parse `YYYY-MM-DDTHH[:MM[:SS]]` into a UTC instant.
fn parse_explicit_timestamp(s: &str) -> Result<DateTime<Utc>, String> {
    let invalid = || format!("invalid timestamp '{s}' (expected YYYY-MM-DDTHH[:MM[:SS]])");
    let (date, time) = s.split_once('T').ok_or_else(invalid)?;

    let mut d = date.split('-');
    let year: i32 = d.next().and_then(|x| x.parse().ok()).ok_or_else(invalid)?;
    let month: u32 = d.next().and_then(|x| x.parse().ok()).ok_or_else(invalid)?;
    let day: u32 = d.next().and_then(|x| x.parse().ok()).ok_or_else(invalid)?;
    if d.next().is_some() {
        return Err(invalid());
    }

    let mut t = time.split(':');
    let hour: u32 = t.next().and_then(|x| x.parse().ok()).ok_or_else(invalid)?;
    let minute: u32 = match t.next() {
        Some(m) => m.parse().map_err(|_| invalid())?,
        None => 0,
    };
    let second: u32 = match t.next() {
        Some(sec) => sec.parse().map_err(|_| invalid())?,
        None => 0,
    };
    if t.next().is_some() {
        return Err(invalid());
    }

    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
        .ok_or_else(invalid)
}

/// The `raw_file` index column stores paths like
/// `raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl` — zero-padded, so it sorts
/// lexicographically in the same order as chronologically. This formats the
/// prefix for a given instant, for use in `WHERE raw_file >= ? AND raw_file
/// < ?` range predicates (no new indexed column needed for sub-hour
/// precision).
fn raw_file_bound(t: DateTime<Utc>) -> String {
    format!(
        "raw/{:04}/{:02}/{:02}/{:02}/{:02}/{:02}",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// The `[lo, hi)` `raw_file` string bounds for a window, for a
/// `WHERE raw_file >= ? AND raw_file < ?` predicate.
pub fn raw_file_range(win: &Window) -> (String, String) {
    (raw_file_bound(win.start), raw_file_bound(win.end))
}

/// Recover the exact UTC event time from a `raw_file` column value
/// (`raw/YYYY/MM/DD/HH/MM/SS/<source>.jsonl`). Returns `None` for anything
/// that doesn't match that shape (e.g. a pre-migration row with no
/// `raw_file`).
pub fn parse_raw_file_time(raw_file: &str) -> Option<DateTime<Utc>> {
    let rest = raw_file.strip_prefix("raw/")?;
    let mut p = rest.split('/');
    let year: i32 = p.next()?.parse().ok()?;
    let month: u32 = p.next()?.parse().ok()?;
    let day: u32 = p.next()?.parse().ok()?;
    let hour: u32 = p.next()?.parse().ok()?;
    let minute: u32 = p.next()?.parse().ok()?;
    let second: u32 = p.next()?.parse().ok()?;
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second).single()
}

#[cfg(test)]
mod digest_window_tests {
    use super::*;

    fn ymdhms(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).single().unwrap()
    }

    // ── parse_duration ───────────────────────────────────────────────────

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration("45s").unwrap(), Duration::seconds(45));
        assert_eq!(parse_duration("10m").unwrap(), Duration::minutes(10));
        assert_eq!(parse_duration("6h").unwrap(), Duration::hours(6));
        assert_eq!(parse_duration("24h").unwrap(), Duration::hours(24));
        assert_eq!(parse_duration("2d").unwrap(), Duration::days(2));
    }

    #[test]
    fn parse_duration_rejects_bad_input() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("h").is_err());
        assert!(parse_duration("10").is_err());
        assert!(parse_duration("10x").is_err());
        assert!(parse_duration("0h").is_err());
        assert!(parse_duration("-5h").is_err());
        assert!(parse_duration("abch").is_err());
    }

    // ── parse_window ─────────────────────────────────────────────────────

    #[test]
    fn parse_window_relative_ends_at_now() {
        let now = ymdhms(2026, 6, 29, 20, 0, 0);
        let w = parse_window("6h", now).unwrap();
        assert_eq!(w.end, now);
        assert_eq!(w.start, ymdhms(2026, 6, 29, 14, 0, 0));
    }

    #[test]
    fn parse_window_relative_crosses_month_boundary() {
        let now = ymdhms(2026, 3, 1, 2, 0, 0);
        let w = parse_window("6h", now).unwrap();
        assert_eq!(w.start, ymdhms(2026, 2, 28, 20, 0, 0));
    }

    #[test]
    fn parse_window_relative_crosses_year_boundary() {
        let now = ymdhms(2027, 1, 1, 2, 0, 0);
        let w = parse_window("6h", now).unwrap();
        assert_eq!(w.start, ymdhms(2026, 12, 31, 20, 0, 0));
    }

    #[test]
    fn parse_window_explicit_range_hour_precision() {
        let now = ymdhms(2026, 6, 29, 23, 0, 0);
        let w = parse_window("2026-06-29T18..2026-06-29T20", now).unwrap();
        assert_eq!(w.start, ymdhms(2026, 6, 29, 18, 0, 0));
        assert_eq!(w.end, ymdhms(2026, 6, 29, 20, 0, 0));
    }

    #[test]
    fn parse_window_explicit_range_minute_second_precision() {
        let now = ymdhms(2026, 6, 29, 23, 0, 0);
        let w = parse_window("2026-06-29T18:05:30..2026-06-29T18:10:00", now).unwrap();
        assert_eq!(w.start, ymdhms(2026, 6, 29, 18, 5, 30));
        assert_eq!(w.end, ymdhms(2026, 6, 29, 18, 10, 0));
    }

    #[test]
    fn parse_window_rejects_backwards_range() {
        let now = ymdhms(2026, 6, 29, 23, 0, 0);
        assert!(parse_window("2026-06-29T20..2026-06-29T18", now).is_err());
        assert!(parse_window("2026-06-29T18..2026-06-29T18", now).is_err());
    }

    #[test]
    fn parse_window_rejects_malformed_range() {
        let now = ymdhms(2026, 6, 29, 23, 0, 0);
        assert!(parse_window("2026-06-29T18..not-a-time", now).is_err());
        assert!(parse_window("2026-13-01T18..2026-06-29T20", now).is_err()); // bad month
    }

    // ── Window::baseline ─────────────────────────────────────────────────

    #[test]
    fn baseline_is_same_duration_immediately_before() {
        let w = Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 20, 0, 0) };
        let b = w.baseline();
        assert_eq!(b.start, ymdhms(2026, 6, 29, 8, 0, 0));
        assert_eq!(b.end, ymdhms(2026, 6, 29, 14, 0, 0));
        assert_eq!(b.duration(), w.duration());
    }

    #[test]
    fn baseline_crosses_month_boundary() {
        let w = Window { start: ymdhms(2026, 3, 1, 0, 0, 0), end: ymdhms(2026, 3, 1, 6, 0, 0) };
        let b = w.baseline();
        assert_eq!(b.start, ymdhms(2026, 2, 28, 18, 0, 0));
        assert_eq!(b.end, ymdhms(2026, 3, 1, 0, 0, 0));
    }

    // ── Window::lookback ─────────────────────────────────────────────────

    #[test]
    fn lookback_ends_at_self_end_with_the_given_duration() {
        let w = Window { start: ymdhms(2026, 6, 29, 14, 0, 0), end: ymdhms(2026, 6, 29, 15, 0, 0) };
        let lb = w.lookback(Duration::hours(24));
        assert_eq!(lb.end, w.end);
        assert_eq!(lb.start, ymdhms(2026, 6, 28, 15, 0, 0));
    }

    #[test]
    fn lookback_is_independent_of_self_duration() {
        // A 5-minute window still yields a full 24h lookback, unlike
        // `baseline()` which would mirror the 5-minute span.
        let w = Window { start: ymdhms(2026, 6, 29, 14, 55, 0), end: ymdhms(2026, 6, 29, 15, 0, 0) };
        let lb = w.lookback(Duration::hours(24));
        assert_eq!(lb.duration(), Duration::hours(24));
        assert_ne!(lb.duration(), w.duration());
    }

    // ── raw_file_range / parse_raw_file_time ────────────────────────────

    #[test]
    fn raw_file_range_formats_zero_padded_bounds() {
        let w = Window { start: ymdhms(2026, 6, 22, 8, 5, 3), end: ymdhms(2026, 6, 22, 9, 0, 0) };
        let (lo, hi) = raw_file_range(&w);
        assert_eq!(lo, "raw/2026/06/22/08/05/03");
        assert_eq!(hi, "raw/2026/06/22/09/00/00");
    }

    #[test]
    fn raw_file_range_bounds_sort_correctly_against_real_paths() {
        let w = Window { start: ymdhms(2026, 6, 22, 8, 55, 3), end: ymdhms(2026, 6, 22, 8, 55, 7) };
        let (lo, hi) = raw_file_range(&w);
        // A file at exactly `start` is included; one at exactly `end` is not.
        assert!("raw/2026/06/22/08/55/03/sshd.jsonl" >= lo.as_str());
        assert!("raw/2026/06/22/08/55/07/sshd.jsonl" >= hi.as_str());
        assert!("raw/2026/06/22/08/55/06/sshd.jsonl" < hi.as_str());
        assert!("raw/2026/06/22/08/55/02/sshd.jsonl" < lo.as_str());
    }

    #[test]
    fn parse_raw_file_time_round_trips() {
        let t = ymdhms(2026, 6, 22, 8, 55, 3);
        let raw_file = format!("{}/sshd.jsonl", raw_file_bound(t));
        assert_eq!(parse_raw_file_time(&raw_file), Some(t));
    }

    #[test]
    fn parse_raw_file_time_rejects_malformed() {
        assert_eq!(parse_raw_file_time(""), None);
        assert_eq!(parse_raw_file_time("not-a-raw-file"), None);
        assert_eq!(parse_raw_file_time("raw/2026/06/22/08"), None); // missing MM/SS
        assert_eq!(parse_raw_file_time("raw/2026/13/22/08/05/03/x.jsonl"), None); // bad month, but chrono itself rejects it via .single()
    }
}

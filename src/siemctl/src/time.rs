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

    /// Parse from a bucket filename like `2026062208.db`.
    pub fn from_filename(name: &str) -> Option<Self> {
        let base = name.strip_suffix(".db").unwrap_or(name);
        if base.len() < 10 {
            return None;
        }
        let year: i32 = base[0..4].parse().ok()?;
        let month: u8 = base[4..6].parse().ok()?;
        let day: u8 = base[6..8].parse().ok()?;
        let hour: u8 = base[8..10].parse().ok()?;
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 {
            return None;
        }
        Some(Self { year, month, day, hour })
    }

    /// Returns `data_dir/raw/YYYY/MM/DD/HH`.
    pub fn raw_dir(&self, data_dir: &Path) -> PathBuf {
        data_dir
            .join("raw")
            .join(format!("{:04}", self.year))
            .join(format!("{:02}", self.month))
            .join(format!("{:02}", self.day))
            .join(format!("{:02}", self.hour))
    }

    fn advance(self) -> Self {
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

/// Yield existing `raw/` hour directories in [`from`, `to`] (inclusive).
pub fn hour_dirs_in_range(data_dir: &Path, from: HourBucket, to: HourBucket) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let mut cur = from;
    for _ in 0..(366 * 24 + 1) {
        if cur > to {
            break;
        }
        let dir = cur.raw_dir(data_dir);
        if dir.is_dir() {
            result.push(dir);
        }
        cur = cur.advance();
    }
    result
}

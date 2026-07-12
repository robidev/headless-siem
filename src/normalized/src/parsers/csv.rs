/// CSV / TSV / pipe-delimited parser.
///
/// Auto-detects the delimiter by counting occurrences of `,`, `\t`, `|`, and `;`
/// in the first line and picking the one with the most consistent count across
/// all lines. Returns `None` when no consistent delimiter is found.

use std::collections::HashMap;
use crate::event::{Event, Format};

const CANDIDATES: &[u8] = &[b'\t', b'|', b',', b';'];
/// Minimum fields per row to qualify as structured
const MIN_FIELDS: usize = 2;
/// Minimum rows (including header) to confirm delimiter
const MIN_ROWS: usize = 1;

pub fn parse(raw: &[u8], source_addr: &str) -> Option<Event> {
    let s = std::str::from_utf8(raw).ok()?;
    let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        return None;
    }

    let (delim, _count) = detect_delimiter(&lines)?;

    // Split all rows
    let rows: Vec<Vec<String>> = lines
        .iter()
        .map(|l| split_csv(l, delim))
        .collect();

    let field_count = rows[0].len();
    if field_count < MIN_FIELDS {
        return None;
    }

    // Check consistency: every row must have the same number of fields (±1)
    let consistent = rows.iter().all(|r| {
        (r.len() as isize - field_count as isize).unsigned_abs() <= 1
    });
    if !consistent && rows.len() > MIN_ROWS {
        return None;
    }

    // Build fields
    let mut fields = HashMap::new();

    // If the first row looks like a header (no purely numeric values), use as keys
    let (headers, data_rows): (Vec<String>, &[Vec<String>]) = {
        let first = &rows[0];
        let looks_like_header = first.iter().any(|v| !v.trim().parse::<f64>().is_ok());
        if looks_like_header && rows.len() > 1 {
            (first.clone(), &rows[1..])
        } else {
            // Generate col_0, col_1, ...
            let hdrs = (0..field_count).map(|i| format!("col_{}", i)).collect();
            (hdrs, &rows[..])
        }
    };

    // Flatten all data rows; if multiple rows, prefix with row index
    let multi = data_rows.len() > 1;
    for (ri, row) in data_rows.iter().enumerate() {
        for (ci, val) in row.iter().enumerate() {
            let key = if ci < headers.len() {
                headers[ci].trim().to_owned()
            } else {
                format!("col_{}", ci)
            };
            let field_key = if multi {
                format!("[{}].{}", ri, key)
            } else {
                key
            };
            fields.insert(field_key, val.to_owned());
        }
    }

    let message = format!(
        "{} rows × {} cols (delim: {})",
        data_rows.len(),
        field_count,
        delim_name(delim),
    );

    Some(Event {
        format: Format::Csv,
        source_addr: source_addr.to_owned(),
        facility: None,
        severity: None,
        timestamp: fields.remove("timestamp")
            .or_else(|| fields.remove("time")),
        hostname: fields.remove("hostname")
            .or_else(|| fields.remove("host")),
        app_name: None,
        proc_id: None,
        msg_id: None,
        message,
        fields,
        force_severity: false,
        raw: raw.to_vec(),
    })
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn detect_delimiter(lines: &[&str]) -> Option<(u8, usize)> {
    let mut best: Option<(u8, usize)> = None;
    for &d in CANDIDATES {
        let counts: Vec<usize> = lines.iter().map(|l| count_delim(l, d)).collect();
        let first = counts[0];
        if first < MIN_FIELDS - 1 { continue; }
        // All lines should have the same count
        let consistent = counts.iter().all(|&c| c == first || c == 0);
        if consistent {
            if best.is_none() || first > best.unwrap().1 {
                best = Some((d, first));
            }
        }
    }
    best
}

fn count_delim(s: &str, d: u8) -> usize {
    s.bytes().filter(|&b| b == d).count()
}

/// Minimal CSV splitter: handles double-quoted fields.
fn split_csv(s: &str, delim: u8) -> Vec<String> {
    let delim_char = delim as char;
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut prev_quote = false;

    for c in s.chars() {
        if c == '"' {
            if in_quotes && prev_quote {
                cur.push('"');
                prev_quote = false;
            } else if in_quotes {
                prev_quote = true;
            } else {
                in_quotes = true;
            }
        } else if c == delim_char && !in_quotes {
            if prev_quote { in_quotes = false; prev_quote = false; }
            fields.push(cur.trim().to_owned());
            cur.clear();
        } else {
            if prev_quote { in_quotes = false; prev_quote = false; }
            cur.push(c);
        }
    }
    fields.push(cur.trim().to_owned());
    fields
}

fn delim_name(d: u8) -> &'static str {
    match d {
        b'\t' => "tab",
        b'|'  => "pipe",
        b','  => "comma",
        b';'  => "semicolon",
        _     => "?",
    }
}

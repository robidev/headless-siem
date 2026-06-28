/// Plain-text fallback parser.
///
/// Always succeeds. Stores the raw text as `message`.

use std::collections::HashMap;
use crate::event::{Event, Format};

pub fn parse(raw: &[u8], source_addr: &str) -> Event {
    let message = std::str::from_utf8(raw)
        .unwrap_or("[binary data]")
        .trim()
        .to_owned();

    Event {
        format: Format::Plain,
        source_addr: source_addr.to_owned(),
        facility: None,
        severity: None,
        timestamp: None,
        hostname: None,
        app_name: None,
        proc_id: None,
        msg_id: None,
        message,
        fields: HashMap::new(),
        raw: raw.to_vec(),
    }
}

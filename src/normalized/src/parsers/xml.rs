/// Minimal XML parser.
///
/// Extracts tag names, attributes, and text content — enough to populate
/// the normalized schema without a full DOM.  Nested elements are flattened
/// with dot-notation: `parent.child = "text"`.
///
/// No external XML library is used; this is a hand-rolled streaming tokenizer.

use std::collections::HashMap;
use crate::event::{Event, Format};

pub fn parse(raw: &[u8], source_addr: &str) -> Option<Event> {
    let s = std::str::from_utf8(raw).ok()?;
    let s = s.trim();

    // Quick sanity check
    if !s.starts_with('<') {
        return None;
    }

    let mut fields = HashMap::new();
    extract_fields(s, &mut fields);

    if fields.is_empty() {
        return None;
    }

    // Find a "message" or "msg" key anywhere in the flat map (e.g. "event.message")
    let message = {
        let direct = fields.remove("message").or_else(|| fields.remove("msg")).or_else(|| fields.remove("text"));
        if direct.is_some() {
            direct.unwrap()
        } else {
            // Try dotted keys: "root.message", "root.msg", etc.
            let key = fields.keys()
                .find(|k| k.ends_with(".message") || k.ends_with(".msg") || k.ends_with(".text"))
                .cloned();
            match key {
                Some(k) => fields.remove(&k).unwrap_or_default(),
                None => find_root_element(s).unwrap_or_else(|| "xml".to_owned()),
            }
        }
    };

    Some(Event {
        format: Format::Xml,
        source_addr: source_addr.to_owned(),
        facility: None,
        severity: None,
        timestamp: fields.remove("timestamp")
            .or_else(|| fields.remove("time"))
            .or_else(|| fields.remove("datetime")),
        hostname: fields.remove("hostname")
            .or_else(|| fields.remove("host")),
        app_name: fields.remove("app_name")
            .or_else(|| fields.remove("application")),
        proc_id: None,
        msg_id: None,
        message,
        fields,
        raw: raw.to_vec(),
    })
}

fn find_root_element(s: &str) -> Option<String> {
    let s = s.trim_start_matches(|c: char| c.is_whitespace());
    // Skip XML declaration
    let s = if s.starts_with("<?") {
        s.find(">").map(|i| &s[i + 1..]).unwrap_or(s)
    } else {
        s
    };
    let s = s.trim_start_matches(|c: char| c.is_whitespace());
    if s.starts_with('<') {
        let name_end = s[1..].find(|c: char| c.is_whitespace() || c == '>' || c == '/');
        name_end.map(|e| s[1..1 + e].to_owned())
    } else {
        None
    }
}

/// Walk the XML string and populate `fields` with element/attribute paths.
fn extract_fields(s: &str, fields: &mut HashMap<String, String>) {
    let mut stack: Vec<String> = Vec::new();
    let mut i = 0;
    let bytes = s.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'<' {
            let tag_end = match find_closing_angle(s, i) {
                Some(e) => e,
                None => break,
            };
            let tag_content = &s[i + 1..tag_end];

            if tag_content.starts_with('!') || tag_content.starts_with('?') {
                // Comment or PI — skip
                i = tag_end + 1;
                continue;
            }

            if tag_content.starts_with('/') {
                // Closing tag
                stack.pop();
                i = tag_end + 1;
                continue;
            }

            let self_closing = tag_content.ends_with('/');
            let tag_body = if self_closing {
                &tag_content[..tag_content.len() - 1]
            } else {
                tag_content
            };

            // Tag name
            let name_end = tag_body.find(|c: char| c.is_whitespace()).unwrap_or(tag_body.len());
            let tag_name = tag_body[..name_end].to_owned();
            if tag_name.is_empty() {
                i = tag_end + 1;
                continue;
            }

            if !self_closing {
                stack.push(tag_name.clone());
            }

            let current_path = if stack.is_empty() || self_closing {
                if stack.is_empty() {
                    tag_name.clone()
                } else {
                    format!("{}.{}", stack[..stack.len().saturating_sub(if self_closing {0} else {1})].join("."), tag_name)
                }
            } else {
                stack.join(".")
            };

            // Attributes
            let attr_str = &tag_body[name_end..];
            extract_attributes(attr_str, &current_path, fields);

            i = tag_end + 1;

            // If not self-closing, grab text content up to the next `<`
            if !self_closing {
                if let Some(lt) = s[i..].find('<') {
                    let text = s[i..i + lt].trim();
                    if !text.is_empty() {
                        fields.insert(current_path, text.to_owned());
                    }
                    i += lt;
                }
            }
        } else {
            i += 1;
        }
    }
}

fn find_closing_angle(s: &str, start: usize) -> Option<usize> {
    // Handle `<!-- ... -->`
    if s[start..].starts_with("<!--") {
        return s[start..].find("-->").map(|i| start + i + 2);
    }
    let mut in_str = false;
    let mut str_char = '"';
    for (off, ch) in s[start..].char_indices() {
        if in_str {
            if ch == str_char { in_str = false; }
        } else if ch == '"' || ch == '\'' {
            in_str = true;
            str_char = ch;
        } else if ch == '>' {
            return Some(start + off);
        }
    }
    None
}

fn extract_attributes(s: &str, prefix: &str, fields: &mut HashMap<String, String>) {
    let mut rest = s.trim();
    while !rest.is_empty() {
        rest = rest.trim_start();
        if rest.is_empty() { break; }
        // key="value" or key='value' or key=value
        let eq = match rest.find('=') {
            Some(e) => e,
            None => break,
        };
        let key = rest[..eq].trim().to_owned();
        rest = &rest[eq + 1..];
        let (val, tail) = if rest.starts_with('"') {
            extract_until(&rest[1..], '"')
        } else if rest.starts_with('\'') {
            extract_until(&rest[1..], '\'')
        } else {
            let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
            (rest[..end].to_owned(), &rest[end..])
        };
        if !key.is_empty() {
            fields.insert(format!("{}.@{}", prefix, key), val);
        }
        rest = tail;
    }
}

fn extract_until<'a>(s: &'a str, delim: char) -> (String, &'a str) {
    let mut out = String::new();
    for (i, c) in s.char_indices() {
        if c == delim {
            return (out, &s[i + 1..]);
        }
        out.push(c);
    }
    (out, "")
}

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

/// Parse `sources.toml` and return the union of all `index_fields` values,
/// plus a hard-coded set of always-valid fields present in every bucket.
pub fn load_valid_fields(path: &Path) -> HashSet<String> {
    let mut fields = always_valid();
    fields.extend(load_index_fields(path));
    fields
}

/// Parse `sources.toml` and return only the *declared* `index_fields` union —
/// without the always-valid core fields that [`load_valid_fields`] seeds in.
/// Used by the `validate` cross-check to reason about what was explicitly
/// configured for indexing.
pub fn load_index_fields(path: &Path) -> HashSet<String> {
    let mut fields: HashSet<String> = HashSet::new();
    let Ok(content) = std::fs::read_to_string(path) else {
        return fields;
    };
    let mut in_array = false;
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        if t.starts_with("index_fields") && t.contains('=') {
            in_array = true;
        }
        if in_array {
            // Extract every "quoted_string" on this line.
            let mut rest = t;
            while let Some(i) = rest.find('"') {
                rest = &rest[i + 1..];
                if let Some(j) = rest.find('"') {
                    let f = &rest[..j];
                    if !f.is_empty() {
                        fields.insert(f.to_string());
                    }
                    rest = &rest[j + 1..];
                } else {
                    break;
                }
            }
            if t.contains(']') {
                in_array = false;
            }
        }
    }
    fields
}

/// Fields that are always present in every index bucket regardless of
/// `sources.toml`, so they are always searchable and never count as
/// "unindexed" in the validate cross-check.
pub fn always_valid() -> HashSet<String> {
    ["timestamp", "source", "src_ip", "dst_ip", "src_port", "dst_port",
     "event_type", "username", "severity"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Locate `config/sources.toml` relative to cwd or the running binary.
pub fn find_sources_toml() -> Option<PathBuf> {
    for rel in &["config/sources.toml", "../config/sources.toml"] {
        let p = Path::new(rel);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    // Walk up from the binary: siemctl lives at src/siemctl/target/{debug,release}/siemctl
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?;
    for _ in 0..6 {
        let c = dir.join("config").join("sources.toml");
        if c.is_file() {
            return Some(c);
        }
        dir = dir.parent()?;
    }
    None
}

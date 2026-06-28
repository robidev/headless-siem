use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};

/// Configuration for a single log source (only the fields we need).
#[derive(Debug, Clone)]
pub struct SourceConfig {
    pub index_fields: Vec<String>,
}

/// Top-level configuration loaded from sources.toml.
#[derive(Debug, Clone)]
pub struct Config {
    pub sources: HashMap<String, SourceConfig>,
}

/// Raw TOML structure for a single source entry.
#[derive(Debug, Deserialize)]
struct SourceDef {
    index_fields: Vec<String>,
}

/// Raw TOML structure for the entire sources file.
#[derive(Debug, Deserialize)]
struct SourcesFile {
    source: HashMap<String, SourceDef>,
}

impl Config {
    /// Load configuration from a TOML file at `path`.
    ///
    /// Returns an error if the file cannot be read or parsed.
    /// Unlike normalized's config loader, indexd does not silently
    /// fall back to a default — it needs the real field list.
    pub fn load(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let sources_file: SourcesFile = toml::from_str(&contents)?;

        let mut sources = HashMap::new();
        for (name, def) in sources_file.source {
            sources.insert(
                name,
                SourceConfig {
                    index_fields: def.index_fields,
                },
            );
        }

        Ok(Config { sources })
    }

    /// Collect the union of all `index_fields` across every source,
    /// plus the mandatory fields that are always indexed.
    ///
    /// Returns a sorted, deduplicated list. The ordering is
    /// deterministic (alphabetical via BTreeSet) so the SQLite
    /// schema is stable across restarts.
    pub fn all_index_fields(&self) -> Vec<String> {
        let mut fields: BTreeSet<String> = BTreeSet::new();

        // Mandatory fields — always present in every event
        fields.insert("timestamp".to_string());
        fields.insert("source".to_string());
        fields.insert("byte_offset".to_string());
        fields.insert("raw_file".to_string());

        // Union of all per-source index_fields
        for source_cfg in self.sources.values() {
            for field in &source_cfg.index_fields {
                fields.insert(field.clone());
            }
        }

        fields.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let n = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
            let dir = std::env::temp_dir()
                .join(format!("hsiem_idxcfg_test_{}_{}", std::process::id(), n));
            fs::create_dir_all(&dir).unwrap();
            TempDir { path: dir }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn test_load_and_collect_fields() {
        let tmp = TempDir::new();
        let toml_path = tmp.path.join("sources.toml");
        fs::write(
            &toml_path,
            r#"
[source.sshd]
pattern = "linux/sshd"
index_fields = ["src_ip", "event_type", "username"]

[source.iptables]
pattern = "linux/iptables"
index_fields = ["src_ip", "dst_ip", "dst_port", "event_type"]

[source.default]
pattern = "heuristic"
index_fields = ["src_ip", "dst_ip", "event_type"]
"#,
        )
        .unwrap();

        let config = Config::load(toml_path.to_str().unwrap()).unwrap();
        let fields = config.all_index_fields();

        // Mandatory fields always present
        assert!(fields.contains(&"timestamp".to_string()));
        assert!(fields.contains(&"source".to_string()));
        assert!(fields.contains(&"byte_offset".to_string()));

        // Union of all index_fields
        assert!(fields.contains(&"src_ip".to_string()));
        assert!(fields.contains(&"dst_ip".to_string()));
        assert!(fields.contains(&"dst_port".to_string()));
        assert!(fields.contains(&"event_type".to_string()));
        assert!(fields.contains(&"username".to_string()));

        // No duplicates
        let mut sorted = fields.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(fields.len(), sorted.len());
    }

    #[test]
    fn test_all_index_fields_is_deterministic() {
        let tmp = TempDir::new();
        let toml_path = tmp.path.join("sources.toml");
        fs::write(
            &toml_path,
            r#"
[source.a]
pattern = "a"
index_fields = ["field_z", "field_a"]

[source.b]
pattern = "b"
index_fields = ["field_m"]
"#,
        )
        .unwrap();

        let config = Config::load(toml_path.to_str().unwrap()).unwrap();
        let fields1 = config.all_index_fields();
        let fields2 = config.all_index_fields();

        // Same order every time (BTreeSet → sorted)
        assert_eq!(fields1, fields2);

        // Verify sorted order
        let dynamic: Vec<&str> = fields1
            .iter()
            .filter(|f| {
                *f != "timestamp" && *f != "source" && *f != "byte_offset"
            })
            .map(|s| s.as_str())
            .collect();
        assert!(dynamic.windows(2).all(|w| w[0] < w[1]), "fields should be sorted");
    }

    #[test]
    fn test_missing_file_is_error() {
        let result = Config::load("/nonexistent/sources.toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_toml_is_error() {
        let tmp = TempDir::new();
        let toml_path = tmp.path.join("sources.toml");
        fs::write(&toml_path, "not valid toml {{{").unwrap();

        let result = Config::load(toml_path.to_str().unwrap());
        assert!(result.is_err());
    }
}

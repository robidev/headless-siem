//! Loader for `config/digest.toml` — thresholds for `siemctl digest`'s
//! anomaly flags. Uses `serde`/`toml` directly (unlike `normconfig.rs`'s
//! hand-scan of `normalized.toml`, which is deliberately a best-effort read
//! of *another* crate's config format — this is siemctl's own config, same
//! as `indexd`/`correlated`'s loaders).
//!
//! Every field is optional in the file; anything absent falls back to
//! [`DigestConfig::default`]'s documented default (see
//! `docs/design-digest-command.md`).

use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::digest::DigestConfig;

#[derive(Debug, Deserialize, Default)]
struct RawDigestToml {
    volume: Option<VolumeToml>,
    coverage: Option<CoverageToml>,
    network: Option<NetworkToml>,
    alerts: Option<AlertsToml>,
}

#[derive(Debug, Deserialize, Default)]
struct VolumeToml {
    spike_threshold_pct: Option<f64>,
    new_source_always_flag: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
struct CoverageToml {
    unparsed_min_events: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
struct NetworkToml {
    new_destination_always_flag: Option<bool>,
    wan_interface: Option<String>,
    top_blocked_limit: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
struct AlertsToml {
    concentration_threshold_pct: Option<f64>,
}

/// Locate `config/digest.toml`, same search order as `sources::find_sources_toml`
/// and `normconfig::find_normalized_toml`: relative to the cwd, then walking up
/// from the binary's own location.
pub fn find_digest_toml() -> Option<PathBuf> {
    for rel in &["config/digest.toml", "../config/digest.toml"] {
        let p = Path::new(rel);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?;
    for _ in 0..6 {
        let c = dir.join("config").join("digest.toml");
        if c.is_file() {
            return Some(c);
        }
        dir = dir.parent()?;
    }
    None
}

/// Parse a `digest.toml` file, filling any absent field from
/// [`DigestConfig::default`].
pub fn load(path: &Path) -> Result<DigestConfig, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let raw: RawDigestToml =
        toml::from_str(&text).map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
    Ok(merge(raw, DigestConfig::default()))
}

fn merge(raw: RawDigestToml, defaults: DigestConfig) -> DigestConfig {
    let volume = raw.volume.unwrap_or_default();
    let coverage = raw.coverage.unwrap_or_default();
    let network = raw.network.unwrap_or_default();
    let alerts = raw.alerts.unwrap_or_default();

    DigestConfig {
        spike_threshold_pct: volume.spike_threshold_pct.unwrap_or(defaults.spike_threshold_pct),
        new_source_always_flag: volume.new_source_always_flag.unwrap_or(defaults.new_source_always_flag),
        unparsed_min_events: coverage.unparsed_min_events.unwrap_or(defaults.unparsed_min_events),
        concentration_threshold_pct: alerts
            .concentration_threshold_pct
            .unwrap_or(defaults.concentration_threshold_pct),
        wan_interface: network.wan_interface.unwrap_or(defaults.wan_interface),
        top_blocked_limit: network.top_blocked_limit.unwrap_or(defaults.top_blocked_limit),
        new_destination_always_flag: network
            .new_destination_always_flag
            .unwrap_or(defaults.new_destination_always_flag),
    }
}

/// Load from the discovered `config/digest.toml`, or fall back to
/// documented defaults if no config file exists. A malformed file is a
/// warning, not a fatal error — the digest still runs on defaults.
pub fn load_or_default() -> DigestConfig {
    match find_digest_toml() {
        Some(path) => load(&path).unwrap_or_else(|e| {
            eprintln!("siemctl: warning: {e} — using default digest thresholds");
            DigestConfig::default()
        }),
        None => DigestConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_toml_yields_all_defaults() {
        let cfg = merge(toml::from_str("").unwrap(), DigestConfig::default());
        let defaults = DigestConfig::default();
        assert_eq!(cfg.spike_threshold_pct, defaults.spike_threshold_pct);
        assert_eq!(cfg.unparsed_min_events, defaults.unparsed_min_events);
        assert_eq!(cfg.wan_interface, defaults.wan_interface);
    }

    #[test]
    fn partial_toml_overrides_only_given_fields() {
        let text = r#"
[volume]
spike_threshold_pct = 25

[network]
wan_interface = "wan0"
"#;
        let cfg = merge(toml::from_str(text).unwrap(), DigestConfig::default());
        assert_eq!(cfg.spike_threshold_pct, 25.0);
        assert_eq!(cfg.wan_interface, "wan0");
        // Untouched fields keep their defaults.
        assert_eq!(cfg.unparsed_min_events, DigestConfig::default().unparsed_min_events);
        assert!(cfg.new_source_always_flag);
    }

    #[test]
    fn full_toml_matches_the_documented_example() {
        let text = r#"
[volume]
spike_threshold_pct = 50
new_source_always_flag = true

[coverage]
unparsed_min_events = 50

[network]
new_destination_always_flag = true

[alerts]
concentration_threshold_pct = 80
"#;
        let cfg = merge(toml::from_str(text).unwrap(), DigestConfig::default());
        assert_eq!(cfg.spike_threshold_pct, 50.0);
        assert!(cfg.new_source_always_flag);
        assert_eq!(cfg.unparsed_min_events, 50);
        assert!(cfg.new_destination_always_flag);
        assert_eq!(cfg.concentration_threshold_pct, 80.0);
    }

    #[test]
    fn load_rejects_malformed_toml() {
        let dir = std::env::temp_dir().join(format!("hsiem_digest_cfg_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("digest.toml");
        std::fs::write(&path, "not valid toml [[[").unwrap();
        let result = load(&path);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_err());
    }

    #[test]
    fn load_reads_a_real_file() {
        let dir = std::env::temp_dir().join(format!("hsiem_digest_cfg_test2_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("digest.toml");
        std::fs::write(&path, "[network]\nwan_interface = \"eth1\"\n").unwrap();
        let cfg = load(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(cfg.wan_interface, "eth1");
    }
}

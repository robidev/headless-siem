# ── Headless SIEM — Unified Build System (just) ────────────────────────
# Builds 5 binaries: normalized, indexd, ruled, correlated, siemctl (all Rust).
# The five crates form a Cargo workspace (see ./Cargo.toml): one Cargo.lock,
# one shared ./target/ directory.

bin_dir     := "/usr/local/bin"
systemd_dir := "/etc/systemd/system"
systemd_src := "config/systemd"

# Build all binaries (release mode)
all:
    @echo "=== Building workspace (release) ==="
    cargo build --release

# Run all tests (cargo test + integration tests)
test:
    @echo "=== Testing workspace ==="
    cargo test
    @echo "=== Running integration tests ==="
    @for t in tests/integration/*.sh; do \
        echo "--- $(basename "$t") ---"; \
        bash "$t" || exit 1; \
    done

# Clean all build artifacts
clean:
    @echo "=== Cleaning workspace ==="
    cargo clean

# Install binaries to /usr/local/bin and systemd units
install:
    @echo "=== Installing binaries to {{bin_dir}} ==="
    install -m 755 target/release/normalized   {{bin_dir}}/headless-siem-normalized
    install -m 755 target/release/indexd       {{bin_dir}}/headless-siem-indexd
    install -m 755 target/release/ruled        {{bin_dir}}/headless-siem-ruled
    install -m 755 target/release/correlated   {{bin_dir}}/headless-siem-correlated
    install -m 755 target/release/siemctl      {{bin_dir}}/siemctl
    @echo "=== Installing systemd units to {{systemd_dir}} ==="
    install -m 644 {{systemd_src}}/headless-siem-normalized.service  {{systemd_dir}}/
    install -m 644 {{systemd_src}}/headless-siem-indexd.service      {{systemd_dir}}/
    install -m 644 {{systemd_src}}/headless-siem-ruled.service       {{systemd_dir}}/
    install -m 644 {{systemd_src}}/headless-siem-correlated.service  {{systemd_dir}}/
    install -m 644 {{systemd_src}}/headless-siem-pipes.service       {{systemd_dir}}/
    @echo "=== Reloading systemd ==="
    systemctl daemon-reload
    @echo "=== Install complete ==="

# ── Headless SIEM — Unified Build System (just) ────────────────────────
# Builds 5 binaries: normalized, indexd, ruled, correlated, siemctl (all Rust)

rust_crates := "normalized indexd ruled correlated siemctl"
bin_dir     := "/usr/local/bin"
systemd_dir := "/etc/systemd/system"
systemd_src := "config/systemd"

# Build all binaries (release mode)
all:
    @for crate in {{rust_crates}}; do \
        echo "=== Building src/$crate (release) ==="; \
        cd src/$crate && cargo build --release || exit 1; \
        cd ../..; \
    done

# Run all tests (cargo test + integration tests)
test:
    @for crate in {{rust_crates}}; do \
        echo "=== Testing src/$crate ==="; \
        cd src/$crate && cargo test || exit 1; \
        cd ../..; \
    done
    @echo "=== Running integration tests ==="
    @for t in tests/integration/*.sh; do \
        echo "--- $(basename "$t") ---"; \
        bash "$t" || exit 1; \
    done

# Clean all build artifacts
clean:
    @for crate in {{rust_crates}}; do \
        echo "=== Cleaning src/$crate ==="; \
        cd src/$crate && cargo clean || exit 1; \
        cd ../..; \
    done

# Install binaries to /usr/local/bin and systemd units
install:
    @echo "=== Installing binaries to {{bin_dir}} ==="
    install -m 755 src/normalized/target/release/normalized   {{bin_dir}}/headless-siem-normalized
    install -m 755 src/indexd/target/release/indexd           {{bin_dir}}/headless-siem-indexd
    install -m 755 src/ruled/target/release/ruled             {{bin_dir}}/headless-siem-ruled
    install -m 755 src/correlated/target/release/correlated   {{bin_dir}}/headless-siem-correlated
    install -m 755 src/siemctl/target/release/siemctl         {{bin_dir}}/siemctl
    @echo "=== Installing systemd units to {{systemd_dir}} ==="
    install -m 644 {{systemd_src}}/headless-siem-normalized.service  {{systemd_dir}}/
    install -m 644 {{systemd_src}}/headless-siem-indexd.service      {{systemd_dir}}/
    install -m 644 {{systemd_src}}/headless-siem-ruled.service       {{systemd_dir}}/
    install -m 644 {{systemd_src}}/headless-siem-correlated.service  {{systemd_dir}}/
    install -m 644 {{systemd_src}}/headless-siem-pipes.service       {{systemd_dir}}/
    @echo "=== Reloading systemd ==="
    systemctl daemon-reload
    @echo "=== Install complete ==="

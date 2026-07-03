# ── Headless SIEM — Unified Build System ───────────────────────────────
# Builds 5 binaries: normalized, indexd, ruled, correlated, siemctl (all Rust).
# The five crates form a Cargo workspace (see ./Cargo.toml): one Cargo.lock,
# one shared ./target/ directory.

.PHONY: all test clean install

BIN_DIR     = /usr/local/bin
SYSTEMD_DIR = /etc/systemd/system
SYSTEMD_SRC = config/systemd

# ── Build all binaries ────────────────────────────────────────────────
all:
	@echo "=== Building workspace (release) ==="
	cargo build --release

# ── Run all tests ─────────────────────────────────────────────────────
test:
	@echo "=== Testing workspace ==="
	cargo test
	@echo "=== Running integration tests ==="
	@for t in tests/integration/*.sh; do \
		echo "--- $$(basename $$t) ---"; \
		bash "$$t" || exit 1; \
	done

# ── Clean all build artifacts ─────────────────────────────────────────
clean:
	@echo "=== Cleaning workspace ==="
	cargo clean

# ── Install binaries and systemd units ────────────────────────────────
install:
	@echo "=== Installing binaries to $(BIN_DIR) ==="
	install -m 755 target/release/normalized   $(BIN_DIR)/headless-siem-normalized
	install -m 755 target/release/indexd       $(BIN_DIR)/headless-siem-indexd
	install -m 755 target/release/ruled        $(BIN_DIR)/headless-siem-ruled
	install -m 755 target/release/correlated   $(BIN_DIR)/headless-siem-correlated
	install -m 755 target/release/siemctl      $(BIN_DIR)/siemctl
	@echo "=== Installing systemd units to $(SYSTEMD_DIR) ==="
	install -m 644 $(SYSTEMD_SRC)/headless-siem-normalized.service    $(SYSTEMD_DIR)/
	install -m 644 $(SYSTEMD_SRC)/headless-siem-indexd.service        $(SYSTEMD_DIR)/
	install -m 644 $(SYSTEMD_SRC)/headless-siem-ruled.service         $(SYSTEMD_DIR)/
	install -m 644 $(SYSTEMD_SRC)/headless-siem-correlated.service    $(SYSTEMD_DIR)/
	install -m 644 $(SYSTEMD_SRC)/headless-siem-pipes.service         $(SYSTEMD_DIR)/
	install -m 644 $(SYSTEMD_SRC)/headless-siem-alert-watch.service   $(SYSTEMD_DIR)/
	@echo "=== NOTE: this target installs raw units referencing dev-tree paths."
	@echo "    Use config/systemd/install.sh for a full production install"
	@echo "    (rewrites paths, installs config/, creates /var/lib/headless-siem)."
	@echo "=== Reloading systemd ==="
	systemctl daemon-reload
	@echo "=== Install complete ==="

# ── Headless SIEM — Unified Build System ───────────────────────────────
# Builds 5 binaries: normalized, indexd, ruled, correlated, siemctl (all Rust)

.PHONY: all test clean install

RUST_CRATES = normalized indexd ruled correlated siemctl
BIN_DIR     = /usr/local/bin
SYSTEMD_DIR = /etc/systemd/system
SYSTEMD_SRC = config/systemd

# ── Build all binaries ────────────────────────────────────────────────
all:
	@for crate in $(RUST_CRATES); do \
		echo "=== Building src/$$crate (release) ==="; \
		cd src/$$crate && cargo build --release || exit 1; \
		cd ../..; \
	done

# ── Run all tests ─────────────────────────────────────────────────────
test:
	@for crate in $(RUST_CRATES); do \
		echo "=== Testing src/$$crate ==="; \
		cd src/$$crate && cargo test || exit 1; \
		cd ../..; \
	done
	@echo "=== Running integration tests ==="
	@for t in tests/integration/*.sh; do \
		echo "--- $$(basename $$t) ---"; \
		bash "$$t" || exit 1; \
	done

# ── Clean all build artifacts ─────────────────────────────────────────
clean:
	@for crate in $(RUST_CRATES); do \
		echo "=== Cleaning src/$$crate ==="; \
		cd src/$$crate && cargo clean || exit 1; \
		cd ../..; \
	done

# ── Install binaries and systemd units ────────────────────────────────
install:
	@echo "=== Installing binaries to $(BIN_DIR) ==="
	install -m 755 src/normalized/target/release/normalized   $(BIN_DIR)/headless-siem-normalized
	install -m 755 src/indexd/target/release/indexd           $(BIN_DIR)/headless-siem-indexd
	install -m 755 src/ruled/target/release/ruled             $(BIN_DIR)/headless-siem-ruled
	install -m 755 src/correlated/target/release/correlated   $(BIN_DIR)/headless-siem-correlated
	install -m 755 src/siemctl/target/release/siemctl         $(BIN_DIR)/siemctl
	@echo "=== Installing systemd units to $(SYSTEMD_DIR) ==="
	install -m 644 $(SYSTEMD_SRC)/headless-siem-normalized.service  $(SYSTEMD_DIR)/
	install -m 644 $(SYSTEMD_SRC)/headless-siem-indexd.service      $(SYSTEMD_DIR)/
	install -m 644 $(SYSTEMD_SRC)/headless-siem-ruled.service       $(SYSTEMD_DIR)/
	install -m 644 $(SYSTEMD_SRC)/headless-siem-correlated.service  $(SYSTEMD_DIR)/
	install -m 644 $(SYSTEMD_SRC)/headless-siem-pipes.service       $(SYSTEMD_DIR)/
	@echo "=== Reloading systemd ==="
	systemctl daemon-reload
	@echo "=== Install complete ==="

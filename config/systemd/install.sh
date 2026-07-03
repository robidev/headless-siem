#!/usr/bin/env bash
# ── Headless SIEM Install Script ──────────────────────────────────────
# Installs binaries to /usr/local/bin, config to /etc/headless-siem,
# and systemd units to /etc/systemd/system/.
#
# Usage: sudo bash install.sh [--release|--debug]
#   --release  Install release binaries (default)
#   --debug    Install debug binaries (for development)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_TYPE="${1:-release}"

if [[ "$BUILD_TYPE" != "release" && "$BUILD_TYPE" != "debug" ]]; then
    echo "Usage: sudo bash install.sh [--release|--debug]"
    exit 1
fi

echo "=== Headless SIEM Install (${BUILD_TYPE}) ==="

# ── Check we're root ──────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

# ── Determine binary paths ────────────────────────────────────────────
# Workspace build: all binaries land in the shared $PROJECT_ROOT/target/.
if [[ "$BUILD_TYPE" == "release" ]]; then
    BUILD_DIR="$PROJECT_ROOT/target/release"
else
    BUILD_DIR="$PROJECT_ROOT/target/debug"
fi
NORMALIZED="$BUILD_DIR/normalized"
INDEXD="$BUILD_DIR/indexd"
RULED="$BUILD_DIR/ruled"
CORRELATED="$BUILD_DIR/correlated"
SIEMCTL="$BUILD_DIR/siemctl"

# ── Verify binaries exist ─────────────────────────────────────────────
echo "Checking binaries..."
for bin in "$NORMALIZED" "$INDEXD" "$RULED" "$CORRELATED" "$SIEMCTL"; do
    if [[ ! -x "$bin" ]]; then
        echo "ERROR: Binary not found: $bin"
        echo "Run 'make all' first to build."
        exit 1
    fi
    echo "  OK: $bin"
done

# ── Install binaries ──────────────────────────────────────────────────
echo ""
echo "Installing binaries to /usr/local/bin/..."
cp "$NORMALIZED" /usr/local/bin/headless-siem-normalized
cp "$INDEXD" /usr/local/bin/headless-siem-indexd
cp "$RULED" /usr/local/bin/headless-siem-ruled
cp "$CORRELATED" /usr/local/bin/headless-siem-correlated
cp "$SIEMCTL" /usr/local/bin/siemctl
chmod 755 /usr/local/bin/headless-siem-{normalized,indexd,ruled,correlated} /usr/local/bin/siemctl
echo "  Done."

# ── Install config ────────────────────────────────────────────────────
echo ""
echo "Installing config to /etc/headless-siem/..."
mkdir -p /etc/headless-siem
# sources.toml: index field definitions for indexd and siemctl
cp -r "$PROJECT_ROOT/config/sources.toml" /etc/headless-siem/
# normalized.toml: optional override/extraction rules for normalized
# (copy only if it exists — normalized works with defaults without it)
if [[ -f "$PROJECT_ROOT/config/normalized.toml" ]]; then
    cp "$PROJECT_ROOT/config/normalized.toml" /etc/headless-siem/
fi
cp -r "$PROJECT_ROOT/config/rules" /etc/headless-siem/
mkdir -p /etc/headless-siem/rsyslog.d
cp "$PROJECT_ROOT/config/rsyslog.d/50-headless-siem.conf" /etc/headless-siem/rsyslog.d/
echo "  Done."

# ── Create data directory ─────────────────────────────────────────────
echo ""
echo "Creating data directory at /var/lib/headless-siem/..."
mkdir -p /var/lib/headless-siem/{raw,index,alerts/correlated}
chown -R user:user /var/lib/headless-siem
echo "  Done."

# ── Install systemd units ─────────────────────────────────────────────
echo ""
echo "Installing systemd units to /etc/systemd/system/..."

# Update service files to use installed paths
for svc in normalized indexd ruled correlated pipes; do
    SRC="$PROJECT_ROOT/config/systemd/headless-siem-${svc}.service"
    if [[ -f "$SRC" ]]; then
        # Copy and adjust paths for installed layout
        sed \
            -e "s|/home/user/projects/headless-siem/target/release/normalized|/usr/local/bin/headless-siem-normalized|g" \
            -e "s|/home/user/projects/headless-siem/target/release/indexd|/usr/local/bin/headless-siem-indexd|g" \
            -e "s|/home/user/projects/headless-siem/target/release/ruled|/usr/local/bin/headless-siem-ruled|g" \
            -e "s|/home/user/projects/headless-siem/target/release/correlated|/usr/local/bin/headless-siem-correlated|g" \
            -e "s|/home/user/projects/headless-siem/data|/var/lib/headless-siem|g" \
            -e "s|/home/user/projects/headless-siem/config|/etc/headless-siem|g" \
            -e "s|WorkingDirectory=/home/user/projects/headless-siem|WorkingDirectory=/var/lib/headless-siem|g" \
            -e "s|HEADLESS_SIEM_ROOT=/home/user/projects/headless-siem|HEADLESS_SIEM_ROOT=/etc/headless-siem|g" \
            "$SRC" > "/etc/systemd/system/headless-siem-${svc}.service"
        echo "  Installed: headless-siem-${svc}.service"
    fi
done

# ── Reload systemd ────────────────────────────────────────────────────
systemctl daemon-reload
echo "  systemd daemon-reload complete."

# ── Enable and start services ──────────────────────────────────────────
echo ""
echo "Enabling services..."
systemctl enable headless-siem-pipes.service
systemctl enable headless-siem-normalized.service
systemctl enable headless-siem-indexd.service
systemctl enable headless-siem-ruled.service
systemctl enable headless-siem-correlated.service

echo ""
echo "Starting services..."
systemctl start headless-siem-pipes.service
sleep 1
systemctl start headless-siem-normalized.service
systemctl start headless-siem-indexd.service
systemctl start headless-siem-ruled.service
systemctl start headless-siem-correlated.service

# ── Verify ─────────────────────────────────────────────────────────────
echo ""
echo "=== Checking service status ==="
sleep 2
for svc in pipes normalized indexd ruled correlated; do
    STATUS=$(systemctl is-active headless-siem-${svc}.service 2>/dev/null || echo "unknown")
    echo "  headless-siem-${svc}.service: $STATUS"
done

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Quick checks:"
echo "  siemctl status --data-dir /var/lib/headless-siem"
echo "  systemctl status headless-siem-normalized"
echo "  journalctl -u headless-siem-ruled -f"
echo ""
echo "To feed logs via rsyslog, copy the config and restart rsyslog:"
echo "  cp /etc/headless-siem/rsyslog.d/50-headless-siem.conf /etc/rsyslog.d/"
echo "  systemctl restart rsyslog"

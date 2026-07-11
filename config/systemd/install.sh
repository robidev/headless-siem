#!/usr/bin/env bash
# ── Headless SIEM Install Script ──────────────────────────────────────
# Installs binaries to /usr/local/bin, config to /etc/headless-siem,
# and systemd units to /etc/systemd/system/.
#
# Usage: sudo bash install.sh [release|debug]
#   release  Install release binaries (default)
#   debug    Install debug binaries (for development)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_TYPE="${1:-release}"

if [[ "$BUILD_TYPE" != "release" && "$BUILD_TYPE" != "debug" ]]; then
    echo "Usage: sudo bash install.sh [release|debug]"
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
# `install` (not cp): does an atomic unlink+rename rather than an in-place
# write, so re-running this against a service that's still running doesn't
# fail with "Text file busy".
install -m 755 "$NORMALIZED" /usr/local/bin/headless-siem-normalized
install -m 755 "$INDEXD" /usr/local/bin/headless-siem-indexd
install -m 755 "$RULED" /usr/local/bin/headless-siem-ruled
install -m 755 "$CORRELATED" /usr/local/bin/headless-siem-correlated
install -m 755 "$SIEMCTL" /usr/local/bin/siemctl
echo "  Done."

# ── Record deployed revision ──────────────────────────────────────────
# Stamps the git commit each binary was built from, so `scripts/
# check-deploy-drift` can later tell "merged to master" apart from
# "actually running in production" — a gap that's bitten this project
# more than once (a merged fix sitting unbuilt/uninstalled while
# investigation continued against the stale binary).
echo ""
echo "Recording deployed revision..."
mkdir -p /etc/headless-siem
GIT_HEAD="$(git -C "$PROJECT_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
DEPLOY_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
    for bin in normalized indexd ruled correlated siemctl; do
        echo "${bin}=${GIT_HEAD} ${DEPLOY_TS}"
    done
} > /etc/headless-siem/.deployed-revisions
echo "  Done (all 5 binaries stamped at ${GIT_HEAD:0:8})."

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
# correlations.toml: cross-rule correlation window/threshold definitions for correlated
cp "$PROJECT_ROOT/config/correlations.toml" /etc/headless-siem/
mkdir -p /etc/headless-siem/rsyslog.d
cp "$PROJECT_ROOT/config/rsyslog.d/50-headless-siem.conf" /etc/headless-siem/rsyslog.d/
mkdir -p /etc/headless-siem/notify
cp "$PROJECT_ROOT/config/notify/alert-watch.sh" /etc/headless-siem/notify/
chmod 755 /etc/headless-siem/notify/alert-watch.sh
echo "  Done."

# ── Create data directory ─────────────────────────────────────────────
echo ""
echo "Creating data directory at /var/lib/headless-siem/..."
mkdir -p /var/lib/headless-siem/{raw,index,alerts/correlated}
mkdir -p /var/lib/headless-siem/alert-watch
chown -R user:user /var/lib/headless-siem
echo "  Done."

# ── Install systemd units ─────────────────────────────────────────────
echo ""
echo "Installing systemd units to /etc/systemd/system/..."

# Update service files to use installed paths
for svc in normalized indexd ruled correlated pipes alert-watch retention; do
    SRC="$PROJECT_ROOT/config/systemd/headless-siem-${svc}.service"
    if [[ -f "$SRC" ]]; then
        # siemctl isn't in the substitution list below (unlike the other 4
        # binaries) because only retention.service invokes it, and it needs
        # its own line since the target filename differs (siemctl, not
        # headless-siem-siemctl).
        sed \
            -e "s|/home/user/projects/headless-siem/target/release/normalized|/usr/local/bin/headless-siem-normalized|g" \
            -e "s|/home/user/projects/headless-siem/target/release/indexd|/usr/local/bin/headless-siem-indexd|g" \
            -e "s|/home/user/projects/headless-siem/target/release/ruled|/usr/local/bin/headless-siem-ruled|g" \
            -e "s|/home/user/projects/headless-siem/target/release/correlated|/usr/local/bin/headless-siem-correlated|g" \
            -e "s|/home/user/projects/headless-siem/target/release/siemctl|/usr/local/bin/siemctl|g" \
            -e "s|/home/user/projects/headless-siem/data|/var/lib/headless-siem|g" \
            -e "s|/home/user/projects/headless-siem/config|/etc/headless-siem|g" \
            -e "s|WorkingDirectory=/home/user/projects/headless-siem|WorkingDirectory=/var/lib/headless-siem|g" \
            -e "s|HEADLESS_SIEM_ROOT=/home/user/projects/headless-siem|HEADLESS_SIEM_ROOT=/etc/headless-siem|g" \
            "$SRC" > "/etc/systemd/system/headless-siem-${svc}.service"
        echo "  Installed: headless-siem-${svc}.service"
    fi
done

# The retention timer has no dev-tree paths to rewrite — install as-is.
install -m 644 "$PROJECT_ROOT/config/systemd/headless-siem-retention.timer" /etc/systemd/system/

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
systemctl enable headless-siem-alert-watch.service
# retention.service is a oneshot triggered by the timer — enable the timer,
# not the service itself.
systemctl enable headless-siem-retention.timer

echo ""
echo "Starting services..."
systemctl start headless-siem-pipes.service
sleep 1
systemctl start headless-siem-normalized.service
systemctl start headless-siem-indexd.service
systemctl start headless-siem-ruled.service
systemctl start headless-siem-correlated.service
systemctl start headless-siem-alert-watch.service
systemctl start headless-siem-retention.timer

# ── Verify ─────────────────────────────────────────────────────────────
echo ""
echo "=== Checking service status ==="
sleep 2
for svc in pipes normalized indexd ruled correlated alert-watch; do
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
echo ""
echo "headless-siem-alert-watch depends on /usr/local/bin/soc-notify, which"
echo "this installer does NOT provide (it's an llm-based-soc deployment"
echo "artifact, not part of the SIEM itself — see"
echo "llm-based-soc/documentation/escalation.md). Until soc-notify exists,"
echo "alert-watch logs an error per high/critical alert instead of paging"
echo "you; check with:"
echo "  journalctl -u headless-siem-alert-watch -f"

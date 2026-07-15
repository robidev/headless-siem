#!/usr/bin/env bash
# ── Headless SIEM Uninstall Script ────────────────────────────────────
# Reverses install.sh: stops + disables + removes the systemd units,
# removes the installed binaries from /usr/local/bin, and removes the
# config at /etc/headless-siem/. Also removes the binaries/units left
# behind by the raw `make install`/`just install` targets, since they
# use the same names and locations.
#
# The data directory (/var/lib/headless-siem — raw logs, index DBs,
# alerts) is only touched if you explicitly ask for it; see usage below.
#
# STATUS: written but not yet exercised against a real install — see
# llm-based-soc's archived plan appendix issue #42. Read through the "Plan"
# output (--dry-run) before trusting this against a live system.
#
# Usage: sudo bash uninstall.sh --keep-data|--purge-data [--yes] [--dry-run]
#   --keep-data    Stop/remove services, binaries, and config; leave
#                   /var/lib/headless-siem in place untouched.
#   --purge-data   Same as above, and also delete /var/lib/headless-siem
#                   entirely. Irreversible — asks for interactive
#                   confirmation unless --yes is also given.
#   --yes          Skip the interactive confirmation prompt (for
#                   scripted/non-interactive use). Has no effect without
#                   --purge-data.
#   --dry-run      Print what would be done and exit 0. Does not require
#                   root and touches nothing.
#
# One of --keep-data/--purge-data is required (no default) — the data
# question is left explicit on purpose, rather than guessing.

set -euo pipefail

DATA_DIR="/var/lib/headless-siem"
CONFIG_DIR="/etc/headless-siem"
SYSTEMD_DIR="/etc/systemd/system"
BIN_DIR="/usr/local/bin"

MODE=""
ASSUME_YES=0
DRY_RUN=0

for arg in "$@"; do
    case "$arg" in
        --keep-data) MODE="keep" ;;
        --purge-data) MODE="purge" ;;
        --yes|-y) ASSUME_YES=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --help|-h)
            sed -n '2,27p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg (see --help)"
            exit 1
            ;;
    esac
done

if [[ "$DRY_RUN" -eq 0 && -z "$MODE" ]]; then
    echo "ERROR: pass --keep-data or --purge-data (see --help)."
    exit 1
fi

SERVICES=(alert-watch correlated ruled indexd normalized pipes)
UNITS=(
    headless-siem-alert-watch.service
    headless-siem-correlated.service
    headless-siem-ruled.service
    headless-siem-indexd.service
    headless-siem-normalized.service
    headless-siem-pipes.service
    headless-siem-retention.service
    headless-siem-retention.timer
)
BINARIES=(
    "$BIN_DIR/headless-siem-normalized"
    "$BIN_DIR/headless-siem-indexd"
    "$BIN_DIR/headless-siem-ruled"
    "$BIN_DIR/headless-siem-correlated"
    "$BIN_DIR/siemctl"
)
RSYSLOG_CONF="/etc/rsyslog.d/50-headless-siem.conf"

# ── Dry run: just describe the plan ───────────────────────────────────
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "=== Headless SIEM Uninstall — DRY RUN (nothing will be changed) ==="
    echo ""
    echo "Would stop + disable, in this order: ${SERVICES[*]}"
    echo "  (headless-siem-retention.timer would also be stopped/disabled)"
    echo ""
    echo "Would remove systemd unit files from $SYSTEMD_DIR:"
    for u in "${UNITS[@]}"; do
        [[ -f "$SYSTEMD_DIR/$u" ]] && echo "  $SYSTEMD_DIR/$u (exists)" || echo "  $SYSTEMD_DIR/$u (not present)"
    done
    echo ""
    echo "Would remove binaries from $BIN_DIR:"
    for b in "${BINARIES[@]}"; do
        [[ -e "$b" ]] && echo "  $b (exists)" || echo "  $b (not present)"
    done
    echo ""
    echo "Would remove config directory: $CONFIG_DIR $( [[ -d "$CONFIG_DIR" ]] && echo '(exists)' || echo '(not present)')"
    echo "Would remove rsyslog drop-in if present: $RSYSLOG_CONF $( [[ -f "$RSYSLOG_CONF" ]] && echo '(exists)' || echo '(not present)')"
    echo ""
    if [[ "$MODE" == "purge" ]]; then
        echo "Mode: --purge-data — WOULD DELETE $DATA_DIR entirely."
        [[ -d "$DATA_DIR" ]] && du -sh "$DATA_DIR" 2>/dev/null | sed 's/^/  current size: /'
    elif [[ "$MODE" == "keep" ]]; then
        echo "Mode: --keep-data — $DATA_DIR would be left untouched."
        [[ -d "$DATA_DIR" ]] && du -sh "$DATA_DIR" 2>/dev/null | sed 's/^/  current size: /'
    else
        echo "No --keep-data/--purge-data given — real run would refuse to proceed."
    fi
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

echo "=== Headless SIEM Uninstall (data: ${MODE}) ==="

# ── Stop + disable services ────────────────────────────────────────────
echo ""
echo "Stopping services..."
for svc in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "headless-siem-${svc}.service" 2>/dev/null; then
        systemctl stop "headless-siem-${svc}.service"
        echo "  stopped headless-siem-${svc}.service"
    fi
done
if systemctl is-active --quiet headless-siem-retention.timer 2>/dev/null; then
    systemctl stop headless-siem-retention.timer
    echo "  stopped headless-siem-retention.timer"
fi

echo ""
echo "Disabling services..."
for svc in "${SERVICES[@]}"; do
    systemctl disable "headless-siem-${svc}.service" 2>/dev/null || true
done
systemctl disable headless-siem-retention.timer 2>/dev/null || true
echo "  Done."

# ── Remove systemd unit files ──────────────────────────────────────────
echo ""
echo "Removing systemd unit files from $SYSTEMD_DIR..."
for u in "${UNITS[@]}"; do
    if [[ -f "$SYSTEMD_DIR/$u" ]]; then
        rm -f "$SYSTEMD_DIR/$u"
        echo "  removed $u"
    fi
done
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true
echo "  systemd daemon-reload complete."

# ── Remove binaries ─────────────────────────────────────────────────────
echo ""
echo "Removing binaries from $BIN_DIR..."
for b in "${BINARIES[@]}"; do
    if [[ -e "$b" ]]; then
        rm -f "$b"
        echo "  removed $b"
    fi
done

# ── Remove config ───────────────────────────────────────────────────────
echo ""
if [[ -d "$CONFIG_DIR" ]]; then
    echo "Removing config directory $CONFIG_DIR..."
    rm -rf "$CONFIG_DIR"
    echo "  Done."
else
    echo "Config directory $CONFIG_DIR not present, nothing to remove."
fi

# ── Remove rsyslog drop-in, if present ─────────────────────────────────
echo ""
if [[ -f "$RSYSLOG_CONF" ]]; then
    rm -f "$RSYSLOG_CONF"
    echo "Removed $RSYSLOG_CONF."
    if systemctl list-unit-files rsyslog.service &>/dev/null && systemctl is-active --quiet rsyslog; then
        systemctl restart rsyslog
        echo "Restarted rsyslog."
    fi
else
    echo "$RSYSLOG_CONF not present, nothing to remove."
fi

# ── Data directory ──────────────────────────────────────────────────────
echo ""
if [[ "$MODE" == "purge" ]]; then
    if [[ -d "$DATA_DIR" ]]; then
        echo "About to permanently delete $DATA_DIR:"
        du -sh "$DATA_DIR" 2>/dev/null | sed 's/^/  /'
        if [[ "$ASSUME_YES" -ne 1 ]]; then
            read -r -p "Type 'yes' to permanently delete $DATA_DIR: " CONFIRM
            if [[ "$CONFIRM" != "yes" ]]; then
                echo "Aborted — $DATA_DIR left in place. Everything else above was already removed."
                exit 1
            fi
        fi
        rm -rf "$DATA_DIR"
        echo "  Deleted $DATA_DIR."
    else
        echo "$DATA_DIR not present, nothing to purge."
    fi
else
    if [[ -d "$DATA_DIR" ]]; then
        echo "Data directory $DATA_DIR left in place (--keep-data):"
        du -sh "$DATA_DIR" 2>/dev/null | sed 's/^/  /'
    fi
fi

echo ""
echo "=== Uninstall complete ==="
echo ""
echo "NOT touched by this script (out of scope):"
echo "  - llm-based-soc-baseline.timer/.service (separate project, not installed by install.sh)"
echo "  - /usr/local/bin/soc-notify (llm-based-soc deployment artifact, not part of this repo)"
echo "  - rsyslog itself, if it was installed independently of headless-siem"

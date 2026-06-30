#!/usr/bin/env bash
#
# dev.sh — Headless SIEM development harness
#
# Runs the full pipeline as background processes without systemd.
# Receives syslog on UDP :5514 (non-privileged; no root needed).
# Configure pfSense, HAProxy, Proxmox, Linux hosts to forward syslog
# UDP to <this-host>:5514.
#
# COMMANDS
#   build                 (Re)build debug binaries:  cargo build
#   start [--fresh]       Start all stages; --fresh wipes data/ first
#   stop                  Stop all stages
#   restart               stop + start (data preserved)
#   status                Show running processes + siemctl status
#   reset                 stop + wipe data/ + start fresh
#   send "<syslog line>"  Inject one raw syslog line for quick testing
#   replay <file>         Feed a log file through the live pipeline
#   dry-run <file>        Parse + rule-match a file without touching disk
#   query [args...]       siemctl search  e.g.: ./dev.sh query 'src_ip == 1.2.3.4'
#   tail [args...]        siemctl tail
#   logs [stage]          Tail stderr of a stage (all|normalized|indexd|ruled|correlated)
#   reload rules          Restart ruled + correlated (new/edited Sigma rules)
#   reload norm           Restart normalized + ruled + correlated (new normalized.toml)
#   reload index          Restart indexd only (new sources.toml fields)
#
# ENVIRONMENT OVERRIDES
#   SIEM_DATA_DIR   Where to store JSONL, indexes, alerts  (default: ./data)
#   SIEM_PIPE_DIR   Where to put named pipes, PIDs, logs   (default: /tmp/headless-siem-dev)
#   SIEM_PORT       UDP+TCP syslog listen port              (default: 5514)
#
# HOT-RELOAD LIMITATIONS
#
#   reload rules  (restarts: ruled, correlated)
#     ✓ New, edited, or deleted config/rules/*.yml take effect.
#     ✗ ~1–3 s alert gap while ruled restarts.
#     ✗ Events buffered in the inter-process pipe at restart time are evaluated
#       by the NEW rule set — replay them afterward if you need both old+new.
#     ✗ In-flight correlation windows in correlated are discarded (fresh state).
#
#   reload norm  (restarts: normalized, ruled, correlated — indexd unaffected)
#     ✓ Changes to extract/override rules in normalized.toml take effect.
#     ✗ When normalized exits it sends EOF to ruled; ruled exits on EOF.
#       So ruled and correlated must restart too.
#     ✗ UDP events arriving during the ~2 s restart window are silently dropped.
#     ✗ New extraction fields only appear in index buckets created AFTER the
#       restart. Old .db files keep their original schema. Run 'reload index'
#       afterward if you added new fields to sources.toml as well.
#
#   reload index  (restarts: indexd only)
#     ✓ Safe at any time; normalized/ruled/correlated are unaffected.
#     ✗ New index_fields in sources.toml only appear in buckets created AFTER
#       the restart; existing .db files do not gain new columns.
#     ✗ To retroactively index raw JSONL with new fields: stop everything, wipe
#       data/index/, restart — indexd will re-index all raw files from scratch.
#     ✗ Brief window (~1 s) between stop and start where new JSONL written by
#       normalized is not picked up by inotify (caught on next restart).
#
#   Cannot hot-reload without full reset:
#     • Schema changes to existing index buckets (column additions/renames)
#     • Changes to [storage] data_dir in normalized.toml
#     • Any change requiring retroactive re-indexing of historical data

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Configuration ─────────────────────────────────────────────────────────────
DATA_DIR="${SIEM_DATA_DIR:-$SCRIPT_DIR/data}"
CONFIG_DIR="$SCRIPT_DIR/config"
BIN_DIR="$SCRIPT_DIR/target/debug"
PIPE_DIR="${SIEM_PIPE_DIR:-/tmp/headless-siem-dev}"
PID_DIR="$PIPE_DIR/pids"
LOG_DIR="$PIPE_DIR/logs"
SYSLOG_PORT="${SIEM_PORT:-5514}"

NORM_PIPE="$PIPE_DIR/normalized-out.pipe"
RULED_PIPE="$PIPE_DIR/ruled-out.pipe"
DEV_CONFIG="$PIPE_DIR/normalized-dev.toml"

# ── Helpers ───────────────────────────────────────────────────────────────────

die()  { echo "dev.sh: $*" >&2; exit 1; }
info() { echo ">> $*"; }

require_bins() {
    for b in normalized indexd ruled correlated siemctl; do
        [ -x "$BIN_DIR/$b" ] || die "Missing binary: $BIN_DIR/$b — run: ./dev.sh build"
    done
}

save_pid() { echo "$2" > "$PID_DIR/$1.pid"; }

get_pid() {
    local pidfile="$PID_DIR/$1.pid"
    [ -f "$pidfile" ] || return 1
    local pid
    pid=$(cat "$pidfile")
    kill -0 "$pid" 2>/dev/null || return 1
    echo "$pid"
}

stop_process() {
    local name="$1"
    local pid
    pid=$(get_pid "$name") || return 0
    info "Stopping $name (pid $pid)..."
    kill "$pid" 2>/dev/null || true
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        sleep 0.5
        kill -0 "$pid" 2>/dev/null || { rm -f "$PID_DIR/$name.pid"; return 0; }
    done
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$PID_DIR/$name.pid"
}

# Open both named pipes in O_RDWR mode (non-blocking; doesn't require a reader
# or writer to already be present). This lets downstream consumers start their
# O_RDONLY opens without blocking. Caller must close fd 7 and fd 8 afterward.
open_pipes() {
    [ -p "$NORM_PIPE" ]  || mkfifo "$NORM_PIPE"
    [ -p "$RULED_PIPE" ] || mkfifo "$RULED_PIPE"
    exec 7<> "$NORM_PIPE"
    exec 8<> "$RULED_PIPE"
}

close_pipe_holders() {
    exec 7>&- 8>&-
}

make_dev_config() {
    # Rewrite the syslog listen ports to the non-privileged dev port.
    sed \
        -e "s/udp_port = [0-9]*/udp_port = $SYSLOG_PORT/" \
        -e "s/tcp_port = [0-9]*/tcp_port = $SYSLOG_PORT/" \
        "$CONFIG_DIR/normalized.toml" \
        > "$DEV_CONFIG"
}

start_normalized() {
    "$BIN_DIR/normalized" \
        --config "$DEV_CONFIG" \
        --data-dir "$DATA_DIR" \
        > "$NORM_PIPE" \
        2>"$LOG_DIR/normalized.log" &
    save_pid normalized $!
    info "normalized  pid=$!  (UDP+TCP :$SYSLOG_PORT → $DATA_DIR)"
}

start_indexd() {
    "$BIN_DIR/indexd" \
        --data-dir "$DATA_DIR" \
        --config "$CONFIG_DIR/sources.toml" \
        2>"$LOG_DIR/indexd.log" &
    save_pid indexd $!
    info "indexd      pid=$!  (inotify on $DATA_DIR/raw/)"
}

start_ruled() {
    "$BIN_DIR/ruled" \
        --rules "$CONFIG_DIR/rules" \
        --output "$DATA_DIR/alerts" \
        < "$NORM_PIPE" \
        > "$RULED_PIPE" \
        2>"$LOG_DIR/ruled.log" &
    save_pid ruled $!
    info "ruled       pid=$!  (config/rules/*.yml → $DATA_DIR/alerts/)"
}

start_correlated() {
    "$BIN_DIR/correlated" \
        --config "$CONFIG_DIR/correlations.toml" \
        --output "$DATA_DIR/correlated" \
        < "$RULED_PIPE" \
        2>"$LOG_DIR/correlated.log" &
    save_pid correlated $!
    info "correlated  pid=$!  (config/correlations.toml → $DATA_DIR/correlated/)"
}

# Send one line as a UDP datagram to the running normalized instance.
# Tries /dev/udp (bash built-in), then logger, then nc in that order.
send_udp() {
    local line="$1"
    if { echo "$line" > /dev/udp/127.0.0.1/"$SYSLOG_PORT"; } 2>/dev/null; then
        return 0
    elif command -v logger &>/dev/null; then
        logger -n 127.0.0.1 -P "$SYSLOG_PORT" -- "$line"
    elif command -v nc &>/dev/null; then
        printf '%s\n' "$line" | nc -u -w1 127.0.0.1 "$SYSLOG_PORT"
    else
        die "No UDP send tool found (/dev/udp unavailable, logger and nc not in PATH)"
    fi
}

# ── Commands ──────────────────────────────────────────────────────────────────

cmd_build() {
    info "Building debug binaries..."
    cargo build
    info "Build complete: $BIN_DIR/"
}

cmd_start() {
    local fresh=0
    for arg in "$@"; do [ "$arg" = "--fresh" ] && fresh=1; done

    require_bins

    if get_pid normalized &>/dev/null; then
        die "Pipeline already running. Use 'restart' or 'stop' first."
    fi

    [ "$fresh" -eq 1 ] && { info "Wiping $DATA_DIR"; rm -rf "$DATA_DIR"; }

    mkdir -p "$PID_DIR" "$LOG_DIR" "$DATA_DIR/raw" "$DATA_DIR/index"
    make_dev_config
    open_pipes  # opens fd 7 (NORM_PIPE) and fd 8 (RULED_PIPE) in O_RDWR

    # Start consumers before producers: open_pipes holds the write ends open so
    # each consumer's O_RDONLY open does not block.
    start_correlated
    start_ruled
    start_indexd
    start_normalized

    close_pipe_holders
    info "Pipeline up. Syslog UDP :$SYSLOG_PORT  |  data: $DATA_DIR"
    info "Logs: $LOG_DIR/  |  try: ./dev.sh logs all"
}

cmd_stop() {
    stop_process normalized
    stop_process ruled
    stop_process correlated
    stop_process indexd
    info "All processes stopped."
}

cmd_restart() {
    cmd_stop
    cmd_start "$@"
}

cmd_status() {
    echo "── Process Status ──────────────────────────────────────────────────"
    local name pid
    for name in normalized indexd ruled correlated; do
        if pid=$(get_pid "$name" 2>/dev/null); then
            printf "  %-14s  running  (pid %s)\n" "$name" "$pid"
        else
            printf "  %-14s  STOPPED\n" "$name"
        fi
    done
    echo "── siemctl status ──────────────────────────────────────────────────"
    "$BIN_DIR/siemctl" status --data-dir "$DATA_DIR" 2>/dev/null \
        || echo "  (data directory not found or empty)"
}

cmd_reset() {
    cmd_stop
    info "Wiping $DATA_DIR"
    rm -rf "$DATA_DIR"
    cmd_start
}

cmd_send() {
    [ $# -ge 1 ] || die "Usage: ./dev.sh send \"<syslog line>\""
    get_pid normalized &>/dev/null || die "Pipeline is not running — start it first"
    send_udp "$*"
    info "Sent: $*"
}

cmd_replay() {
    local file="${1:-}"
    [ -n "$file" ]   || die "Usage: ./dev.sh replay <file>"
    [ -f "$file" ]   || die "File not found: $file"
    get_pid normalized &>/dev/null || die "Pipeline is not running — start it first"

    local count=0
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        send_udp "$line"
        count=$((count + 1))
        # Throttle every 100 lines to avoid overrunning the UDP socket buffer.
        [ $((count % 100)) -eq 0 ] && sleep 0.05
    done < "$file"
    info "Replayed $count lines from $file"
}

cmd_dryrun() {
    local file="${1:-}"
    [ -n "$file" ] || die "Usage: ./dev.sh dry-run <file>"
    [ -f "$file" ] || die "File not found: $file"
    require_bins
    "$BIN_DIR/siemctl" dry-run \
        --file "$file" \
        --config "$CONFIG_DIR/normalized.toml" \
        --rules  "$CONFIG_DIR/rules"
}

cmd_query() {
    require_bins
    "$BIN_DIR/siemctl" search --data-dir "$DATA_DIR" "$@"
}

cmd_tail_events() {
    require_bins
    "$BIN_DIR/siemctl" tail --data-dir "$DATA_DIR" "$@"
}

cmd_logs() {
    local stage="${1:-all}"
    mkdir -p "$LOG_DIR"
    case "$stage" in
        all)
            # tail -F interleaves all four logs, labelling each with the filename.
            tail -F \
                "$LOG_DIR/normalized.log" \
                "$LOG_DIR/indexd.log" \
                "$LOG_DIR/ruled.log" \
                "$LOG_DIR/correlated.log" \
                2>/dev/null
            ;;
        normalized|indexd|ruled|correlated)
            [ -f "$LOG_DIR/$stage.log" ] \
                || die "$stage has not been started yet (no log file)"
            tail -F "$LOG_DIR/$stage.log"
            ;;
        *)
            die "Unknown stage '$stage' — use: all  normalized  indexd  ruled  correlated"
            ;;
    esac
}

cmd_reload() {
    local what="${1:-}"
    case "$what" in
        rules)
            info "Reloading Sigma rules (ruled + correlated)..."
            # Hold NORM_PIPE open (O_RDWR) so normalized does not get SIGPIPE
            # while ruled is down. Any events in the buffer at this moment may
            # be consumed by fd 9 (lost). Inject fresh test events after reload.
            exec 9<> "$NORM_PIPE"
            exec 10<> "$RULED_PIPE"
            stop_process ruled
            stop_process correlated
            start_correlated
            start_ruled
            exec 9>&- 10>&-
            info "Rules reloaded — $(ls "$CONFIG_DIR/rules"/*.yml 2>/dev/null | wc -l) rule file(s) active"
            ;;
        norm)
            info "Reloading normalization config (normalized + ruled + correlated)..."
            make_dev_config
            exec 7<> "$NORM_PIPE"
            exec 8<> "$RULED_PIPE"
            stop_process normalized
            stop_process ruled
            stop_process correlated
            start_correlated
            start_ruled
            start_normalized
            exec 7>&- 8>&-
            info "Normalization config reloaded. indexd is unaffected."
            ;;
        index)
            info "Reloading indexd..."
            stop_process indexd
            start_indexd
            info "indexd reloaded from $CONFIG_DIR/sources.toml"
            info "Note: existing .db buckets keep their old schema — new fields"
            info "      only appear in buckets created from this point onward."
            ;;
        "")
            die "Usage: ./dev.sh reload <rules|norm|index>"
            ;;
        *)
            die "Unknown reload target '$what' — use: rules  norm  index"
            ;;
    esac
}

# ── Dispatch ──────────────────────────────────────────────────────────────────

case "${1:-}" in
    build)      shift; cmd_build "$@" ;;
    start)      shift; cmd_start "$@" ;;
    stop)       shift; cmd_stop ;;
    restart)    shift; cmd_restart "$@" ;;
    status)     shift; cmd_status ;;
    reset)      shift; cmd_reset ;;
    send)       shift; cmd_send "$@" ;;
    replay)     shift; cmd_replay "$@" ;;
    dry-run)    shift; cmd_dryrun "$@" ;;
    query)      shift; cmd_query "$@" ;;
    tail)       shift; cmd_tail_events "$@" ;;
    logs)       shift; cmd_logs "${1:-all}" ;;
    reload)     shift; cmd_reload "${1:-}" ;;
    help|--help|-h)
        grep '^#' "$0" | grep -E '^\#   |^\# (COMMANDS|ENVIRONMENT|HOT-RELOAD)' \
            | sed 's/^# \?//'
        ;;
    "")
        echo "Usage: ./dev.sh <command> [args]"
        echo "Run './dev.sh help' for the full command and limitations reference."
        exit 1
        ;;
    *)
        die "Unknown command '$1' — run: ./dev.sh help"
        ;;
esac

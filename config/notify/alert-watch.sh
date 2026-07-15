#!/usr/bin/env bash
# alert-watch.sh — inotify-based defense-in-depth notifier for high/critical
# alerts, independent of the LLM analyst's 10-minute cadence.
#
# Roadmap: docs/roadmap-soc-improvements.md item 3 ("Notification
# dispatch"), the "alternative" design — an inotify watcher script on
# data/alerts/ outside the SIEM binaries, rather than an exec hook inside
# `ruled`. Chosen because it needs no changes to ruled/correlated and keeps
# the SIEM's own binaries free of notification-channel concerns.
#
# WHY THIS EXISTS SEPARATELY FROM THE LLM ANALYST CRON: if the agent loop
# is down (crashed, rate-limited, mid-deploy, whatever), a critical alert
# must still reach a human. This script is intentionally NOT gated by the
# llm-based-soc kill switch (llm-based-soc/PAUSED) that the agent roles
# check — pausing the agents should not also silence this path. It has no
# dependency on the SOC ticketing system or any LLM call: just inotify,
# jq, and the notify script.
#
# Watches data/alerts/ (both ruled's alerts.jsonl, which carries a `level`
# field, and correlated's correlated.jsonl under data/alerts/correlated/,
# which doesn't — see handle_line() below) and calls the configured notify
# script for every new alert meeting the level threshold.
#
# Two layers of detection run concurrently: a reactive inotifywait watch
# (low-latency, the common path) and a periodic mtime-based reconciliation
# sweep (a backstop — confirmed live that a brand-new, multi-level-deep
# alerts/YYYY/MM/DD/HH/ bucket, the first alert of a new hour, can be
# created faster than inotifywait installs a watch on the newly-created
# intermediate directories, in which case the kernel never generates an
# event for it at all; see sweep_recent()'s doc comment for the full
# analysis). Both layers funnel through the same offset-tracked
# process_file(), so there's no double-notify risk from having both active.
#
# USAGE:
#   alert-watch.sh
#
# ENVIRONMENT:
#   SIEM_DATA_DIR              Data directory to watch (default: ./data)
#   ALERT_WATCH_STATE_DIR      Per-file read-offset state (default:
#                              /var/lib/headless-siem/alert-watch)
#   SOC_NOTIFY_SCRIPT          Notify script, called as
#                              "<script> <priority> <subject> <body-file>"
#                              (default: /usr/local/bin/soc-notify)
#   ALERT_WATCH_LEVEL          Minimum ruled alert level to notify on:
#                              low|medium|high|critical (default: high)
#   ALERT_WATCH_SWEEP_INTERVAL       Reconciliation sweep interval, seconds
#                                    (default: 60)
#   ALERT_WATCH_SWEEP_LOOKBACK_MINUTES  How far back (by mtime) the sweep
#                                       looks (default: 15)
#
# A silent failure here means a missed critical alert, so every failure
# path logs loudly to stderr (captured by journald under the systemd unit)
# rather than swallowing errors.

set -uo pipefail
# Deliberately not `set -e`: one malformed alert line or one failed notify
# call must not kill the watcher — a dead watcher misses everything after
# it, not just the one bad line.

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DATA_DIR="${SIEM_DATA_DIR:-$PROJECT_ROOT/data}"
ALERTS_DIR="$DATA_DIR/alerts"
STATE_DIR="${ALERT_WATCH_STATE_DIR:-/var/lib/headless-siem/alert-watch}"
NOTIFY_SCRIPT="${SOC_NOTIFY_SCRIPT:-/usr/local/bin/soc-notify}"
LEVEL_THRESHOLD="${ALERT_WATCH_LEVEL:-high}"
LOG_PREFIX="[alert-watch]"

# How often the periodic reconciliation sweep runs, and how far back (by
# mtime) it looks — see the sweep_recent()/sweep_loop() doc comment below
# for why this exists. Overridable for tests that don't want to wait a
# full minute for the backstop to prove itself.
SWEEP_INTERVAL_SECONDS="${ALERT_WATCH_SWEEP_INTERVAL:-60}"
SWEEP_LOOKBACK_MINUTES="${ALERT_WATCH_SWEEP_LOOKBACK_MINUTES:-15}"

log() { echo "$LOG_PREFIX $*" >&2; }

command -v inotifywait >/dev/null 2>&1 || {
    log "FATAL: inotifywait not found — install inotify-tools"
    exit 1
}
command -v jq >/dev/null 2>&1 || {
    log "FATAL: jq not found"
    exit 1
}

mkdir -p "$STATE_DIR"
mkdir -p "$ALERTS_DIR"

# level -> numeric rank, for threshold comparison. Unknown/missing levels
# rank 0 and are never forwarded (fail closed on the *filter*, not on the
# notify call itself — an alert we can't classify is not one we invent a
# severity for).
level_rank() {
    case "$1" in
        critical) echo 4 ;;
        high)     echo 3 ;;
        medium)   echo 2 ;;
        low)      echo 1 ;;
        *)        echo 0 ;;
    esac
}
THRESHOLD_RANK="$(level_rank "$LEVEL_THRESHOLD")"

# Deterministic, collision-free per-file state filename.
state_file_for() {
    printf '%s' "$1" | md5sum | cut -d' ' -f1 | sed "s#^#$STATE_DIR/#; s#\$#.offset#"
}

# notify_alert LINE LEVEL — invoke the configured notify script.
notify_alert() {
    local line="$1" level="$2"
    local rule_id subject tmpfile rc
    rule_id="$(printf '%s' "$line" | jq -r '.rule_id // .correlation_id // "unknown"' 2>/dev/null)"
    [ -z "$rule_id" ] && rule_id="unknown"
    subject="[$level] $rule_id"

    tmpfile="$(mktemp)"
    printf '%s' "$line" | jq . > "$tmpfile" 2>/dev/null || printf '%s\n' "$line" > "$tmpfile"

    if [ ! -x "$NOTIFY_SCRIPT" ]; then
        log "ERROR: notify script not found or not executable: $NOTIFY_SCRIPT (alert: $subject)"
        rm -f "$tmpfile"
        return 1
    fi

    "$NOTIFY_SCRIPT" "$level" "$subject" "$tmpfile"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        log "notified: $subject"
    else
        log "ERROR: notify script exited $rc for: $subject"
    fi
    rm -f "$tmpfile"
    return "$rc"
}

# handle_line FILE LINE — decide whether one new alert line meets the
# threshold and dispatch it.
handle_line() {
    local file="$1" line="$2"
    [ -z "$line" ] && return 0

    case "$file" in
        */alerts/correlated/*)
            # Correlated alerts carry no `level` field (see
            # roadmap-soc-improvements.md's ground-truth notes and
            # soc-structure/overall.md's "treat correlated as at least
            # medium priority" convention). A correlation is, by
            # definition, a multi-step compound pattern matched across
            # several base alerts — inherently rarer and higher-signal
            # than a single rule firing, so this watcher always notifies
            # on a new correlated alert rather than trying to invent a
            # level for it.
            notify_alert "$line" "high"
            return 0
            ;;
    esac

    local level rank
    level="$(printf '%s' "$line" | jq -r '.level // empty' 2>/dev/null)"
    [ -z "$level" ] && return 0
    rank="$(level_rank "$level")"
    if [ "$rank" -ge "$THRESHOLD_RANK" ]; then
        notify_alert "$line" "$level"
    fi
}

# process_file FILE — read and handle any lines appended since the last
# time this file was processed (tracked by byte offset). Handles the file
# having shrunk (retention/reindex/truncation) by restarting from 0 rather
# than erroring or hanging.
process_file() {
    local file="$1"
    [ -f "$file" ] || return 0
    local state last_offset size
    state="$(state_file_for "$file")"
    last_offset=0
    [ -f "$state" ] && last_offset="$(cat "$state" 2>/dev/null || echo 0)"
    case "$last_offset" in ''|*[!0-9]*) last_offset=0 ;; esac
    size="$(stat -c%s "$file" 2>/dev/null || echo 0)"

    if [ "$size" -lt "$last_offset" ]; then
        log "WARN: $file shrank ($last_offset -> $size bytes) — re-reading from start"
        last_offset=0
    fi

    if [ "$size" -gt "$last_offset" ]; then
        while IFS= read -r line; do
            handle_line "$file" "$line"
        done < <(tail -c "+$((last_offset + 1))" "$file")
    fi
    printf '%s' "$size" > "$state"
}

# sweep_recent — re-check any *.jsonl under $ALERTS_DIR modified in the
# last $SWEEP_LOOKBACK_MINUTES, regardless of whether inotify ever told us
# about it.
#
# WHY THIS EXISTS: recursive inotify watching has an inherent TOCTOU race
# for a brand-new, multi-level-deep directory chain created in one burst —
# `ruled`/`correlated` create data/alerts/YYYY/MM/DD/HH/ on the first alert
# of a new hour via a single fs::create_dir_all + file write, which can
# complete faster than inotifywait wakes up and installs a watch on the
# newly-created intermediate directories. When that happens, the kernel
# never generates a CREATE event for the deeper levels at all — there's
# nothing to "catch up on" later from the event stream, because the event
# never existed. This is the exact same failure mode fixed for indexd in
# llm-based-soc's archived plan §1.6 (see indexd's RECENT_FILE_SWEEP_INTERVAL doc
# comment for the full race analysis) — confirmed live here too: a
# brand-new hour bucket's first alert.jsonl was written and never
# processed by the reactive watch below.
#
# process_file()'s byte-offset tracking makes re-checking an
# already-fully-processed file a fast no-op, so this is cheap to run
# often. `-mmin` bounds the walk to recently-touched files, not the whole
# alerts tree.
sweep_recent() {
    local f
    while IFS= read -r -d '' f; do
        process_file "$f"
    done < <(find "$ALERTS_DIR" -name '*.jsonl' -mmin "-$SWEEP_LOOKBACK_MINUTES" -print0 2>/dev/null)
}

# sweep_loop — runs sweep_recent on a timer, as a background job alongside
# the event-driven main loop below. Started before the signal trap is
# armed isn't required (it shares this script's process group either way,
# and the group-kill in cleanup() takes it out along with inotifywait).
sweep_loop() {
    while true; do
        sleep "$SWEEP_INTERVAL_SECONDS"
        sweep_recent
    done
}

# ── Initial baseline: don't replay history on (re)start ─────────────────
existing_count=0
while IFS= read -r -d '' f; do
    size="$(stat -c%s "$f" 2>/dev/null || echo 0)"
    printf '%s' "$size" > "$(state_file_for "$f")"
    existing_count=$((existing_count + 1))
done < <(find "$ALERTS_DIR" -name '*.jsonl' -print0 2>/dev/null)
log "baseline established for $existing_count existing alert file(s) — watching for new alerts only"
log "watching $ALERTS_DIR (level threshold: $LEVEL_THRESHOLD, notify: $NOTIFY_SCRIPT)"

# ── Signal handling ───────────────────────────────────────────────────────
# `inotifywait -m` runs as a separate process on the read end of a pipe
# below. A plain `kill $script_pid` (what systemd's SIGTERM-then-SIGKILL
# stop sequence sends) does NOT reliably reach a pipeline's other members —
# without this trap, `systemctl stop`/`restart` orphans inotifywait, which
# keeps running and (on the next start) causes duplicate notifications for
# every subsequent alert, exactly the kind of silent-until-it-isn't failure
# this whole script exists to avoid elsewhere. `kill -- -$$` signals the
# entire process group (this script + inotifywait + the read loop).
cleanup() {
    # Disable the trap FIRST: `kill -- -$$` below signals the whole
    # process group, which includes this script itself — without
    # resetting the trap first, that self-signal re-invokes cleanup(),
    # which sends another group-kill, which re-invokes cleanup() again,
    # forever. (Caught in testing: an unbounded "shutting down" loop that
    # never actually exits — the exact opposite of the clean shutdown this
    # trap exists to guarantee.)
    trap - TERM INT
    log "shutting down"
    kill -- -$$ 2>/dev/null
    exit 0
}
trap cleanup TERM INT

# Periodic reconciliation backstop (see sweep_recent()'s doc comment) —
# runs alongside the event-driven loop below, not instead of it.
sweep_loop &
log "reconciliation sweep running every ${SWEEP_INTERVAL_SECONDS}s (lookback ${SWEEP_LOOKBACK_MINUTES}m)"

# ── Main loop ─────────────────────────────────────────────────────────────
# close_write: every append (ruled/correlated open+append+close per line).
# moved_to: defense-in-depth in case a writer ever switches to temp+rename
# (normalized's own bucket files do; ruled/correlated don't today, but this
# script shouldn't silently blind itself if that changes).
inotifywait -m -r -e close_write -e moved_to --format '%w%f' "$ALERTS_DIR" 2>/dev/null |
while IFS= read -r changed_file; do
    case "$changed_file" in
        *.jsonl) process_file "$changed_file" ;;
    esac
done

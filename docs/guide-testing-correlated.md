# How to Test and Debug correlated

A step-by-step guide to testing and debugging the `correlated` sliding-window correlation engine.

---

## Table of Contents

1. [How correlated Works](#how-correlated-works)
2. [Quick Smoke Test](#quick-smoke-test)
3. [Testing Threshold Triggers](#testing-threshold-triggers)
4. [Testing Eviction (Window Expiry)](#testing-eviction-window-expiry)
5. [Testing Deduplication](#testing-deduplication)
6. [Testing Multiple Rules Independently](#testing-multiple-rules-independently)
7. [Testing with Real ruled Output](#testing-with-real-ruled-output)
8. [Debugging: Why Didn't It Correlate?](#debugging-why-didnt-it-correlate)
9. [Debugging: Why Did It Correlate Too Much?](#debugging-why-did-it-correlate-too-much)
10. [Verifying Filesystem Output](#verifying-filesystem-output)
11. [Troubleshooting](#troubleshooting)
12. [Quick Reference](#quick-reference)

---

## How correlated Works

`correlated` reads alert JSONL from stdin (produced by `ruled`), maintains a **per-rule sliding window** of recent alerts, and emits a **correlation alert** when the count exceeds a threshold within the window.

### Architecture

```
stdin (alert JSONL from ruled)
    │
    ▼
┌──────────────────────────────────────────────────┐
│  CorrelationEngine                                │
│                                                   │
│  windows: HashMap<rule_id, VecDeque<AlertEntry>>  │
│                                                   │
│  For each incoming alert:                         │
│    1. Push alert into rule_id's window            │
│    2. Evict entries older than (now - window)     │
│    3. If count ≥ threshold → emit correlation    │
│       (but only once per window per rule_id)      │
│                                                   │
│  last_correlation: HashMap<rule_id, timestamp>    │
│    Prevents repeat correlation alerts within      │
│    the same window.                               │
└──────────────────────────────────────────────────┘
    │
    ▼
stdout: original alerts (passthrough) + correlation alerts (injected)
```

### Key Parameters

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `--window` | 300s (5 min) | How far back to look |
| `--threshold` | 5 | How many alerts trigger correlation |

### Correlation Alert Format

```json
{
  "_correlated": true,
  "rule_id": "1001-ssh-brute-force",
  "rule_title": "SSH Brute Force Detection",
  "count": 7,
  "window_seconds": 300,
  "first_seen": 1782126000,
  "last_seen": 1782126015,
  "sample_events": [
    { "src_ip": "10.0.0.5", "event_type": "SSH_FAILED_PASSWORD" },
    { "src_ip": "10.0.0.5", "event_type": "SSH_FAILED_PASSWORD" },
    { "src_ip": "10.0.0.5", "event_type": "SSH_FAILED_PASSWORD" }
  ]
}
```

### What correlated Does NOT Do

- It does **not** correlate across different `rule_id` values — each rule has its own window
- It does **not** look at event fields (IPs, usernames) — it only counts by `rule_id`
- It does **not** drop or filter alerts — all original alerts pass through to stdout unchanged
- It does **not** persist state across restarts — windows are in-memory only

---

## Quick Smoke Test

Verify `correlated` starts and basic passthrough works:

```bash
# Build if needed
cargo build --release -p correlated

# Help
./target/release/correlated --help

# Single alert passes through unchanged
echo '{"_ruled":true,"rule_id":"test-1","rule_title":"Test","level":"low","event":{"src_ip":"10.0.0.1"},"timestamp":1782126000}' | \
  ./target/release/correlated | jq .

# Expected: the same alert echoed back (no correlation — only 1 event)
```

**Check:**
- The alert is echoed to stdout unchanged
- No `_correlated` line appears (below threshold)

---

## Testing Threshold Triggers

The core behavior: when N alerts for the same `rule_id` arrive within the window, a correlation alert fires.

### Test: Exactly at Threshold

```bash
# 5 alerts for rule-1, threshold=5 → should correlate on the 5th
for i in $(seq 1 5); do
  echo "{\"_ruled\":true,\"rule_id\":\"rule-1\",\"rule_title\":\"Brute Force\",\"level\":\"medium\",\"event\":{\"src_ip\":\"10.0.0.1\"},\"timestamp\":1782126000}"
done | ./target/release/correlated --threshold 5 --window 300 | jq .
```

**Expected output:** 6 lines — 5 original alerts + 1 correlation alert.

```bash
# Count lines
... | wc -l
# → 6

# Find the correlation alert
... | jq 'select(._correlated == true)'
```

**Check the correlation alert fields:**

```bash
... | jq 'select(._correlated == true) | {rule_id, rule_title, count, window_seconds, first_seen, last_seen}'
```

Expected:
```json
{
  "rule_id": "rule-1",
  "rule_title": "Brute Force",
  "count": 5,
  "window_seconds": 300,
  "first_seen": ...,
  "last_seen": ...
}
```

### Test: Below Threshold (No Correlation)

```bash
# 4 alerts for rule-1, threshold=5 → should NOT correlate
for i in $(seq 1 4); do
  echo "{\"_ruled\":true,\"rule_id\":\"rule-1\",\"rule_title\":\"Brute Force\",\"level\":\"medium\",\"event\":{\"src_ip\":\"10.0.0.1\"},\"timestamp\":1782126000}"
done | ./target/release/correlated --threshold 5 --window 300 | jq .
```

**Expected:** 4 lines, all original alerts, no `_correlated`.

```bash
... | jq 'select(._correlated == true)' 
# → no output
```

### Test: Custom Threshold

```bash
# threshold=2, 3 alerts → should correlate on the 2nd
for i in $(seq 1 3); do
  echo "{\"_ruled\":true,\"rule_id\":\"rule-1\",\"rule_title\":\"Test\",\"level\":\"low\",\"event\":{\"src_ip\":\"10.0.0.1\"},\"timestamp\":1782126000}"
done | ./target/release/correlated --threshold 2 --window 300 | jq .
```

**Expected:** 4 lines — 3 original + 1 correlation (fired at count=2, then dedup suppressed at count=3).

---

## Testing Eviction (Window Expiry)

Old alerts are evicted from the window. If alerts arrive slowly enough that old ones expire before the threshold is reached, no correlation fires.

### Test: Alerts Spread Across Time (Simulated)

Since `correlated` uses wall-clock time, you can't directly test eviction with piped input (all events arrive at nearly the same instant). The unit tests in `correlation.rs` test this with `feed_at()` using fixed timestamps. For integration testing, use a **long window** and **high threshold** to verify the window fills up:

```bash
# 10 alerts, threshold=10, window=300 → should correlate
for i in $(seq 1 10); do
  echo "{\"_ruled\":true,\"rule_id\":\"rule-1\",\"rule_title\":\"Test\",\"level\":\"low\",\"event\":{\"src_ip\":\"10.0.0.1\"},\"timestamp\":1782126000}"
done | ./target/release/correlated --threshold 10 --window 300 | jq 'select(._correlated == true)'
```

**Expected:** 1 correlation alert with `count: 10`.

### Test: Eviction Prevents Correlation

To test eviction in real time, you'd need to send alerts slowly over a period longer than the window. A practical approach:

```bash
# Send 4 alerts quickly, wait for window to expire, send 1 more
# threshold=5, window=5 (5 seconds)

# Terminal 1: start correlated with a short window
mkfifo /tmp/corr_test
./target/release/correlated --threshold 5 --window 5 < /tmp/corr_test &

# Terminal 2: send 4 alerts
for i in $(seq 1 4); do
  echo "{\"_ruled\":true,\"rule_id\":\"rule-1\",\"rule_title\":\"Test\",\"level\":\"low\",\"event\":{\"src_ip\":\"10.0.0.1\"},\"timestamp\":1782126000}" > /tmp/corr_test
done

# Wait 6 seconds (window is 5s)
sleep 6

# Send 1 more alert — the first 4 should have been evicted
echo "{\"_ruled\":true,\"rule_id\":\"rule-1\",\"rule_title\":\"Test\",\"level\":\"low\",\"event\":{\"src_ip\":\"10.0.0.1\"},\"timestamp\":1782126000}" > /tmp/corr_test

# Cleanup
rm /tmp/corr_test
kill %1
```

**Expected:** No correlation alert — the first 4 were evicted, so the count never reached 5.

---

## Testing Deduplication

`correlated` suppresses repeat correlation alerts within the same window for the same `rule_id`. This prevents alert storms.

### Test: Dedup Suppresses Repeat Correlations

```bash
# 10 alerts, threshold=3 → first correlation at count=3, then suppressed for counts 4-10
for i in $(seq 1 10); do
  echo "{\"_ruled\":true,\"rule_id\":\"rule-1\",\"rule_title\":\"Brute Force\",\"level\":\"medium\",\"event\":{\"src_ip\":\"10.0.0.1\"},\"timestamp\":1782126000}"
done | ./target/release/correlated --threshold 3 --window 300 | jq 'select(._correlated == true)'
```

**Expected:** Exactly 1 correlation alert (not 8).

```bash
# Count correlation alerts
... | jq -s '[.[] | select(._correlated == true)] | length'
# → 1
```

### Test: Dedup Is Per-Rule

```bash
# 5 alerts for rule-1, 5 alerts for rule-2, threshold=3
# Both should correlate independently
(
  for i in $(seq 1 5); do
    echo "{\"_ruled\":true,\"rule_id\":\"rule-1\",\"rule_title\":\"Rule One\",\"level\":\"medium\",\"event\":{\"src_ip\":\"10.0.0.1\"},\"timestamp\":1782126000}"
  done
  for i in $(seq 1 5); do
    echo "{\"_ruled\":true,\"rule_id\":\"rule-2\",\"rule_title\":\"Rule Two\",\"level\":\"medium\",\"event\":{\"src_ip\":\"10.0.0.2\"},\"timestamp\":1782126000}"
  done
) | ./target/release/correlated --threshold 3 --window 300 | jq 'select(._correlated == true) | {rule_id, count}'
```

**Expected:** 2 correlation alerts — one for `rule-1` and one for `rule-2`.

---

## Testing Multiple Rules Independently

Each `rule_id` has its own independent window. Alerts for one rule don't affect another.

### Test: One Rule Hits Threshold, Another Doesn't

```bash
# rule-1: 5 alerts (hits threshold=3)
# rule-2: 2 alerts (below threshold)
(
  for i in $(seq 1 5); do
    echo "{\"_ruled\":true,\"rule_id\":\"rule-1\",\"rule_title\":\"Rule One\",\"level\":\"medium\",\"event\":{\"src_ip\":\"10.0.0.1\"},\"timestamp\":1782126000}"
  done
  for i in $(seq 1 2); do
    echo "{\"_ruled\":true,\"rule_id\":\"rule-2\",\"rule_title\":\"Rule Two\",\"level\":\"medium\",\"event\":{\"src_ip\":\"10.0.0.2\"},\"timestamp\":1782126000}"
  done
) | ./target/release/correlated --threshold 3 --window 300 | jq 'select(._correlated == true) | {rule_id, count}'
```

**Expected:** Only 1 correlation alert, for `rule-1` with `count: 3`.

### Test: Interleaved Alerts

```bash
# Interleave alerts from two rules
(
  echo '{"_ruled":true,"rule_id":"rule-1","rule_title":"R1","level":"low","event":{"src_ip":"10.0.0.1"},"timestamp":1}'
  echo '{"_ruled":true,"rule_id":"rule-2","rule_title":"R2","level":"low","event":{"src_ip":"10.0.0.2"},"timestamp":1}'
  echo '{"_ruled":true,"rule_id":"rule-1","rule_title":"R1","level":"low","event":{"src_ip":"10.0.0.1"},"timestamp":1}'
  echo '{"_ruled":true,"rule_id":"rule-2","rule_title":"R2","level":"low","event":{"src_ip":"10.0.0.2"},"timestamp":1}'
  echo '{"_ruled":true,"rule_id":"rule-1","rule_title":"R1","level":"low","event":{"src_ip":"10.0.0.1"},"timestamp":1}'
) | ./target/release/correlated --threshold 3 --window 300 | jq 'select(._correlated == true) | {rule_id, count}'
```

**Expected:** 1 correlation alert for `rule-1` with `count: 3`. `rule-2` only has 2 alerts, below threshold.

---

## Testing with Real ruled Output

The full pipeline test:

```bash
# Create test events that will trigger ruled alerts
cat > /tmp/test_events.jsonl << 'EOF'
{"_raw":"Jun 22 08:55:03 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2","_source":"sshd"}
{"_raw":"Jun 22 08:55:04 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2","_source":"sshd"}
{"_raw":"Jun 22 08:55:05 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2","_source":"sshd"}
{"_raw":"Jun 22 08:55:06 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2","_source":"sshd"}
{"_raw":"Jun 22 08:55:07 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2","_source":"sshd"}
{"_raw":"Jun 22 08:55:08 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2","_source":"sshd"}
EOF

# Full pipeline: normalized → ruled → correlated
cat /tmp/test_events.jsonl | \
  ../normalized/target/release/normalized --dry-run | \
  ../ruled/target/release/ruled --rules ../config/rules | \
  ./target/release/correlated --threshold 3 --window 300 | \
  jq .
```

**Check:**
- Normalized output has `_normalized: true` and extracted fields
- Ruled output has `_ruled: true` alerts
- Correlated output has both original alerts AND a `_correlated: true` line

### Count Each Type

```bash
cat /tmp/test_events.jsonl | \
  ../normalized/target/release/normalized --dry-run | \
  ../ruled/target/release/ruled --rules ../config/rules | \
  ./target/release/correlated --threshold 3 --window 300 | \
  jq -r 'if ._correlated == true then "correlation" elif ._ruled == true then "alert" elif ._normalized == true then "normalized" else "other" end' | \
  sort | uniq -c
```

---

## Debugging: Why Didn't It Correlate?

### Step 1: Check the Alert Has a rule_id

`correlated` extracts `rule_id` from the alert JSON. If it's missing, the alert is grouped under `"unknown"`:

```bash
cat alerts.jsonl | jq '{rule_id, rule_title}'
```

If `rule_id` is missing or null, check your Sigma rule YAML — it needs an `id` field.

### Step 2: Check All Alerts Have the Same rule_id

Correlation is **per rule_id**. If your alerts have different `rule_id` values, they go into different windows:

```bash
cat alerts.jsonl | jq -r '.rule_id' | sort | uniq -c
```

If you expected them to be the same rule but they have different IDs, fix your rule YAML.

### Step 3: Check the Count vs. Threshold

Count how many alerts you're sending for each rule:

```bash
cat alerts.jsonl | jq -r '.rule_id' | sort | uniq -c
```

If the count is below your `--threshold`, correlation won't fire. Either lower the threshold or send more alerts.

### Step 4: Check the Window

If alerts arrive slowly (spread over time longer than `--window`), old ones are evicted before the threshold is reached:

```bash
# Check the timestamps of your alerts
cat alerts.jsonl | jq '.timestamp'
```

If the time span between first and last alert exceeds `--window`, increase the window:

```bash
correlated --window 600 --threshold 5   # 10-minute window
```

### Step 5: Check for Malformed JSON

`correlated` skips lines that aren't valid JSON:

```bash
# Count valid vs invalid lines
python3 -c "
import sys, json
valid = 0
invalid = 0
for line in sys.stdin:
    try:
        json.loads(line)
        valid += 1
    except:
        invalid += 1
print(f'valid: {valid}, invalid: {invalid}')
" < alerts.jsonl
```

### Step 6: Check for Empty Lines

Empty lines are silently skipped:

```bash
grep -c '^$' alerts.jsonl
```

---

## Debugging: Why Did It Correlate Too Much?

### Check: Is Dedup Working?

Dedup suppresses repeat correlations within the same window. If you're getting multiple correlation alerts for the same `rule_id` in rapid succession, check:

```bash
# Count correlation alerts per rule_id
... | jq 'select(._correlated == true) | .rule_id' | sort | uniq -c
```

If you see more than 1 per `rule_id` within a short time, the dedup window may have expired between bursts. Increase `--window`:

```bash
correlated --window 600 --threshold 5
```

### Check: Are You Sending Too Many Alerts?

If your threshold is too low, even normal activity triggers correlation:

```bash
# Count alerts per rule per minute (approximate)
cat alerts.jsonl | jq -r '.rule_id' | sort | uniq -c | sort -rn
```

If a rule fires hundreds of times per minute, correlation will trigger constantly. Options:
- **Raise the threshold**: `--threshold 50`
- **Tighten the rule**: Add filters in your Sigma rule to reduce false positives
- **Shorten the window**: `--window 60` (only burst within 1 minute counts)

### Check: Are Different Rules Firing on the Same Events?

If multiple rules match the same events, each rule gets its own window and can independently trigger correlation:

```bash
# See which rules are firing
cat alerts.jsonl | jq -r '[.rule_id, .rule_title] | @tsv' | sort | uniq -c | sort -rn
```

This is expected behavior — each rule is independent. If you want to reduce noise, consolidate overlapping rules.

---

## Verifying Filesystem Output

When `--output` is specified, correlation alerts are written to time-bucketed files:

```
data/YYYY/MM/DD/HH/correlated.jsonl
```

### Check Files Exist

```bash
# Run correlated with output
cat alerts.jsonl | correlated --threshold 3 --output ./data

# Find correlation files
find data/ -name "correlated.jsonl" | sort
```

### Inspect Correlation Alerts

```bash
# Latest correlation file
find data/ -name "correlated.jsonl" | sort | tail -1 | xargs cat | jq .

# Count correlations by rule
find data/ -name "correlated.jsonl" | sort | tail -1 | xargs cat | \
  jq -r '.rule_id' | sort | uniq -c

# Check sample events
find data/ -name "correlated.jsonl" | sort | tail -1 | xargs cat | \
  jq '{rule_id, count, samples: [.sample_events[] | .src_ip]}'
```

### Verify Original Alerts Still Pass Through

Correlation alerts are **injected** into the output stream — original alerts still appear:

```bash
cat alerts.jsonl | correlated --threshold 3 --output ./data | \
  jq -r 'if ._correlated == true then "CORR" elif ._ruled == true then "ALERT" else "OTHER" end' | \
  sort | uniq -c
```

You should see both `ALERT` and `CORR` lines.

---

## Troubleshooting

### "correlated: unknown flag"

You're using a flag that doesn't exist. Valid flags: `--window`, `--threshold`, `--output`, `--help`.

### "correlated: --window must be a positive integer"

The value after `--window` isn't a valid number:

```bash
# Wrong
correlated --window abc

# Right
correlated --window 300
```

### "correlated: --threshold must be a positive integer"

Same as above — threshold must be a number:

```bash
correlated --threshold 5    # correct
correlated --threshold 0    # valid but useless (always correlates)
```

### "correlated: skipping malformed JSON"

A line on stdin isn't valid JSON. `correlated` skips it and continues. Check your input:

```bash
python3 -c "import sys, json; [json.loads(l) for l in sys.stdin]" < input.jsonl
```

### No output at all

1. Check that stdin isn't empty
2. Check that input is valid JSONL
3. Check that alerts have `rule_id` fields
4. Check that `correlated` isn't crashing (check stderr)

### Correlation fires on the first alert

If `--threshold 1`, correlation fires on every alert. Use a threshold of at least 2.

### Correlation never fires

See [Debugging: Why Didn't It Correlate?](#debugging-why-didnt-it-correlate) above.

---

## Quick Reference

### CLI

```bash
correlated [--window <seconds>] [--threshold <count>] [--output <path>]
```

### Common Test Commands

```bash
# Smoke test
echo '{"_ruled":true,"rule_id":"test","rule_title":"T","level":"low","event":{},"timestamp":1}' | \
  correlated | jq .

# Test threshold trigger (5 alerts, threshold=3)
for i in $(seq 1 5); do
  echo "{\"_ruled\":true,\"rule_id\":\"r1\",\"rule_title\":\"T\",\"level\":\"low\",\"event\":{\"src_ip\":\"10.0.0.1\"},\"timestamp\":1}"
done | correlated --threshold 3 --window 300 | jq 'select(._correlated == true)'

# Count correlation alerts
... | jq -s '[.[] | select(._correlated == true)] | length'

# Full pipeline test
cat events.jsonl | normalized --dry-run | ruled --rules config/rules | correlated --threshold 3 | jq .

# Inspect correlation output
... | jq 'select(._correlated == true) | {rule_id, count, window_seconds, first_seen, last_seen}'

# Check sample events
... | jq 'select(._correlated == true) | .sample_events'

# Filesystem output
correlated --threshold 3 --output ./data
find data/ -name "correlated.jsonl" | sort | tail -1 | xargs cat | jq .
```

### Debugging Checklist

- [ ] Input is valid JSONL (no malformed lines)
- [ ] Alerts have `rule_id` field (not null/missing)
- [ ] Alert count per `rule_id` ≥ `--threshold`
- [ ] Alerts arrive within `--window` seconds of each other
- [ ] Dedup isn't suppressing a legitimate new burst (check timestamps)
- [ ] Different `rule_id` values aren't accidentally mixed
- [ ] Filesystem output exists at `data/YYYY/MM/DD/HH/correlated.jsonl` (if `--output` used)
- [ ] Original alerts pass through unchanged (not dropped)

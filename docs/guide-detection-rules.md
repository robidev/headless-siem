# How to Write and Verify a Detection Rule

A step-by-step guide to creating Sigma-style detection rules for the Headless SIEM rule engine (`ruled`).

---

## Table of Contents

1. [How ruled Works](#how-ruled-works)
2. [Rule File Format](#rule-file-format)
3. [Writing Your First Rule](#writing-your-first-rule)
4. [Field Match Modifiers](#field-match-modifiers)
5. [Condition Expressions](#condition-expressions)
6. [Logsource Filtering](#logsource-filtering)
7. [Keyword-Based Detection](#keyword-based-detection)
8. [Testing a Rule with --dry-run](#testing-a-rule-with---dry-run)
9. [Verifying Alerts in Production](#verifying-alerts-in-production)
10. [Understanding Deduplication](#understanding-deduplication)
11. [Troubleshooting](#troubleshooting)
12. [Quick Reference](#quick-reference)

---

## How ruled Works

`ruled` is a **Sigma-style rule engine** that reads normalized JSONL events from stdin, evaluates them against YAML rule files, and writes alert JSONL to stdout.

### Architecture

```
stdin (JSONL from normalized)
    │
    ▼
┌─────────────────────────────────────────────┐
│  ruled                                       │
│                                               │
│  1. Load YAML rules from --rules directory   │
│  2. For each event, evaluate every rule      │
│  3. If rule matches → emit alert JSONL       │
│  4. Deduplicate within 5-second window        │
│                                               │
│  Output:                                      │
│    stdout: alert JSONL (one per match)        │
│    --output dir: alerts.jsonl (time-bucketed) │
└─────────────────────────────────────────────┘
    │
    ▼
stdout (alert JSONL) + data/alerts/YYYY/MM/DD/HH/alerts.jsonl
```

### Key Source Files

| File | Purpose |
|------|---------|
| `src/ruled/src/main.rs` | CLI, stdin loop, signal handling |
| `src/ruled/src/rules.rs` | YAML parsing, condition AST, matching engine |
| `src/ruled/src/output.rs` | AlertRouter, dedup, filesystem output |

### Alert Output Format

Each alert is a JSON object:

```json
{
  "_ruled": true,
  "rule_id": "1001-ssh-brute-force",
  "rule_title": "SSH Brute Force Detection",
  "level": "medium",
  "event": { "src_ip": "10.0.0.5", "event_type": "SSH_FAILED_PASSWORD", ... },
  "timestamp": 1782126000
}
```

- `_ruled: true` — always present on alerts
- `rule_id` — the rule's `id` field from YAML
- `rule_title` — the rule's `title` field
- `level` — severity: `low`, `medium`, `high`, `critical`
- `event` — the **original normalized event** that triggered the rule
- `timestamp` — Unix epoch seconds when the alert was generated

---

## Rule File Format

Rules are **Sigma-style YAML files** stored in a directory tree. `ruled` loads all `.yml` and `.yaml` files recursively.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique rule identifier (e.g. `"1001-ssh-brute-force"`) |
| `title` | string | Human-readable rule name |
| `detection` | mapping | Detection logic (selections + condition) |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `status` | string | `""` | `stable`, `experimental`, `deprecated` (deprecated rules are skipped) |
| `level` | string | `""` | Severity: `low`, `medium`, `high`, `critical` |
| `description` | string | `""` | Human-readable description |
| `tags` | list | `[]` | Arbitrary string tags |
| `logsource` | mapping | none | Filter by source type (product, service, category) |

### Minimal Rule Example

```yaml
title: Detect SSH Failed Logins
id: 1001-ssh-failed
status: stable
level: medium
logsource:
  service: sshd
detection:
  selection:
    event_type: SSH_FAILED_PASSWORD
  condition: selection
```

### Existing Rules Reference

The project ships with 4 example rules in `config/rules/`:

| Rule | ID | What it detects |
|------|----|-----------------|
| `ssh-brute-force.yml` | `1001-ssh-brute-force` | SSH failed password attempts |
| `sudo-execution.yml` | `1002-sudo-execution` | All sudo command executions |
| `iptables-deny.yml` | `1003-iptables-deny` | Firewall deny events |
| `suspicious-ssh.yml` | `1004-suspicious-ssh` | SSH failures from external IPs |

---

## Writing Your First Rule

Let's write a rule that detects **failed sudo attempts** — when someone tries to use sudo but fails authentication.

### Step 1: Understand the Event

First, look at what a normalized sudo event looks like:

```bash
echo '{"_raw":"Jun 22 08:55:03 myhost sudo: pam_unix(sudo:auth): authentication failure; logname=uid=1000 euid=0 tty=/dev/pts/0 ruser=user rhost= user=user","_source":"sudo"}' | \
  normalized --dry-run --source sudo | jq .
```

Expected output (with sudo extraction rules in normalized.toml):

```json
{
  "event_type": "SUDO_AUTH_FAILURE",
  "username": "user",
  "severity": "WARN",
  "timestamp": "Jun 22 08:55:03",
  "_normalized": true,
  "_source_type": "sudo"
}
```

### Step 2: Identify the Matching Fields

From the normalized output, the fields we can match on are:
- `_source_type: "sudo"` — only match sudo events
- `event_type` — contains `"FAILURE"` or `"AUTH_FAILURE"`

### Step 3: Write the Rule

Create `config/rules/sudo-auth-failure.yml`:

```yaml
title: Sudo Authentication Failure
id: 1005-sudo-auth-failure
status: stable
level: medium
description: Detects failed sudo authentication attempts
logsource:
  service: sudo
detection:
  selection:
    _source_type: sudo
    event_type|contains: "FAILURE"
  condition: selection
```

### Step 4: Test It

```bash
# Create a test event
echo '{"event_type":"SUDO_AUTH_FAILURE","username":"user","_source_type":"sudo","timestamp":"Jun 22 08:55:03"}' | \
  ruled --rules config/rules --dry-run
```

### What Each Part Does

```yaml
detection:
  selection:                    # Named selection (can be any name)
    _source_type: sudo          # Field must equal "sudo"
    event_type|contains: "FAILURE"  # Field must contain "FAILURE" (case-insensitive)
  condition: selection          # Condition: the "selection" must match
```

- **`selection`** — a named group of field-value pairs. All pairs must match (AND logic within a selection).
- **`_source_type: sudo`** — exact match on the `_source_type` field.
- **`event_type|contains: "FAILURE"`** — the `|contains` modifier does a case-insensitive substring match.
- **`condition: selection`** — references the named selection. The condition is evaluated as a boolean expression.

---

## Field Match Modifiers

`ruled` supports four field match types, specified with `|modifier` syntax on the field name:

### Equals (default, no modifier)

Exact string match. Numbers and booleans are converted to strings for comparison.

```yaml
selection:
  event_type: SSH_FAILED_PASSWORD    # event_type must be exactly "SSH_FAILED_PASSWORD"
  severity: ERROR                     # severity must be exactly "ERROR"
```

### Contains (`|contains`)

Case-insensitive substring match.

```yaml
selection:
  event_type|contains: "FAILED"      # matches "SSH_FAILED_PASSWORD", "LOGIN_FAILED", etc.
  message|contains: "authentication"  # matches any message containing "authentication"
```

### StartsWith (`|startswith`)

Prefix match.

```yaml
selection:
  src_ip|startswith: "10.0."         # matches 10.0.0.5, 10.0.1.100, etc.
  username|startswith: "admin"       # matches "admin", "administrator", etc.
```

### EndsWith (`|endswith`)

Suffix match.

```yaml
selection:
  username|endswith: "admin"         # matches "rootadmin", "webadmin", etc.
  event_type|endswith: "FAILED"      # matches "SSH_FAILED", "SUDO_FAILED", etc.
```

### Multiple Modifiers in One Selection

All field matches within a selection must succeed (AND logic):

```yaml
selection:
  _source_type: sshd                  # must be sshd
  event_type|contains: "FAILED"      # must contain FAILED
  src_ip|startswith: "192.168."      # must start with 192.168.
  severity: ERROR                     # must be ERROR
```

This selection only matches if **all four** conditions are true.

---

## Condition Expressions

The `condition` field is a boolean expression that combines named selections. It supports:

### Simple Reference

```yaml
condition: selection
```

The named selection must match.

### AND (`and`)

```yaml
condition: sel1 and sel2
```

Both selections must match.

### OR (`or`)

```yaml
condition: sel1 or sel2
```

At least one selection must match.

### NOT (`not`)

```yaml
condition: not filter
```

The selection must NOT match.

### AND NOT (`and not`)

```yaml
condition: selection and not filter
```

Selection must match AND filter must NOT match. This is the most common pattern for excluding false positives.

### Parentheses

```yaml
condition: (sel1 or sel2) and not filter
```

Group sub-expressions.

### 1 of them

```yaml
condition: 1 of them
```

Any named selection matches. Useful when you have many selections and want to match any of them.

### 1 of pattern

```yaml
condition: 1 of sel_*
```

Any selection whose name matches the glob pattern. `*` matches any sequence of characters.

### Condition Precedence

From lowest to highest:
1. `or`
2. `and`
3. `and not`
4. `not`

So `sel1 or sel2 and not filter` is parsed as `sel1 or (sel2 and not filter)`.

### Real-World Condition Examples

**Exclude internal IPs (false positive filter):**

```yaml
detection:
  selection:
    event_type|contains: "FAILED"
  filter:
    src_ip|startswith: "10.0."
  condition: selection and not filter
```

This fires on failed events from any IP **except** those starting with `10.0.` (internal network).

**Match multiple event types:**

```yaml
detection:
  sel_failed_password:
    event_type: SSH_FAILED_PASSWORD
  sel_failed_key:
    event_type: SSH_FAILED_KEY
  sel_invalid_user:
    event_type: SSH_INVALID_USER
  condition: sel_failed_password or sel_failed_key or sel_invalid_user
```

Or equivalently with `1 of them`:

```yaml
detection:
  sel_failed_password:
    event_type: SSH_FAILED_PASSWORD
  sel_failed_key:
    event_type: SSH_FAILED_KEY
  sel_invalid_user:
    event_type: SSH_INVALID_USER
  condition: 1 of them
```

**Match any selection with a naming pattern:**

```yaml
detection:
  sel_ssh:
    event_type: SSH_FAILED_PASSWORD
  sel_sudo:
    event_type: SUDO_AUTH_FAILURE
  sel_iptables:
    event_type: IPTABLES_DENY
  condition: 1 of sel_*
```

---

## Logsource Filtering

The `logsource` section filters events by their `_source_type` field **before** evaluating the detection logic. This is a performance optimization — events from non-matching sources skip the rule entirely.

### Available Fields

| Field | Matches against | Example |
|-------|----------------|---------|
| `product` | `_source_type` contains this string | `product: linux` |
| `service` | `_source_type` contains this string | `service: sshd` |
| `category` | `_source_type` contains this string | `category: authentication` |

### How It Works

The matching is a **substring contains** check against `_source_type`:

```yaml
logsource:
  service: sshd
```

This matches events where `_source_type` contains `"sshd"` — so `"sshd"` itself matches, and `"sshd-journal"` would also match.

### Multiple Logsource Fields

All specified fields must match (AND logic):

```yaml
logsource:
  product: linux
  service: sshd
```

This only matches events where `_source_type` contains both `"linux"` and `"sshd"`.

### No Logsource Filter

If `logsource` is omitted or empty, the rule evaluates against **all** events regardless of source:

```yaml
# This rule runs against every event
detection:
  keywords:
    - "FAILED"
  condition: keywords
```

### When to Use Logsource vs. _source_type in Selections

| Approach | When to use |
|----------|-------------|
| `logsource: { service: sshd }` | The rule is **only** relevant to sshd events. Faster — non-sshd events skip the rule entirely. |
| `selection: { _source_type: sshd }` | You need to combine source matching with other conditions in a complex boolean expression. |

For most rules, use `logsource` for the source filter and keep selections focused on field matching.

---

## Keyword-Based Detection

When you don't have structured fields to match on (e.g., Layer 2 or Layer 3 events), use keyword detection. Keywords are searched in the **raw JSON string representation** of the event (case-insensitive).

### Keyword Rule Example

```yaml
title: Suspicious Command Execution
id: 2001-suspicious-cmd
status: experimental
level: high
description: Detects suspicious commands in raw log text
detection:
  keywords:
    - "wget"
    - "curl"
    - "nc -e"
    - "bash -i"
    - "/dev/tcp"
  condition: keywords
```

This fires if the event's JSON string contains **any** of the listed keywords.

### How Keywords Work

The matching engine serializes the entire event to a JSON string, lowercases it, and checks if any keyword (also lowercased) is a substring:

```rust
// rules.rs — eval_keywords()
let raw = serde_json::to_string(event).unwrap_or_default().to_lowercase();
self.detection.keywords.iter().any(|kw| raw.contains(&kw.to_lowercase()))
```

This means keywords match against **field names and values** in the JSON. For example, the keyword `"failed"` would match:

```json
{"event_type": "SSH_FAILED_PASSWORD", "message": "authentication failed"}
```

Because the serialized string contains `"failed"` in both the field name and value.

### Combining Keywords with Selections

You can reference `keywords` in conditions just like named selections:

```yaml
detection:
  keywords:
    - "wget"
    - "curl"
  filter:
    src_ip|startswith: "10.0."
  condition: keywords and not filter
```

This fires on keyword matches from external IPs only.

---

## Testing a Rule with --dry-run

`ruled` doesn't have a `--dry-run` flag — it always writes to stdout. But you can test rules by piping sample events and checking the output.

### Basic Test

```bash
# Pipe a single event through ruled
echo '{"event_type":"SSH_FAILED_PASSWORD","src_ip":"10.0.0.5","_source_type":"sshd"}' | \
  ruled --rules config/rules
```

If the rule matches, you'll see an alert on stdout. If not, there's no output.

### Test with Multiple Events

```bash
# Create a test file with events that should and shouldn't match
cat > /tmp/test_events.jsonl << 'EOF'
{"event_type":"SSH_FAILED_PASSWORD","src_ip":"10.0.0.5","_source_type":"sshd","timestamp":"Jun 22 08:55:03"}
{"event_type":"SSH_SUCCESS","src_ip":"10.0.0.5","_source_type":"sshd","timestamp":"Jun 22 08:55:04"}
{"event_type":"SSH_FAILED_PASSWORD","src_ip":"192.168.1.100","_source_type":"sshd","timestamp":"Jun 22 08:55:05"}
{"event_type":"SUDO_AUTH_FAILURE","username":"user","_source_type":"sudo","timestamp":"Jun 22 08:55:06"}
EOF

cat /tmp/test_events.jsonl | ruled --rules config/rules | jq .
```

### Check Which Rules Fired

```bash
cat /tmp/test_events.jsonl | ruled --rules config/rules | jq '{rule_id, rule_title, level}'
```

### Count Alerts by Rule

```bash
cat /tmp/test_events.jsonl | ruled --rules config/rules | jq -r '.rule_id' | sort | uniq -c
```

### Verify an Event Does NOT Fire

```bash
# This event should NOT match the suspicious-ssh rule (it's from internal IP)
echo '{"event_type":"SSH_FAILED_PASSWORD","src_ip":"10.0.0.5","_source_type":"sshd"}' | \
  ruled --rules config/rules
# Should produce NO output (filtered by "and not filter" with src_ip|startswith: "10.0.")
```

### Test a Single Rule in Isolation

Create a temporary directory with only your new rule:

```bash
mkdir -p /tmp/test-rules
cp config/rules/sudo-auth-failure.yml /tmp/test-rules/

echo '{"event_type":"SUDO_AUTH_FAILURE","_source_type":"sudo"}' | \
  ruled --rules /tmp/test-rules | jq .
```

### Test the Full Pipeline End-to-End

```bash
# Feed raw log through normalized, then through ruled
echo '{"_raw":"Jun 22 08:55:03 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2","_source":"sshd"}' | \
  normalized --dry-run | \
  ruled --rules config/rules | jq .
```

---

## Verifying Alerts in Production

### Check stdout

`ruled` writes alerts to stdout. In a pipeline:

```bash
tail -f /var/log/syslog | \
  jq -c '{_raw: ., _source: "sshd"}' | \
  normalized --data-dir ./data | \
  ruled --rules config/rules --output ./data
```

Alerts appear on stdout as JSONL.

### Check Filesystem Output

If `--output` is specified, alerts are also written to time-bucketed files:

```
data/alerts/YYYY/MM/DD/HH/alerts.jsonl
```

```bash
# Find recent alert files
find data/alerts/ -name "alerts.jsonl" | sort | tail -5

# Inspect the latest
find data/alerts/ -name "alerts.jsonl" | sort | tail -1 | xargs cat | jq .

# Count alerts by rule
find data/alerts/ -name "alerts.jsonl" | sort | tail -1 | xargs cat | \
  jq -r '.rule_id' | sort | uniq -c | sort -rn

# Count alerts by level
find data/alerts/ -name "alerts.jsonl" | sort | tail -1 | xargs cat | \
  jq -r '.level' | sort | uniq -c

# Find high/critical alerts
find data/alerts/ -name "alerts.jsonl" -exec cat {} \; | \
  jq 'select(.level == "high" or .level == "critical")' | jq .
```

### Verify the Alert Contains the Original Event

```bash
find data/alerts/ -name "alerts.jsonl" | sort | tail -1 | xargs cat | \
  jq '{rule_id, level, event_src_ip: .event.src_ip, event_type: .event.event_type}'
```

The `event` field in the alert is the **complete original normalized event** — you can extract any field from it.

### Verify Deduplication

Send the same event twice within 5 seconds — the second should be suppressed:

```bash
# First event — should produce alert
echo '{"event_type":"SSH_FAILED_PASSWORD","src_ip":"10.0.0.5","_source_type":"sshd"}' | \
  ruled --rules config/rules | jq .

# Second identical event immediately — should produce NO output
echo '{"event_type":"SSH_FAILED_PASSWORD","src_ip":"10.0.0.5","_source_type":"sshd"}' | \
  ruled --rules config/rules
# (no output = deduplicated)
```

### Verify Logsource Filtering

```bash
# Event with non-matching source — should NOT fire sshd rules
echo '{"event_type":"SSH_FAILED_PASSWORD","src_ip":"10.0.0.5","_source_type":"iptables"}' | \
  ruled --rules config/rules
# Should produce NO output (logsource filter: service: sshd doesn't match "iptables")
```

---

## Understanding Deduplication

`ruled` has a built-in deduplication mechanism in `output.rs` to prevent alert storms.

### How It Works

1. When an alert is emitted, a dedup key is built from `src_ip` + `event_type`
2. The key is stored with the current timestamp
3. If the same `(rule_id, dedup_key)` appears within **5 seconds**, the alert is suppressed
4. After 5 seconds, the same event will fire again

### Dedup Key Construction

```rust
// output.rs — build_dedup_key()
let src_ip = event.get("src_ip").and_then(|v| v.as_str()).unwrap_or("");
let event_type = event.get("event_type").and_then(|v| v.as_str()).unwrap_or("");
format!("{}|{}", src_ip, event_type)
```

If neither `src_ip` nor `event_type` is present, it falls back to the first 64 characters of the event's JSON string.

### What This Means for Your Rules

- **Same IP + same event type within 5 seconds** → only the first alert fires
- **Different IPs** → both fire (different dedup keys)
- **Different event types from same IP** → both fire
- **Same IP + same event type after 5 seconds** → fires again

### Dedup Is Per-Rule

Dedup keys are scoped to `(rule_id, dedup_key)`. The same event can trigger multiple different rules — dedup only prevents the **same rule** from firing on the **same event pattern** repeatedly.

### When Dedup Might Surprise You

If you have a rule that matches on `event_type|contains: "FAILED"` and you get a burst of 50 failed logins from the same IP in 2 seconds, you'll only get **one alert** (the first one). The other 49 are suppressed. This is intentional — it prevents alert fatigue.

---

## Troubleshooting

### "ruled: loaded 0 rules"

The rules directory is empty or contains no valid `.yml`/`.yaml` files. Check:

```bash
ls config/rules/*.yml
```

### "ruled: skipping invalid rule file"

The YAML file has a syntax error or is missing required fields (`id`, `title`, `detection.condition`). Check:

```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('config/rules/my-rule.yml'))" && echo "OK"

# Check required fields
python3 -c "
import yaml
r = yaml.safe_load(open('config/rules/my-rule.yml'))
assert 'id' in r, 'missing id'
assert 'title' in r, 'missing title'
assert 'condition' in r.get('detection', {}), 'missing detection.condition'
print('OK')
"
```

### "ruled: skipping deprecated rule"

The rule has `status: deprecated`. Deprecated rules are automatically skipped. Either remove the rule file or change the status.

### Rule doesn't fire when expected

**Step 1: Check the event has the right fields**

```bash
echo '{"_raw":"your log line","_source":"sshd"}' | normalized --dry-run | jq 'keys'
```

Make sure the fields you're matching on actually exist in the normalized output.

**Step 2: Check logsource filtering**

If your rule has `logsource: { service: sshd }`, verify the event's `_source_type` contains `"sshd"`:

```bash
echo '{"_raw":"your log line","_source":"sshd"}' | normalized --dry-run | jq '._source_type'
```

**Step 3: Test field matches individually**

Create a minimal rule with just one field match and test:

```yaml
# /tmp/debug-rule.yml
title: Debug Rule
id: debug-001
status: stable
detection:
  selection:
    event_type: SSH_FAILED_PASSWORD
  condition: selection
```

```bash
echo '{"event_type":"SSH_FAILED_PASSWORD","_source_type":"sshd"}' | ruled --rules /tmp
```

**Step 4: Check for modifier issues**

- `|contains` is case-insensitive — `"FAILED"` matches `"ssh_failed_password"`
- `|startswith` and `|endswith` are case-sensitive
- Equals (no modifier) is exact match

**Step 5: Check condition logic**

```yaml
# This requires BOTH to match (AND)
condition: sel1 and sel2

# This requires AT LEAST ONE to match (OR)
condition: sel1 or sel2

# This requires sel1 to match AND filter to NOT match
condition: sel1 and not filter
```

### Rule fires too often (false positives)

**Add a filter selection:**

```yaml
detection:
  selection:
    event_type|contains: "FAILED"
  filter_internal:
    src_ip|startswith: "10.0."
  filter_known:
    src_ip: "192.168.1.100"
  condition: selection and not filter_internal and not filter_known
```

**Tighten the logsource:**

```yaml
logsource:
  product: linux
  service: sshd
```

**Use more specific field matches:**

```yaml
# Too broad
event_type|contains: "FAILED"

# More specific
event_type: SSH_FAILED_PASSWORD
```

### Alert output is empty but rule should match

Check that the event has a `timestamp` field. While `ruled` doesn't require it, `normalized` Layer 3 events (`_normalized: false`) may not have one. If your rule matches on a field that only exists in Layer 1/2 output, Layer 3 events won't match.

---

## Quick Reference

### Rule Template

```yaml
title: <Human-readable name>
id: <unique-id>
status: stable
level: <low|medium|high|critical>
description: <What this rule detects>
logsource:
  service: <source-type>
detection:
  <selection-name>:
    <field>: <value>
    <field>|<modifier>: <value>
  condition: <expression>
```

### CLI

```bash
# Basic usage
ruled --rules config/rules

# With filesystem output
ruled --rules config/rules --output ./data

# Full pipeline
normalized --dry-run | ruled --rules config/rules

# Test a single event
echo '{"event_type":"SSH_FAILED","_source_type":"sshd"}' | ruled --rules config/rules | jq .
```

### Field Modifiers

| Modifier | Example | Matches |
|----------|---------|---------|
| (none) | `event_type: SSH_FAILED` | Exact match |
| `\|contains` | `event_type\|contains: "FAILED"` | Case-insensitive substring |
| `\|startswith` | `src_ip\|startswith: "10.0."` | Prefix match |
| `\|endswith` | `username\|endswith: "admin"` | Suffix match |

### Condition Operators

| Operator | Example | Meaning |
|----------|---------|---------|
| `sel1 and sel2` | Both must match |
| `sel1 or sel2` | At least one must match |
| `not filter` | Must NOT match |
| `sel1 and not filter` | sel1 matches AND filter doesn't |
| `1 of them` | Any named selection matches |
| `1 of sel_*` | Any selection matching glob |
| `(a or b) and not c` | Grouped expression |

### Verification Checklist

- [ ] Rule YAML is valid (`python3 -c "import yaml; yaml.safe_load(open('...'))"`)
- [ ] Rule has `id`, `title`, and `detection.condition`
- [ ] `ruled` loads the rule (check startup log: "loaded N rules")
- [ ] Test event with matching fields produces an alert
- [ ] Test event with non-matching fields produces no output
- [ ] Logsource filter works (non-matching source → no alert)
- [ ] Dedup suppresses duplicate alerts within 5 seconds
- [ ] Alert JSON contains `_ruled: true`, `rule_id`, `event`
- [ ] Filesystem output exists at `data/alerts/YYYY/MM/DD/HH/alerts.jsonl` (if `--output` used)
- [ ] False positive filters work (e.g., `and not filter` excludes internal IPs)

# Design Proposal: LLM-Driven SOC Analyst

Running a Claude model on a cron schedule as an automated first-responder,
using the digest and alert interface as its primary inputs.

---

## Concept

Rather than a human operator polling the SIEM, a Claude model runs on a fixed
cadence. It reads the digest, triages any flagged anomalies against runbooks
and network documentation, and either logs an all-clear or escalates with a
structured assessment. Humans are pulled in only when the model determines
escalation is warranted.

---

## Cadence

10-minute cron cycle. At this interval the digest window is small, context is
fresh, and response time is acceptable for a non-production homelab. For a
production environment the cadence would be driven by alert SLA requirements.

144 cron runs per day. Expected distribution:
- ~90% quiet runs — digest shows nothing unusual
- ~9% triage runs — one or more anomalies requiring reasoning
- ~1% investigation runs — potential incident requiring follow-up queries

---

## Tiered model selection

A single model for all runs is wasteful. A tiered escalation uses cheap fast
models for the common case and reserves capable models for when they are
actually needed.

### Tier 1 — Every run: Haiku, LOW effort

**Input:** digest (structured text, ~2–5 KB), previous-window baseline  
**Task:** binary classification — is anything in this digest worth looking at?  
**Output:** "clear" log entry, or escalation flag with the specific anomalies

Haiku reads the digest and applies a simple decision: do any flagged rows
(volume spikes, new sources, new destinations, first-time alert rules) exceed
the threshold for human-level reasoning? If not, it logs a timestamped
all-clear and exits. If yes, it hands off to Tier 2 with a structured summary
of what triggered escalation.

90%+ of runs end at Tier 1. This is where the cost efficiency of the tiered
approach comes from.

### Tier 2 — Anomalies flagged: Sonnet, MEDIUM effort

**Input:** digest, flagged alerts (full JSONL with embedded events), network
topology document, relevant runbook sections  
**Task:** FP/TP triage — is this a real signal or a known false positive? Is
it urgent?  
**Output:** structured triage note: classification, confidence, recommended
action, supporting reasoning

Sonnet reasons across sources. Examples of what this tier handles well:
- Distinguishing an OpenVPN misconfiguration (pfSense client pointing at its
  own WAN IP) from an external brute-force attempt
- Recognising Suricata TCP stream reassembly alerts on Cloudflare ranges as
  tuning candidates, not incidents
- Correlating a volume spike in one source with a config change event in
  another to establish a causal explanation

Sonnet covers ~90% of realistic triage decisions correctly when given the
digest, alert context, network topology, and runbooks.

### Tier 3 — Uncertain or high-severity: Sonnet with tool access, HIGH effort

**Input:** Tier 2 output plus siemctl tool access  
**Task:** iterative investigation — run follow-up queries to resolve
uncertainty or build a complete incident picture  
**Output:** incident report with timeline, affected entities, confidence
assessment, and escalation recommendation

When Tier 2 produces an uncertain verdict or a high-severity assessment,
Sonnet gets access to siemctl as a tool and can run 3–5 targeted queries:
entity timeline for a suspicious IP, cross-source correlation, full event
retrieval via `SELECT _raw`. It iterates until it has enough information to
either close the alert or write a human-escalation report.

The complexity at this tier is breadth of data access, not reasoning depth.
Sonnet handles this well; Opus is not required.

### When Opus would be warranted

Novel multi-stage attack chains where the correct interpretation is not
covered by any runbook and requires synthesising many weak signals into a
coherent hypothesis. In a homelab context this is effectively never. In an
enterprise context it is rare enough that a human-in-the-loop is preferable
to automated Opus.

---

## Context provided per run

| Document | Tier | Notes |
|---|---|---|
| Digest (current window) | 1, 2, 3 | Generated fresh each run |
| Network topology | 2, 3 | Static; loaded from memory or docs |
| Alert JSONL (flagged rules only) | 2, 3 | Passed by Tier 1 escalation |
| Runbooks (relevant sections only) | 2, 3 | Filtered by alert type, not full doc |
| Previous triage notes | 2, 3 | Last N shifts for continuity |
| siemctl tool access | 3 | Only when Tier 2 escalates |

Loading full runbooks on every Tier 2 run is wasteful. The escalation from
Tier 1 should include the alert type and source, so Tier 2 can load only the
relevant runbook sections (e.g. openvpn runbook for VPN anomalies, filterlog
runbook for firewall anomalies).

---

## Prerequisites

This architecture only works effectively if the signal-to-noise ratio of the
alert stream is reasonable. Two items from the SOC improvements roadmap are
blocking:

**1. `siemctl alerts` (roadmap item 1)**  
Without an alert query interface, Tier 2 cannot retrieve the alerts it needs
to triage. Currently alerts are inaccessible except via raw filesystem `jq`.

**2. Alert suppression rules (roadmap item 4)**  
Without SIEM-level suppression, Tier 2 will spend the majority of its budget
on known false positives (e.g. Suricata TCP stream rules on CDN traffic) and
never reach the real signals. The model cannot be effective if it is drowning
in noise it cannot suppress.

The digest (roadmap item in `design-digest-command.md`) is the third
prerequisite, but it is what drives the entire trigger mechanism — without it,
Tier 1 has nothing to read.

---

## Cost profile (homelab estimate)

| Tier | Frequency | Model | Relative cost |
|---|---|---|---|
| 1 (all-clear) | ~130/day | Haiku | Negligible |
| 1 (escalation) | ~14/day | Haiku | Negligible |
| 2 (triage) | ~14/day | Sonnet | Low |
| 3 (investigation) | ~1–2/day | Sonnet + tools | Moderate |

Daily cost is dominated by the Tier 2 triage runs. Tier 3 is rare enough to
be a rounding error. The bulk of runs (Tier 1 all-clear) cost essentially
nothing.

---

## Output and memory

Each run produces a structured log entry regardless of outcome:

```
2026-06-29T20:10:00Z  tier=1  result=clear  window=20:00-20:10
2026-06-29T20:20:00Z  tier=2  result=triage  rule=openvpn-tls-error  verdict=fp  confidence=high  note="pfSense OVPNclient misconfigured, pointing at own WAN IP. Recurring since 17:36. No external involvement."
2026-06-29T20:30:00Z  tier=1  result=clear  window=20:20-20:30
```

Triage verdicts (FP classifications, suppression recommendations) feed back
into the alert suppression config over time, progressively reducing Tier 2
load as known FPs are eliminated from the alert stream.

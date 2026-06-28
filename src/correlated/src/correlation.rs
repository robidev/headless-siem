use crate::config::CorrelationRule;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Extract a field value from a `ruled` alert, checking inside the nested
/// `"event"` object first (the standard alert format), then at the top level.
fn extract_field<'a>(alert: &'a Value, field: &str) -> Option<&'a str> {
    if let Some(inner) = alert.get("event") {
        if let Some(v) = inner.get(field).and_then(|v| v.as_str()) {
            return Some(v);
        }
    }
    alert.get(field).and_then(|v| v.as_str())
}

/// State for one correlation chain: one (rule, join_value) pair.
#[derive(Debug)]
struct ChainState {
    /// Count of qualifying alerts received for each step so far.
    step_counts: Vec<usize>,
    /// Up to 3 sample events per step (from the nested `event` object).
    step_samples: Vec<Vec<Value>>,
    /// When the first alert in this chain arrived (epoch seconds).
    chain_start: u64,
    /// For ordered rules: index of the next step awaiting satisfaction.
    current_step: usize,
}

impl ChainState {
    fn new(num_steps: usize, now: u64) -> Self {
        ChainState {
            step_counts: vec![0; num_steps],
            step_samples: (0..num_steps).map(|_| Vec::new()).collect(),
            chain_start: now,
            current_step: 0,
        }
    }

    fn is_satisfied(&self, rule: &CorrelationRule) -> bool {
        rule.steps
            .iter()
            .enumerate()
            .all(|(i, step)| self.step_counts[i] >= step.min_count)
    }
}

/// Cross-rule correlation engine driven by `CorrelationRule` configs.
///
/// For each rule, the engine maintains a sliding-window state machine per
/// join-field value (e.g. per `src_ip`). When all steps are satisfied within
/// the window, a correlation alert is emitted and the chain resets.
pub struct CrossRuleEngine {
    rules: Vec<CorrelationRule>,
    /// `states[rule_idx][join_value]` → chain state.
    states: Vec<HashMap<String, ChainState>>,
    /// Counter used to trigger periodic eviction of expired chains.
    feed_count: usize,
}

impl CrossRuleEngine {
    pub fn new(rules: Vec<CorrelationRule>) -> Self {
        let n = rules.len();
        CrossRuleEngine {
            states: (0..n).map(|_| HashMap::new()).collect(),
            rules,
            feed_count: 0,
        }
    }

    #[allow(dead_code)]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Feed one alert from `ruled`. Returns any correlation alerts triggered.
    pub fn feed(&mut self, alert: &Value) -> Vec<Value> {
        self.feed_at(alert, now_secs())
    }

    /// Feed with an explicit timestamp for deterministic testing.
    pub(crate) fn feed_at(&mut self, alert: &Value, now: u64) -> Vec<Value> {
        let alert_rule_id = match alert.get("rule_id").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => return Vec::new(),
        };

        self.feed_count += 1;
        if self.feed_count % 500 == 0 {
            self.evict_expired(now);
        }

        let mut triggered: Vec<Value> = Vec::new();

        for rule_idx in 0..self.rules.len() {
            // Which steps in this rule match the incoming alert's rule_id?
            let matching_steps: Vec<usize> = self.rules[rule_idx]
                .steps
                .iter()
                .enumerate()
                .filter(|(_, s)| s.rule_id == alert_rule_id)
                .map(|(i, _)| i)
                .collect();

            if matching_steps.is_empty() {
                continue;
            }

            // Extract the join-field value from the alert's nested event.
            let join_field = self.rules[rule_idx].join_field.clone();
            let join_value = match extract_field(alert, &join_field) {
                Some(v) if !v.is_empty() => v.to_string(),
                _ => continue,
            };

            // Snapshot the rule metadata we need so we're not holding a borrow
            // on self.rules while mutating self.states.
            let window_secs = self.rules[rule_idx].window_seconds;
            let ordered = self.rules[rule_idx].ordered;
            let num_steps = self.rules[rule_idx].steps.len();
            let step_min_counts: Vec<usize> = self.rules[rule_idx]
                .steps
                .iter()
                .map(|s| s.min_count)
                .collect();

            // Get or create the chain state.
            {
                let state = self.states[rule_idx]
                    .entry(join_value.clone())
                    .or_insert_with(|| ChainState::new(num_steps, now));
                // Reset the chain if its window has expired.
                if now.saturating_sub(state.chain_start) > window_secs {
                    *state = ChainState::new(num_steps, now);
                }
            }

            // Apply the alert to the matching step(s).
            {
                let state = self.states[rule_idx].get_mut(&join_value).unwrap();
                for &step_idx in &matching_steps {
                    let should_count = if ordered {
                        step_idx == state.current_step
                    } else {
                        state.step_counts[step_idx] < step_min_counts[step_idx]
                    };

                    if should_count {
                        state.step_counts[step_idx] += 1;
                        // Store up to 3 sample events (prefer the inner event object).
                        if state.step_samples[step_idx].len() < 3 {
                            let sample = alert
                                .get("event")
                                .cloned()
                                .unwrap_or_else(|| alert.clone());
                            state.step_samples[step_idx].push(sample);
                        }
                        // For ordered rules, advance the cursor once a step is done.
                        if ordered
                            && state.current_step == step_idx
                            && state.step_counts[step_idx] >= step_min_counts[step_idx]
                        {
                            state.current_step += 1;
                        }
                    }
                }
            }

            // Check whether all steps are now satisfied.
            let is_satisfied = self.states[rule_idx][&join_value].is_satisfied(&self.rules[rule_idx]);

            if is_satisfied {
                let state = self.states[rule_idx].remove(&join_value).unwrap();
                let rule = &self.rules[rule_idx];
                let sample_events: Vec<Value> = state
                    .step_samples
                    .iter()
                    .flat_map(|s| s.iter().cloned())
                    .take(5)
                    .collect();

                triggered.push(serde_json::json!({
                    "_correlated": true,
                    "correlation_id":    rule.id,
                    "correlation_title": rule.title,
                    "join_field":        rule.join_field,
                    "join_value":        join_value,
                    "window_seconds":    rule.window_seconds,
                    "chain_start":       state.chain_start,
                    "chain_end":         now,
                    "step_counts":       state.step_counts,
                    "sample_events":     sample_events,
                }));
            }
        }

        triggered
    }

    /// Evict chain states whose window has expired.
    fn evict_expired(&mut self, now: u64) {
        for rule_idx in 0..self.rules.len() {
            let window = self.rules[rule_idx].window_seconds;
            self.states[rule_idx]
                .retain(|_, state| now.saturating_sub(state.chain_start) <= window);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CorrelationRule, Step};

    fn make_rule(
        id: &str,
        join_field: &str,
        window_secs: u64,
        ordered: bool,
        steps: Vec<(&str, usize)>,
    ) -> CorrelationRule {
        CorrelationRule {
            id: id.to_string(),
            title: id.to_string(),
            description: String::new(),
            join_field: join_field.to_string(),
            window_seconds: window_secs,
            ordered,
            steps: steps
                .into_iter()
                .map(|(rule_id, min_count)| Step {
                    rule_id: rule_id.to_string(),
                    min_count,
                })
                .collect(),
        }
    }

    /// Build a realistic ruled alert (rule_id at top, event fields nested under "event").
    fn alert(rule_id: &str, src_ip: &str) -> Value {
        serde_json::json!({
            "_ruled": true,
            "rule_id": rule_id,
            "rule_title": "Test Rule",
            "level": "medium",
            "event": { "src_ip": src_ip, "_source_type": "sshd" },
            "timestamp": 0u64
        })
    }

    fn alert_user(rule_id: &str, username: &str) -> Value {
        serde_json::json!({
            "_ruled": true,
            "rule_id": rule_id,
            "rule_title": "Test Rule",
            "level": "medium",
            "event": { "username": username },
            "timestamp": 0u64
        })
    }

    // ── ordered two-step chain ────────────────────────────────────────────

    #[test]
    fn test_ordered_brute_force_success() {
        let rule = make_rule(
            "cred-guess",
            "src_ip",
            300,
            true,
            vec![("ssh-fail", 3), ("ssh-ok", 1)],
        );
        let mut eng = CrossRuleEngine::new(vec![rule]);
        let t = 1_000u64;

        // 3 failures
        for i in 0..3 {
            let r = eng.feed_at(&alert("ssh-fail", "10.0.0.1"), t + i);
            assert!(r.is_empty(), "no correlation before step 0 done");
        }
        // 1 success → chain satisfied
        let r = eng.feed_at(&alert("ssh-ok", "10.0.0.1"), t + 10);
        assert_eq!(r.len(), 1);
        let c = &r[0];
        assert_eq!(c["_correlated"], true);
        assert_eq!(c["correlation_id"], "cred-guess");
        assert_eq!(c["join_value"], "10.0.0.1");
        assert_eq!(c["step_counts"][0], 3);
        assert_eq!(c["step_counts"][1], 1);
    }

    #[test]
    fn test_ordered_insufficient_first_step() {
        let rule = make_rule("r", "src_ip", 300, true, vec![("fail", 5), ("ok", 1)]);
        let mut eng = CrossRuleEngine::new(vec![rule]);
        // Only 4 failures
        for i in 0..4 {
            let r = eng.feed_at(&alert("fail", "10.0.0.1"), 1000 + i);
            assert!(r.is_empty());
        }
        // Success arrives — but step 0 not satisfied, so step 1 is not reachable
        let r = eng.feed_at(&alert("ok", "10.0.0.1"), 1005);
        assert!(r.is_empty());
    }

    #[test]
    fn test_ordered_wrong_order_no_fire() {
        let rule = make_rule("r", "src_ip", 300, true, vec![("fail", 3), ("ok", 1)]);
        let mut eng = CrossRuleEngine::new(vec![rule]);
        // Success before failures: with ordered=true, "ok" only counts for step 1,
        // which isn't current (step 0 = "fail" is still pending).
        let r = eng.feed_at(&alert("ok", "10.0.0.1"), 1000);
        assert!(r.is_empty());
        // Now 3 failures — step 0 moves to step 1
        for i in 0..3 {
            eng.feed_at(&alert("fail", "10.0.0.1"), 1001 + i);
        }
        // No more "ok" arrives → chain not satisfied
        assert!(eng.states[0].get("10.0.0.1").is_some());
    }

    #[test]
    fn test_ordered_different_ips_independent() {
        let rule = make_rule("r", "src_ip", 300, true, vec![("fail", 2), ("ok", 1)]);
        let mut eng = CrossRuleEngine::new(vec![rule]);
        // Failures from IP A, success from IP B — should not correlate
        eng.feed_at(&alert("fail", "10.0.0.1"), 1000);
        eng.feed_at(&alert("fail", "10.0.0.1"), 1001);
        let r = eng.feed_at(&alert("ok", "10.0.0.2"), 1002);
        assert!(r.is_empty(), "different IPs should not correlate");
    }

    #[test]
    fn test_ordered_same_ip_correlates() {
        let rule = make_rule("r", "src_ip", 300, true, vec![("fail", 2), ("ok", 1)]);
        let mut eng = CrossRuleEngine::new(vec![rule]);
        eng.feed_at(&alert("fail", "10.0.0.1"), 1000);
        eng.feed_at(&alert("fail", "10.0.0.1"), 1001);
        let r = eng.feed_at(&alert("ok", "10.0.0.1"), 1002);
        assert_eq!(r.len(), 1);
    }

    // ── window expiry ─────────────────────────────────────────────────────

    #[test]
    fn test_window_expired_resets_chain() {
        let rule = make_rule("r", "src_ip", 300, true, vec![("fail", 2), ("ok", 1)]);
        let mut eng = CrossRuleEngine::new(vec![rule]);
        // Two failures at t=0
        eng.feed_at(&alert("fail", "10.0.0.1"), 0);
        eng.feed_at(&alert("fail", "10.0.0.1"), 1);
        // Step 0 is satisfied. Now the window expires (t=400 > 300s window).
        // The chain resets, so "ok" alone at t=400 can't complete the 2-step chain.
        let r = eng.feed_at(&alert("ok", "10.0.0.1"), 400);
        assert!(r.is_empty(), "expired window should reset the chain");
    }

    #[test]
    fn test_within_window_fires() {
        let rule = make_rule("r", "src_ip", 300, true, vec![("fail", 2), ("ok", 1)]);
        let mut eng = CrossRuleEngine::new(vec![rule]);
        eng.feed_at(&alert("fail", "10.0.0.1"), 0);
        eng.feed_at(&alert("fail", "10.0.0.1"), 1);
        // t=299 is still inside the 300s window
        let r = eng.feed_at(&alert("ok", "10.0.0.1"), 299);
        assert_eq!(r.len(), 1);
    }

    // ── unordered rule ────────────────────────────────────────────────────

    #[test]
    fn test_unordered_fires_in_any_order() {
        let rule = make_rule("r", "src_ip", 300, false, vec![("a", 1), ("b", 1)]);
        let mut eng = CrossRuleEngine::new(vec![rule]);
        // "b" before "a" — should still fire with ordered=false
        eng.feed_at(&alert("b", "10.0.0.1"), 1000);
        let r = eng.feed_at(&alert("a", "10.0.0.1"), 1001);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn test_unordered_single_step_threshold() {
        let rule = make_rule("r", "src_ip", 300, false, vec![("fail", 5)]);
        let mut eng = CrossRuleEngine::new(vec![rule]);
        for i in 0..4 {
            let r = eng.feed_at(&alert("fail", "10.0.0.1"), 1000 + i);
            assert!(r.is_empty());
        }
        let r = eng.feed_at(&alert("fail", "10.0.0.1"), 1004);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0]["step_counts"][0], 5);
    }

    // ── state resets after fire ───────────────────────────────────────────

    #[test]
    fn test_state_resets_and_can_fire_again() {
        let rule = make_rule("r", "src_ip", 300, true, vec![("fail", 2), ("ok", 1)]);
        let mut eng = CrossRuleEngine::new(vec![rule]);
        // First chain
        eng.feed_at(&alert("fail", "10.0.0.1"), 1000);
        eng.feed_at(&alert("fail", "10.0.0.1"), 1001);
        let r1 = eng.feed_at(&alert("ok", "10.0.0.1"), 1002);
        assert_eq!(r1.len(), 1, "first chain should fire");
        // State was removed; a new chain can start
        eng.feed_at(&alert("fail", "10.0.0.1"), 1010);
        eng.feed_at(&alert("fail", "10.0.0.1"), 1011);
        let r2 = eng.feed_at(&alert("ok", "10.0.0.1"), 1012);
        assert_eq!(r2.len(), 1, "second chain should fire");
    }

    // ── multiple rules ────────────────────────────────────────────────────

    #[test]
    fn test_two_rules_fire_independently() {
        let r1 = make_rule("chain-a", "src_ip", 300, true, vec![("fail", 2), ("ok", 1)]);
        let r2 = make_rule("threshold-b", "src_ip", 300, false, vec![("fail", 3)]);
        let mut eng = CrossRuleEngine::new(vec![r1, r2]);
        eng.feed_at(&alert("fail", "10.0.0.1"), 1000);
        eng.feed_at(&alert("fail", "10.0.0.1"), 1001);
        // At this point: chain-a step 0 satisfied (2 fails), threshold-b at 2/3.
        let r = eng.feed_at(&alert("ok", "10.0.0.1"), 1002);
        // chain-a fires (step 0+1 done). threshold-b hasn't reached 3.
        assert_eq!(r.len(), 1);
        assert_eq!(r[0]["correlation_id"], "chain-a");

        let r = eng.feed_at(&alert("fail", "10.0.0.1"), 1003);
        // threshold-b now has 3 fails → fires
        assert_eq!(r.len(), 1);
        assert_eq!(r[0]["correlation_id"], "threshold-b");
    }

    // ── join field lookup ─────────────────────────────────────────────────

    #[test]
    fn test_join_field_from_nested_event() {
        // The alert has `event.src_ip` — the engine must look inside "event"
        let rule = make_rule("r", "src_ip", 300, false, vec![("fail", 2)]);
        let mut eng = CrossRuleEngine::new(vec![rule]);
        eng.feed_at(&alert("fail", "10.0.0.1"), 1000);
        let r = eng.feed_at(&alert("fail", "10.0.0.1"), 1001);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0]["join_value"], "10.0.0.1");
    }

    #[test]
    fn test_join_field_username() {
        let rule = make_rule("r", "username", 60, true, vec![("created", 1), ("sudo", 1)]);
        let mut eng = CrossRuleEngine::new(vec![rule]);
        eng.feed_at(&alert_user("created", "alice"), 1000);
        let r = eng.feed_at(&alert_user("sudo", "alice"), 1005);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0]["join_value"], "alice");
    }

    #[test]
    fn test_missing_join_field_skips_alert() {
        let rule = make_rule("r", "src_ip", 300, false, vec![("fail", 1)]);
        let mut eng = CrossRuleEngine::new(vec![rule]);
        // Alert has no src_ip in event
        let bad = serde_json::json!({
            "_ruled": true,
            "rule_id": "fail",
            "event": { "username": "alice" }
        });
        let r = eng.feed_at(&bad, 1000);
        assert!(r.is_empty(), "missing join field should be skipped");
    }

    // ── sample_events ─────────────────────────────────────────────────────

    #[test]
    fn test_sample_events_use_inner_event() {
        let rule = make_rule("r", "src_ip", 300, false, vec![("fail", 2)]);
        let mut eng = CrossRuleEngine::new(vec![rule]);
        eng.feed_at(&alert("fail", "10.0.0.1"), 1000);
        let r = eng.feed_at(&alert("fail", "10.0.0.1"), 1001);
        assert_eq!(r.len(), 1);
        let samples = r[0]["sample_events"].as_array().unwrap();
        // Samples should be the inner event objects, not the full alert wrappers
        assert!(samples[0].get("_ruled").is_none(), "should be inner event, not alert wrapper");
        assert_eq!(samples[0]["src_ip"], "10.0.0.1");
    }
}

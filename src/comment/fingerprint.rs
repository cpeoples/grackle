//! Comment marker payload, per-finding fingerprints, and run-to-run deltas.
//!
//! Every comment body ends with a stable HTML marker carrying a small JSON
//! payload. A later scan locates that marker, updates the same comment in
//! place, and reads the previous payload to compute resolved/new findings.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MARKER_PREFIX: &str = "<!-- grackle:mr-comment:v1";
const MARKER_SUFFIX: &str = "-->";

/// Named ids kept verbatim in the marker; the rest are covered by the digest.
const MARKER_RULE_SAMPLE: usize = 12;
/// Fingerprints kept verbatim; the full set is digested for O(1) change checks.
const MARKER_FINGERPRINT_SAMPLE: usize = 50;
const FINGERPRINT_LEN: usize = 16;
/// Rule names spelled out in a delta receipt before collapsing to "(+N more)".
const RESOLVED_RULES_HEADLINE_CAP: usize = 8;

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Stable per-finding identity: a truncated SHA-256 of `rule_id|path|line`, the
/// same triple the scanner dedups on, so the same finding hashes identically
/// across consecutive scans.
pub fn finding_fingerprint(rule_id: &str, path: &str, line: usize) -> String {
    sha256_hex(&format!("{rule_id}|{path}|{line}"))[..FINGERPRINT_LEN].to_string()
}

/// Decoded marker payload from a previous comment.
#[derive(Debug, Default, Clone)]
pub struct Marker {
    pub findings_count: i64,
    pub open_rule_ids: Vec<String>,
    pub finding_fingerprints: Vec<String>,
    pub finding_fingerprints_total: Option<i64>,
    pub finding_rule_ids: BTreeMap<String, String>,
}

/// Serialize the trailing HTML marker. `open_rule_ids` cites cleared rules in a
/// resolved banner; the fingerprint sample + digest let the next run compute an
/// exact per-finding delta even when the sample is truncated.
pub fn encode_marker(
    findings_count: usize,
    commit_sha: &str,
    open_rule_ids: &BTreeSet<String>,
    fingerprint_to_rule: &BTreeMap<String, String>,
) -> String {
    let sorted_ids: Vec<&String> = open_rule_ids.iter().collect();
    let digest = sha256_hex(
        &sorted_ids
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
    );

    let sample_ids: Vec<String> = sorted_ids
        .iter()
        .take(MARKER_RULE_SAMPLE)
        .map(|s| s.to_string())
        .collect();

    let all_fps: Vec<&String> = fingerprint_to_rule.keys().collect();
    let fp_digest = sha256_hex(
        &all_fps
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let sample_rule_map: BTreeMap<&String, &String> = fingerprint_to_rule
        .iter()
        .take(MARKER_FINGERPRINT_SAMPLE)
        .filter(|(_, rid)| !rid.is_empty())
        .collect();
    let sample_fps: Vec<&&String> = sample_rule_map.keys().collect();

    let payload = serde_json::json!({
        "version": 1,
        "findings_count": findings_count,
        "commit_sha": commit_sha,
        "open_rule_ids": sample_ids,
        "open_rule_ids_total": sorted_ids.len(),
        "open_rule_ids_digest": digest,
        "finding_fingerprints": sample_fps,
        "finding_fingerprints_total": all_fps.len(),
        "finding_fingerprints_digest": fp_digest,
        "finding_rule_ids": sample_rule_map,
    });
    let as_json = serde_json::to_string(&payload).unwrap();
    format!("{MARKER_PREFIX} {as_json} {MARKER_SUFFIX}")
}

/// Extract and parse the JSON payload from an existing comment's marker.
/// Tolerant: a malformed or future-version marker returns `None`, and the
/// caller treats the run as a fresh post rather than crashing.
pub fn decode_marker(body: &str) -> Option<Marker> {
    let start = body.find("<!-- grackle:mr-comment:v")?;
    let rest = &body[start..];
    let json_start = rest.find('{')?;
    let json_end = rest.rfind('}')?;
    if json_end < json_start {
        return None;
    }
    let json = &rest[json_start..=json_end];
    let data: serde_json::Value = serde_json::from_str(json).ok()?;
    let obj = data.as_object()?;

    let finding_rule_ids = obj
        .get("finding_rule_ids")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    Some(Marker {
        findings_count: obj
            .get("findings_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        open_rule_ids: string_vec(obj.get("open_rule_ids")),
        finding_fingerprints: string_vec(obj.get("finding_fingerprints")),
        finding_fingerprints_total: obj
            .get("finding_fingerprints_total")
            .and_then(|v| v.as_i64()),
        finding_rule_ids,
    })
}

fn string_vec(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Compact comparison of two consecutive scans of the same MR. Counts are exact
/// when the previous marker carried fingerprints; `approximate` signals the
/// previous sample was truncated and the delta is a lower bound.
#[derive(Debug, Clone)]
pub struct Delta {
    pub resolved: usize,
    pub new: usize,
    pub still_open: usize,
    pub approximate: bool,
    pub resolved_rule_ids: Vec<String>,
    pub new_rule_ids: Vec<String>,
}

/// A current finding, reduced to what the delta needs.
pub struct CurrentFinding {
    pub rule_id: String,
    pub fingerprint: String,
}

pub fn compute_delta(previous: Option<&Marker>, current: &[CurrentFinding]) -> Option<Delta> {
    let previous = previous?;

    let current_fps: BTreeSet<&str> = current.iter().map(|f| f.fingerprint.as_str()).collect();
    let current_rules: BTreeSet<String> = current
        .iter()
        .map(|f| f.rule_id.clone())
        .filter(|r| !r.is_empty())
        .collect();

    let has_fps =
        !previous.finding_fingerprints.is_empty() || previous.finding_fingerprints_total.is_some();

    if has_fps {
        let prev_fps: BTreeSet<&str> = previous
            .finding_fingerprints
            .iter()
            .map(String::as_str)
            .collect();
        let resolved = prev_fps.difference(&current_fps).count();
        let new = current_fps.difference(&prev_fps).count();
        let still_open = current_fps.intersection(&prev_fps).count();

        let mut prev_families: BTreeSet<String> =
            previous.finding_rule_ids.values().cloned().collect();
        prev_families.extend(previous.open_rule_ids.iter().cloned());

        let resolved_rule_ids: Vec<String> =
            prev_families.difference(&current_rules).cloned().collect();
        let new_rule_ids: Vec<String> = current_rules.difference(&prev_families).cloned().collect();

        let approximate = matches!(
            previous.finding_fingerprints_total,
            Some(total) if total as usize > prev_fps.len()
        );
        return Some(Delta {
            resolved,
            new,
            still_open,
            approximate,
            resolved_rule_ids,
            new_rule_ids,
        });
    }

    let prev_rules: BTreeSet<String> = previous.open_rule_ids.iter().cloned().collect();
    if prev_rules.is_empty() && previous.findings_count == 0 {
        return None;
    }
    let resolved: Vec<String> = prev_rules.difference(&current_rules).cloned().collect();
    let new: Vec<String> = current_rules.difference(&prev_rules).cloned().collect();
    let still_open = current_rules.intersection(&prev_rules).count();
    if resolved.is_empty() && new.is_empty() {
        return None;
    }
    Some(Delta {
        resolved: resolved.len(),
        new: new.len(),
        still_open,
        approximate: true,
        resolved_rule_ids: resolved,
        new_rule_ids: new,
    })
}

fn format_rule_ids_suffix(label: &str, rule_ids: &[String]) -> String {
    let head: Vec<&String> = rule_ids.iter().take(RESOLVED_RULES_HEADLINE_CAP).collect();
    let overflow = rule_ids.len() - head.len();
    let mut rendered = head
        .iter()
        .map(|r| format!("`{r}`"))
        .collect::<Vec<_>>()
        .join(", ");
    if overflow > 0 {
        rendered += &format!(" (+{overflow} more)");
    }
    format!("{label}: {rendered}")
}

/// One-line trajectory summary for the comment header, or `""` when nothing
/// meaningfully changed.
pub fn render_delta_line(delta: Option<&Delta>) -> String {
    let Some(delta) = delta else {
        return String::new();
    };
    if delta.resolved == 0 && delta.new == 0 {
        return String::new();
    }
    let unit = if delta.approximate { "rule" } else { "finding" };
    let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });

    let mut line = if delta.new == 0 && delta.resolved > 0 {
        let mut l = format!("**Progress:** {} resolved", plural(delta.resolved, unit));
        if delta.still_open > 0 {
            l += &format!(" - {} still open", delta.still_open);
        }
        l
    } else if delta.resolved == 0 && delta.new > 0 {
        let mut l = format!(
            "**{}** since last scan",
            plural(delta.new, &format!("new {unit}"))
        );
        if delta.still_open > 0 {
            l += &format!(" - {} still open", delta.still_open);
        }
        l
    } else {
        format!(
            "{} resolved - {} new - {} still open since last scan",
            delta.resolved, delta.new, delta.still_open
        )
    };

    if !delta.resolved_rule_ids.is_empty() {
        line += "  \n";
        line += &format_rule_ids_suffix("Resolved rules", &delta.resolved_rule_ids);
    }
    if !delta.new_rule_ids.is_empty() {
        line += "  \n";
        line += &format_rule_ids_suffix("New rules", &delta.new_rule_ids);
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_round_trips() {
        let mut rules = BTreeSet::new();
        rules.insert("rule_a".to_string());
        rules.insert("rule_b".to_string());
        let mut fp_map = BTreeMap::new();
        fp_map.insert(
            finding_fingerprint("rule_a", "a.yml", 3),
            "rule_a".to_string(),
        );
        let body = format!(
            "body text\n\n{}",
            encode_marker(2, "deadbeef", &rules, &fp_map)
        );
        let decoded = decode_marker(&body).unwrap();
        assert_eq!(decoded.findings_count, 2);
        assert_eq!(decoded.open_rule_ids, vec!["rule_a", "rule_b"]);
    }

    #[test]
    fn decode_missing_marker_is_none() {
        assert!(decode_marker("just a normal comment").is_none());
    }

    #[test]
    fn delta_reports_resolved_and_new() {
        let mut rules = BTreeSet::new();
        rules.insert("rule_a".to_string());
        let mut fp_map = BTreeMap::new();
        let fp_a = finding_fingerprint("rule_a", "a.yml", 3);
        fp_map.insert(fp_a.clone(), "rule_a".to_string());
        let body = encode_marker(1, "sha", &rules, &fp_map);
        let prev = decode_marker(&body).unwrap();

        let current = vec![CurrentFinding {
            rule_id: "rule_b".to_string(),
            fingerprint: finding_fingerprint("rule_b", "b.yml", 9),
        }];
        let delta = compute_delta(Some(&prev), &current).unwrap();
        assert_eq!(delta.resolved, 1);
        assert_eq!(delta.new, 1);
        assert_eq!(delta.resolved_rule_ids, vec!["rule_a"]);
        assert_eq!(delta.new_rule_ids, vec!["rule_b"]);
    }
}

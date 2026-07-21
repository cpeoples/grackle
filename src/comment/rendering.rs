//! Markdown body for the sticky summary comment: severity header, optional
//! run-to-run delta, findings grouped by rule in collapsible blocks, secret
//! redaction of snippets, and the trailing state marker.

use crate::comment::context::{file_deep_link, PlatformContext};
use crate::comment::fingerprint::{
    compute_delta, encode_marker, finding_fingerprint, render_delta_line, CurrentFinding, Marker,
};
use crate::rules::{Confidence, Finding, Severity};
use crate::scanner::FileResult;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

const PROJECT_URL: &str = "https://github.com/cpeoples/grackle";
/// Well under GitHub's 65536-char body cap; leaves room for the marker.
const MAX_COMMENT_BYTES: usize = 60_000;
const MAX_FINDINGS_PER_RULE: usize = 5;
/// Above this total, the body leads with a dashboard and summarizes the tail.
const DASHBOARD_THRESHOLD: usize = 40;
const TOP_RULES_IN_DASHBOARD: usize = 10;
const SNIPPET_MAX_LINES: usize = 20;

/// A finding paired with its repo-root-relative display path.
pub struct RenderFinding<'a> {
    pub path: String,
    pub finding: &'a Finding,
}

fn severity_weight(sev: Severity) -> u8 {
    match sev {
        Severity::Critical => 2,
        Severity::High => 1,
    }
}

/// Flatten scan results into `(display_path, finding)` pairs. `path_display`
/// maps a scanner path to the repo-root-relative path used in links.
pub fn collect<'a>(
    results: &'a [FileResult],
    path_display: impl Fn(&std::path::Path) -> String,
) -> Vec<RenderFinding<'a>> {
    let mut out = Vec::new();
    for file in results {
        let path = path_display(&file.path);
        for finding in &file.findings {
            out.push(RenderFinding {
                path: path.clone(),
                finding,
            });
        }
    }
    out
}

/// Build the full comment body, including the trailing marker, ready to POST.
pub fn render_comment_body(
    ctx: &PlatformContext,
    findings: &[RenderFinding<'_>],
    previous: Option<&Marker>,
) -> String {
    let delta = {
        let current: Vec<CurrentFinding> = findings
            .iter()
            .map(|rf| CurrentFinding {
                rule_id: rf.finding.rule_id.to_string(),
                fingerprint: finding_fingerprint(
                    rf.finding.rule_id,
                    &rf.path,
                    rf.finding.line_number,
                ),
            })
            .collect();
        compute_delta(previous, &current)
    };

    let mut body = String::new();
    body.push_str(&severity_header(findings));
    body.push('\n');

    let delta_line = render_delta_line(delta.as_ref());
    if !delta_line.is_empty() {
        body.push('\n');
        body.push_str(&delta_line);
        body.push('\n');
    }

    if findings.is_empty() {
        body.push_str("\nNo fork-triggerable coding agents found in the scanned workflows.\n");
    } else if findings.len() > DASHBOARD_THRESHOLD {
        body.push('\n');
        body.push_str(&render_dashboard(findings));
    } else {
        body.push('\n');
        body.push_str(&render_drilldown(ctx, findings));
    }

    body.push_str(&footer(ctx));

    // Guard the byte budget: if the drilldown pushed us over, fall back to the
    // dashboard, which is bounded.
    if body.len() > MAX_COMMENT_BYTES
        && findings.len() <= DASHBOARD_THRESHOLD
        && !findings.is_empty()
    {
        body = String::new();
        body.push_str(&severity_header(findings));
        body.push('\n');
        if !delta_line.is_empty() {
            body.push('\n');
            body.push_str(&delta_line);
            body.push('\n');
        }
        body.push('\n');
        body.push_str(&render_dashboard(findings));
        body.push_str(&footer(ctx));
    }

    body.push('\n');
    body.push_str(&marker(ctx, findings));
    body
}

fn severity_header(findings: &[RenderFinding<'_>]) -> String {
    if findings.is_empty() {
        return "## \u{2705} grackle: no findings".to_string();
    }
    let critical = findings
        .iter()
        .filter(|f| f.finding.severity == Severity::Critical)
        .count();
    let high = findings.len() - critical;
    let mut parts = Vec::new();
    if critical > 0 {
        parts.push(format!("{critical} critical"));
    }
    if high > 0 {
        parts.push(format!("{high} high"));
    }
    format!(
        "## grackle: {} ({})",
        plural(findings.len(), "finding"),
        parts.join(", ")
    )
}

fn render_drilldown(ctx: &PlatformContext, findings: &[RenderFinding<'_>]) -> String {
    let mut out = String::new();
    for (rule_id, group) in group_by_rule(findings) {
        out.push_str(&render_rule_block(ctx, rule_id, &group));
        out.push('\n');
    }
    out
}

fn render_rule_block(ctx: &PlatformContext, rule_id: &str, group: &[&RenderFinding<'_>]) -> String {
    let first = group[0].finding;
    let sev = first.severity.as_str();
    let confidence = group_confidence(group);
    let mut out = format!(
        "<details>\n<summary><strong>{sev}</strong> ({confidence} confidence) {} - {} ({})</summary>\n<br>\n\n",
        escape_html(first.title),
        rule_id,
        plural(group.len(), "occurrence"),
    );
    out.push_str("**Recommendation:** ");
    out.push_str(first.recommendation);
    out.push_str("\n\n");
    if let Some(tags) = compliance_tags(&first.metadata) {
        out.push_str(&format!("Compliance: {tags}\n\n"));
    }

    for rf in group.iter().take(MAX_FINDINGS_PER_RULE) {
        let f = rf.finding;
        let location = match file_deep_link(ctx, &rf.path, f.line_number) {
            Some(url) => format!("[`{}:{}`]({url})", rf.path, f.line_number),
            None => format!("`{}:{}`", rf.path, f.line_number),
        };
        out.push_str(&format!("- {location}\n"));
        out.push_str("\n```yaml\n");
        out.push_str(&redact_snippet(&f.code_snippet));
        out.push_str("\n```\n\n");
    }
    let overflow = group.len().saturating_sub(MAX_FINDINGS_PER_RULE);
    if overflow > 0 {
        out.push_str(&format!("_{} more not shown._\n\n", overflow));
    }
    out.push_str("</details>\n");
    out
}

/// Compact ranked table used when there are too many findings to drill into.
fn render_dashboard(findings: &[RenderFinding<'_>]) -> String {
    let groups = group_by_rule(findings);
    let mut ranked: Vec<(&str, Vec<&RenderFinding<'_>>)> = groups.into_iter().collect();
    ranked.sort_by(|a, b| {
        let rank =
            |g: &[&RenderFinding<'_>]| g.len() * severity_weight(g[0].finding.severity) as usize;
        rank(&b.1).cmp(&rank(&a.1)).then(a.0.cmp(b.0))
    });

    let mut out = String::from("| Severity | Confidence | Rule | Count |\n|---|---|---|---|\n");
    for (rule_id, group) in ranked.iter().take(TOP_RULES_IN_DASHBOARD) {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            group[0].finding.severity.as_str(),
            group_confidence(group),
            rule_id,
            group.len()
        ));
    }
    let shown: usize = ranked
        .iter()
        .take(TOP_RULES_IN_DASHBOARD)
        .map(|(_, g)| g.len())
        .sum();
    let remaining = findings.len() - shown;
    if remaining > 0 {
        out.push_str(&format!(
            "\n_{} across {} more rules not shown._\n",
            plural(remaining, "finding"),
            ranked.len() - TOP_RULES_IN_DASHBOARD.min(ranked.len())
        ));
    }
    out
}

/// Small metadata footer: a single `<sub>` line with the scanned commit, the
/// scanner credit, and optional run logs, joined by a middot.
fn footer(ctx: &PlatformContext) -> String {
    let mut bits: Vec<String> = Vec::new();
    if !ctx.commit_sha.is_empty() {
        let short: String = ctx.commit_sha.chars().take(12).collect();
        bits.push(format!("commit `{short}`"));
    }
    bits.push(format!(
        "Scanned with [grackle]({PROJECT_URL}){}",
        version_suffix()
    ));
    if let Some(url) = &ctx.run_url {
        bits.push(format!("[run logs]({url})"));
    }
    format!("\n---\n<sub>{}</sub>\n", bits.join(" \u{00b7} "))
}

/// Version suffix for the credit link. Empty for dev/local builds so a reviewer
/// never sees a build-metadata tail in a public comment.
fn version_suffix() -> String {
    let v = env!("CARGO_PKG_VERSION");
    if v.contains('+') || v.contains(".dev") {
        String::new()
    } else {
        format!(" v{}", v.trim_start_matches('v'))
    }
}

fn marker(ctx: &PlatformContext, findings: &[RenderFinding<'_>]) -> String {
    let mut open_rules = BTreeSet::new();
    let mut fp_to_rule = BTreeMap::new();
    for rf in findings {
        open_rules.insert(rf.finding.rule_id.to_string());
        fp_to_rule.insert(
            finding_fingerprint(rf.finding.rule_id, &rf.path, rf.finding.line_number),
            rf.finding.rule_id.to_string(),
        );
    }
    encode_marker(findings.len(), &ctx.commit_sha, &open_rules, &fp_to_rule)
}

/// Highest confidence in a rule group, so a block's header reflects the
/// strongest assessment among its occurrences rather than an arbitrary first.
fn group_confidence(group: &[&RenderFinding<'_>]) -> &'static str {
    group
        .iter()
        .map(|rf| rf.finding.confidence)
        .max_by(|a, b| a.score().total_cmp(&b.score()))
        .unwrap_or(Confidence::Medium)
        .as_str()
}

fn group_by_rule<'a>(
    findings: &'a [RenderFinding<'a>],
) -> BTreeMap<&'a str, Vec<&'a RenderFinding<'a>>> {
    let mut groups: BTreeMap<&str, Vec<&RenderFinding<'a>>> = BTreeMap::new();
    for rf in findings {
        groups.entry(rf.finding.rule_id).or_default().push(rf);
    }
    groups
}

fn compliance_tags(m: &crate::rules::metadata::Metadata) -> Option<String> {
    let mut tags: Vec<String> = Vec::new();
    tags.extend(m.cwe.iter().map(|id| compliance_link(id)));
    tags.extend(m.owasp_appsec.iter().map(|id| compliance_link(id)));
    if tags.is_empty() {
        return None;
    }
    Some(tags.join(" "))
}

/// Link a compliance reference to its canonical page when the identifier shape
/// is one we can resolve (CWE, OWASP Top 10 2021); otherwise render it as plain
/// code so an unknown framework still shows.
fn compliance_link(id: &str) -> String {
    if let Some(num) = id.strip_prefix("CWE-") {
        return format!("[`{id}`](https://cwe.mitre.org/data/definitions/{num}.html)");
    }
    if let Some(url) = owasp_appsec_url(id) {
        return format!("[`{id}`]({url})");
    }
    format!("`{id}`")
}

/// Map an OWASP Top 10 2021 category id (e.g. `A01:2021`) to its page.
fn owasp_appsec_url(id: &str) -> Option<&'static str> {
    Some(match id {
        "A01:2021" => "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "A02:2021" => "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "A03:2021" => "https://owasp.org/Top10/A03_2021-Injection/",
        "A04:2021" => "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        "A05:2021" => "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "A06:2021" => "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        "A07:2021" => {
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        }
        "A08:2021" => "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "A09:2021" => "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
        "A10:2021" => "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        _ => return None,
    })
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

static SECRET_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    // Long opaque token-shaped runs, and provider prefixes with a secret tail.
    regex::Regex::new(
        r"(?i)(gh[pousr]_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|[A-Za-z0-9_\-]{40,})",
    )
    .unwrap()
});

/// Redact secret-shaped runs and clamp the snippet to a sane height so a huge
/// pasted job can't blow the byte budget. `${{ secrets.* }}` references are
/// left intact: they are the reviewer's signal, not the secret value.
fn redact_snippet(snippet: &str) -> String {
    let mut lines: Vec<String> = snippet
        .lines()
        .map(|line| {
            SECRET_RE
                .replace_all(line, |caps: &regex::Captures| {
                    let matched = &caps[0];
                    // Keep obvious workflow tokens (secrets.X interpolation) readable.
                    if matched.contains('.') {
                        matched.to_string()
                    } else {
                        "***REDACTED***".to_string()
                    }
                })
                .into_owned()
        })
        .collect();
    if lines.len() > SNIPPET_MAX_LINES {
        let kept = SNIPPET_MAX_LINES - 1;
        let dropped = lines.len() - kept;
        lines.truncate(kept);
        lines.push(format!("# ... {dropped} more lines"));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comment::context::Platform;
    use crate::comment::fingerprint::decode_marker;
    use crate::rules::metadata::RCE_CRITICAL;

    fn ctx() -> PlatformContext {
        PlatformContext {
            platform: Platform::GitHub,
            api_url: "https://api.github.com".into(),
            project_ref: "o/r".into(),
            mr_number: 7,
            commit_sha: "abc123".into(),
            token: "t".into(),
            run_url: Some("https://ci.example/run/1".into()),
        }
    }

    fn finding(rule_id: &'static str, line: usize) -> Finding {
        Finding {
            rule_id,
            severity: Severity::Critical,
            title: "Fork-triggerable agent with <write> access",
            confidence: Confidence::High,
            line_number: line,
            locations: vec![line],
            recommendation: "Gate the agent behind a maintainer approval.",
            metadata: RCE_CRITICAL,
            code_snippet: "run: aider --yes --message \"$(cat task.md)\"".into(),
            remediation: String::new(),
        }
    }

    #[test]
    fn body_headers_counts_and_escapes_title() {
        let f = finding("agent-write", 12);
        let findings = vec![RenderFinding {
            path: ".github/workflows/ci.yml".into(),
            finding: &f,
        }];
        let body = render_comment_body(&ctx(), &findings, None);
        assert!(body.starts_with("## grackle: 1 finding (1 critical)"));
        assert!(body.contains("Fork-triggerable agent with &lt;write&gt; access"));
        assert!(body.contains("agent-write"));
        assert!(body.contains("[grackle]"));
    }

    #[test]
    fn empty_findings_reports_clean() {
        let body = render_comment_body(&ctx(), &[], None);
        assert!(body.contains("\u{2705} grackle: no findings"));
        assert!(body.contains("No fork-triggerable coding agents found"));
    }

    #[test]
    fn body_marker_round_trips_open_rules() {
        let f = finding("agent-write", 3);
        let findings = vec![RenderFinding {
            path: "a.yml".into(),
            finding: &f,
        }];
        let body = render_comment_body(&ctx(), &findings, None);
        let decoded = decode_marker(&body).expect("body carries a state marker");
        assert_eq!(decoded.findings_count, 1);
        assert_eq!(decoded.open_rule_ids, vec!["agent-write"]);
    }

    #[test]
    fn large_result_set_uses_bounded_dashboard() {
        let f = finding("agent-write", 1);
        let findings: Vec<RenderFinding> = (0..DASHBOARD_THRESHOLD + 5)
            .map(|_| RenderFinding {
                path: "a.yml".into(),
                finding: &f,
            })
            .collect();
        let body = render_comment_body(&ctx(), &findings, None);
        assert!(!body.contains("<details>"));
        assert!(body.len() <= MAX_COMMENT_BYTES);
    }

    #[test]
    fn compliance_refs_are_linked() {
        assert_eq!(
            compliance_link("CWE-77"),
            "[`CWE-77`](https://cwe.mitre.org/data/definitions/77.html)"
        );
        assert_eq!(
            compliance_link("A03:2021"),
            "[`A03:2021`](https://owasp.org/Top10/A03_2021-Injection/)"
        );
        assert_eq!(compliance_link("UNKNOWN-1"), "`UNKNOWN-1`");
    }

    #[test]
    fn rule_block_labels_the_recommendation() {
        let f = finding("agent-write", 12);
        let findings = vec![RenderFinding {
            path: "a.yml".into(),
            finding: &f,
        }];
        let body = render_comment_body(&ctx(), &findings, None);
        assert!(body.contains("**Recommendation:**"));
        assert!(body.contains("[`CWE-77`](https://cwe.mitre.org/data/definitions/77.html)"));
    }

    #[test]
    fn footer_carries_commit_and_credit() {
        let f = finding("agent-write", 12);
        let findings = vec![RenderFinding {
            path: "a.yml".into(),
            finding: &f,
        }];
        let body = render_comment_body(&ctx(), &findings, None);
        assert!(body.contains("commit `abc123`"));
        assert!(body.contains("Scanned with [grackle]"));
        assert!(body.contains("[run logs](https://ci.example/run/1)"));
    }

    #[test]
    fn redacts_token_but_keeps_secrets_reference() {
        let snippet = "run: deploy --token ghp_abcdefghijklmnopqrstuvwxyz0123456789\nenv:\n  T: ${{ secrets.TOKEN }}";
        let out = redact_snippet(snippet);
        assert!(out.contains("***REDACTED***"));
        assert!(out.contains("${{ secrets.TOKEN }}"));
    }

    #[test]
    fn clamps_long_snippet() {
        let long = (0..40)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let out = redact_snippet(&long);
        assert!(out.lines().count() <= SNIPPET_MAX_LINES);
        assert!(out.contains("more lines"));
    }
}

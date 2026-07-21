//! Rule model and evaluation engine.
//!
//! A [`RuleSpec`] is pure data: an anchor regex, an evaluation [`Family`], the
//! compliance [`Metadata`], and self-contained examples. The [`Engine`] owns
//! all evaluation logic and the family-specific post-filters, so rules never
//! reach into scanner internals, keeping a clean data/engine separation.

pub mod action;
pub mod gitlab;
pub mod installed;
pub mod metadata;
pub mod remediation;

use crate::workflow::{
    claude_action_self_gated, gitlab_agent_reachable_and_writable,
    gitlab_job_gated_on_internal_var, gitlab_job_is_manual_gated, has_fork_reachable_trigger,
    has_ghaw_membership_gate, has_indirect_author_association_gate,
    has_secret_bearing_fork_trigger, has_transitive_label_gate, has_transitive_permission_gate,
    is_workflow_call_only, job_can_write, job_exposes_secret, job_gated_by_failclosed_allowlist,
    job_gated_by_permission_check, job_gated_by_step_permission_check,
    job_gated_by_transitive_non_fork_event, job_gated_on_non_fork_event,
    job_has_ungated_review_bypass, workflow_call_only_without_untrusted_input,
    workflow_level_write, workflow_run_escalation, AUTHOR_GATE,
};
use fancy_regex::Regex;
use metadata::Metadata;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
        }
    }
}

/// How a rule is post-filtered after its anchor matches. The two families have
/// genuinely different reachability semantics, which is the real axis the rule
/// set splits on (not vendor).
#[derive(Debug, Clone, Copy)]
pub enum Family {
    /// An installed-agent CLI/action (the agent name is the anchor). Survives
    /// only when the workflow is fork-reachable, ungated, the enclosing job can
    /// write, and a whole-file `proof` confirms the family. Mirrors
    /// `_suppress_installed_agent_when_safe`.
    Installed {
        proof: &'static LazyLock<regex::Regex>,
        /// OpenHands caller stubs delegate to a self-gating reusable resolver;
        /// such delegation suppresses the finding.
        openhands_delegation: bool,
    },
    /// An action/CLI configured to open itself to forks (`allowed_non_write_users:
    /// "*"`, a write sandbox, etc.). Survives only when the workflow is
    /// fork-reachable, ungated, and the enclosing job can write. Mirrors
    /// `_suppress_fork_triggerable_ai_when_not_reachable`.
    Action,
    /// A `.gitlab-ci.yml` agent job. GitLab's fork-pipeline model differs from
    /// GitHub Actions, so reachability, gating, and write capability are decided
    /// by the GitLab-native check in [`crate::workflow`] rather than the GitHub
    /// `on:`/`jobs:`/`permissions:` context. A whole-file `proof` keeps a bare
    /// agent name from matching unrelated tooling, as in [`Family::Installed`].
    /// The proof uses the linear `regex` engine so a large generated file cannot
    /// backtrack.
    Gitlab {
        proof: &'static LazyLock<regex::Regex>,
    },
    /// A CLI agent invoked with shell autonomy (`--dangerously-skip-permissions`,
    /// `--allowedTools "...Bash..."`, `--yolo`) on the fork's checked-out code in a
    /// job that hands it a repository/CI **secret**, but that grackle cannot
    /// prove writes to the repo (no `contents: write`, no `git push`; often no
    /// `permissions:` block at all, so the token scope is repo-configured and
    /// invisible to a file read). The arbitrary shell still runs on
    /// attacker-controlled PR contents and can exfiltrate the injected token, so
    /// this is a real risk independent of repo-write, reported at HIGH, one tier
    /// below the [`Family::Installed`] repo-write CRITICAL. Survives on the same
    /// reachability/gate filter as `Installed`, but requires a secret in reach
    /// and the *absence* of provable write (a write-capable job is the CRITICAL
    /// rule's job, and overlap suppression keeps this from double-firing there).
    ForkShellExec {
        proof: &'static LazyLock<regex::Regex>,
    },
}

/// Pure rule data. Regexes are compiled once when the registry is built.
pub struct RuleSpec {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub anchor: Regex,
    pub family: Family,
    pub metadata: Metadata,
    pub recommendation: &'static str,
    /// Workflows that must produce exactly one finding (self-validating corpus).
    pub positive_examples: &'static [&'static str],
    /// Workflows that must produce no finding.
    pub negative_examples: &'static [&'static str],
}

/// How much a finding depends on facts a static scan can prove versus repo
/// runtime state it cannot read. `High` means the vulnerable composition is
/// unambiguous in the file and the reachability path does not depend on a
/// repository setting. `Medium` means part of the exposure (a fork pull
/// request's secret scope, or a narrower OR-gate bypass) is config-dependent
/// and a maintainer's runtime state decides it. `Low` is held for the weakest
/// reachability we still report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }

    /// A coarse numeric for machine consumers (JSON, SARIF `rank`). Deliberately
    /// banded, not a calibrated probability: the ordinal is the source of truth.
    pub fn score(self) -> f64 {
        match self {
            Confidence::High => 0.9,
            Confidence::Medium => 0.7,
            Confidence::Low => 0.4,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    /// Confidence that this finding is a real, reachable exposure at runtime.
    /// Derived from the same reachability, gate, and write signals the engine
    /// already computes, so it needs no per-rule data.
    pub confidence: Confidence,
    pub line_number: usize,
    /// Every line in the same job where this rule's anchor matched (an install
    /// step plus a run step, repeated `run:` blocks, etc.). Always includes
    /// `line_number` as its first element. One vulnerable job is one finding,
    /// but a reviewer still sees each spot the agent is invoked.
    pub locations: Vec<usize>,
    pub recommendation: &'static str,
    pub metadata: Metadata,
    /// The offending workflow block around the anchor line, so a reviewer sees
    /// the vulnerable code without opening the file.
    pub code_snippet: String,
    /// A copy-pasteable secure-fix write-up derived from `code_snippet`: the
    /// vulnerable code, why it is dangerous, and a corrected workflow.
    pub remediation: String,
}

/// Shared cross-cutting state computed once per file so a rule sweep does not
/// recompute reachability / gate / write for every rule.
struct FileContext<'a> {
    lines: Vec<&'a str>,
    /// `lines` joined by `\n`, built once so anchor windows can be taken as
    /// slices rather than re-joined per start line.
    joined: String,
    /// Byte offset of each line's start within `joined`.
    line_starts: Vec<usize>,
    reachable: bool,
    gated: bool,
    /// At least one job in the file has an OR-gate bypass: an ungated
    /// fork-reachable disjunct (a `pull_request_review`+`changes_requested`
    /// review, or a *bare* `event_name == 'pull_request'`) sitting alongside an
    /// author-gated sibling. When set, the coarse whole-file [`AUTHOR_GATE`]
    /// must not wholesale-suppress the file; per-job gating in the anchor filter
    /// stays authoritative instead.
    review_bypass: bool,
    workflow_write: bool,
    openhands_delegates: bool,
}

impl<'a> FileContext<'a> {
    fn new(content: &'a str) -> Self {
        Self::build(content, None)
    }

    /// Build a context for a reusable (`workflow_call`) callee whose in-repo
    /// caller reachability has been resolved from disk. `caller_fork_reachable`
    /// is `Some(true)` when a same-repo caller wires this file and is itself
    /// fork-reachable, `Some(false)` when caller(s) exist but none is
    /// fork-reachable, and `None` when the scan has no repo context. For a file
    /// whose only fork-reachable trigger is `workflow_call`, a resolved
    /// `Some(false)` means no fork contributor can reach it through this repo,
    /// so it is not treated as reachable; `Some(true)` or `None` preserve the
    /// conservative default.
    fn with_reusable_reachability(content: &'a str, caller_fork_reachable: Option<bool>) -> Self {
        Self::build(content, caller_fork_reachable)
    }

    fn build(content: &'a str, caller_fork_reachable: Option<bool>) -> Self {
        let lines: Vec<&str> = content.lines().collect();
        let joined = lines.join("\n");
        let mut line_starts = Vec::with_capacity(lines.len());
        let mut offset = 0;
        for line in &lines {
            line_starts.push(offset);
            offset += line.len() + 1; // + separating '\n'
        }
        // Cheap early-out before the per-job scan: an OR-gate bypass needs a
        // real `||` and either a `changes_requested` review disjunct or a bare
        // `pull_request` event disjunct. Only `if:` lines can carry a gate, so
        // the scan is restricted to those to keep it linear in file size.
        let review_bypass = content.contains("||")
            && (content.contains("changes_requested") || content.contains("event_name"))
            && lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.contains("if:"))
                .any(|(i, _)| job_has_ungated_review_bypass(&lines, i));
        // A reusable workflow whose sole fork-reachable trigger is
        // `workflow_call` is only reachable through a caller. When repo-level
        // resolution proves no same-repo caller is fork-reachable, the callee
        // is unreachable via this repo and must not be reported as a confirmed
        // fork-triggerable finding.
        let reachable = if caller_fork_reachable == Some(false) && is_workflow_call_only(content) {
            false
        } else {
            has_fork_reachable_trigger(content) || workflow_run_escalation(content)
        };
        Self {
            lines,
            joined,
            line_starts,
            reachable,
            gated: AUTHOR_GATE.is_match(content)
                || has_ghaw_membership_gate(content)
                || has_indirect_author_association_gate(content)
                || has_transitive_permission_gate(content)
                || has_transitive_label_gate(content)
                || workflow_call_only_without_untrusted_input(content),
            review_bypass,
            workflow_write: workflow_level_write(content),
            openhands_delegates: OPENHANDS_DELEGATION.is_match(content).unwrap_or(false),
        }
    }
}

/// The OpenHands resolver ships as a reusable workflow that self-gates on
/// `author_association` in the called repo, so a caller that merely delegates to
/// it is not fork-exploitable regardless of the permissions it passes in.
static OPENHANDS_DELEGATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)uses\s*:\s*[^\n]*?/\.github/workflows/openhands-resolver\.yml").unwrap()
});

/// Byte offset of each line's start within `text` (as `FileContext` computes
/// for the joined workflow), so `anchor_lines` can be run against an arbitrary
/// body such as a composite action definition.
fn line_starts_of(text: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut offset = 0;
    for line in text.lines() {
        starts.push(offset);
        offset += line.len() + 1;
    }
    starts
}

/// Longest snippet we quote around a finding. A step or job is usually a
/// handful of lines; the cap keeps a pathological block from swamping output.
const SNIPPET_MAX_LINES: usize = 24;

/// Leading-space indent of a line, or `None` for blank / comment-only lines.
fn indent_of(line: &str) -> Option<usize> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    Some(line.len() - trimmed.len())
}

/// Return the enclosing workflow block around `line_number` (1-based): the
/// smallest step (`- uses:` / `- run:` / `- name:`) that contains it, else the
/// job it lives in. Walks back to the nearest list item at a smaller indent,
/// forward to the next sibling, then strips the common indent so the quoted
/// block reads as a self-contained excerpt. Falls back to the single offending
/// line when no enclosing item is found or the block would be too long.
fn enclosing_block(lines: &[&str], line_number: usize) -> String {
    let single = || {
        lines
            .get(line_number - 1)
            .map(|l| l.trim())
            .unwrap_or("")
            .to_string()
    };
    if line_number == 0 || line_number > lines.len() {
        return single();
    }
    let Some(offender_indent) = indent_of(lines[line_number - 1]) else {
        return single();
    };

    let mut opener: Option<usize> = None;
    for i in (0..line_number - 1).rev() {
        let Some(indent) = indent_of(lines[i]) else {
            continue;
        };
        if indent < offender_indent && lines[i].trim_start().starts_with("- ") {
            opener = Some(i);
            break;
        }
    }
    let Some(start) = opener else { return single() };
    let start_indent = indent_of(lines[start]).unwrap_or(0);

    let mut end = lines.len();
    for (i, line) in lines.iter().enumerate().skip(start + 1) {
        let Some(indent) = indent_of(line) else {
            continue;
        };
        if indent <= start_indent {
            end = i;
            break;
        }
    }

    if end - start > SNIPPET_MAX_LINES {
        return single();
    }
    let block: Vec<&str> = lines[start..end]
        .iter()
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .skip_while(|l| l.is_empty())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if block.is_empty() {
        return single();
    }
    let common = block
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    block
        .iter()
        .map(|l| if l.len() >= common { &l[common..] } else { *l })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Compile an anchor pattern with `re.IGNORECASE | re.MULTILINE` semantics:
/// every rule regex is matched case-insensitively with `^`/`$` bound to line
/// boundaries. Prepending `(?im)` stacks with any inline flags a pattern
/// already declares (e.g. its own `(?s)`).
///
/// A bounded backtrack limit keeps a pathological input (e.g. a machine
/// generated lock file with very long embedded lines) from spinning: past the
/// limit fancy-regex returns `Err`, which the scan treats as no match rather
/// than hanging. The limit is generous enough that no real workflow match is
/// lost.
pub(crate) fn compile_anchor(pattern: &str) -> Regex {
    build_bounded(&format!("(?im){pattern}"))
}

/// Backtrack ceiling for the complex agent/proof patterns. fancy-regex's
/// default is 1,000,000 per attempt, which on a 300 KB generated workflow can
/// compound into minutes of CPU. 200,000 bails a runaway match attempt in well
/// under a millisecond while still clearing every hand-written workflow we
/// match.
const BACKTRACK_LIMIT: usize = 200_000;

/// Build a fancy-regex with the shared bounded backtrack limit.
pub(crate) fn build_bounded(pattern: &str) -> Regex {
    fancy_regex::RegexBuilder::new(pattern)
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
        .unwrap()
}

impl RuleSpec {
    /// 1-based line numbers where the anchor matches. Every anchor bounds its
    /// own span with `{0,N}` char quantifiers, so a single left-to-right pass
    /// over the joined text yields the same match lines as re-scanning each
    /// overlapping window would, at a fraction of the cost. `line_starts[i]` is
    /// the byte offset of line `i` within `joined`; a match's line is found by
    /// binary search on those offsets. Results are deduplicated.
    fn anchor_lines(&self, joined: &str, line_starts: &[usize]) -> Vec<usize> {
        let mut seen = std::collections::BTreeSet::new();
        let mut from = 0;
        while from <= joined.len() {
            match self.anchor.find_from_pos(joined, from) {
                Ok(Some(m)) => {
                    let line = line_starts.partition_point(|&s| s <= m.start());
                    seen.insert(line);
                    // Advance past this match; guard against zero-width matches.
                    from = m.end().max(m.start() + 1);
                }
                _ => break,
            }
        }
        seen.into_iter().collect()
    }

    fn to_finding(&self, line_number: usize, lines: &[&str], confidence: Confidence) -> Finding {
        let code_snippet = enclosing_block(lines, line_number);
        let remediation =
            remediation::secure_fix(self.id, self.title, self.recommendation, &code_snippet);
        Finding {
            rule_id: self.id,
            severity: self.severity,
            title: self.title,
            confidence,
            line_number,
            locations: vec![line_number],
            recommendation: self.recommendation,
            metadata: self.metadata,
            code_snippet,
            remediation,
        }
    }

    /// Confidence for a finding from this rule, given how its job was reached.
    /// A CRITICAL repo-write / shell-autonomy finding whose job is directly
    /// fork-reachable and ungated is `High`: the whole composition is provable
    /// from the file. A HIGH finding is `Medium`, because its worst case (a fork
    /// pull request's provider-secret scope) depends on repo state a scan cannot
    /// read. Any finding reached only through an OR-gate bypass drops one tier,
    /// since that path is narrower than a plainly ungated trigger.
    fn confidence_for(&self, reached_via_bypass: bool) -> Confidence {
        let base = match self.severity {
            Severity::Critical => Confidence::High,
            Severity::High => Confidence::Medium,
        };
        if reached_via_bypass {
            match base {
                Confidence::High => Confidence::Medium,
                _ => Confidence::Low,
            }
        } else {
            base
        }
    }

    /// Whether this rule's agent signature is present in an arbitrary body
    /// (a composite action's `runs:` steps), independent of workflow
    /// reachability. Used for local-action resolution, where reachability and
    /// write capability come from the caller workflow, not the action file.
    /// GitLab rules never apply here (a composite action is GitHub-only).
    fn agent_in_action_body(&self, body: &str) -> bool {
        let starts = line_starts_of(body);
        match self.family {
            Family::Installed { proof, .. } => {
                proof.is_match(body) && !self.anchor_lines(body, &starts).is_empty()
            }
            Family::Action => !self.anchor_lines(body, &starts).is_empty(),
            Family::Gitlab { .. } => false,
            // Shell-exec risk is judged from the caller job's env/secret context,
            // not a composite action body, so it does not resolve here.
            Family::ForkShellExec { .. } => false,
        }
    }

    fn evaluate(&self, content: &str, ctx: &FileContext) -> Vec<Finding> {
        // Cheap whole-file gates run before the per-window anchor scan: on a
        // large machine-generated workflow this rejects most rules without ever
        // paying for the windowed match.
        match self.family {
            Family::Gitlab { proof } => {
                if !proof.is_match(content) || !gitlab_agent_reachable_and_writable(content) {
                    return Vec::new();
                }
                let lines = self.anchor_lines(&ctx.joined, &ctx.line_starts);
                if lines.is_empty() {
                    return Vec::new();
                }
                return lines
                    .into_iter()
                    .filter(|&ln| {
                        let idx = ln.saturating_sub(1);
                        !gitlab_job_gated_on_internal_var(&ctx.lines, idx)
                            && !gitlab_job_is_manual_gated(&ctx.lines, idx)
                    })
                    .map(|ln| self.to_finding(ln, &ctx.lines, self.confidence_for(false)))
                    .collect();
            }
            Family::Installed {
                proof,
                openhands_delegation,
            } => {
                if !ctx.reachable || (ctx.gated && !ctx.review_bypass) {
                    return Vec::new();
                }
                if !proof.is_match(content) {
                    return Vec::new();
                }
                if openhands_delegation && ctx.openhands_delegates {
                    return Vec::new();
                }
            }
            Family::Action => {
                if !ctx.reachable || (ctx.gated && !ctx.review_bypass) {
                    return Vec::new();
                }
            }
            Family::ForkShellExec { proof } => {
                if !ctx.reachable || (ctx.gated && !ctx.review_bypass) {
                    return Vec::new();
                }
                // The exfiltration premise requires the run to actually carry a
                // secret: a plain `pull_request` from a fork gets none, so an
                // arbitrary shell there has nothing to steal beyond an ephemeral
                // read-only checkout and is not this class.
                if !has_secret_bearing_fork_trigger(content) {
                    return Vec::new();
                }
                if !proof.is_match(content) {
                    return Vec::new();
                }
            }
        }
        let lines = self.anchor_lines(&ctx.joined, &ctx.line_starts);
        if lines.is_empty() {
            return Vec::new();
        }
        lines
            .into_iter()
            .filter(|&ln| {
                let idx = ln.saturating_sub(1);
                let author_ok = if ctx.gated && ctx.review_bypass {
                    // Whole-file gate was lifted for an OR-gate-bypass file. A
                    // job survives iff it carries the ungated review bypass
                    // itself: the bypass disjunct is fork-reachable regardless
                    // of an author gate on a *sibling* disjunct of the same
                    // `if:`. Jobs without their own bypass stay suppressed.
                    job_has_ungated_review_bypass(&ctx.lines, idx)
                } else {
                    true
                };
                author_ok
                    && {
                        // Write capability is the axis the two severities split
                        // on. The repo-write families (Installed / Action) require
                        // a provable write. ForkShellExec is the complement: it
                        // fires precisely when the job can *not* be shown to write
                        // but hands the shell a secret to exfiltrate, so it never
                        // overlaps a CRITICAL repo-write finding in the same job.
                        let writes = job_can_write(&ctx.lines, idx, ctx.workflow_write);
                        match self.family {
                            Family::ForkShellExec { .. } => {
                                !writes && job_exposes_secret(&ctx.lines, idx)
                            }
                            _ => writes,
                        }
                    }
                    && !job_gated_on_non_fork_event(&ctx.lines, idx)
                    && !job_gated_by_transitive_non_fork_event(&ctx.lines, idx)
                    && !job_gated_by_step_permission_check(&ctx.lines, idx)
                    && !job_gated_by_failclosed_allowlist(&ctx.lines, idx)
                    && !claude_action_self_gated(content, &ctx.lines, idx)
            })
            .map(|ln| {
                let idx = ln.saturating_sub(1);
                let via_bypass = ctx.gated
                    && ctx.review_bypass
                    && job_has_ungated_review_bypass(&ctx.lines, idx);
                self.to_finding(ln, &ctx.lines, self.confidence_for(via_bypass))
            })
            .collect()
    }
}

/// Compiled rule set plus the overlap-suppression groups. Owns evaluation.
pub struct Engine {
    rules: Vec<RuleSpec>,
}

impl Engine {
    pub fn new() -> Self {
        let mut rules = installed::rules();
        rules.extend(action::rules());
        rules.extend(gitlab::rules());
        Self { rules }
    }

    pub fn rules(&self) -> &[RuleSpec] {
        &self.rules
    }

    /// Validate every rule against its own positive/negative examples. Returns
    /// the rule count on success, or the list of misclassifications. This is
    /// the built-in corpus check exposed via `--self-test` and exercised by the
    /// unit tests.
    pub fn self_test(&self) -> Result<usize, Vec<String>> {
        let mut failures = Vec::new();
        for rule in &self.rules {
            for (i, ex) in rule.positive_examples.iter().enumerate() {
                if !self.scan(ex).iter().any(|f| f.rule_id == rule.id) {
                    failures.push(format!("{} positive_examples[{i}] did not fire", rule.id));
                }
            }
            for (i, ex) in rule.negative_examples.iter().enumerate() {
                if self.scan(ex).iter().any(|f| f.rule_id == rule.id) {
                    failures.push(format!(
                        "{} negative_examples[{i}] fired (false positive)",
                        rule.id
                    ));
                }
            }
        }
        if failures.is_empty() {
            Ok(self.rules.len())
        } else {
            Err(failures)
        }
    }

    /// Evaluate every rule against one workflow, then drop findings that a
    /// more specific sibling supersedes at the same location.
    pub fn scan(&self, content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(content);
        let raw: Vec<Finding> = self
            .rules
            .iter()
            .flat_map(|r| r.evaluate(content, &ctx))
            .collect();
        collapse_per_rule(action::suppress_overlaps(raw, &ctx.lines), &ctx.lines)
    }

    /// Scan a workflow with full repo context: `caller_fork_reachable` carries
    /// the resolved reachability of a `workflow_call` callee (see
    /// [`FileContext::with_reusable_reachability`]), and `resolve` supplies
    /// local composite-action bodies for its `uses: ./<path>` references. An
    /// agent hidden inside a resolved action is attributed to the caller
    /// workflow at the `uses:` line, but only when the caller job is
    /// fork-reachable, ungated, and write-capable, so the trust boundary is
    /// judged where it actually lives. Direct-in-workflow findings still take
    /// precedence via overlap suppression. Used by the directory scanner, which
    /// can see sibling workflows and action files on disk.
    pub fn scan_with_repo<F>(
        &self,
        content: &str,
        caller_fork_reachable: Option<bool>,
        mut resolve: F,
    ) -> Vec<Finding>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let ctx = FileContext::with_reusable_reachability(content, caller_fork_reachable);
        let mut raw: Vec<Finding> = self
            .rules
            .iter()
            .flat_map(|r| r.evaluate(content, &ctx))
            .collect();

        if ctx.reachable && !ctx.gated {
            let lines_fired: std::collections::BTreeSet<usize> =
                raw.iter().map(|f| f.line_number).collect();
            for aref in crate::localaction::local_action_refs(content) {
                if lines_fired.contains(&aref.line) {
                    continue;
                }
                let idx = aref.line.saturating_sub(1);
                if !job_can_write(&ctx.lines, idx, ctx.workflow_write)
                    || job_gated_on_non_fork_event(&ctx.lines, idx)
                    || job_gated_by_permission_check(&ctx.lines, idx)
                    || job_gated_by_step_permission_check(&ctx.lines, idx)
                    || job_gated_by_failclosed_allowlist(&ctx.lines, idx)
                {
                    continue;
                }
                let Some(body) = resolve(&aref.rel_path) else {
                    continue;
                };
                if let Some(rule) = self.rules.iter().find(|r| r.agent_in_action_body(&body)) {
                    raw.push(rule.to_finding(aref.line, &ctx.lines, rule.confidence_for(false)));
                }
            }
        }
        collapse_per_rule(action::suppress_overlaps(raw, &ctx.lines), &ctx.lines)
    }
}

/// Collapse findings to one per rule **per job**, keeping the earliest anchor
/// line and recording every matched location in that job. A single workflow
/// job that invokes one agent is one vulnerability, even though the agent CLI
/// often appears on several lines (an install step and a run step, or repeated
/// `run:` blocks); emitting a finding per line would inflate counts and bury
/// the reviewer in duplicates for the same issue. But the *same* rule firing in
/// two *separate* jobs stays two findings, because those are genuinely distinct
/// vulnerable jobs. Ordering by (line, rule_id) keeps output stable.
fn collapse_per_rule(findings: Vec<Finding>, lines: &[&str]) -> Vec<Finding> {
    // Key: (rule_id, enclosing-job start line). Value: the collapsed finding.
    let mut groups: std::collections::HashMap<(&'static str, usize), Finding> =
        std::collections::HashMap::new();
    let mut order: Vec<(&'static str, usize)> = Vec::new();
    for f in findings {
        let job_start =
            crate::workflow::enclosing_job_start(lines, f.line_number.saturating_sub(1));
        let key = (f.rule_id, job_start);
        match groups.get_mut(&key) {
            Some(existing) => {
                let new_line = f.line_number;
                if new_line < existing.line_number {
                    // Re-anchor to the earliest occurrence so snippet/remediation
                    // point at the first place the agent appears in the job,
                    // while preserving every location seen so far.
                    let mut locations = std::mem::take(&mut existing.locations);
                    locations.push(new_line);
                    *existing = f;
                    existing.locations = locations;
                } else {
                    existing.locations.push(new_line);
                }
            }
            None => {
                order.push(key);
                groups.insert(key, f);
            }
        }
    }
    let mut out: Vec<Finding> = order
        .into_iter()
        .filter_map(|k| groups.remove(&k))
        .collect();
    for f in &mut out {
        f.locations.sort_unstable();
        f.locations.dedup();
    }
    out.sort_by(|a, b| {
        a.line_number
            .cmp(&b.line_number)
            .then_with(|| a.rule_id.cmp(b.rule_id))
    });
    out
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every rule's own examples must classify correctly, via the same
    /// `self_test` path exposed on the CLI.
    #[test]
    fn every_rule_classifies_its_own_examples() {
        if let Err(failures) = Engine::new().self_test() {
            panic!("rule self-test failed:\n{}", failures.join("\n"));
        }
    }

    #[test]
    fn rule_ids_are_unique() {
        let engine = Engine::new();
        let mut ids: Vec<&str> = engine.rules().iter().map(|r| r.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate rule id");
    }

    /// The same agent invoked on two lines of ONE job is a single vulnerability:
    /// one finding, with both invocation lines recorded in `locations`.
    #[test]
    fn same_rule_same_job_collapses_to_one_finding_with_all_locations() {
        let wf = "on:\n  issue_comment:\n    types: [created]\npermissions:\n  contents: write\njobs:\n  agent:\n    runs-on: ubuntu-latest\n    steps:\n      - run: opencode run \"$TITLE\"\n      - run: opencode run \"$BODY\"\n";
        let findings = Engine::new().scan(wf);
        let opencode: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "fork_triggerable_opencode_agent_with_repo_write")
            .collect();
        assert_eq!(opencode.len(), 1, "one job = one finding");
        assert!(
            opencode[0].locations.len() >= 2,
            "both invocation lines should be recorded: {:?}",
            opencode[0].locations
        );
    }

    /// The same agent in TWO separate jobs is two genuinely distinct vulnerable
    /// jobs, so it stays two findings.
    #[test]
    fn same_rule_separate_jobs_stay_separate_findings() {
        let wf = "on:\n  issue_comment:\n    types: [created]\npermissions:\n  contents: write\njobs:\n  first:\n    runs-on: ubuntu-latest\n    steps:\n      - run: opencode run \"$BODY\"\n  second:\n    runs-on: ubuntu-latest\n    steps:\n      - run: opencode run \"$TITLE\"\n";
        let findings = Engine::new().scan(wf);
        let opencode = findings
            .iter()
            .filter(|f| f.rule_id == "fork_triggerable_opencode_agent_with_repo_write")
            .count();
        assert_eq!(opencode, 2, "two separate jobs = two findings");
    }

    /// A `claude ... --dangerously-skip-permissions` invocation split across
    /// shell line-continuations (flag on a later `\`-continued line) must still
    /// anchor. The single-line-only anchor previously missed this common style.
    #[test]
    fn claude_cli_flag_on_continuation_line_still_anchors() {
        let wf = concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "permissions:\n  contents: write\n",
            "jobs:\n  agent:\n    if: contains(github.event.comment.body, '@claude')\n",
            "    runs-on: ubuntu-latest\n    steps:\n",
            "      - run: |\n",
            "          claude -p \"$(cat prompt.txt)\" --model claude-opus-4-8 \\\n",
            "            --append-system-prompt \"$PERSONA\" \\\n",
            "            --dangerously-skip-permissions\n",
            "          git push\n",
        );
        let findings = Engine::new().scan(wf);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "fork_triggerable_claude_cli_agent_with_repo_write"),
            "multi-line claude invocation should fire"
        );
    }

    /// OR-gate bypass: a job `if:` that ORs an author-gated comment branch with
    /// an ungated `pull_request_review` + `changes_requested` branch is
    /// fork-reachable via the review branch, so the whole-file author gate must
    /// not suppress the finding.
    #[test]
    fn or_gate_bypass_review_branch_still_fires() {
        let wf = concat!(
            "on:\n  pull_request_review:\n    types: [submitted]\n  issue_comment:\n    types: [created]\n",
            "permissions:\n  contents: write\n",
            "jobs:\n  auto-fix:\n    if: >-\n",
            "      (github.event_name == 'pull_request_review' && github.event.review.state == 'changes_requested') ||\n",
            "      (github.event_name == 'issue_comment' && contains(github.event.comment.body, '/fix') &&\n",
            "       contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.comment.author_association))\n",
            "    runs-on: ubuntu-latest\n    steps:\n",
            "      - run: |\n          claude -p \"$P\" --dangerously-skip-permissions\n          git push\n",
        );
        let findings = Engine::new().scan(wf);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "fork_triggerable_claude_cli_agent_with_repo_write"),
            "ungated review disjunct should keep the finding alive"
        );
    }

    /// The converse: when BOTH disjuncts are author-gated, the whole-file gate
    /// must still suppress (no over-firing from the bypass override).
    #[test]
    fn fully_author_gated_or_still_suppressed() {
        let wf = concat!(
            "on:\n  pull_request_review:\n    types: [submitted]\n  issue_comment:\n    types: [created]\n",
            "permissions:\n  contents: write\n",
            "jobs:\n  auto-fix:\n    if: >-\n",
            "      (github.event_name == 'pull_request_review' && github.event.review.state == 'changes_requested' &&\n",
            "       contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), github.event.review.author_association)) ||\n",
            "      (github.event_name == 'issue_comment' &&\n",
            "       contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), github.event.comment.author_association))\n",
            "    runs-on: ubuntu-latest\n    steps:\n",
            "      - run: |\n          claude -p \"$P\" --dangerously-skip-permissions\n          git push\n",
        );
        let findings = Engine::new().scan(wf);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "fork_triggerable_claude_cli_agent_with_repo_write"),
            "both disjuncts gated => suppressed"
        );
    }

    /// A directly fork-reachable, ungated CRITICAL repo-write finding is the
    /// strongest case a static read can make, so it is High confidence.
    #[test]
    fn direct_critical_finding_is_high_confidence() {
        let wf = concat!(
            "on:\n  issues:\n    types: [opened]\n",
            "permissions:\n  contents: write\n",
            "jobs:\n  triage:\n    runs-on: ubuntu-latest\n    steps:\n",
            "      - run: |\n          claude -p \"$TITLE\" --dangerously-skip-permissions\n          git push\n",
        );
        let f = Engine::new()
            .scan(wf)
            .into_iter()
            .find(|f| f.rule_id == "fork_triggerable_claude_cli_agent_with_repo_write")
            .expect("critical finding");
        assert_eq!(f.confidence, Confidence::High);
    }

    /// The same CRITICAL rule reached only through an OR-gate bypass drops one
    /// tier to Medium: that reachability path is narrower than a plainly ungated
    /// trigger, so the runtime certainty is lower.
    #[test]
    fn bypass_reached_critical_is_medium_confidence() {
        let wf = concat!(
            "on:\n  pull_request_review:\n    types: [submitted]\n  issue_comment:\n    types: [created]\n",
            "permissions:\n  contents: write\n",
            "jobs:\n  auto-fix:\n    if: >-\n",
            "      (github.event_name == 'pull_request_review' && github.event.review.state == 'changes_requested') ||\n",
            "      (github.event_name == 'issue_comment' && contains(github.event.comment.body, '/fix') &&\n",
            "       contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.comment.author_association))\n",
            "    runs-on: ubuntu-latest\n    steps:\n",
            "      - run: |\n          claude -p \"$P\" --dangerously-skip-permissions\n          git push\n",
        );
        let f = Engine::new()
            .scan(wf)
            .into_iter()
            .find(|f| f.rule_id == "fork_triggerable_claude_cli_agent_with_repo_write")
            .expect("critical finding via bypass");
        assert_eq!(f.confidence, Confidence::Medium);
    }

    #[test]
    fn confidence_scores_are_ordered() {
        assert!(Confidence::High.score() > Confidence::Medium.score());
        assert!(Confidence::Medium.score() > Confidence::Low.score());
    }
}

//! Shared workflow-structure primitives. These scope a capability check to the
//! job that runs the agent and decide whether an untrusted contributor can
//! reach it, which is what separates a real finding from an inert one.

use fancy_regex::Regex;
use std::sync::LazyLock;

/// Triggers an untrusted fork contributor can reach. `workflow_call` counts
/// because a reusable workflow inherits its caller's trigger.
const FORK_REACHABLE_TRIGGERS: &[&str] = &[
    "pull_request_target",
    "issue_comment",
    "issues",
    "pull_request",
    "pull_request_review_comment",
    "pull_request_review",
    "discussion",
    "discussion_comment",
    "workflow_call",
];

fn leading_ws(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Whether the `on:` block declares a fork-reachable trigger. Only the `on:`
/// block is parsed so a trigger name is not confused with an unrelated key
/// (e.g. `issues: write` under `permissions:`).
pub fn has_fork_reachable_trigger(content: &str) -> bool {
    static ON_HEADER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"^\s*(?:["']?on["']?)\s*:"#).unwrap());
    static KEY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\s*-?\s*([A-Za-z_]+)\s*:?").unwrap());
    static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z_]+").unwrap());

    let lines: Vec<&str> = content.lines().collect();
    let Some(on_idx) = lines
        .iter()
        .position(|l| ON_HEADER.is_match(l).unwrap_or(false))
    else {
        return false;
    };

    let header = lines[on_idx];
    // Inline forms: `on: [issues, ...]` or `on: pull_request_target`.
    let after_colon = header.split_once(':').map(|x| x.1).unwrap_or("").trim();
    if !after_colon.is_empty() {
        return TOKEN
            .find_iter(after_colon)
            .filter_map(|m| m.ok())
            .any(|m| FORK_REACHABLE_TRIGGERS.contains(&m.as_str()));
    }

    // Mapping form: keys indented deeper than `on:` until the block ends.
    let on_indent = leading_ws(header);
    for line in &lines[on_idx + 1..] {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if leading_ws(line) <= on_indent {
            break;
        }
        if let Ok(Some(caps)) = KEY.captures(line) {
            if let Some(key) = caps.get(1) {
                if FORK_REACHABLE_TRIGGERS.contains(&key.as_str()) {
                    return true;
                }
            }
        }
    }
    false
}

/// Triggers on which a run influenced by an outside contributor executes with
/// the base repository's secrets in the environment. GitHub withholds repo
/// secrets from `pull_request` runs raised by a fork (the common case), so a
/// plain `pull_request` job usually has no secret for an injected shell to
/// steal. Every other fork-reachable trigger here runs on the base ref with
/// full secret access: `pull_request_target`, comment/issue/review/discussion
/// events, and `workflow_run`. `pull_request` and `workflow_call` are
/// deliberately excluded - the former lacks secrets on forks, the latter's
/// reachability (and secret exposure) is decided by its caller.
const SECRET_BEARING_FORK_TRIGGERS: &[&str] = &[
    "pull_request_target",
    "issue_comment",
    "issues",
    "pull_request_review_comment",
    "pull_request_review",
    "discussion",
    "discussion_comment",
];

/// Whether the `on:` block declares a fork-reachable trigger on which the run
/// carries the repository's secrets (see [`SECRET_BEARING_FORK_TRIGGERS`]), or
/// a `workflow_run` escalation (which runs in the base repo with secrets). This
/// is the precondition for the secret-exfiltration risk the shell-exec rule
/// models: a plain `pull_request` from a fork gets no secrets, so an arbitrary
/// shell there has nothing to steal beyond the ephemeral read-only checkout.
pub fn has_secret_bearing_fork_trigger(content: &str) -> bool {
    static ON_HEADER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"^\s*(?:["']?on["']?)\s*:"#).unwrap());
    static KEY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\s*-?\s*([A-Za-z_]+)\s*:?").unwrap());
    static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z_]+").unwrap());

    let lines: Vec<&str> = content.lines().collect();
    let Some(on_idx) = lines
        .iter()
        .position(|l| ON_HEADER.is_match(l).unwrap_or(false))
    else {
        return false;
    };
    let header = lines[on_idx];
    let after_colon = header.split_once(':').map(|x| x.1).unwrap_or("").trim();
    if !after_colon.is_empty() {
        return TOKEN
            .find_iter(after_colon)
            .filter_map(|m| m.ok())
            .any(|m| SECRET_BEARING_FORK_TRIGGERS.contains(&m.as_str()));
    }
    let on_indent = leading_ws(header);
    for line in &lines[on_idx + 1..] {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if leading_ws(line) <= on_indent {
            break;
        }
        if let Ok(Some(caps)) = KEY.captures(line) {
            if let Some(key) = caps.get(1) {
                if SECRET_BEARING_FORK_TRIGGERS.contains(&key.as_str()) {
                    return true;
                }
            }
        }
    }
    workflow_run_escalation(content)
}

/// The `workflow_run` privilege-escalation pattern: a first (unprivileged)
/// workflow runs on a fork PR, and a second workflow triggered by
/// `on: workflow_run` runs in the **base repository** with the base repo's
/// write token and secrets. If that second workflow then ingests data from the
/// triggering run - the fork's uploaded artifact, its `head_sha`, or its linked
/// pull request - and feeds it to a write-capable agent, an outside contributor
/// controls a privileged agent. `workflow_run` is deliberately kept out of the
/// blanket [`FORK_REACHABLE_TRIGGERS`] list because most uses are benign
/// ("comment on my own CI failure"); this function isolates only the dangerous
/// subset with three joint conditions:
///
/// 1. `on:` declares a `workflow_run` trigger.
/// 2. The workflow **ingests triggering-run data** an outside PR controls:
///    `actions/download-artifact` with `run-id: workflow_run.id`, a checkout of
///    `workflow_run.head_sha`, or a read of `workflow_run.pull_requests`.
/// 3. It is **not restricted to same-repo / non-fork sources**: no
///    `workflow_run.head_repository.full_name == github.repository` guard, and
///    it is not filtered to only `push`/`schedule`/`release` producer events.
///
/// Write capability and the agent anchor are judged separately by the calling
/// rule, exactly as for a directly fork-reachable workflow, so a `contents:
/// read` reviewer job never fires.
pub fn workflow_run_escalation(content: &str) -> bool {
    static HAS_WORKFLOW_RUN: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?im)^\s*workflow_run\s*:").unwrap());
    static INGESTS_RUN_DATA: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)actions/download-artifact|workflow_run\.head_sha|workflow_run\.head_branch|workflow_run\.pull_requests|gh\s+run\s+(?:download|view)|workflow_run\.id",
        )
        .unwrap()
    });
    // A same-repo restriction on the *producer's* source: the consumer only acts
    // when the triggering run came from the base repo itself, so a fork PR (which
    // runs in the fork's context with a fork head_repository) never reaches it.
    static SAME_REPO_GUARD: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)workflow_run\.head_repository\.(?:full_name|owner\.login)\s*==\s*github\.(?:repository|repository_owner)|workflow_run\.repository\.full_name\s*==\s*github\.repository|head_repository\.fork\s*==\s*(?:false|['\x22]false['\x22])",
        )
        .unwrap()
    });
    // The consumer only fires for producer events an outsider cannot cause
    // (a push/tag/release to the base repo), and never for a fork PR run.
    static NON_PR_PRODUCER_ONLY: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)workflow_run\.event\s*==\s*['\x22](?:push|schedule|release|workflow_dispatch)['\x22]",
        )
        .unwrap()
    });
    // The consumer restricts itself to `dependabot/` head branches, which only
    // the trusted Dependabot app creates; a fork PR head branch never matches,
    // so an outside contributor cannot reach the escalated job. Only the
    // positive form gates: `!startsWith(head_branch, 'dependabot/')` *excludes*
    // dependabot and therefore still admits fork branches, so the leading `!`
    // must not be treated as a gate.
    static DEPENDABOT_BRANCH_ONLY: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)(?:^|[^!])\s*startsWith\(\s*github\.event\.workflow_run\.head_branch\s*,\s*['\x22]dependabot/",
        )
        .unwrap()
    });
    // An explicit admission of the PR producer event defeats a NON_PR_PRODUCER
    // guard written as an OR (`event == 'push' || event == 'pull_request'`).
    static ADMITS_PR_PRODUCER: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)workflow_run\.event\s*==\s*['\x22]pull_request['\x22]").unwrap()
    });

    if !HAS_WORKFLOW_RUN.is_match(content) || !INGESTS_RUN_DATA.is_match(content) {
        return false;
    }
    if SAME_REPO_GUARD.is_match(content) {
        return false;
    }
    if DEPENDABOT_BRANCH_ONLY.is_match(content) {
        return false;
    }
    if NON_PR_PRODUCER_ONLY.is_match(content) && !ADMITS_PR_PRODUCER.is_match(content) {
        return false;
    }
    true
}

/// Event fields an outside contributor can set, which become the agent's
/// untrusted input when interpolated into a prompt/command: PR and
/// issue title/body, comment/review bodies, branch names, and the raw event
/// payload. Presence of any of these is what makes prompt injection possible.
/// Deliberately broad on the attacker-controlled side; fields an outsider
/// cannot set (`github.event.*.user.login`, numbers, SHAs) are omitted.
pub static UNTRUSTED_EVENT_INPUT: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"(?i)github\.event\.(?:comment\.body|issue\.title|issue\.body|pull_request\.title|pull_request\.body|pull_request\.head\.ref|review\.body|discussion\.title|discussion\.body|head_commit\.message|commits)|github\.head_ref|github\.event\.pull_request\.head\.label|github\.event\.inputs\.",
    )
    .unwrap()
});

/// A reusable workflow (`workflow_call`) analyzed in isolation has no trigger of
/// its own; its reachability is entirely the caller's. grackle conservatively
/// treats `workflow_call` as fork-reachable, but that over-fires on the common
/// pattern of a reusable "run our agents on our own repo" workflow whose agent
/// consumes only *in-repo* files (`.continue/agents/*.md`, a checked-out diff)
/// and never any attacker-controlled `github.event.*` field. Such a workflow
/// cannot be prompt-injected no matter how it is called, because no untrusted
/// input reaches the agent. We suppress ONLY when BOTH hold: (1) `workflow_call`
/// is the *sole* fork-reachable trigger (a workflow that also lists
/// `pull_request`/`issue_comment`/etc. is directly reachable and still fires),
/// and (2) the file references no untrusted event input. If a caller ever wires
/// untrusted input into such a workflow, the finding surfaces on the caller,
/// where the trigger and gate actually live.
pub fn workflow_call_only_without_untrusted_input(content: &str) -> bool {
    static ID_INPUT: LazyLock<regex::Regex> = LazyLock::new(|| {
        // A workflow_call input naming an issue/PR/comment/discussion by number
        // (or a body/title/prompt passed straight through) implies the workflow
        // fetches attacker-controlled content by that id (`gh issue view $N
        // --json body`) or receives it directly. Either way the agent can see
        // untrusted input, so such a reusable workflow is NOT safe to suppress.
        regex::Regex::new(
            r"(?im)^\s*(?:issue_number|issue_id|pr_number|pull_number|pull_request_number|comment_id|comment_body|discussion_number|review_id|prompt|body|title|user_?input|instructions?|extra_instructions|query|message)\s*:",
        )
        .unwrap()
    });
    if !is_workflow_call_only(content) {
        return false;
    }
    if UNTRUSTED_EVENT_INPUT.is_match(content) {
        return false;
    }
    // Restrict the id-input check to the `on: workflow_call: inputs:` block so a
    // step key or an unrelated mapping elsewhere does not trip it.
    let inputs_block = workflow_call_inputs_block(content);
    !ID_INPUT.is_match(&inputs_block)
}

/// The text of the `on: workflow_call: inputs:` mapping (its keys are the
/// caller-supplied input names), or an empty string if absent. Used to decide
/// whether a reusable workflow's declared inputs imply an untrusted-content
/// fetch (an issue/PR number, a passed-through body/prompt).
fn workflow_call_inputs_block(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let Some(inputs_idx) = lines
        .iter()
        .position(|l| l.trim_start().starts_with("inputs:") && leading_ws(l) >= 2)
    else {
        return String::new();
    };
    let base = leading_ws(lines[inputs_idx]);
    let mut out = String::new();
    for line in &lines[inputs_idx + 1..] {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if leading_ws(line) <= base {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Whether `workflow_call` is the only fork-reachable trigger the `on:` block
/// declares (so no direct fork event reaches this workflow on its own).
pub fn is_workflow_call_only(content: &str) -> bool {
    let direct: &[&str] = &[
        "pull_request_target",
        "issue_comment",
        "issues",
        "pull_request",
        "pull_request_review_comment",
        "pull_request_review",
        "discussion",
        "discussion_comment",
    ];
    static ON_HEADER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"^\s*(?:["']?on["']?)\s*:"#).unwrap());
    static KEY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\s*-?\s*([A-Za-z_]+)\s*:?").unwrap());
    static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z_]+").unwrap());

    let lines: Vec<&str> = content.lines().collect();
    let Some(on_idx) = lines
        .iter()
        .position(|l| ON_HEADER.is_match(l).unwrap_or(false))
    else {
        return false;
    };
    let header = lines[on_idx];
    let after_colon = header.split_once(':').map(|x| x.1).unwrap_or("").trim();
    let mut has_wc = false;
    let mut has_direct = false;
    if !after_colon.is_empty() {
        for m in TOKEN.find_iter(after_colon).filter_map(|m| m.ok()) {
            if m.as_str() == "workflow_call" {
                has_wc = true;
            }
            if direct.contains(&m.as_str()) {
                has_direct = true;
            }
        }
        return has_wc && !has_direct;
    }
    let on_indent = leading_ws(header);
    for line in &lines[on_idx + 1..] {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if leading_ws(line) <= on_indent {
            break;
        }
        if let Ok(Some(caps)) = KEY.captures(line) {
            if let Some(key) = caps.get(1) {
                let k = key.as_str();
                if k == "workflow_call" {
                    has_wc = true;
                }
                if direct.contains(&k) {
                    has_direct = true;
                }
            }
        }
    }
    has_wc && !has_direct
}

/// Whether `caller` invokes the reusable workflow named `callee_file` via a
/// same-repo `uses: ./.github/workflows/<callee_file>` (or `.../<callee_file>@ref`)
/// reference. Only the file name is matched so a `uses:` written with or without
/// the `./` prefix, or against a subdirectory, still resolves. Remote
/// `owner/repo/.github/workflows/x.yml@ref` calls are ignored because their
/// callee lives in another repository, not the one being scanned.
pub fn calls_reusable_workflow(caller: &str, callee_file: &str) -> bool {
    let needle = format!("/{callee_file}");
    for line in caller.lines() {
        let t = line.trim_start();
        let Some(rest) = t
            .strip_prefix("- uses:")
            .or_else(|| t.strip_prefix("uses:"))
        else {
            continue;
        };
        let value = rest.trim().trim_matches(|c| c == '"' || c == '\'');
        let path = value.split('@').next().unwrap_or(value);
        if path.starts_with("./") && path.ends_with(&needle) {
            return true;
        }
        if path.ends_with(&needle) && !path.contains("://") && path.matches('/').count() <= 3 {
            // A bare `.github/workflows/x.yml` (no `./`) still resolves in-repo.
            if path.starts_with(".github/workflows/") {
                return true;
            }
        }
    }
    false
}

/// Text of the top-level `jobs:` entry containing `line_index` (0-based), or
/// the whole file when the job structure cannot be parsed. Scopes a per-job
/// capability check to the job that runs the agent so a write permission on an
/// unrelated sibling job does not count.
pub fn enclosing_job_block(lines: &[&str], line_index: usize) -> String {
    static JOBS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*jobs\s*:").unwrap());
    static JOB_KEY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\s*[A-Za-z0-9_.\-]+\s*:").unwrap());

    let Some(jobs_idx) = lines.iter().position(|l| JOBS.is_match(l).unwrap_or(false)) else {
        return lines.join("\n");
    };
    let jobs_indent = leading_ws(lines[jobs_idx]);
    let mut job_indent: Option<usize> = None;
    let mut starts: Vec<usize> = Vec::new();
    for (i, line) in lines.iter().enumerate().skip(jobs_idx + 1) {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = leading_ws(line);
        if indent <= jobs_indent {
            break;
        }
        if job_indent.is_none() {
            job_indent = Some(indent);
        }
        if job_indent == Some(indent) && JOB_KEY.is_match(line).unwrap_or(false) {
            starts.push(i);
        }
    }
    starts.push(lines.len());
    for pair in starts.windows(2) {
        let (start, end) = (pair[0], pair[1]);
        if start <= line_index && line_index < end {
            return lines[start..end].join("\n");
        }
    }
    lines.join("\n")
}

/// The 0-based start line of the top-level `jobs:` entry (GitHub) or top-level
/// job key (GitLab) that contains `line_index`. Used to group findings by the
/// job they live in so the same rule firing on several lines of one job
/// collapses to a single finding, while the same rule in a *separate* job stays
/// distinct. Returns `line_index` unchanged when no job structure is found, so
/// unrelated matches still get distinct keys rather than all colliding on 0.
pub fn enclosing_job_start(lines: &[&str], line_index: usize) -> usize {
    static JOBS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*jobs\s*:").unwrap());
    static JOB_KEY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\s*[A-Za-z0-9_.\-]+\s*:").unwrap());
    static TOP_KEY: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9_.$-]+\s*:").unwrap());

    // GitHub Actions: jobs live under a `jobs:` key.
    if let Some(jobs_idx) = lines.iter().position(|l| JOBS.is_match(l).unwrap_or(false)) {
        let jobs_indent = leading_ws(lines[jobs_idx]);
        let mut job_indent: Option<usize> = None;
        let mut starts: Vec<usize> = Vec::new();
        for (i, line) in lines.iter().enumerate().skip(jobs_idx + 1) {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let indent = leading_ws(line);
            if indent <= jobs_indent {
                break;
            }
            if job_indent.is_none() {
                job_indent = Some(indent);
            }
            if job_indent == Some(indent) && JOB_KEY.is_match(line).unwrap_or(false) {
                starts.push(i);
            }
        }
        starts.push(lines.len());
        for pair in starts.windows(2) {
            let (start, end) = (pair[0], pair[1]);
            if start <= line_index && line_index < end {
                return start;
            }
        }
        return line_index;
    }

    // GitLab CI: jobs are top-level (non-indented) mapping keys.
    let mut starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| TOP_KEY.is_match(l))
        .map(|(i, _)| i)
        .collect();
    if starts.is_empty() {
        return line_index;
    }
    starts.push(lines.len());
    for pair in starts.windows(2) {
        let (start, end) = (pair[0], pair[1]);
        if start <= line_index && line_index < end {
            return start;
        }
    }
    line_index
}

/// Whether the workflow's top-level `permissions:` block (above `jobs:`)
/// defaults to repository write. A top-level `contents: write` / `write-all`
/// applies to every job that does not narrow it.
pub fn workflow_level_write(content: &str) -> bool {
    static JOBS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*jobs\s*:").unwrap());
    static HEADER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^(\s*)permissions\s*:(.*)$").unwrap());
    static WRITE_ALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bwrite-all\b").unwrap());
    static CONTENTS_WRITE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\s*contents\s*:\s*write\b").unwrap());

    let lines: Vec<&str> = content.lines().collect();
    let jobs_idx = lines
        .iter()
        .position(|l| JOBS.is_match(l).unwrap_or(false))
        .unwrap_or(lines.len());

    for i in 0..jobs_idx {
        let Ok(Some(header)) = HEADER.captures(lines[i]) else {
            continue;
        };
        let rest = header.get(2).map(|m| m.as_str()).unwrap_or("");
        if WRITE_ALL.is_match(rest).unwrap_or(false) {
            return true;
        }
        let perms_indent = header.get(1).map(|m| m.as_str().len()).unwrap_or(0);
        for line in &lines[i + 1..jobs_idx] {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            if leading_ws(line) <= perms_indent {
                break;
            }
            if CONTENTS_WRITE.is_match(line).unwrap_or(false) {
                return true;
            }
        }
        break;
    }
    false
}

/// A job can mutate the repo when it declares `contents: write` /
/// `permissions: write-all` or pushes directly (`git push`, `gh pr
/// create|merge`). Lookaround-free, so it uses the linear `regex` engine.
pub static JOB_WRITE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"(?im)^\s*contents\s*:\s*write\b|permissions\s*:\s*write-all\b|\bgit\s+push\b|\bgh\s+pr\s+(?:create|merge)\b",
    )
    .unwrap()
});

/// An author / write-permission gate means only trusted actors reach the job,
/// so the agent is not fork-exploitable. This is a whole-file scan of a large
/// literal alternation with no lookaround, so it uses the linear `regex` engine
/// rather than `fancy-regex` (whose backtracking limit is exceeded on large
/// workflows, which would silently misread a gated workflow as ungated).
pub static AUTHOR_GATE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?i)getCollaboratorPermissionLevel|author_association\s*(?:==|!=|\bin\b|\bnot in\b)|author_association\b[^\n)]{0,120}?\)\s*(?:==|!=)\s*['"]?(?:OWNER|MEMBER|COLLABORATOR)|contains\(\s*fromJSON\('\[\s*"(?:OWNER|MEMBER|COLLABORATOR)|\[\s*['"]OWNER['"]\s*,\s*['"](?:MEMBER|COLLABORATOR)['"]|contains\(\s*['"][^'"\n]*(?:OWNER|MEMBER|COLLABORATOR)[^'"\n]*['"]\s*,\s*[^)\n]*?author_association|contains\(\s*fromJSON\([^)]*\)\s*,\s*[^)\n]*?(?:comment\.user\.login|sender\.login|github\.actor|triggering_actor|pull_request\.user\.login|issue\.user\.login)|contains\(\s*(?:vars|secrets|env)\.[A-Za-z0-9_]+\s*,\s*[^)\n]*?(?:comment\.user\.login|sender\.login|github\.actor|triggering_actor|pull_request\.user\.login|issue\.user\.login)|allow_forks\s*:\s*["']?false|permission\.permission|collaborators/[^/\s]+/permission|["']?(?:admin|maintain|write)["']?\s*[!=]=\s*["']?\$?(?:PERMISSION|permission)|\$?(?:PERMISSION|permission)["']?\s*[!=]=\s*["'](?:admin|maintain|write)|(?:comment\.user\.login|sender\.login|github\.actor|triggering_actor|pull_request\.user\.login|issue\.user\.login|review\.user\.login)\s*==\s*['"]|(?:github\.actor|triggering_actor|sender\.login|comment\.user\.login)\s*==\s*github\.(?:event\.)?repository\.owner\.login|==\s*github\.(?:event\.)?repository\.owner\.login|(?:github\.actor|triggering_actor|sender\.login|comment\.user\.login)\s*==\s*github\.repository_owner\b|==\s*github\.repository_owner\b|contains\(\s*github\.event\.[a-z_.]*labels\.\*\.name|contains\(\s*github\.event\.label\.name|github\.event\.label\.name\s*==|github\.event\.action\s*==\s*['"]labeled|head\.repo\.full_name\s*(?:==|!==|!=)\s*|head\.repo\.fork\b|is_fork\s*(?:==|!=)"#,
    )
    .unwrap()
});

/// GitHub Agentic Workflows (`gh-aw`, github/gh-aw) compiles a `.md` agent spec
/// into a `.lock.yml` whose agent job is gated on a `pre_activation` job that
/// runs a team-membership check (`check_membership.cjs` → `is_team_member`) and
/// exposes it as `needs.pre_activation.outputs.activated`. The agent job reaches
/// that gate transitively (`agent` → `needs: activation` → `activation` with
/// `if: needs.pre_activation.outputs.activated == 'true'` → `needs:
/// pre_activation`), which is two `needs` hops away from the agent invocation
/// and therefore invisible to the per-job / whole-file author-gate scan. A
/// non-member fork drive-by (opening an issue, commenting) never satisfies the
/// membership check, so these workflows are not fork-exploitable. We recognise
/// the pattern only when BOTH the compiled-file marker AND the membership-gate
/// wiring are present, so a hand-written workflow that merely names a
/// `pre_activation` job can never be silently suppressed by this.
pub fn has_ghaw_membership_gate(content: &str) -> bool {
    static GENERATED: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?i)generated by gh-aw").unwrap());
    static ACTIVATION_GATE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)needs\.pre_activation\.outputs\.activated\s*==\s*'true'|is_team_member\s*==\s*'true'|check_membership",
        )
        .unwrap()
    });
    GENERATED.is_match(content) && ACTIVATION_GATE.is_match(content)
}

/// Strip YAML/shell comments from a block before scanning for write/exec
/// primitives, so a security note in a comment (`# never git push here`) is not
/// misread as an actual `git push`. A `#` starts a comment when it begins a
/// line (optionally indented) or is preceded by whitespace and sits outside a
/// quoted string. This is a heuristic, not a full YAML/shell parser, but it is
/// conservative: it only removes text after an unquoted `#`, which cannot
/// introduce a false *negative* for a real command (a real `git push` is never
/// written after a `#` on the same line).
fn strip_comments(block: &str) -> String {
    let mut out = String::with_capacity(block.len());
    for line in block.lines() {
        let bytes = line.as_bytes();
        let mut in_single = false;
        let mut in_double = false;
        let mut cut = line.len();
        let mut prev_ws = true; // start-of-line counts as preceding whitespace
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'\'' if !in_double => in_single = !in_single,
                b'"' if !in_single => in_double = !in_double,
                b'#' if !in_single && !in_double && prev_ws => {
                    cut = i;
                    break;
                }
                _ => {}
            }
            prev_ws = b == b' ' || b == b'\t';
        }
        out.push_str(&line[..cut]);
        out.push('\n');
    }
    out
}

/// Blank out `git push` / `gh pr create|merge` occurrences that are quoted
/// string content or a step `name:` label rather than an executed command.
/// Test/eval workflows routinely reference these verbs as data - echoing a JSON
/// fixture (`echo '{"command":"git push origin main"}'`), grepping for the
/// literal, or naming a step "Block git push" - none of which mutate the repo.
/// Only the shell-verb primitives are rewritten; the `contents: write` /
/// `write-all` YAML forms in [`JOB_WRITE`] are keys, not string data, so they
/// are left intact.
fn strip_echoed_literals(text: &str) -> String {
    static WRITE_VERB: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)\bgit\s+push\b|\bgh\s+pr\s+(?:create|merge)\b").unwrap()
    });
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        // A step name is a label, never a command.
        let is_name = regex_is_name_line(line);
        out.push_str(&blank_quoted_write_verbs(line, is_name, &WRITE_VERB));
        out.push('\n');
    }
    out
}

/// A `name:` step/job label line (`- name: ...` or `name: ...`).
fn regex_is_name_line(line: &str) -> bool {
    static NAME_LINE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^\s*-?\s*name\s*:").unwrap());
    NAME_LINE.is_match(line)
}

/// Replace `git push` / `gh pr create|merge` inside single/double-quoted spans
/// (or on a `name:` label line) with a neutral token so the write scan does not
/// treat quoted data as an executed command.
fn blank_quoted_write_verbs(line: &str, is_name: bool, write_verb: &regex::Regex) -> String {
    if is_name {
        return write_verb.replace_all(line, "").into_owned();
    }
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut quoted = vec![false; line.len()];
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            _ => {}
        }
        quoted[i] = in_single || in_double;
    }
    let mut out = line.to_string();
    // Rewrite from the end so byte offsets stay valid.
    let matches: Vec<_> = write_verb.find_iter(line).collect();
    for m in matches.into_iter().rev() {
        if quoted[m.start()] {
            out.replace_range(m.start()..m.end(), "");
        }
    }
    out
}

/// Whether the job at `line_index` can write to the repo: an in-job write
/// primitive, or a workflow-level write default the job does not narrow.
pub fn job_can_write(lines: &[&str], line_index: usize, workflow_write: bool) -> bool {
    static JOB_PERMS: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?m)^\s+permissions\s*:").unwrap());
    let stripped = strip_comments(&enclosing_job_block(lines, line_index));
    let job_text = strip_echoed_literals(&stripped);
    JOB_WRITE.is_match(&job_text) || (workflow_write && !JOB_PERMS.is_match(&job_text))
}

/// Whether the job at `line_index` puts a repository/CI secret in reach of the
/// step - `${{ secrets.* }}` interpolated into the job (an `env:` value, a
/// `with:` input, an inline arg). This is the concrete harm for an agent that
/// runs an arbitrary shell on untrusted fork code without provable repo-write:
/// the shell can read the process environment and exfiltrate whatever token the
/// workflow injected (an LLM API key, a PAT, `GITHUB_TOKEN`). A job that names
/// no secret has nothing to steal beyond the ephemeral read-only checkout, so
/// it is not this class. `GITHUB_TOKEN` counts because even the default token
/// is a credential a fork run should not hand to attacker-controlled code.
pub fn job_exposes_secret(lines: &[&str], line_index: usize) -> bool {
    static SECRET_REF: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)\$\{\{\s*secrets\.[A-Za-z0-9_]+|github\.token\b").unwrap()
    });
    SECRET_REF.is_match(&enclosing_job_block(lines, line_index))
}

/// A job-level `if:` guard restricting the job to executions an untrusted fork
/// contributor cannot cause, even though the workflow's `on:` lists a
/// fork-reachable trigger. Covers the common "commit back on push / release"
/// shape: exclude pull-request events (`github.event_name != 'pull_request'`),
/// admit only non-fork events (`github.event_name == 'push' | 'schedule' |
/// 'workflow_dispatch'`), require a completed merge (`pull_request.merged ==
/// true`, which only a maintainer can cause), or restrict to a protected
/// default branch (`github.ref == 'refs/heads/main'`).
static JOB_NON_FORK_EVENT_GUARD: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?i)github\.event_name\s*!=\s*['"]pull_request(?:_target)?['"]|github\.event_name\s*==\s*['"](?:push|schedule|workflow_dispatch|release|create|tag)['"]|github\.event\.pull_request\.merged\s*==\s*(?:true|['"]true['"])|github\.ref\s*==\s*['"]refs/heads/"#,
    )
    .unwrap()
});

/// The job's `if:` admits a fork-reachable event. When present, the guard is an
/// OR that still lets an untrusted contributor in (e.g. `event_name ==
/// 'pull_request' || event_name == 'schedule'`), so it must not suppress.
static JOB_ADMITS_FORK_EVENT: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?i)github\.event_name\s*==\s*['"](?:pull_request(?:_target)?|issue_comment|issues|pull_request_review_comment|pull_request_review)['"]|github\.event\.issue\.pull_request"#,
    )
    .unwrap()
});

/// A job hard-disabled with `if: false` (or `if: ${{ false }}`) never runs, so
/// its agent is unreachable regardless of the workflow trigger. Anchored to a
/// job-level `if:` (two-space or deeper indent) so it is only read inside the
/// enclosing job block.
static JOB_DISABLED: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?im)^\s+if\s*:\s*(?:\$\{\{\s*)?false\b").unwrap());

/// Whether the enclosing job of `line_index` is gated by an `if:` that excludes
/// fork-reachable execution (see [`JOB_NON_FORK_EVENT_GUARD`]). Scanned per-job
/// so a guard on an unrelated sibling job does not suppress the agent job. A
/// job whose `if:` also admits a fork-reachable event (an OR that still lets a
/// contributor in) is left firing. A job hard-disabled with `if: false` is
/// always suppressed.
pub fn job_gated_on_non_fork_event(lines: &[&str], line_index: usize) -> bool {
    let job_text = enclosing_job_block(lines, line_index);
    if job_disabled(&job_text) {
        return true;
    }
    // A completed merge is something only a maintainer can cause, so a
    // `pull_request.merged == true` clause is a sound gate even though the job's
    // `if:` also names the fork-reachable trigger it filters (`event_name ==
    // 'pull_request_target' && action == 'closed' && merged == true`). The
    // generic OR-detector below would see the trigger name and let the job fire.
    // Only trust it when the guard is a pure AND-chain: if the job `if:` has no
    // `||`, the merge requirement applies unconditionally.
    if let Some(job_if) = job_level_if(&job_text) {
        if MERGE_GATE.is_match(&job_if) && !job_if.contains("||") {
            return true;
        }
    }
    JOB_NON_FORK_EVENT_GUARD.is_match(&job_text) && !JOB_ADMITS_FORK_EVENT.is_match(&job_text)
}

/// Whether the job at `line_index` is **transitively** gated on a non-fork
/// event: it `needs:` an upstream job whose own `if:` restricts it to
/// maintainer-only executions (a merge/push/etc. guard, see
/// [`job_gated_on_non_fork_event`]), and its own `if:` consumes that upstream's
/// output. A fork PR author cannot make the upstream run, so its output stays
/// empty and the downstream job never fires. Covers the fan-out shape where a
/// merge-gated "resolve" job emits a list and a matrix "write" job runs one leg
/// per entry (`needs.resolve.outputs.origins != '[]'`).
pub fn job_gated_by_transitive_non_fork_event(lines: &[&str], line_index: usize) -> bool {
    let job_text = enclosing_job_block(lines, line_index);
    let Some(job_if) = job_level_if(&job_text) else {
        return false;
    };
    static NEEDS_REF: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"needs\.([A-Za-z0-9_.\-]+)\.outputs\.").unwrap());
    let upstreams: Vec<&str> = NEEDS_REF
        .captures_iter(&job_if)
        .filter_map(|c| c.get(1).map(|m| m.as_str()))
        .collect();
    if upstreams.is_empty() {
        return false;
    }
    static JOB_KEY: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^(\s+)([A-Za-z0-9_.\-]+)\s*:\s*$").unwrap());
    for up in upstreams {
        // Find the upstream job's definition line and probe its own gate.
        if let Some(up_idx) = lines.iter().position(|l| {
            JOB_KEY
                .captures(l)
                .map(|c| c.get(2).map(|m| m.as_str()) == Some(up))
                .unwrap_or(false)
        }) {
            if job_gated_on_non_fork_event(lines, up_idx) {
                return true;
            }
        }
    }
    false
}

/// `pull_request.merged == true` - a completed merge, which only a maintainer
/// can cause.
static MERGE_GATE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?i)github\.event\.pull_request\.merged\s*==\s*(?:true|['"]true['"])"#)
        .unwrap()
});

/// The job-level `if:` expression as a single string (folding a multi-line
/// `if: >` / `if: |` block into one line), or `None` if the job has no `if:`.
/// Only the job's own guard is returned - step-level `if:` at deeper indent is
/// excluded - so reasoning about `&&`/`||` structure is not confused by an
/// unrelated step condition elsewhere in the job.
fn job_level_if(job_text: &str) -> Option<String> {
    static JOB_IF: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?m)^(\s+)if\s*:\s*(.*)$").unwrap());
    let lines: Vec<&str> = job_text.lines().collect();
    let caps = JOB_IF.captures(job_text)?;
    let indent = caps.get(1)?.as_str().len();
    let start = lines.iter().position(|l| JOB_IF.is_match(l))?;
    let first = caps.get(2)?.as_str().trim();
    let mut expr = first
        .trim_start_matches('>')
        .trim_start_matches('|')
        .trim()
        .to_string();
    for line in &lines[start + 1..] {
        if line.trim().is_empty() {
            continue;
        }
        if leading_ws(line) <= indent {
            break;
        }
        expr.push(' ');
        expr.push_str(line.trim());
    }
    Some(expr)
}

/// Whether the job at `line_index` is gated by a **transitive permission check**:
/// its `if:` requires the boolean output of an upstream `needs:` job
/// (`needs.<check>.outputs.<flag> == 'true'`), and the file wires that check to
/// a recognizable maintainer/allow-list gate - an explicit `allowed-users:`
/// list, a `check-permission`-style job/action, or a collaborator-permission
/// API call. This is the multi-job analogue of the inline
/// [`AUTHOR_GATE`]: the agent (often inside a called reusable workflow or a
/// composite action) runs only after a separate job has verified the actor is
/// trusted, so an outside fork contributor cannot reach it. Both halves are
/// required - a bare `needs.*.outputs.* == 'true'` guard with no permission
/// wiring in the file never suppresses, so a build/lint gate cannot be mistaken
/// for an authorization gate.
pub fn job_gated_by_permission_check(lines: &[&str], line_index: usize) -> bool {
    static OUTPUT_GATE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)needs\.[A-Za-z0-9_.\-]+\.outputs\.(?:allowed|is[_-]?member|is[_-]?team[_-]?member|has[_-]?permission|authoriz(?:ed|ation)|permitted|can[_-]?run|approved|is[_-]?collaborator|is[_-]?maintainer|is[_-]?owner|trusted|qualified[_-]?mention)\s*(?:==\s*(?:true|['\x22]true['\x22])|\)|\s*$)",
        )
        .unwrap()
    });
    // Same gate expressed as a JSON-object output: a check job returns a struct
    // and the agent job reads a qualification field off it, e.g.
    // `fromJSON(needs.check.outputs.result).qualifiedMention == true`.
    static OUTPUT_GATE_JSON: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)fromJSON\(\s*needs\.[A-Za-z0-9_.\-]+\.outputs\.[A-Za-z0-9_.\-]+\s*\)\.(?:qualified[A-Za-z]*|allowed|authoriz(?:ed|ation)|isAllowed|is[_-]?member|permitted|approved|trusted)\s*==\s*(?:true|['\x22]true['\x22])",
        )
        .unwrap()
    });
    static PERMISSION_WIRING: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)allowed[_-]?users\b|allowed[_-]?logins?\b|check[_-]?permission|verify[_-]?permission|permission[_-]?check|getCollaboratorPermissionLevel|collaborators/[^/\s]+/permission|author_association|team[_-]?membership|is[_-]?team[_-]?member|check[_-]?membership|(?:allow[_-]?list|whitelist)\s*\.includes\(",
        )
        .unwrap()
    });
    let job_text = enclosing_job_block(lines, line_index);
    // The output gate must be on the agent-bearing job itself (its `if:`),
    // while the permission wiring can be anywhere in the file (the check job).
    (OUTPUT_GATE.is_match(&job_text) || OUTPUT_GATE_JSON.is_match(&job_text))
        && PERMISSION_WIRING.is_match(&lines.join("\n"))
}

/// Whether the job at `line_index` gates its privileged steps on a
/// **same-job allow-list check step**: an
/// early `github-script` (or shell) step verifies the actor against a hardcoded
/// maintainer allow-list and exposes the verdict as a step output
/// (`core.setOutput('authorized', ...)`), and every subsequent write/agent step
/// carries `if: steps.<id>.outputs.<flag> == 'true'`. A fork drive-by is not in
/// the allow-list, so the gated steps never run for it. This is the in-job
/// analogue of [`job_gated_by_permission_check`] (which handles the cross-job
/// `needs.<check>.outputs.*` form). Both halves are required: the step-output
/// gate on privileged steps AND allow-list/permission wiring in the same job,
/// so an ordinary build-status step gate (`if: steps.x.outputs.changed`) can
/// never be mistaken for an authorization gate.
pub fn job_gated_by_step_permission_check(lines: &[&str], line_index: usize) -> bool {
    static STEP_OUTPUT_GATE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)if\s*:.*steps\.[A-Za-z0-9_.\-]+\.outputs\.(?:allowed|is[_-]?member|is[_-]?team[_-]?member|has[_-]?permission|authoriz(?:ed|ation)|permitted|can[_-]?run|approved|is[_-]?collaborator|is[_-]?maintainer|is[_-]?owner|trusted|whitelist(?:ed)?)",
        )
        .unwrap()
    });
    static WIRING: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)setOutput\(\s*['\x22](?:allowed|authoriz(?:ed|ation)|is[_-]?member|is[_-]?team[_-]?member|permitted|approved|trusted|whitelist(?:ed)?)|whitelist\s*(?:=|\.includes|:)|allow[_-]?list\s*(?:=|\.includes|:)|allowed[_-]users\s*:|allowed[_-]logins?\s*:|getCollaboratorPermissionLevel|collaborators/[^/\s]+/permission|author_association|team[_-]?membership|check[_-]?membership|--check[_-]?user\b|check[_-]?user\s*[(:]|is[_-]?authorized\b|verify[_-]?(?:user|actor|author)\b",
        )
        .unwrap()
    });
    let job_text = enclosing_job_block(lines, line_index);
    STEP_OUTPUT_GATE.is_match(&job_text) && WIRING.is_match(&job_text)
}

/// `anthropics/claude-code-action` / `claude-code-base-action` enforce their own
/// authorization: by default only actors with repository *write* access can
/// trigger the action (its `checkWritePermissions`), and bots are refused unless
/// explicitly allowed. So the ubiquitous `@claude` tag-mode wiring
/// (`issue_comment` / `issues` / `pull_request` with `contains(..., '@claude')`)
/// is NOT reachable by an outside fork contributor - the action rejects them
/// before any tool runs. The write-check is only lifted by two documented
/// inputs: `allowed_non_write_users: "*"` (bypasses the write requirement for
/// humans) and `allowed_bots: "*"` (lets any GitHub App trigger it on a public
/// repo). A job that uses the action and sets neither is self-gated, so a
/// finding on it would be a false positive.
///
/// The `content`-level `workflow_run` escalation path is handled separately and
/// is intentionally not covered here: on a `workflow_run` re-trigger the actor
/// identity the action checks is the base-repo run's actor, not the fork PR
/// author, so the built-in check does not defend that shape and the finding must
/// stand.
pub fn claude_action_self_gated(content: &str, lines: &[&str], line_index: usize) -> bool {
    static CLAUDE_ACTION: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)anthropics/claude-code-(?:base-)?action@").unwrap()
    });
    static BYPASS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"(?im)^\s*allowed_(?:non_write_users|bots)\s*:\s*["']?\*"#).unwrap()
    });
    let job_text = enclosing_job_block(lines, line_index);
    if !CLAUDE_ACTION.is_match(&job_text) {
        return false;
    }
    if BYPASS.is_match(&job_text) {
        return false;
    }
    // The action's write-check does not defend the workflow_run re-trigger shape.
    !workflow_run_escalation(content)
}

/// A fail-closed allowlist guard: a step (typically `actions/github-script`)
/// that aborts the whole job - via `core.setFailed(...)`, `process.exit`, or a
/// shell `exit 1` - when the triggering actor is not present in a maintainer-
/// controlled allowlist. Because a failed step stops every step that follows,
/// the agent step is only reachable for allowlisted actors, so an untrusted
/// fork contributor cannot reach it. Both halves are required: the membership
/// test on the actor AND the fail-closed abort in the same job.
pub fn job_gated_by_failclosed_allowlist(lines: &[&str], line_index: usize) -> bool {
    static MEMBERSHIP: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)(?:allowed|allowlist|whitelist|permitted|authorized)[A-Za-z_]*\s*(?:\.has\(|\.includes\(|\.indexOf\()|\bALLOWED_ACTORS\b|\bALLOWED_USERS\b|\bALLOWLIST\b|\bWHITELIST\b|(?:allow|permit)[_-]?list[A-Za-z_]*\.(?:has|includes|indexOf)",
        )
        .unwrap()
    });
    static ABORT: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)core\.setFailed\(|process\.exit\(\s*1|\bexit\s+1\b|throw\s+new\s+Error\(",
        )
        .unwrap()
    });
    let job_text = enclosing_job_block(lines, line_index);
    MEMBERSHIP.is_match(&job_text) && ABORT.is_match(&job_text)
}

/// A weaker, indirect form of the author gate: the workflow binds
/// `github.event.*.author_association` to an env var or JS variable, then an
/// inline script compares that value against a trusted role
/// (`OWNER`/`MEMBER`/`COLLABORATOR`) and refuses everyone else. The main
/// [`AUTHOR_GATE`] regex expects `author_association` adjacent to the
/// comparison; some workflows instead do
/// `ACTOR_ASSOCIATION: ${{ github.event.comment.author_association }}` and later
/// `if (association !== 'OWNER' && association !== 'MEMBER') return;`. Both
/// halves are required - the `author_association` capture AND a role comparison
/// in the same file - so a workflow that merely echoes the association without
/// acting on it is not mistaken for a gate.
pub fn has_indirect_author_association_gate(content: &str) -> bool {
    static CAPTURE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?i)author_association").unwrap());
    static ROLE_COMPARE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r#"(?i)(?:==|!=|!==|===|\bin\b|includes\s*\()\s*[\[('"]*\s*(?:OWNER|MEMBER|COLLABORATOR)\b|['"](?:OWNER|MEMBER|COLLABORATOR)['"]\s*(?:!==?|===?)"#,
        )
        .unwrap()
    });
    CAPTURE.is_match(content) && ROLE_COMPARE.is_match(content)
}

/// Whole-file analogue of [`job_gated_by_permission_check`]: some job's `if:`
/// requires an upstream check job's authorization output - either the direct
/// `needs.<check>.outputs.<authz-flag>` form or the JSON-struct form
/// `fromJSON(needs.<check>.outputs.<x>).<qualifier> == true` - and the file wires
/// that check to a maintainer allow-list or permission API. Used by the coarse
/// whole-file gate so a multi-job "check mention against an allow-list, then run
/// the agent" workflow (the dragon-ai pattern) is recognized as gated even when
/// the authorization flag has a bespoke name.
pub fn has_transitive_permission_gate(content: &str) -> bool {
    static OUTPUT_GATE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)needs\.[A-Za-z0-9_.\-]+\.outputs\.(?:allowed|is[_-]?member|is[_-]?team[_-]?member|has[_-]?permission|authoriz(?:ed|ation)|permitted|can[_-]?run|approved|is[_-]?collaborator|is[_-]?maintainer|is[_-]?owner|trusted|qualified[_-]?mention)\s*(?:==\s*(?:true|['\x22]true['\x22])|\)|\s*$)",
        )
        .unwrap()
    });
    static OUTPUT_GATE_JSON: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)fromJSON\(\s*needs\.[A-Za-z0-9_.\-]+\.outputs\.[A-Za-z0-9_.\-]+\s*\)\.(?:qualified[A-Za-z]*|allowed|authoriz(?:ed|ation)|isAllowed|is[_-]?member|permitted|approved|trusted)\s*==\s*(?:true|['\x22]true['\x22])",
        )
        .unwrap()
    });
    static PERMISSION_WIRING: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)allowed[_-]?users\b|allowed[_-]?logins?\b|check[_-]?permission|verify[_-]?permission|permission[_-]?check|getCollaboratorPermissionLevel|collaborators/[^/\s]+/permission|author_association|team[_-]?membership|is[_-]?team[_-]?member|check[_-]?membership|(?:allow[_-]?list|whitelist)\s*\.includes\(",
        )
        .unwrap()
    });
    (OUTPUT_GATE.is_match(content) || OUTPUT_GATE_JSON.is_match(content))
        && PERMISSION_WIRING.is_match(content)
}

/// A transitive **label** gate: an upstream job derives a boolean output from
/// the pull request's labels (a maintainer-controlled property a fork
/// contributor cannot set) and a downstream job runs the agent only when that
/// output is set. The steveash/assayer pattern: a `prepare` job reads
/// `.labels[].name`, sets `should_run=true` only for a fixed label set, and the
/// agent job carries `if: needs.prepare.outputs.should_run == 'true'`. Both
/// halves are required - the downstream `needs.*.outputs.*` guard AND evidence
/// the file computes that output from label membership - so a plain build-status
/// output gate is never mistaken for an authorization gate.
pub fn has_transitive_label_gate(content: &str) -> bool {
    static OUTPUT_GUARD: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)needs\.[A-Za-z0-9_.\-]+\.outputs\.[A-Za-z0-9_.\-]+\s*==\s*(?:true|['\x22]true['\x22])",
        )
        .unwrap()
    });
    static LABEL_WIRING: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)\.labels\[\]\.name|github\.event\.label\.name|labels\.\*\.name|contains\(\s*github\.event\.(?:pull_request|issue)\.labels|pull_request\.labels\.\*\.name",
        )
        .unwrap()
    });
    OUTPUT_GUARD.is_match(content) && LABEL_WIRING.is_match(content)
}

/// An OR-gate bypass: the job's `if:` ORs an author-gated branch with an
/// *ungated* fork-reachable branch, so a whole-file author gate over-suppresses
/// the open branch. Two shapes are recognized:
///
/// * a `pull_request_review` review whose `state == 'changes_requested'` runs
///   the agent with no author/fork check on that disjunct - a second account
///   submitting a "request changes" review on an attacker's PR reaches the
///   write-capable job; and
/// * a *bare* `event_name == 'pull_request'` disjunct - the entire disjunct is
///   just that equality with no further condition (`&&`) - sitting in an OR
///   next to an author-gated sibling. This is the "only collaborators can open
///   PRs" misconception: on a public repo any fork can open a PR, so the whole
///   job is fork-reachable. The disjunct must be *exactly* bare; a
///   `pull_request && <anything>` disjunct is left to the coarse gate because
///   the extra term is nearly always a real fork/same-repo/draft guard.
///
/// Returns true only when such a disjunct exists AND carries no
/// author-association / fork-exclusion / same-repo guard of its own, so
/// correctly-gated look-alikes are untouched. Used as a positive override of
/// the coarse whole-file gate.
pub fn job_has_ungated_review_bypass(lines: &[&str], line_index: usize) -> bool {
    static REVIEW_STATE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)review\.state\s*==\s*['\x22]changes_requested['\x22]").unwrap()
    });
    static BARE_PR: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)^github\.event_name\s*==\s*['\x22]pull_request['\x22]$"#).unwrap()
    });
    static GUARD: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)author_association|head\.repo\.fork|head\.repo\.full_name\s*==\s*github\.repository|head\.repo\.id\s*==\s*github\.repository_id|repository_owner|\.login\s*==|actor\s*==|getCollaboratorPermissionLevel|is[_-]?member|team|membership|permitted|allowed|activated|approved",
        )
        .unwrap()
    });
    let job = enclosing_job_block(lines, line_index);
    // Isolate the job header `if:` expression (through `steps:`), dropping
    // comment lines so prose like "keep the member guard" cannot be mistaken
    // for a gate, then inspect each top-level (paren-depth-0) `||` disjunct in
    // isolation.
    let header: String = job
        .lines()
        .take_while(|l| l.trim() != "steps:")
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ");
    // Reduce to just the boolean expression after `if:`, stripping the job key
    // and any block scalar indicator (`|`, `>`, `>-`) so a bare disjunct like
    // `(github.event_name == 'pull_request')` compares cleanly.
    let expr = match header.split_once("if:") {
        Some((_, rest)) => rest.trim_start_matches([' ', '|', '>', '-']).trim(),
        None => header.as_str(),
    };
    // A bare-PR disjunct only counts inside a real OR next to another disjunct;
    // a lone `if: event_name == 'pull_request'` job is already handled as
    // ungated by the whole-file path.
    let is_or = split_top_level_or(expr).len() > 1;
    split_top_level_or(expr).iter().any(|d| {
        let trimmed = strip_wrapping_parens(d.trim());
        let review = REVIEW_STATE.is_match(&trimmed).unwrap_or(false);
        let bare = is_or && BARE_PR.is_match(&trimmed).unwrap_or(false);
        (review || bare) && !GUARD.is_match(&trimmed).unwrap_or(false)
    })
}

/// Split an `if:` expression on `||` that sit at parenthesis depth 0, so a
/// nested `(a || b)` stays inside one disjunct.
fn split_top_level_or(expr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    let bytes = expr.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => {
                depth += 1;
                cur.push('(');
            }
            b')' => {
                depth -= 1;
                cur.push(')');
            }
            b'|' if depth == 0 && i + 1 < bytes.len() && bytes[i + 1] == b'|' => {
                out.push(std::mem::take(&mut cur));
                i += 2;
                continue;
            }
            c => cur.push(c as char),
        }
        i += 1;
    }
    out.push(cur);
    out
}

/// Remove one or more balanced layers of surrounding parentheses/whitespace so
/// `((event_name == 'pull_request'))` compares equal to the bare form.
fn strip_wrapping_parens(s: &str) -> String {
    let mut cur = s.trim();
    loop {
        if !(cur.starts_with('(') && cur.ends_with(')')) {
            break;
        }
        // Confirm the outer parens are balanced as a single group.
        let inner = &cur[1..cur.len() - 1];
        let mut depth = 0i32;
        let mut balanced = true;
        for b in inner.bytes() {
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth < 0 {
                        balanced = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if !balanced || depth != 0 {
            break;
        }
        cur = inner.trim();
    }
    cur.to_string()
}

/// Whether a job is hard-disabled by a job-level `if: false`. Only the job
/// header (everything before its `steps:` key) is inspected so a disabled
/// *step* (`if: false` on one step) does not mask the whole job.
fn job_disabled(job_text: &str) -> bool {
    let header: String = job_text
        .lines()
        .take_while(|l| l.trim() != "steps:")
        .collect::<Vec<_>>()
        .join("\n");
    JOB_DISABLED.is_match(&header)
}

// --- GitLab CI (.gitlab-ci.yml) primitives -------------------------------
//
// GitLab's structure and threat model differ from GitHub Actions: jobs are
// top-level keys (no `jobs:`/`on:`/`permissions:` wrappers), triggers live in
// each job's `rules:`/`only:`, and a fork merge-request pipeline runs in the
// fork with the fork's variables, so the parent's protected secrets are never
// injected. A `.gitlab-ci.yml` agent job is therefore only a concern when it
// runs on merge-request/diff content, carries write/exec capability, and is
// not self-gated against fork sources.

/// A `.gitlab-ci.yml` reacts to a merge request (the untrusted-diff surface).
pub static GITLAB_MR_TRIGGER: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?im)CI_PIPELINE_SOURCE\s*==\s*["']merge_request_event["']|^\s*-?\s*merge_requests\b|CI_PIPELINE_SOURCE\s*==\s*["']external_pull_request_event["']|CI_MERGE_REQUEST_IID|CI_MERGE_REQUEST_SOURCE_BRANCH"#,
    )
    .unwrap()
});

/// The job explicitly refuses fork-sourced merge requests
/// (`$CI_MERGE_REQUEST_SOURCE_PROJECT_ID != $CI_PROJECT_ID`), so an untrusted
/// fork cannot reach it. Presence anywhere in the file suppresses the finding,
/// matching how the author-gate check is whole-file for GitHub.
pub static GITLAB_FORK_GUARD: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"(?i)CI_MERGE_REQUEST_SOURCE_PROJECT_ID\s*(?:!=|==)\s*\$?\{?CI_PROJECT_ID|CI_PROJECT_ID\s*(?:!=|==)\s*\$?\{?CI_MERGE_REQUEST_SOURCE_PROJECT_ID",
    )
    .unwrap()
});

/// A whole-file gate that only a trusted, non-fork pipeline can satisfy: a
/// source-branch-name pattern (`CI_MERGE_REQUEST_SOURCE_BRANCH_NAME =~
/// /^prefix.../`) that only the project's own automation produces. Safe to test
/// file-wide because a fork MR cannot control its source branch to match a
/// project-internal naming scheme. The GitLab analogue of the GitHub author
/// gate; the custom-variable form is checked per-job (see
/// [`gitlab_job_gated_on_internal_var`]) to avoid an unrelated job's gate
/// suppressing the agent job.
pub static GITLAB_TRUSTED_GATE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)CI_MERGE_REQUEST_SOURCE_BRANCH_NAME\s*=~\s*/").unwrap()
});

/// The text of the top-level `.gitlab-ci.yml` job (a top-level, non-indented
/// mapping key) that contains `line_index` (0-based). GitLab jobs are
/// top-level keys with indented bodies, unlike GitHub's `jobs:` wrapper.
pub fn gitlab_job_block(lines: &[&str], line_index: usize) -> String {
    static TOP_KEY: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9_.$-]+\s*:").unwrap());
    let mut starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| TOP_KEY.is_match(l))
        .map(|(i, _)| i)
        .collect();
    starts.push(lines.len());
    for pair in starts.windows(2) {
        let (start, end) = (pair[0], pair[1]);
        if start <= line_index && line_index < end {
            return lines[start..end].join("\n");
        }
    }
    lines.join("\n")
}

/// Whether the agent's own job is gated on a custom pipeline variable a fork
/// merge-request pipeline never sets (`$MY_VAR != ""` / `$MY_VAR == "..."` in a
/// `rules: if:`), excluding GitLab's `CI_*` / `GITLAB_*` builtins. Scoped to the
/// enclosing job so a sibling job's gate does not suppress the agent.
pub fn gitlab_job_gated_on_internal_var(lines: &[&str], line_index: usize) -> bool {
    static VAR_GATE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?i)\$\{?(?!CI_|GITLAB_)[A-Z][A-Z0-9_]{2,}\}?\s*(?:!=\s*""|==\s*["'][^"']+["'])"#,
        )
        .unwrap()
    });
    let job = gitlab_job_block(lines, line_index);
    job.lines()
        .filter(|l| l.contains("if:") || l.trim_start().starts_with("- if:"))
        .any(|l| VAR_GATE.is_match(l).unwrap_or(false))
}

/// Whether the agent's GitLab job only runs on **manual** action for its
/// fork-reachable (merge-request) path. In a GitLab MR pipeline a `when:
/// manual` job is not started automatically - a project member with pipeline
/// access must click "play" - so an outside fork contributor opening an MR
/// cannot drive it. The job is manual-gated only when *every* rule that admits
/// the merge-request event carries `when: manual`, and the job has **no** other
/// rule that auto-runs on a fork-controllable trigger (a comment/commit-message
/// match such as `$CI_COMMIT_MESSAGE =~ /@bot/`, a webhook variable gate, or a
/// bare `merge_request_event` rule with no `when`). This mirrors the GitHub
/// manual-dispatch gate and is scoped to the enclosing job so a sibling job's
/// `when: manual` never suppresses an auto-running agent job. Conservative by
/// design: if the job mixes a manual MR rule with any auto-run trigger, it is
/// **not** treated as gated.
pub fn gitlab_job_is_manual_gated(lines: &[&str], line_index: usize) -> bool {
    static MR_RULE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)CI_PIPELINE_SOURCE\s*==\s*["']merge_request_event["']"#).unwrap()
    });
    static WHEN_MANUAL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?im)^\s*when\s*:\s*manual\b").unwrap());
    // A rule that fires automatically on attacker-controllable content: a
    // commit-message / comment match, or a bare MR trigger without `when`.
    static AUTO_TRIGGER: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?i)CI_COMMIT_MESSAGE\s*=~|CI_MERGE_REQUEST_TITLE\s*=~|CI_MERGE_REQUEST_DESCRIPTION\s*=~|AI_FLOW_INPUT|@(?:claude|opencode|gemini|codex|cursor|bot)\b"#,
        )
        .unwrap()
    });

    let job = gitlab_job_block(lines, line_index);
    let job = strip_comments(&job);
    let jl: Vec<&str> = job.lines().collect();

    // Must have at least one MR-admitting rule and at least one `when: manual`.
    if !MR_RULE.is_match(&job).unwrap_or(false) || !WHEN_MANUAL.is_match(&job).unwrap_or(false) {
        return false;
    }
    // Any explicit auto-run trigger disqualifies the manual gate.
    if AUTO_TRIGGER.is_match(&job).unwrap_or(false) {
        return false;
    }
    // Every MR-admitting rule must have `when: manual` before the next rule
    // item begins. A rule item starts with `- ` (a new list entry); the manual
    // clause must appear within the same rule's scope, not a later rule's.
    for (i, line) in jl.iter().enumerate() {
        if MR_RULE.is_match(line).unwrap_or(false) {
            let mut has_manual = false;
            for l in jl.iter().skip(i + 1) {
                let t = l.trim_start();
                // Next rule item (or a dedent to a sibling key) ends this rule.
                if t.starts_with("- ") || (!l.starts_with(char::is_whitespace) && !t.is_empty()) {
                    break;
                }
                if WHEN_MANUAL.is_match(l).unwrap_or(false) {
                    has_manual = true;
                    break;
                }
            }
            if !has_manual {
                return false;
            }
        }
    }
    true
}

/// Write / execute capability the agent is handed: dangerous auto-approve
/// flags, a tool grant that includes Bash/Edit/Write, or a real project/personal
/// access token used to push or post back to the API. `CI_JOB_TOKEN` is
/// deliberately excluded because a fork pipeline's job token is scoped to the
/// fork and cannot mutate the parent.
pub static GITLAB_AGENT_WRITE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?im)--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|--full-auto\b|--approval-mode[\s=]+["']?(?:yolo|auto_edit)|--permission-mode[\s=]+["']?(?:acceptEdits|bypassPermissions)|--allowed-?[Tt]ools[\s=]+["'][^"']*\b(?:Bash|Edit|Write|MultiEdit)\b|\bgit\s+push\b|PRIVATE-TOKEN\s*:|GITLAB_ACCESS_TOKEN|GITLAB_TOKEN|GITLAB_API_TOKEN|PROJECT_ACCESS_TOKEN|(?:GITLAB|CLAUDE)[A-Z_]*OAUTH_TOKEN"#,
    )
    .unwrap()
});

/// The tool grant is restricted to read-only tools (`Read`, `Grep`, `Glob`,
/// `WebFetch`, `LS`) with no Bash/Edit/Write, so even a fully reachable job
/// cannot mutate the repo. Suppresses the finding, mirroring the read-only
/// negative cases in the GitHub families.
pub static GITLAB_READONLY_TOOLS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)--allowed-?tools[\s=]+["'](?:\s*(?:Read|Grep|Glob|WebFetch|WebSearch|LS)\b[,\s"']*)+["']"#,
    )
    .unwrap()
});

/// The agent runs in plan (read-only) mode: it may read the diff and print a
/// review but cannot edit files or run commands. A posting-back access token is
/// then only a review comment, not repo mutation, so this is treated as
/// read-only unless a genuine write signal is also present (see
/// [`GITLAB_HARD_WRITE`]).
pub static GITLAB_PLAN_MODE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(?i)--permission-mode[\s=]+["']?plan\b"#).unwrap());

/// A genuine repo-mutation signal, as opposed to a comment-posting access token.
/// A dangerous auto-approve flag, a tool grant including Bash/Edit/Write, or a
/// direct `git push` all mutate the repo regardless of `--permission-mode plan`.
pub static GITLAB_HARD_WRITE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?im)--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|--full-auto\b|--approval-mode[\s=]+["']?(?:yolo|auto_edit)|--permission-mode[\s=]+["']?(?:acceptEdits|bypassPermissions)|--allowed-?[Tt]ools[\s=]+["'][^"']*\b(?:Bash|Edit|Write|MultiEdit)\b|\bgit\s+push\b"#,
    )
    .unwrap()
});

/// Whether a GitLab agent job is fork-reachable and write-capable and not
/// self-gated: merge-request trigger, write/exec capability, no fork guard, and
/// its tool grant is not read-only. This is the whole-file GitLab analogue of
/// the GitHub `reachable && !gated && job_can_write` composite.
pub fn gitlab_agent_reachable_and_writable(content: &str) -> bool {
    if GITLAB_FORK_GUARD.is_match(content) || GITLAB_TRUSTED_GATE.is_match(content) {
        return false;
    }
    // Plan (read-only) mode with no genuine mutation signal: a posting-back token
    // is only a review comment, not repo write.
    if GITLAB_PLAN_MODE.is_match(content) && !GITLAB_HARD_WRITE.is_match(content) {
        return false;
    }
    if GITLAB_READONLY_TOOLS.is_match(content).unwrap_or(false)
        && !GITLAB_AGENT_WRITE.is_match(content)
    {
        return false;
    }
    GITLAB_MR_TRIGGER.is_match(content) && GITLAB_AGENT_WRITE.is_match(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commented_git_push_is_not_a_write_primitive() {
        // A security note in a YAML comment must not be read as a real push.
        let wf = "on:\n  pull_request_target:\njobs:\n  review:\n    permissions:\n      contents: read\n    steps:\n      - name: note\n        # a stray git push here would use base creds; we forbid it\n        run: echo reviewing\n      - run: echo done\n";
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("reviewing")).unwrap();
        assert!(
            !job_can_write(&lines, idx, false),
            "commented git push must not count as write capability"
        );
    }

    #[test]
    fn real_git_push_is_still_a_write_primitive() {
        let wf = "on:\n  pull_request_target:\njobs:\n  review:\n    permissions:\n      contents: read\n    steps:\n      - run: git push origin HEAD\n";
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("git push")).unwrap();
        assert!(job_can_write(&lines, idx, false));
    }

    #[test]
    fn echoed_git_push_literal_is_not_a_write_primitive() {
        // A test/eval workflow that echoes a `git push` string to assert a guard
        // blocks it must not be read as a real push.
        let wf = "on:\n  pull_request:\njobs:\n  e2e:\n    steps:\n      - run: |\n          echo '{\"command\":\"git push origin main\"}' | ./guard\n      - run: echo done\n";
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("guard")).unwrap();
        assert!(
            !job_can_write(&lines, idx, false),
            "an echoed git push string literal must not count as write capability"
        );
    }

    #[test]
    fn detects_fork_reachable_mapping() {
        let wf = "on:\n  issue_comment:\n    types: [created]\njobs:\n  a:\n    steps: []\n";
        assert!(has_fork_reachable_trigger(wf));
    }

    #[test]
    fn detects_fork_reachable_inline() {
        assert!(has_fork_reachable_trigger("on: [push, pull_request]\n"));
    }

    #[test]
    fn detects_discussion_triggers_reachable() {
        // Anyone can open a discussion or comment on one, exactly like issues.
        assert!(has_fork_reachable_trigger(
            "on:\n  discussion:\n    types: [created]\njobs:\n  a:\n    steps: []\n"
        ));
        assert!(has_fork_reachable_trigger(
            "on:\n  discussion_comment:\n    types: [created]\njobs:\n  a:\n    steps: []\n"
        ));
    }

    #[test]
    fn schedule_only_is_not_reachable() {
        assert!(!has_fork_reachable_trigger(
            "on:\n  schedule:\n    - cron: '0 0 * * *'\n"
        ));
    }

    #[test]
    fn workflow_run_ingesting_fork_pr_is_escalation_reachable() {
        // The classic escalation: a second workflow triggered by workflow_run
        // runs privileged in the base repo, admits the fork-PR producer event,
        // and ingests the fork run's artifact / head_sha. No same-repo guard.
        let wf = "\
on:
  workflow_run:
    workflows: [Test]
    types: [completed]
jobs:
  fix:
    if: github.event.workflow_run.conclusion == 'failure' && github.event.workflow_run.event == 'pull_request'
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: ${{ github.event.workflow_run.id }}
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
";
        assert!(workflow_run_escalation(wf));
    }

    #[test]
    fn workflow_run_guarded_to_same_repo_is_not_escalation() {
        // A head_repository == github.repository guard means a fork PR (which
        // runs in the fork's context) never reaches the privileged consumer.
        let wf = "\
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  fix:
    if: github.event.workflow_run.head_repository.full_name == github.repository
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
";
        assert!(!workflow_run_escalation(wf));
    }

    #[test]
    fn workflow_run_for_push_producer_only_is_not_escalation() {
        // Consumer only acts on a push/release producer run, which an outside
        // contributor cannot cause; no fork PR reaches it.
        let wf = "\
on:
  workflow_run:
    workflows: [Release]
    types: [completed]
jobs:
  promote:
    if: github.event.workflow_run.event == 'push'
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
";
        assert!(!workflow_run_escalation(wf));
    }

    #[test]
    fn workflow_run_without_run_data_ingestion_is_not_escalation() {
        // A workflow_run consumer that merely comments on its own CI, never
        // checking out or downloading the fork run's data, is not our concern.
        let wf = "\
on:
  workflow_run:
    workflows: [Test]
    types: [completed]
jobs:
  notify:
    steps:
      - run: echo 'CI finished'
";
        assert!(!workflow_run_escalation(wf));
    }

    #[test]
    fn workflow_call_only_with_in_repo_agent_input_is_suppressed() {
        // A reusable workflow whose agent runs on in-repo agent files and takes
        // no attacker-controlled github.event.* input cannot be prompt-injected
        // regardless of caller, so it must be treated as not fork-exploitable.
        let wf = "\
on:
  workflow_call:
    inputs:
      agents-path:
        default: '.continue/agents'
permissions:
  contents: write
jobs:
  run-agent:
    steps:
      - run: cn -p --agent \"$AGENT_FILE\"
";
        assert!(workflow_call_only_without_untrusted_input(wf));
    }

    #[test]
    fn workflow_call_with_untrusted_input_still_fires() {
        // If a reusable workflow interpolates attacker-controlled event input,
        // it is genuinely injectable and must NOT be suppressed.
        let wf = "\
on:
  workflow_call: {}
jobs:
  run-agent:
    steps:
      - run: opencode run \"${{ github.event.comment.body }}\"
";
        assert!(!workflow_call_only_without_untrusted_input(wf));
    }

    #[test]
    fn workflow_call_with_issue_number_input_still_fires() {
        // Passing an issue/PR number as a workflow_call input implies the agent
        // fetches attacker-controlled issue/PR body by that id at runtime
        // (`gh issue view $N --json body`), an indirect untrusted-input path
        // that must NOT be suppressed.
        let wf = "\
on:
  workflow_call:
    inputs:
      issue_number:
        required: true
        type: number
jobs:
  run-agent:
    steps:
      - run: |
          gh issue view \"$ISSUE_NUMBER\" --json body > /tmp/body.txt
          claude -p \"$(cat /tmp/body.txt)\"
        env:
          ISSUE_NUMBER: ${{ inputs.issue_number }}
";
        assert!(!workflow_call_only_without_untrusted_input(wf));
    }

    #[test]
    fn workflow_call_plus_direct_fork_trigger_is_not_suppressed() {
        // workflow_call alongside a direct fork trigger is directly reachable;
        // the suppression only applies when workflow_call is the SOLE reachable
        // trigger.
        let wf = "\
on:
  workflow_call: {}
  issue_comment:
    types: [created]
jobs:
  run-agent:
    steps:
      - run: cn -p --agent agent.md
";
        assert!(!workflow_call_only_without_untrusted_input(wf));
    }

    #[test]
    fn permissions_issues_write_is_not_a_trigger() {
        let wf = "on:\n  workflow_dispatch:\npermissions:\n  issues: write\njobs:\n  a: {}\n";
        assert!(!has_fork_reachable_trigger(wf));
    }

    #[test]
    fn top_level_contents_write_is_default() {
        let wf = "permissions:\n  contents: write\njobs:\n  a:\n    steps: []\n";
        assert!(workflow_level_write(wf));
    }

    #[test]
    fn top_level_write_all_is_default() {
        assert!(workflow_level_write(
            "permissions: write-all\njobs:\n  a: {}\n"
        ));
    }

    #[test]
    fn author_gate_matches_collaborator_permission_check() {
        let gated = "on:\n  issue_comment:\njobs:\n  a:\n    steps:\n      - run: |\n          permission=$(gh api \"repos/$REPO/collaborators/$u/permission\" --jq '.permission')\n          [[ \"$permission\" == admin || \"$permission\" == write ]]\n";
        assert!(AUTHOR_GATE.is_match(gated));
    }

    #[test]
    fn author_gate_matches_repository_owner_equality() {
        assert!(AUTHOR_GATE.is_match("    if: github.actor == github.repository_owner\n"));
    }

    #[test]
    fn ghaw_compiled_membership_gate_is_recognized() {
        // A gh-aw `.lock.yml` gates its agent transitively through a
        // `pre_activation` team-membership job (two `needs` hops from the agent
        // invocation), which the per-job / whole-file author-gate scan cannot
        // see. The compiled-file marker + activation wiring must count as gated.
        let content = "\
# This file was automatically generated by gh-aw (v0.36.0). DO NOT EDIT.
on:
  issues:
    types: [opened]
jobs:
  activation:
    needs: pre_activation
    if: needs.pre_activation.outputs.activated == 'true'
  agent:
    needs: activation
    steps:
      - run: copilot --allow-all-tools --prompt \"$(cat prompt.txt)\"
  pre_activation:
    outputs:
      activated: ${{ steps.check_membership.outputs.is_team_member == 'true' }}
    steps:
      - id: check_membership
        run: node check_membership.cjs
";
        assert!(has_ghaw_membership_gate(content));
    }

    #[test]
    fn handwritten_workflow_naming_pre_activation_is_not_falsely_gated() {
        // Without the gh-aw compiled marker, merely referencing a pre_activation
        // job must NOT be treated as a membership gate, so a real ungated agent
        // is still caught.
        let content = "\
on:
  issue_comment:
    types: [created]
jobs:
  agent:
    if: contains(github.event.comment.body, '@agent')
    steps:
      - run: opencode run \"${{ github.event.comment.body }}\"
";
        assert!(!has_ghaw_membership_gate(content));
    }

    #[test]
    fn author_gate_matches_vars_allowlist() {
        assert!(AUTHOR_GATE.is_match(
            "    if: contains(vars.CLAUDE_ALLOWED_USERS, github.event.comment.user.login)\n"
        ));
    }

    #[test]
    fn author_gate_matches_reversed_contains_association() {
        assert!(AUTHOR_GATE.is_match(
            "    if: contains('MEMBER,OWNER,COLLABORATOR', github.event.comment.author_association)\n"
        ));
    }

    #[test]
    fn author_gate_matches_review_user_login_bot() {
        // A gate on the reviewer's login (only a specific bot can trigger the
        // job) is sound: a fork PR author cannot post a review authored by that
        // bot identity.
        assert!(
            AUTHOR_GATE.is_match("    if: github.event.review.user.login == 'coderabbitai[bot]'\n")
        );
    }

    #[test]
    fn workflow_run_dependabot_branch_is_not_escalation() {
        let content = concat!(
            "on:\n  workflow_run:\n    workflows: [\"CI\"]\n    types: [completed]\n",
            "jobs:\n  fix:\n    if: |\n",
            "      github.event.workflow_run.conclusion == 'failure' &&\n",
            "      startsWith(github.event.workflow_run.head_branch, 'dependabot/')\n",
            "    steps:\n      - run: echo ${{ github.event.workflow_run.head_branch }}\n"
        );
        assert!(!workflow_run_escalation(content));
    }

    #[test]
    fn workflow_run_fork_head_branch_checkout_is_escalation() {
        let content = concat!(
            "on:\n  workflow_run:\n    workflows: [\"CI\"]\n    types: [completed]\n",
            "jobs:\n  fix:\n    if: github.event.workflow_run.conclusion == 'failure'\n",
            "    steps:\n      - uses: actions/checkout@v4\n        with:\n",
            "          ref: ${{ github.event.workflow_run.head_branch }}\n"
        );
        assert!(workflow_run_escalation(content));
    }

    #[test]
    fn workflow_run_negated_dependabot_skip_is_still_escalation() {
        // `!startsWith(head_branch, 'dependabot/')` *excludes* dependabot and
        // therefore still runs on fork PR branches: it must not be mistaken for
        // a dependabot-only gate.
        let content = concat!(
            "on:\n  workflow_run:\n    workflows: [\"CI\"]\n    types: [completed]\n",
            "jobs:\n  fix:\n    if: |\n",
            "      github.event.workflow_run.conclusion == 'failure' &&\n",
            "      !startsWith(github.event.workflow_run.head_branch, 'dependabot/') &&\n",
            "      !startsWith(github.event.workflow_run.head_branch, 'renovate/')\n",
            "    steps:\n      - uses: actions/checkout@v4\n        with:\n",
            "          ref: ${{ github.event.workflow_run.head_branch }}\n"
        );
        assert!(workflow_run_escalation(content));
    }

    #[test]
    fn claude_action_bare_tag_mode_is_self_gated() {
        // claude-code-action enforces its own write-access check, so a bare
        // @claude mention workflow with no bypass input is not reachable by an
        // outside fork contributor.
        let content = concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  claude:\n",
            "    if: contains(github.event.comment.body, '@claude')\n",
            "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
            "          allowed_tools: Bash(git:*),Edit,Write\n"
        );
        let lines: Vec<&str> = content.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.contains("claude-code-action@"))
            .unwrap();
        assert!(claude_action_self_gated(content, &lines, idx));
    }

    #[test]
    fn claude_action_with_allowed_non_write_users_star_is_not_self_gated() {
        let content = concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  claude:\n    steps:\n",
            "      - uses: anthropics/claude-code-action@v1\n        with:\n",
            "          allowed_non_write_users: \"*\"\n",
            "          allowed_tools: Bash(git:*),Edit,Write\n"
        );
        let lines: Vec<&str> = content.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.contains("claude-code-action@"))
            .unwrap();
        assert!(!claude_action_self_gated(content, &lines, idx));
    }

    #[test]
    fn claude_action_with_allowed_bots_star_is_not_self_gated() {
        let content = concat!(
            "on:\n  issues:\n    types: [opened]\n",
            "jobs:\n  claude:\n    steps:\n",
            "      - uses: anthropics/claude-code-action@v1\n        with:\n",
            "          allowed_bots: \"*\"\n",
            "          claude_args: '--permission-mode auto'\n"
        );
        let lines: Vec<&str> = content.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.contains("claude-code-action@"))
            .unwrap();
        assert!(!claude_action_self_gated(content, &lines, idx));
    }

    #[test]
    fn claude_action_via_workflow_run_is_not_self_gated() {
        // On a workflow_run re-trigger the built-in write-check inspects the
        // base run's actor, not the fork PR author, so it does not defend this
        // shape and the finding must stand.
        let content = concat!(
            "on:\n  workflow_run:\n    workflows: [\"CI\"]\n    types: [completed]\n",
            "jobs:\n  fix:\n",
            "    if: github.event.workflow_run.conclusion == 'failure'\n",
            "    steps:\n      - uses: actions/checkout@v4\n        with:\n",
            "          ref: ${{ github.event.workflow_run.head_branch }}\n",
            "      - uses: anthropics/claude-code-action@v1\n        with:\n",
            "          prompt: ${{ github.event.workflow_run.head_branch }}\n"
        );
        let lines: Vec<&str> = content.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.contains("claude-code-action@"))
            .unwrap();
        assert!(!claude_action_self_gated(content, &lines, idx));
    }

    #[test]
    fn author_gate_matches_pull_request_user_login_bot_pin() {
        // Dependabot PRs always branch inside the base repo (never a fork), so
        // pinning the PR author login is a sound trust gate.
        assert!(AUTHOR_GATE
            .is_match("    if: github.event.pull_request.user.login == 'dependabot[bot]'\n"));
    }

    #[test]
    fn read_only_top_level_is_not_write() {
        assert!(!workflow_level_write(
            "permissions:\n  contents: read\njobs:\n  a: {}\n"
        ));
    }

    #[test]
    fn gitlab_mr_agent_with_write_is_reachable() {
        let ci = "review:\n  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n  script:\n    - claude -p \"$DIFF\" --dangerously-skip-permissions\n";
        assert!(gitlab_agent_reachable_and_writable(ci));
    }

    #[test]
    fn gitlab_fork_guard_suppresses() {
        let ci = "review:\n  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\" && $CI_MERGE_REQUEST_SOURCE_PROJECT_ID != $CI_PROJECT_ID'\n      when: never\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n  script:\n    - claude -p \"$DIFF\" --dangerously-skip-permissions\n";
        assert!(!gitlab_agent_reachable_and_writable(ci));
    }

    #[test]
    fn gitlab_readonly_tools_suppress() {
        let ci = "review:\n  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n  script:\n    - claude -p \"review\" --allowedTools \"Read,Grep,Glob\"\n";
        assert!(!gitlab_agent_reachable_and_writable(ci));
    }

    #[test]
    fn gitlab_job_token_only_is_not_write() {
        let ci = "review:\n  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n  script:\n    - export TOKEN=$CI_JOB_TOKEN\n    - aider --message \"$DIFF\"\n";
        assert!(!gitlab_agent_reachable_and_writable(ci));
    }

    #[test]
    fn gitlab_plan_mode_with_posting_token_is_not_write() {
        let ci = "review:\n  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n  script:\n    - claude -p \"review\" --permission-mode plan < diff.patch\n    - curl --header \"PRIVATE-TOKEN: $GITLAB_API_TOKEN\" --form body=@review.md \"$CI_API_V4_URL/notes\"\n";
        assert!(!gitlab_agent_reachable_and_writable(ci));
    }

    #[test]
    fn gitlab_plan_mode_with_git_push_still_fires() {
        let ci = "review:\n  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n  script:\n    - claude -p \"fix\" --permission-mode plan\n    - git push origin HEAD\n";
        assert!(gitlab_agent_reachable_and_writable(ci));
    }

    #[test]
    fn job_guard_excluding_pull_request_suppresses() {
        let wf = "on:\n  pull_request:\njobs:\n  update:\n    if: github.event_name != 'pull_request'\n    steps:\n      - run: opencode run \"$DIFF\"\n";
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("opencode")).unwrap();
        assert!(job_gated_on_non_fork_event(&lines, idx));
    }

    #[test]
    fn job_guard_requiring_merge_suppresses() {
        let wf = "on:\n  pull_request:\n    types: [closed]\njobs:\n  release:\n    if: github.event.pull_request.merged == true\n    steps:\n      - run: opencode run \"$PROMPT\"\n";
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("opencode")).unwrap();
        assert!(job_gated_on_non_fork_event(&lines, idx));
    }

    #[test]
    fn merge_and_chain_naming_the_trigger_still_suppresses() {
        // `event_name == 'pull_request_target' && ... && merged == true` is a
        // pure AND: the merge requirement is decisive even though the trigger
        // name appears in the guard (which the generic OR detector keys on).
        let wf = concat!(
            "on:\n  pull_request_target:\n    types: [closed]\n",
            "jobs:\n  index:\n    if: >\n",
            "      github.event_name == 'pull_request_target' &&\n",
            "      github.event.action == 'closed' &&\n",
            "      github.event.pull_request.merged == true\n",
            "    steps:\n      - run: opencode run \"$PROMPT\"\n"
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("opencode")).unwrap();
        assert!(job_gated_on_non_fork_event(&lines, idx));
    }

    #[test]
    fn merge_or_disjunct_readmitting_fork_does_not_suppress() {
        // A `||` disjunct re-admits a bare fork event without the merge, so the
        // guard is not sound and must not suppress.
        let wf = concat!(
            "on:\n  pull_request_target:\n",
            "jobs:\n  index:\n    if: >\n",
            "      github.event.pull_request.merged == true ||\n",
            "      github.event_name == 'pull_request_target'\n",
            "    steps:\n      - run: opencode run \"$PROMPT\"\n"
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("opencode")).unwrap();
        assert!(!job_gated_on_non_fork_event(&lines, idx));
    }

    #[test]
    fn transitive_merge_gate_fan_out_suppresses() {
        // A matrix "write" job that runs only when a merge-gated "resolve" job
        // produced output is transitively maintainer-only.
        let wf = concat!(
            "on:\n  pull_request_target:\n    types: [closed]\n",
            "jobs:\n  resolve:\n    if: >\n",
            "      github.event.action == 'closed' &&\n",
            "      github.event.pull_request.merged == true\n",
            "    outputs:\n      origins: ${{ steps.parse.outputs.origins }}\n",
            "    steps:\n      - id: parse\n        run: echo 'origins=[\"1\"]' >> $GITHUB_OUTPUT\n",
            "  write:\n    needs: resolve\n    if: ${{ needs.resolve.outputs.origins != '[]' }}\n",
            "    steps:\n      - run: opencode run \"$PROMPT\"\n"
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("opencode")).unwrap();
        assert!(job_gated_by_transitive_non_fork_event(&lines, idx));
    }

    #[test]
    fn job_guard_admitting_pull_request_does_not_suppress() {
        let wf = "on:\n  pull_request:\njobs:\n  review:\n    if: github.event_name == 'pull_request'\n    steps:\n      - run: opencode run \"$DIFF\"\n";
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("opencode")).unwrap();
        assert!(!job_gated_on_non_fork_event(&lines, idx));
    }

    #[test]
    fn job_guard_or_of_events_including_pr_does_not_suppress() {
        let wf = "on:\n  pull_request:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  review:\n    if: github.event_name == 'pull_request' || github.event_name == 'schedule'\n    steps:\n      - run: opencode run \"$DIFF\"\n";
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("opencode")).unwrap();
        assert!(!job_gated_on_non_fork_event(&lines, idx));
    }

    #[test]
    fn disabled_job_is_suppressed() {
        let wf = "on:\n  issues:\njobs:\n  triage:\n    if: false\n    steps:\n      - run: opencode run \"$BODY\"\n";
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("opencode")).unwrap();
        assert!(job_gated_on_non_fork_event(&lines, idx));
    }

    #[test]
    fn disabled_sibling_job_does_not_suppress_active_agent_job() {
        let wf = "on:\n  issue_comment:\njobs:\n  agent:\n    if: contains(github.event.comment.body, '@bot')\n    steps:\n      - run: cursor-agent \"$PROMPT\"\n  old:\n    if: false\n    steps:\n      - run: echo disabled\n";
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.contains("cursor-agent"))
            .unwrap();
        assert!(!job_gated_on_non_fork_event(&lines, idx));
    }

    #[test]
    fn transitive_permission_gate_via_job_output_suppresses() {
        // The agent-bearing (or reusable-workflow-calling) job runs only if an
        // upstream permission-check job approved the actor.
        let wf = concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n",
            "  check-permission:\n    runs-on: ubuntu-latest\n",
            "    outputs:\n      allowed: ${{ steps.p.outputs.allowed }}\n",
            "    steps:\n      - id: p\n        uses: ./.github/actions/check-permission\n",
            "        with:\n          allowed-users: alice|bob\n",
            "  handle:\n    needs: check-permission\n",
            "    if: needs.check-permission.outputs.allowed == 'true'\n",
            "    uses: ./.github/workflows/agent.yaml\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("agent.yaml")).unwrap();
        assert!(job_gated_by_permission_check(&lines, idx));
    }

    #[test]
    fn transitive_json_output_allowlist_gate_suppresses() {
        // A check job returns a struct and the agent job reads a qualification
        // field off it (`fromJSON(needs.check.outputs.result).qualifiedMention`),
        // while the check computes it from a committed allow-list of logins.
        let wf = concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n",
            "  check-mention:\n    runs-on: ubuntu-latest\n",
            "    outputs:\n      result: ${{ steps.check.outputs.result }}\n",
            "    steps:\n      - id: check\n        uses: actions/github-script@v6\n",
            "        with:\n          script: |\n",
            "            const allowedUsers = ['alice','bob'];\n",
            "            const isAllowed = allowedUsers.includes(context.payload.comment.user.login);\n",
            "            return { qualifiedMention: isAllowed };\n",
            "  respond:\n    needs: check-mention\n",
            "    if: fromJSON(needs.check-mention.outputs.result).qualifiedMention == true\n",
            "    permissions:\n      contents: write\n",
            "    steps:\n      - run: claude -p \"$P\" --allowedTools \"Bash(git:*)\"\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("claude -p")).unwrap();
        assert!(job_gated_by_permission_check(&lines, idx));
    }

    #[test]
    fn transitive_label_gate_suppresses() {
        // A prepare job derives a boolean from the PR's labels and the agent job
        // runs only when it is set. Labels are maintainer-controlled, so a fork
        // contributor cannot reach the agent (assayer pattern).
        let wf = concat!(
            "on:\n  pull_request:\n    types: [opened, labeled]\n",
            "jobs:\n",
            "  prepare:\n    outputs:\n      should_run: ${{ steps.gate.outputs.should_run }}\n",
            "    steps:\n      - id: gate\n        run: |\n",
            "          LABELS=$(gh api \"repos/$R/pulls/$N\" | jq -c '[.labels[].name]')\n",
            "          if echo \"$LABELS\" | jq -e 'any(.[]; . == \"approved\")'; then\n",
            "            echo should_run=true >> \"$GITHUB_OUTPUT\"\n          fi\n",
            "  agent:\n    needs: prepare\n",
            "    if: needs.prepare.outputs.should_run == 'true'\n",
            "    permissions:\n      contents: write\n",
            "    steps:\n      - run: claude -p \"$DIFF\" --dangerously-skip-permissions\n",
        );
        assert!(has_transitive_label_gate(wf));
    }

    #[test]
    fn build_status_output_gate_is_not_a_label_gate() {
        // A `should_run` output derived from a changed-files check, not labels,
        // is a build-status gate and must not be mistaken for authorization.
        let wf = concat!(
            "on:\n  pull_request:\n",
            "jobs:\n",
            "  prepare:\n    outputs:\n      should_run: ${{ steps.diff.outputs.changed }}\n",
            "    steps:\n      - id: diff\n        run: echo changed=true >> \"$GITHUB_OUTPUT\"\n",
            "  agent:\n    needs: prepare\n    if: needs.prepare.outputs.should_run == 'true'\n",
            "    steps:\n      - run: claude -p \"$DIFF\" --dangerously-skip-permissions\n",
        );
        assert!(!has_transitive_label_gate(wf));
    }

    #[test]
    fn calls_reusable_workflow_matches_local_and_bare_paths() {
        let local = "jobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n";
        let bare = "jobs:\n  a:\n    uses: .github/workflows/agent.yml\n";
        let pinned = "jobs:\n  a:\n    uses: ./.github/workflows/agent.yml@main\n";
        let remote = "jobs:\n  a:\n    uses: other/repo/.github/workflows/agent.yml@v1\n";
        let unrelated = "jobs:\n  a:\n    uses: ./.github/workflows/other.yml\n";
        assert!(calls_reusable_workflow(local, "agent.yml"));
        assert!(calls_reusable_workflow(bare, "agent.yml"));
        assert!(calls_reusable_workflow(pinned, "agent.yml"));
        assert!(!calls_reusable_workflow(remote, "agent.yml"));
        assert!(!calls_reusable_workflow(unrelated, "agent.yml"));
    }

    #[test]
    fn indirect_author_association_gate_suppresses() {
        // author_association captured to an env var, then compared to trusted
        // roles in an inline script with a rejecting branch.
        let wf = concat!(
            "env:\n  ACTOR_ASSOCIATION: ${{ github.event.comment.author_association }}\n",
            "run: |\n",
            "  const association = process.env.ACTOR_ASSOCIATION;\n",
            "  if (association !== 'OWNER' && association !== 'MEMBER') return;\n",
        );
        assert!(has_indirect_author_association_gate(wf));
    }

    #[test]
    fn author_association_echoed_without_role_compare_is_not_a_gate() {
        // The association is only surfaced in a comment/log, never used to gate.
        let wf = concat!(
            "env:\n  ASSOC: ${{ github.event.comment.author_association }}\n",
            "run: echo \"comment by $ASSOC\"\n",
        );
        assert!(!has_indirect_author_association_gate(wf));
    }

    #[test]
    fn step_level_allowlist_gate_suppresses() {
        // Every write/agent step is gated on a same-job allow-list check step's
        // output: a fork drive-by is not in the
        // hardcoded whitelist, so the gated steps never run for it.
        let wf = concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  agent:\n    permissions:\n      contents: write\n",
            "    steps:\n",
            "      - id: whitelist\n        uses: actions/github-script@v7\n",
            "        with:\n          script: |\n",
            "            const whitelist = ['alice','bob'];\n",
            "            core.setOutput('authorized', whitelist.includes(context.actor) ? 'true' : 'false');\n",
            "      - name: Run agent\n        if: steps.whitelist.outputs.authorized == 'true'\n",
            "        run: opencode run \"${{ github.event.comment.body }}\"\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("opencode")).unwrap();
        assert!(job_gated_by_step_permission_check(&lines, idx));
    }

    #[test]
    fn step_level_build_status_gate_does_not_suppress() {
        // A `if: steps.build.outputs.changed` step gate is a build-status gate,
        // not an authorization gate, so the agent step must still fire.
        let wf = concat!(
            "on:\n  issue_comment:\n",
            "jobs:\n  agent:\n    permissions:\n      contents: write\n",
            "    steps:\n",
            "      - id: build\n        run: echo changed=true >> $GITHUB_OUTPUT\n",
            "      - if: steps.build.outputs.changed == 'true'\n",
            "        run: opencode run \"$DIFF\"\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("opencode")).unwrap();
        assert!(!job_gated_by_step_permission_check(&lines, idx));
    }

    #[test]
    fn step_output_check_user_script_gate_suppresses() {
        // The agent step is gated on an output produced by a script that checks
        // the comment author against a config allowlist (roboportal pattern):
        // `parse-config.ts --check-user "$AUTHOR" >> $GITHUB_OUTPUT`.
        let wf = concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  agent:\n    permissions:\n      contents: write\n",
            "    steps:\n",
            "      - id: auth\n        env:\n          AUTHOR: ${{ github.event.comment.user.login }}\n",
            "        run: npx tsx parse-config.ts --check-user \"$AUTHOR\" >> \"$GITHUB_OUTPUT\"\n",
            "      - name: Run Claude Code\n        if: steps.auth.outputs.authorized == 'true'\n",
            "        uses: anthropics/claude-code-base-action@beta\n",
            "        with:\n          allowed_tools: \"Read,Write,Edit\"\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.contains("claude-code"))
            .unwrap();
        assert!(job_gated_by_step_permission_check(&lines, idx));
    }

    #[test]
    fn failclosed_actor_allowlist_guard_suppresses() {
        // A github-script guard step aborts the whole job (core.setFailed) when
        // the actor is not in the allowlist secret (bananayong pattern). Every
        // later step, including the agent, is only reachable for allowlisted
        // actors, so a fork drive-by never runs it.
        let wf = concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  agent:\n    permissions:\n      contents: write\n",
            "    steps:\n",
            "      - id: allowlist\n        uses: actions/github-script@v7\n",
            "        env:\n          ALLOWED_ACTORS: ${{ secrets.AGENT_ALLOWED_ACTORS }}\n",
            "        with:\n          script: |\n",
            "            const allowed = new Set((process.env.ALLOWED_ACTORS||'').split(','));\n",
            "            if (!allowed.has(context.actor)) { core.setFailed('not allowlisted'); }\n",
            "      - name: Run agent\n        uses: anthropics/claude-code-action@v1\n",
            "        with:\n          allowed_tools: \"Bash(git:*)\"\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.contains("claude-code-action"))
            .unwrap();
        assert!(job_gated_by_failclosed_allowlist(&lines, idx));
    }

    #[test]
    fn plain_agent_job_is_not_a_failclosed_allowlist() {
        // No actor-membership guard and no fail-closed abort: the agent job is
        // fork-reachable and must not be mistaken for a gated one.
        let wf = concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  agent:\n    permissions:\n      contents: write\n",
            "    steps:\n",
            "      - uses: anthropics/claude-code-action@v1\n",
            "        with:\n          allowed_tools: \"Bash(git:*)\"\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.contains("claude-code-action"))
            .unwrap();
        assert!(!job_gated_by_failclosed_allowlist(&lines, idx));
    }

    #[test]
    fn or_gate_bypass_ungated_review_disjunct_is_detected() {
        // The job `if:` ORs an author-gated comment branch with an ungated
        // `pull_request_review` + `changes_requested` branch. The review branch
        // is fork-reachable (a second account can request changes on a PR), so
        // the whole-file author gate must not mask it.
        let wf = concat!(
            "on:\n  pull_request_review:\n    types: [submitted]\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  auto-fix:\n    if: >-\n",
            "      (github.event_name == 'pull_request_review' && github.event.review.state == 'changes_requested') ||\n",
            "      (github.event_name == 'issue_comment' && contains(github.event.comment.body, '/fix') &&\n",
            "       contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.comment.author_association))\n",
            "    steps:\n      - run: claude -p \"$P\" --dangerously-skip-permissions\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("claude")).unwrap();
        assert!(job_has_ungated_review_bypass(&lines, idx));
    }

    #[test]
    fn author_gated_review_disjunct_is_not_a_bypass() {
        // The `pull_request_review` branch carries its own author_association
        // check, so it is not an open branch and must not be flagged.
        let wf = concat!(
            "on:\n  pull_request_review:\n    types: [submitted]\n",
            "jobs:\n  auto-fix:\n    if: >-\n",
            "      github.event.review.state == 'changes_requested' &&\n",
            "      contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), github.event.review.author_association)\n",
            "    steps:\n      - run: claude -p \"$P\" --dangerously-skip-permissions\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("claude")).unwrap();
        assert!(!job_has_ungated_review_bypass(&lines, idx));
    }

    #[test]
    fn review_disjunct_with_fork_exclusion_is_not_a_bypass() {
        // A same-repo fork-exclusion on the review branch closes it to forks.
        let wf = concat!(
            "on:\n  pull_request_review:\n    types: [submitted]\n",
            "jobs:\n  fix:\n    if: >-\n",
            "      github.event.review.state == 'changes_requested' &&\n",
            "      !github.event.pull_request.head.repo.fork\n",
            "    steps:\n      - run: claude -p \"$P\" --dangerously-skip-permissions\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("claude")).unwrap();
        assert!(!job_has_ungated_review_bypass(&lines, idx));
    }

    #[test]
    fn bare_pull_request_disjunct_beside_gated_sibling_is_a_bypass() {
        // The `pull_request` disjunct is bare (no further condition), so any fork
        // can open a PR and reach the write-capable job even though the
        // issue_comment sibling is properly author-gated (dcc-v2 pattern).
        let wf = concat!(
            "on:\n  pull_request:\n    types: [opened]\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  review:\n    if: |\n",
            "      (github.event_name == 'pull_request') ||\n",
            "      (github.event_name == 'issue_comment' && contains(github.event.comment.body, '@claude') &&\n",
            "       contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), github.event.comment.author_association))\n",
            "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          claude_args: \"--permission-mode bypassPermissions\"\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.contains("claude_args"))
            .unwrap();
        assert!(job_has_ungated_review_bypass(&lines, idx));
    }

    #[test]
    fn qualified_pull_request_disjunct_is_not_a_bare_bypass() {
        // The `pull_request` disjunct carries a same-repo guard, so it is not
        // bare and must not be treated as a bypass.
        let wf = concat!(
            "on:\n  pull_request:\n  issue_comment:\n",
            "jobs:\n  review:\n    if: |\n",
            "      (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository) ||\n",
            "      (github.event_name == 'issue_comment' && contains(fromJSON('[\"OWNER\"]'), github.event.comment.author_association))\n",
            "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          claude_args: \"--permission-mode bypassPermissions\"\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.contains("claude_args"))
            .unwrap();
        assert!(!job_has_ungated_review_bypass(&lines, idx));
    }

    #[test]
    fn lone_bare_pull_request_without_or_is_not_a_bypass_override() {
        // A single bare `pull_request` gate with no OR is already ungated by the
        // whole-file path; the override must not claim it (needs a real OR).
        let wf = concat!(
            "on:\n  pull_request:\n",
            "jobs:\n  review:\n    if: github.event_name == 'pull_request'\n",
            "    steps:\n      - run: claude -p \"$P\" --dangerously-skip-permissions\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("claude")).unwrap();
        assert!(!job_has_ungated_review_bypass(&lines, idx));
    }

    #[test]
    fn bare_job_output_gate_without_permission_wiring_does_not_suppress() {
        // A `needs.build.outputs.changed == 'true'` guard is a build gate, not
        // an authorization gate: with no permission wiring in the file it must
        // not be mistaken for one.
        let wf = concat!(
            "on:\n  pull_request:\n",
            "jobs:\n",
            "  build:\n    outputs:\n      changed: ${{ steps.d.outputs.changed }}\n",
            "    steps:\n      - id: d\n        run: echo changed=true >> $GITHUB_OUTPUT\n",
            "  agent:\n    needs: build\n",
            "    if: needs.build.outputs.changed == 'true'\n",
            "    steps:\n      - run: opencode run \"$DIFF\"\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("opencode")).unwrap();
        assert!(!job_gated_by_permission_check(&lines, idx));
    }

    #[test]
    fn permission_wiring_without_output_gate_on_agent_job_does_not_suppress() {
        // The file contains a permission check, but the agent job does NOT
        // depend on its output -- so the agent is still reachable and must fire.
        let wf = concat!(
            "on:\n  issue_comment:\n",
            "jobs:\n",
            "  check-permission:\n    steps:\n      - uses: ./.github/actions/check-permission\n",
            "        with:\n          allowed-users: alice\n",
            "  agent:\n    steps:\n      - run: opencode run \"$DIFF\"\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("opencode")).unwrap();
        assert!(!job_gated_by_permission_check(&lines, idx));
    }

    #[test]
    fn gitlab_manual_only_mr_job_is_gated() {
        // The sole MR-event rule carries `when: manual`, so an outside fork
        // contributor cannot auto-run the agent.
        let wf = concat!(
            "review:\n",
            "  rules:\n",
            "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
            "      when: manual\n",
            "  script:\n",
            "    - claude -p \"/review-mr ${CI_MERGE_REQUEST_IID}\" --dangerously-skip-permissions\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("claude -p")).unwrap();
        assert!(gitlab_job_is_manual_gated(&lines, idx));
    }

    #[test]
    fn gitlab_manual_rule_plus_auto_comment_rule_is_not_gated() {
        // One rule is manual, but a second rule auto-runs on a commit-message
        // match (`@opencode`) that a fork contributor controls.
        let wf = concat!(
            "opencode-review:\n",
            "  rules:\n",
            "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
            "      when: manual\n",
            "      allow_failure: true\n",
            "    - if: $CI_COMMIT_MESSAGE =~ /@opencode/\n",
            "  script:\n",
            "    - opencode run \"review this\" --agent qa\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.contains("opencode run"))
            .unwrap();
        assert!(!gitlab_job_is_manual_gated(&lines, idx));
    }

    #[test]
    fn gitlab_bare_mr_rule_without_when_is_not_gated() {
        // A `when: manual` on a sibling deploy rule does not gate the agent job,
        // whose MR rule defaults to on_success and thus auto-runs.
        let wf = concat!(
            "agent:\n",
            "  rules:\n",
            "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
            "    - if: '$CI_COMMIT_TAG'\n",
            "      when: manual\n",
            "  script:\n",
            "    - claude -p \"$CI_MERGE_REQUEST_IID\" --dangerously-skip-permissions\n",
        );
        let lines: Vec<&str> = wf.lines().collect();
        let idx = lines.iter().position(|l| l.contains("claude -p")).unwrap();
        assert!(!gitlab_job_is_manual_gated(&lines, idx));
    }
}

//! GitLab CI agent rule. A `.gitlab-ci.yml` job that runs a coding agent on
//! merge-request content with write/exec capability and no fork guard.
//!
//! GitLab's fork-pipeline model means the parent's protected variables are
//! never injected into a fork merge-request pipeline, so this is scored HIGH
//! rather than CRITICAL: final exploitability also depends on project settings
//! (whether the token is Protected, branch protection, who may push a branch)
//! that are not visible in the file. The rule fires on the dangerous,
//! file-visible shape and the remediation explains the settings side.

use super::metadata::REPO_MUTATION_HIGH;
use super::{Family, RuleSpec, Severity};
use std::sync::LazyLock;

/// Keeps a bare agent name from matching unrelated tooling: the file must
/// reference a known agent CLI or its provider auth, the same proof approach
/// the installed-agent family uses. Built on the linear `regex` engine (the one
/// lookbehind, `(?<![\w-])aider`, is rewritten as `(?:^|[^\w-])aider`) so a
/// large generated `.gitlab-ci.yml` cannot trigger catastrophic backtracking.
static PROOF: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?i)@anthropic-ai/claude-code|claude\.ai/install|ANTHROPIC_API_?KEY|CLAUDE_CODE|claude\s+-p\b|@openai/codex|codex\s+exec|aider-chat|(?:^|[^\w-])aider\b|cursor\.com/install|cursor-agent|CURSOR_API_?KEY|qwen-code|@qwen-code|opencode\s+run|block/goose|goose\s+run|@google/gemini-cli|gemini\s+--yolo|GEMINI_API_?KEY|--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--permission-mode[\s=]+["']?(?:bypassPermissions|acceptEdits|auto)"#,
    )
    .unwrap()
});

const REC: &str = "A merge-request pipeline runs in the context that owns the agent's write credentials, so an untrusted diff can drive the agent via prompt injection. Gate the job against fork sources (add a rule: if $CI_MERGE_REQUEST_SOURCE_PROJECT_ID != $CI_PROJECT_ID with when: never), restrict the agent to read-only tools (for example --allowedTools \"Read,Grep,Glob\") when it only reviews, mark the API/personal access token as Protected so it is never exposed to fork pipelines, and never embed the token in the agent prompt. Treat the merge-request diff, title, and description as untrusted data.";

pub fn rules() -> Vec<RuleSpec> {
    vec![agent_with_write_or_exec()]
}

fn agent_with_write_or_exec() -> RuleSpec {
    RuleSpec {
        id: "fork_reachable_gitlab_ci_agent_with_write_or_exec",
        severity: Severity::High,
        title: "Fork-reachable GitLab CI coding agent with write or execute capability",
        anchor: crate::rules::compile_anchor(
            r#"(?:^|[\s;&|])(?:claude\s+(?:--\S+\s+)*-p\b|codex\s+exec\b|aider\b|cursor-agent\b|qwen\b[^\n]*\s-p\b|opencode\s+run\b|goose\s+run\b|gemini\b[^\n]*--yolo\b|gemini\b[^\n]*--approval-mode[\s=]+["']?(?:yolo|auto_edit))"#,
        ),
        family: Family::Gitlab { proof: &PROOF },
        metadata: REPO_MUTATION_HIGH,
        recommendation: REC,
        positive_examples: POSITIVE,
        negative_examples: NEGATIVE,
    }
}

/// Synthetic merge-request pipelines that must fire exactly once. No values are
/// copied from real repositories; every project path, token name, and prompt is
/// invented for the fixture.
static POSITIVE: &[&str] = &[
    // acceptEdits + Bash/Write tool grant, token posts back to the API.
    concat!(
        "stages:\n  - review\n",
        "ai-review:\n  stage: review\n  image: node:22\n",
        "  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
        "  script:\n",
        "    - npm install -g @anthropic-ai/claude-code\n",
        "    - |\n",
        "      claude -p \"Review MR !${CI_MERGE_REQUEST_IID} and post a note using PRIVATE-TOKEN $REVIEW_TOKEN\" \\\n",
        "        --permission-mode acceptEdits \\\n",
        "        --allowedTools \"Bash Read Edit Write\"\n",
    ),
    // dangerously-skip-permissions on the raw diff, git push write sink.
    concat!(
        "codex-fix:\n",
        "  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
        "  script:\n",
        "    - npm i -g @openai/codex\n",
        "    - git diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME...HEAD > diff.patch\n",
        "    - codex exec --full-auto \"$(cat diff.patch)\"\n",
        "    - git push origin HEAD\n",
    ),
    // Codex raw bypass flag on merge-request content, token posts back.
    concat!(
        "codex-review:\n",
        "  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
        "  script:\n",
        "    - npm -g i @openai/codex\n",
        "    - codex exec --dangerously-bypass-approvals-and-sandbox \"Review MR !${CI_MERGE_REQUEST_IID} and post with $REVIEW_API_TOKEN\"\n",
    ),
    // Gemini CLI in --yolo mode on merge-request title/description.
    concat!(
        "gemini-review:\n",
        "  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
        "  script:\n",
        "    - npm i -g @google/gemini-cli\n",
        "    - export TITLE=\"$CI_MERGE_REQUEST_TITLE\"\n",
        "    - gemini --yolo --prompt \"Review: $TITLE\"\n",
        "    - 'curl --header \"PRIVATE-TOKEN: $REVIEW_TOKEN\" --data body=done \"$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes\"'\n",
    ),
];

/// Synthetic pipelines that must not fire. Each carries a single, file-visible
/// reason it is safe: a fork guard, read-only tools, or a fork-scoped job token.
static NEGATIVE: &[&str] = &[
    // Explicit fork guard: fork-sourced merge requests are refused.
    concat!(
        "codex-review:\n",
        "  rules:\n",
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\" && $CI_MERGE_REQUEST_SOURCE_PROJECT_ID != $CI_PROJECT_ID'\n",
        "      when: never\n",
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
        "  script:\n",
        "    - npm i -g @openai/codex\n",
        "    - codex exec --full-auto \"review this\"\n",
    ),
    // Read-only tool grant: the agent cannot mutate the repo.
    concat!(
        "claude-review:\n",
        "  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
        "  script:\n",
        "    - npm install -g @anthropic-ai/claude-code\n",
        "    - claude -p \"Review MR !${CI_MERGE_REQUEST_IID}\" --allowedTools \"Read,Grep,Glob\"\n",
    ),
    // Fork-scoped CI_JOB_TOKEN only, no dangerous capability.
    concat!(
        "aider-review:\n",
        "  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
        "  script:\n",
        "    - export GITLAB_URL=$CI_API_V4_URL\n",
        "    - export TOKEN=$CI_JOB_TOKEN\n",
        "    - aider --message \"summarize MR !${CI_MERGE_REQUEST_IID}\"\n",
    ),
    // Plan (read-only) mode: the posting-back token is only a review comment.
    concat!(
        "claude-review:\n",
        "  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
        "  script:\n",
        "    - npm install -g @anthropic-ai/claude-code\n",
        "    - claude -p \"Review MR !${CI_MERGE_REQUEST_IID}\" --permission-mode plan < diff.patch > review.md\n",
        "    - 'curl --header \"PRIVATE-TOKEN: $GITLAB_API_TOKEN\" --form body=@review.md \"$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes\"'\n",
    ),
];

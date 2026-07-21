//! Action-based rules: an agent action/CLI configured to open itself to fork
//! contributors (`allowed_non_write_users: "*"`, a write sandbox, YOLO/auto
//! approval). All share the [`Family::Action`] post-filter. Ported from the
//! four `fork_triggerable_ai_agent_*` / `..._gemini_or_copilot_...` /
//! `..._codex_...` rules in `ai_ml_security.yml`.

use super::metadata::{RCE_CRITICAL, REPO_MUTATION_HIGH};
use super::{Family, Finding, RuleSpec, Severity};

const REC_EXEC: &str = "Do not open an AI agent to fork contributors (allowed_non_write_users / allowed_bots \"*\") while granting shell or file-write tools in a job that can write to the repository. Gate the job on repository write access (author_association in OWNER/MEMBER/COLLABORATOR or getCollaboratorPermissionLevel), run the agent read-only, and hand its output to a separate reviewed job for any commit. Treat the PR diff and any in-tree agent policy files as untrusted data.";

const REC_GH: &str = "Do not open an AI agent to fork contributors while granting repository-mutating GitHub tools (gh pr/issue write verbs or MCP write verbs). Gate the job on repository write access and scope the agent's tools to read-only. Treat PR/issue content as untrusted data.";

const REC_CODEX: &str = "Do not run OpenAI Codex on untrusted PR/issue content with a writable sandbox (danger-full-access / workspace-write / --full-auto / approval-policy never) in a job that can write to the repository. Use a read-only sandbox, keep safety-strategy drop-sudo, and gate the job on repository write access. Split privilege so any write happens in a separate non-AI job.";

#[allow(clippy::too_many_arguments)]
fn action(
    id: &'static str,
    severity: Severity,
    title: &'static str,
    anchor: &str,
    metadata: super::metadata::Metadata,
    recommendation: &'static str,
    positive_examples: &'static [&'static str],
    negative_examples: &'static [&'static str],
) -> RuleSpec {
    RuleSpec {
        id,
        severity,
        title,
        anchor: crate::rules::compile_anchor(anchor),
        family: Family::Action,
        metadata,
        recommendation,
        positive_examples,
        negative_examples,
    }
}

pub fn rules() -> Vec<RuleSpec> {
    vec![
        write_or_exec_tools(),
        repo_mutating_gh_tools(),
        gemini_or_copilot(),
        codex(),
        junie(),
        bonk(),
        cogni(),
        letta(),
        code_agent(),
        ai_refactor(),
        a5c(),
        iflow(),
        sweep(),
        pr_agent(),
    ]
}

fn write_or_exec_tools() -> RuleSpec {
    action(
        "fork_triggerable_ai_agent_with_write_or_exec_tools",
        Severity::Critical,
        "Fork-triggerable AI coding agent granted shell / write tools in a privileged CI job",
        r#"(?m)(?:^\s*allowed_(?:non_write_users|bots)\s*:\s*["']?\*["']?(?:(?!allowed_(?:non_write_users|bots)|^\s*-?\s*(?:uses|name)\s*:|^\s{0,6}\w[\w-]*\s*:\s*$)[\s\S]){0,12000}?(?<!dis)allowed[_-]?[Tt]ools[\s=:]+(?:(?!disallowedTools|allowed_(?:non_write_users|bots)|(?:direct_|system_|user_)?prompt\s*:|^\s*\w[\w-]*\s*:\s*(?:[|>]|["']|$))[\s\S]){0,400}?(?:\bBash\b(?!\s*\()|\bBash\(\s*\*\s*\)|\bBash\(\s*(?:gh\s*:\s*\*|gh\s+api\b|git\s*:\s*\*|git\s+(?:add|commit|push|branch|checkout|rebase|reset|tag|merge|clone|remote)\b|(?:ba)?sh\b|zsh\b|python[0-9.]*\b|node\b|npm\b|pnpm\b|yarn\b|npx\b|pip[0-9]*\b|ruby\b|perl\b|go\b|curl\b|wget\b|eval\b|exec\b|chmod\b|cp\b|mv\b|mkdir\b|rm\b|tee\b|echo\b|cat\s*>|\.?/|~/)|(?<![\w(])(?-i:MultiEdit|NotebookEdit|EditFile|WriteFile|Edit|Write)(?:\([^)]*\))?(?![\w]))|anthropics/claude-code-(?:base-)?action@(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,4000}?"allowedTools"\s*:\s*\[(?:(?!\]|allowed_(?:non_write_users|bots))[\s\S]){0,400}?(?:"\s*Bash\s*"|"\s*Edit\s*"|"\s*Write\s*"|"\s*MultiEdit\s*"|"\s*NotebookEdit\s*")|anthropics/claude-code-(?:base-)?action@(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,4000}?claude_args\s*:(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,400}?(?:--permission-mode[\s=]+['"]?(?:bypassPermissions|acceptEdits|auto)|--dangerously-skip-permissions)|anthropics/claude-code-(?:base-)?action@(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,4000}?(?<!dis)allowed[_-]?[Tt]ools\s*:(?:(?!disallowedTools|(?:direct_|system_|user_)?prompt\s*:|^\s*-?\s*(?:uses|name)\s*:|^\s{0,10}\w[\w-]*\s*:\s*(?:[|>]|["']|$|\S))[\s\S]){0,1200}?(?:\bBash\b(?!\s*\()|\bBash\(\s*\*\s*\)|\bBash\(\s*(?:gh\s*:\s*\*|gh\s+api\b|git\s*:\s*\*|git\s+(?:add|commit|push|branch|checkout|rebase|reset|tag|merge|clone|remote)\b|(?:ba)?sh\b|zsh\b|python[0-9.]*\b|node\b|npm\b|pnpm\b|yarn\b|npx\b|pip[0-9]*\b|ruby\b|perl\b|go\b|curl\b|wget\b|eval\b|exec\b|chmod\b|cp\b|mv\b|mkdir\b|rm\b|tee\b|echo\b|cat\s*>|\.?/|~/)|(?<![\w(])(?-i:MultiEdit|NotebookEdit|EditFile|WriteFile|Edit|Write)(?:\([^)]*\))?(?![\w])|mcp__[a-z_]*__(?:create|add|update|delete|merge|push|commit|apply)_)|anthropics/claude-code-(?:base-)?action@(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,4000}?^\s*settings\s*:\s*[|>](?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,1600}?"allow"\s*:\s*\[(?:(?!\][\s\S]{0,40}?\})[\s\S]){0,800}?"\s*(?:Bash(?:\(\s*\*\s*\))?|Bash\(\s*(?:gh\s+api\b|git\s*:\s*\*|git\s+(?:add|commit|push|branch|checkout|rebase|reset|tag|merge|clone|remote)\b|(?:ba)?sh\b|zsh\b|python[0-9.]*\b|node\b|npm\b|pnpm\b|yarn\b|npx\b|pip[0-9]*\b|ruby\b|perl\b|go\b|curl\b|wget\b|eval\b|exec\b|chmod\b|cp\b|mv\b|mkdir\b|rm\b|tee\b|cat\s*>|\.?/|~/)|MultiEdit|NotebookEdit|Edit|Write)(?:\([^"]*\))?\s*"|anthropics/claude-code-(?:base-)?action@(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,4000}?claude_args\s*:(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,600}?--allowed-?tools[\s=]+['"][^'"]*?(?:\bBash(?![\w(])|\bBash\(\s*\*\s*\)|\bBash\(\s*(?:gh\s+api\b|git\s*:\s*\*|git\s+(?:add|commit|push|branch|checkout|rebase|reset|tag|merge|clone|remote)\b|(?:ba)?sh\b|zsh\b|python[0-9.]*\b|node\b|npm\b|pnpm\b|yarn\b|npx\b|pip[0-9]*\b|ruby\b|perl\b|go\b|curl\b|wget\b|eval\b|exec\b|chmod\b|cp\b|mv\b|mkdir\b|rm\b|tee\b|\.?/|~/)|(?<![\w(])(?:MultiEdit|NotebookEdit|Edit|Write)(?![\w(])))"#,
        RCE_CRITICAL,
        REC_EXEC,
        &[
            concat!(
                "on:\n  pull_request_target:\n    types: [opened]\n",
                "jobs:\n  agent:\n    permissions:\n      contents: write\n",
                "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
                "          allowed_non_write_users: \"*\"\n",
                "          allowed_tools: Bash,Edit,Write\n"
            ),
            // claude-code-action v1 autonomous mode: full write/exec granted via
            // claude_args, and its built-in write-check is bypassed for fork
            // contributors by allowed_non_write_users: "*". Fork-reachable +
            // writable job.
            concat!(
                "on:\n  pull_request_target:\n    types: [opened]\n",
                "jobs:\n  agent:\n    permissions:\n      contents: write\n",
                "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
                "          allowed_non_write_users: \"*\"\n",
                "          prompt: ${{ github.event.pull_request.body }}\n",
                "          claude_args: '--max-turns 40 --permission-mode bypassPermissions'\n"
            ),
            // `auto` permission-mode auto-approves all tools (reads, writes, and
            // Bash) with only a background classifier - autonomous write/exec.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  agent:\n    permissions:\n      contents: write\n",
                "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
                "          allowed_non_write_users: \"*\"\n",
                "          prompt: ${{ github.event.comment.body }}\n",
                "          claude_args: '--max-turns 40 --permission-mode auto'\n"
            ),
            // Block-scalar claude_args with the autonomy flag on a continuation
            // line, as a composite action wires it.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  agent:\n    permissions:\n      contents: write\n",
                "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
                "          allowed_bots: \"*\"\n",
                "          prompt: ${{ github.event.comment.body }}\n",
                "          claude_args: |\n",
                "            --dangerously-skip-permissions\n",
                "            --max-turns 120\n"
            ),
            // claude-code-action with a YAML `allowed_tools:` block scalar
            // granting shell/write tools, with the write-check bypassed via
            // allowed_non_write_users so any fork contributor can trigger it.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  claude:\n    permissions:\n      contents: write\n      pull-requests: write\n",
                "    steps:\n      - uses: anthropics/claude-code-action@beta\n        with:\n",
                "          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}\n",
                "          allowed_non_write_users: \"*\"\n",
                "          allowed_tools: |\n",
                "            Bash(git:*)\n",
                "            Bash(python:*)\n",
                "            Edit\n",
                "            Write\n"
            ),
            // Write/exec granted only through the inline `settings:` JSON
            // permissions.allow block, with the write-check bypassed.
            concat!(
                "on:\n  issues:\n    types: [opened]\n",
                "jobs:\n  claude:\n    permissions:\n      contents: write\n",
                "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
                "          allowed_non_write_users: \"*\"\n",
                "          claude_args: \"--model claude-opus-4 --max-turns 40\"\n",
                "          settings: |\n",
                "            {\n",
                "              \"permissions\": {\n",
                "                \"allow\": [\n",
                "                  \"Bash(npm install *)\",\n",
                "                  \"Bash(npm run *)\"\n",
                "                ]\n",
                "              }\n",
                "            }\n"
            ),
            // Tool grant carried CLI-style inside claude_args via
            // `--allowed-tools`, granting shell/edit tools, write-check bypassed.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  claude:\n    permissions:\n      contents: write\n      issues: write\n",
                "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
                "          allowed_bots: \"*\"\n",
                "          claude_args: |\n",
                "            --allowed-tools \"Bash(git:*),Edit,Write\"\n"
            ),
        ],
        &[
            concat!(
                "on:\n  pull_request:\n    types: [opened]\n",
                "jobs:\n  agent:\n    permissions:\n      contents: read\n",
                "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
                "          allowed_non_write_users: \"*\"\n",
                "          allowed_tools: Read,Grep,Glob\n"
            ),
            // claude_args present but no auto-approve flag: the agent still
            // prompts for permission, so it is not autonomously write-capable.
            concat!(
                "on:\n  pull_request:\n    types: [opened]\n",
                "jobs:\n  agent:\n    permissions:\n      contents: read\n",
                "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
                "          prompt: \"Review this PR\"\n",
                "          claude_args: '--max-turns 10 --model sonnet'\n"
            ),
            // claude-code-action with a read-only allowed_tools: block scalar:
            // no shell/write/exec tool granted, so it is not write-capable.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  claude:\n    permissions:\n      contents: read\n",
                "    steps:\n      - uses: anthropics/claude-code-action@beta\n        with:\n",
                "          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}\n",
                "          allowed_tools: |\n",
                "            Read\n",
                "            Grep\n",
                "            Glob\n"
            ),
            // settings: JSON permissions.allow granting only read-only tools:
            // not write-capable, must not match the settings-JSON branch.
            concat!(
                "on:\n  issues:\n    types: [opened]\n",
                "jobs:\n  claude:\n    permissions:\n      contents: read\n",
                "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
                "          settings: |\n",
                "            {\n",
                "              \"permissions\": {\n",
                "                \"allow\": [\n",
                "                  \"Read\",\n",
                "                  \"Grep\",\n",
                "                  \"Glob\"\n",
                "                ]\n",
                "              }\n",
                "            }\n"
            ),
            // claude_args --allowed-tools granting only read/comment-only gh
            // verbs (view/diff/list/comment): no code-mutating capability, so
            // it must not match the CLI --allowed-tools branch.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  claude:\n    permissions:\n      contents: read\n",
                "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
                "          claude_args: |\n",
                "            --allowedTools \"Bash(gh issue view:*),Bash(gh pr diff:*),Bash(gh pr comment:*),Read,Grep\"\n"
            ),
            // Bare `@claude` tag-mode granting write/exec tools but WITHOUT any
            // write-check bypass: claude-code-action only lets repository
            // write-access actors trigger it, so an outside fork contributor
            // cannot reach the agent. Self-gated => not fork-exploitable.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "  issues:\n    types: [opened]\n",
                "jobs:\n  claude:\n",
                "    if: contains(github.event.comment.body, '@claude')\n",
                "    permissions:\n      contents: write\n      pull-requests: write\n",
                "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
                "          allowed_tools: Bash(git:*),Edit,Write\n"
            ),
        ],
    )
}

fn repo_mutating_gh_tools() -> RuleSpec {
    action(
        "fork_triggerable_ai_agent_with_repo_mutating_gh_tools",
        Severity::High,
        "Fork-triggerable AI agent granted repository-mutating GitHub tools",
        r#"(?m)^\s*allowed_(?:non_write_users|bots)\s*:\s*["']?\*["']?(?:(?!allowed_(?:non_write_users|bots)|^\s*-?\s*(?:uses|name)\s*:|^\s{0,6}\w[\w-]*\s*:\s*$)[\s\S]){0,12000}?(?<!dis)allowed[_-]?[Tt]ools[\s=:]+(?:(?!disallowedTools|allowed_(?:non_write_users|bots)|(?:direct_|system_|user_)?prompt\s*:|^\s*\w[\w-]*\s*:\s*(?:[|>]|["']|$))[\s\S]){0,400}?(?:\bBash\(\s*gh\s+(?:pr|issue)\s*:\s*\*|\bBash\(\s*gh\s+(?:pr|issue)\s+(?:comment|edit|close|reopen|review|merge|ready|lock|unlock)\b|\bBash\(\s*gh\s+label\s+(?:create|edit|delete|clone)\b|\bBash\(\s*gh\s+label\b(?!\s+list)|mcp__github(?:_[a-z_]*)?__(?:create|add|update|delete|merge|close|reopen|edit|submit)_)"#,
        REPO_MUTATION_HIGH,
        REC_GH,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  agent:\n    permissions:\n      contents: write\n      issues: write\n",
            "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
            "          allowed_non_write_users: \"*\"\n",
            "          allowed_tools: Bash(gh issue comment:*)\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  agent:\n    permissions:\n      contents: read\n",
            "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n",
            "          allowed_non_write_users: \"*\"\n",
            "          allowed_tools: Bash(gh pr view:*)\n"
        )],
    )
}

fn gemini_or_copilot() -> RuleSpec {
    action(
        "fork_triggerable_gemini_or_copilot_agent_with_write_or_exec",
        Severity::Critical,
        "Fork-triggerable Gemini / Copilot AI agent with shell or write access in a privileged CI job",
        r#"(?m)(?:(?:google-github-actions/run-gemini-cli@|google-gemini/gemini-cli-action@|GEMINI_API_KEY|gemini_api_key)(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,4000}?(?:"?run_shell_command"?\s*[:=]\s*true|"?YOLO"?|yolo_mode\s*:\s*true|approval[_-]?mode\s*:\s*["']?(?:yolo|auto|always)|--allow-shell|allow[_-]?shell\s*:\s*true|run_shell_command\s*\(\s*(?:\)|bash|sh|zsh|python|node|eval|exec|sed|perl|ruby|xargs|(?:git|gh)\s*\)|git\s+(?:push|commit|add|checkout|config|branch|merge|rebase|reset|tag)|gh\s+(?:pr|issue)\s+(?:edit|comment|close|reopen|merge|review|create|ready|lock|unlock)|gh\s+label(?!\s+list)))|(?:(?:google-github-actions/run-gemini-cli@|google-gemini/gemini-cli-action@)(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,4000}?^\s*prompt\s*:(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,1200}?\$\{\{\s*(?:github\.event\.(?:issue|comment|pull_request|review|discussion)\.(?:body|title)|needs\.[a-z0-9_.\-]+\.outputs\.[a-z0-9_]*(?:prompt|body|comment|issue|task|instruction))\b))"#,
        RCE_CRITICAL,
        REC_EXEC,
        &[
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  gemini:\n    permissions:\n      contents: write\n",
                "    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n",
                "          settings: |\n            { \"tools\": { \"run_shell_command\": true } }\n"
            ),
            concat!(
                "on:\n  issues:\n    types: [opened]\n",
                "jobs:\n  gemini:\n    permissions:\n      contents: write\n      pull-requests: write\n",
                "    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n",
                "          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}\n",
                "          prompt: |\n",
                "            Read the issue: ${{ github.event.issue.body }}\n",
                "            Modify files to implement the request and commit them.\n"
            ),
        ],
        &[
            concat!(
                "on:\n  pull_request:\n    types: [opened]\n",
                "jobs:\n  gemini:\n    permissions:\n      contents: read\n",
                "    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n",
                "          settings: |\n            { \"tools\": { \"run_shell_command\": false } }\n"
            ),
            concat!(
                "on:\n  pull_request:\n    types: [opened]\n",
                "jobs:\n  gemini:\n    permissions:\n      contents: read\n",
                "    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n",
                "          prompt: 'Review PR #${{ github.event.pull_request.number }} and post a summary comment.'\n"
            ),
        ],
    )
}

fn codex() -> RuleSpec {
    action(
        "fork_triggerable_codex_agent_with_write_or_exec_sandbox",
        Severity::Critical,
        "Fork-triggerable OpenAI Codex agent with a write / full-access sandbox in a privileged CI job",
        r#"(?m)openai/codex-action@(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,3000}?(?:(?:allow[_-]?users\s*:\s*["']?\*|allow[_-]?bots\s*:\s*["']?true)(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,1500}?(?:sandbox\s*:\s*["']?(?:danger-full-access|workspace-write|danger|unsafe)|--dangerously-bypass-approvals-and-sandbox|--full-auto|approval[_-]?policy\s*:\s*["']?never)|(?:sandbox\s*:\s*["']?(?:danger-full-access|workspace-write|danger|unsafe)|--dangerously-bypass-approvals-and-sandbox|--full-auto|approval[_-]?policy\s*:\s*["']?never)(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,1500}?(?:allow[_-]?users\s*:\s*["']?\*|allow[_-]?bots\s*:\s*["']?true))|(?:npm\s+i(?:nstall)?\s+-g\s+@openai/codex|@openai/codex\b|\bcodex\s+exec\b)(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,2000}?(?:--dangerously-bypass-approvals-and-sandbox|--full-auto|--yolo|--sandbox[=\s]+(?:danger-full-access|workspace-write)|(?<!\w)-s[=\s]+(?:danger-full-access|workspace-write)|sandbox_mode\s*=\s*["'](?:danger-full-access|workspace-write))"#,
        RCE_CRITICAL,
        REC_CODEX,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  codex:\n    permissions:\n      contents: write\n",
            "    steps:\n      - uses: openai/codex-action@v1\n        with:\n",
            "          allow-users: \"*\"\n          sandbox: workspace-write\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  codex:\n    permissions:\n      contents: read\n",
            "    steps:\n      - uses: openai/codex-action@v1\n        with:\n",
            "          allow-users: \"*\"\n          sandbox: read-only\n"
        )],
    )
}

/// JetBrains Junie (`JetBrains/junie-github-action`) self-gates by default:
/// only actors with write access trigger it, and bot actors are blocked, so the
/// common `@junie-agent` mention wiring is not fork-exploitable. That built-in
/// validation is skipped when a custom `prompt:` input is provided, which
/// automation uses. A fork-reachable Junie step with a `prompt:` that carries
/// untrusted PR/issue content into a write-capable job is the same class as the
/// other agents here. Anchor on `junie-github-action` followed by a `prompt:`
/// input within the same step, never on the mention-only default.
fn junie() -> RuleSpec {
    action(
        "fork_triggerable_junie_agent_with_prompt_bypass",
        Severity::Critical,
        "Fork-triggerable JetBrains Junie agent with a custom prompt bypassing its built-in write-access gate",
        r#"(?m)JetBrains/junie-github-action@(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,2000}?^\s*(?:prompt|user_prompt|custom_prompt)\s*:"#,
        RCE_CRITICAL,
        REC_EXEC,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  junie:\n    permissions:\n      contents: write\n      pull-requests: write\n",
            "    steps:\n      - uses: JetBrains/junie-github-action@v1\n        with:\n",
            "          junie_api_key: ${{ secrets.JUNIE_API_KEY }}\n",
            "          prompt: ${{ github.event.comment.body }}\n"
        )],
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  junie:\n    if: contains(github.event.comment.body, '@junie-agent')\n",
            "    permissions:\n      contents: write\n",
            "    steps:\n      - uses: JetBrains/junie-github-action@v1\n        with:\n",
            "          junie_api_key: ${{ secrets.JUNIE_API_KEY }}\n"
        )],
    )
}

/// Bonk (`ask-bonk/ask-bonk`) is a code-review/change agent built on OpenCode.
/// Its installation token defaults to full write access and it responds to
/// `/bonk` / `@ask-bonk` mentions in issues and PRs. Its author gate is the
/// `permissions:` input: `admin`/`write`/`CODEOWNERS` restrict triggers to
/// trusted actors, and `token_permissions: NO_PUSH` drops repo-write. The
/// dangerous shape is a fork-reachable, write-capable Bonk step configured with
/// none of those (mention-only, or `permissions: any`, with the default
/// writable token). Anchor on the action use only when neither a safe
/// `permissions:` value nor `token_permissions: NO_PUSH` appears in the step,
/// and let the standard fork+write+author-gate post-filter do the rest.
fn bonk() -> RuleSpec {
    action(
        "fork_triggerable_bonk_agent_with_write_token",
        Severity::Critical,
        "Fork-triggerable Bonk (OpenCode) agent with a writable token and no maintainer/CODEOWNERS gate",
        r#"(?m)ask-bonk/ask-bonk(?:/github)?@(?![\s\S]{0,2500}?(?:permissions\s*:\s*["']?(?:admin|write|CODEOWNERS)|token_permissions\s*:\s*["']?NO_PUSH))(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,60}"#,
        RCE_CRITICAL,
        REC_EXEC,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  bonk:\n    if: contains(github.event.comment.body, '/bonk')\n",
            "    permissions:\n      contents: write\n      pull-requests: write\n",
            "    steps:\n      - uses: ask-bonk/ask-bonk/github@main\n        with:\n",
            "          model: opencode/claude-opus-4-5\n"
        )],
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  bonk:\n    if: contains(github.event.comment.body, '/bonk')\n",
            "    permissions:\n      contents: write\n",
            "    steps:\n      - uses: ask-bonk/ask-bonk/github@main\n        with:\n",
            "          model: opencode/claude-opus-4-5\n          permissions: CODEOWNERS\n"
        )],
    )
}

/// Cogni (`Cogni-AI-OU/cogni-ai-agent-action`) takes a `prompt:` (typically the
/// issue/PR/comment body) and is granted `contents: write` / `issues: write`
/// with no built-in author gate, so on a fork-reachable write-capable trigger
/// it is directly exploitable. Anchor on the action use; the standard
/// fork+write+author-gate post-filter suppresses correctly-gated callers.
fn cogni() -> RuleSpec {
    action(
        "fork_triggerable_cogni_agent_with_repo_write",
        Severity::Critical,
        "Fork-triggerable Cogni AI agent with repository write access in a privileged CI job",
        r#"(?m)Cogni-AI-OU/cogni-ai-agent-action@"#,
        RCE_CRITICAL,
        REC_EXEC,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  cogni:\n    permissions:\n      contents: write\n      issues: write\n",
            "    steps:\n      - uses: Cogni-AI-OU/cogni-ai-agent-action@main\n        with:\n",
            "          prompt: ${{ github.event.comment.body }}\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  cogni:\n    permissions:\n      contents: read\n",
            "    steps:\n      - uses: Cogni-AI-OU/cogni-ai-agent-action@main\n        with:\n",
            "          prompt: \"Review this PR\"\n"
        )],
    )
}

/// Letta Code (`letta-ai/letta-code-action`) can read files, run shell, commit,
/// push, and open PRs. It self-gates by default on the same
/// `allowed_non_write_users` / `allowed_bots` input convention as the Claude
/// action; setting either to `*` opens it to any fork contributor. Anchor on
/// the action use only when one of those inputs opens it to `*`. The generic
/// write/exec-tools rule does not cover this because Letta grants shell/commit
/// capability implicitly rather than via Claude's `allowed_tools: Bash,...`.
fn letta() -> RuleSpec {
    action(
        "fork_triggerable_letta_agent_opened_to_forks",
        Severity::Critical,
        "Fork-triggerable Letta Code agent opened to non-write users with shell / commit access",
        r#"(?m)letta-ai/letta-code-action@(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,2500}?^\s*allowed_(?:non_write_users|bots)\s*:\s*["']?\*["']?"#,
        RCE_CRITICAL,
        REC_EXEC,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  letta:\n    permissions:\n      contents: write\n      pull-requests: write\n",
            "    steps:\n      - uses: letta-ai/letta-code-action@v0\n        with:\n",
            "          letta_api_key: ${{ secrets.LETTA_API_KEY }}\n",
            "          allowed_non_write_users: \"*\"\n"
        )],
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  letta:\n    permissions:\n      contents: write\n",
            "    steps:\n      - uses: letta-ai/letta-code-action@v0\n        with:\n",
            "          letta_api_key: ${{ secrets.LETTA_API_KEY }}\n"
        )],
    )
}

/// code-agent (`potproject/code-agent`) wraps Claude Code / Codex, reads the
/// issue/PR/comment body, and is granted `contents: write` + `pull-requests:
/// write` with no author gate beyond `sender.type != 'Bot'` (which a fork
/// contributor satisfies). Anchor on the action use; the standard
/// fork+write+author-gate post-filter suppresses correctly-gated callers.
fn code_agent() -> RuleSpec {
    action(
        "fork_triggerable_code_agent_with_repo_write",
        Severity::Critical,
        "Fork-triggerable code-agent (Claude Code / Codex wrapper) with repository write access",
        r#"(?m)potproject/code-agent@"#,
        RCE_CRITICAL,
        REC_EXEC,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  code-agent:\n    permissions:\n      contents: write\n      pull-requests: write\n",
            "    steps:\n      - uses: potproject/code-agent@main\n        with:\n",
            "          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  code-agent:\n    permissions:\n      contents: read\n",
            "    steps:\n      - uses: potproject/code-agent@main\n        with:\n",
            "          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}\n"
        )],
    )
}

/// ai-github-action (`cognitivecomputations/ai-github-action`) rewrites files
/// and pushes them in its `mode: pr` edit modes, granted `contents: write` with
/// no author gate, so on a fork-reachable write-capable trigger it edits the
/// checked-out fork branch directly. Anchor on the action use with a `mode:`
/// input; the fork+write+author-gate post-filter handles gating.
fn ai_refactor() -> RuleSpec {
    action(
        "fork_triggerable_ai_github_action_with_repo_write",
        Severity::Critical,
        "Fork-triggerable AI refactor agent (cognitivecomputations/ai-github-action) with repository write access",
        r#"(?m)cognitivecomputations/ai-github-action@(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,1500}?^\s*mode\s*:"#,
        RCE_CRITICAL,
        REC_EXEC,
        &[concat!(
            "on:\n  pull_request:\n    types: [opened, synchronize]\n",
            "jobs:\n  ai-refactor:\n    permissions:\n      contents: write\n      pull-requests: write\n",
            "    steps:\n      - uses: cognitivecomputations/ai-github-action@v1\n        with:\n",
            "          mode: \"pr\"\n          instructions: \"refactor\"\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  ai-refactor:\n    permissions:\n      contents: read\n",
            "    steps:\n      - uses: cognitivecomputations/ai-github-action@v1\n        with:\n",
            "          mode: \"review\"\n"
        )],
    )
}

/// a5c (`a5c-ai/action`) dispatches Claude Code / Codex on a wide set of
/// triggers and is granted `contents`/`pull-requests`/`packages: write` with no
/// author gate in the static config, so a fork-reachable write-capable caller
/// matches. Anchor on the action use; the standard fork+write+author-gate
/// post-filter suppresses callers that add an explicit maintainer gate.
fn a5c() -> RuleSpec {
    action(
        "fork_triggerable_a5c_agent_with_repo_write",
        Severity::Critical,
        "Fork-triggerable a5c agent router with repository write access in a privileged CI job",
        r#"(?m)a5c-ai/action@"#,
        RCE_CRITICAL,
        REC_EXEC,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  a5c:\n    permissions:\n      contents: write\n      pull-requests: write\n",
            "    steps:\n      - uses: a5c-ai/action@main\n        with:\n",
            "          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  a5c:\n    if: github.event.pull_request.author_association == 'MEMBER'\n",
            "    permissions:\n      contents: write\n",
            "    steps:\n      - uses: a5c-ai/action@main\n"
        )],
    )
}

/// iFlow CLI (`iflow-ai/iflow-cli-action`) takes a `prompt:` (typically the
/// issue/PR/comment body) and can commit and open PRs with no built-in author
/// gate, so a fork-reachable write-capable caller that pipes untrusted content
/// into `prompt:` is exploitable. Anchor on the action use followed by a
/// `prompt:` input; the standard fork+write+author-gate post-filter suppresses
/// callers that add an `author_association` / membership gate.
fn iflow() -> RuleSpec {
    action(
        "fork_triggerable_iflow_agent_with_prompt",
        Severity::Critical,
        "Fork-triggerable iFlow CLI coding agent driven by an untrusted prompt in a privileged CI job",
        r#"(?m)iflow-ai/iflow-cli-action@(?:(?!^\s*-?\s*(?:uses|name)\s*:)[\s\S]){0,2000}?^\s*prompt\s*:"#,
        RCE_CRITICAL,
        REC_EXEC,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  iflow:\n    permissions:\n      contents: write\n      pull-requests: write\n",
            "    steps:\n      - uses: iflow-ai/iflow-cli-action@v2\n        with:\n",
            "          api_key: ${{ secrets.IFLOW_API_KEY }}\n",
            "          prompt: ${{ github.event.comment.body }}\n"
        )],
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  iflow:\n    if: contains(fromJSON('[\"OWNER\", \"MEMBER\", \"COLLABORATOR\"]'), github.event.comment.author_association)\n",
            "    permissions:\n      contents: write\n",
            "    steps:\n      - uses: iflow-ai/iflow-cli-action@v2\n        with:\n",
            "          prompt: ${{ github.event.comment.body }}\n"
        )],
    )
}

/// Sweep (`sweepai/sweep-action`, `sweep-ai/sweep`) reads an issue, edits the
/// codebase, and opens a PR with the GitHub App installation's permissions and
/// no author-write-access check of its own. The safe trigger is the
/// maintainer-controlled `Sweep` label (`github.event.label.name == 'sweep'`),
/// which the standard author-gate post-filter treats as sound. The dangerous
/// shape is a fork-reachable trigger (an `issues`/`issue_comment` `Sweep:` text
/// prefix any outside author can set) with repo write and no label/author gate.
/// Anchor on the action use; the fork+write+author-gate post-filter suppresses
/// label-gated callers.
fn sweep() -> RuleSpec {
    action(
        "fork_triggerable_sweep_agent_with_repo_write",
        Severity::Critical,
        "Fork-triggerable Sweep AI agent with repository write access in a privileged CI job",
        r#"(?m)(?:sweepai|sweep-ai)/sweep(?:-action)?@"#,
        RCE_CRITICAL,
        REC_EXEC,
        &[concat!(
            "on:\n  issues:\n    types: [opened, edited]\n",
            "jobs:\n  sweep:\n    if: startsWith(github.event.issue.title, 'Sweep:')\n",
            "    permissions:\n      contents: write\n      pull-requests: write\n",
            "    steps:\n      - uses: sweepai/sweep-action@v1\n        with:\n",
            "          github_token: ${{ secrets.GITHUB_TOKEN }}\n"
        )],
        &[concat!(
            "on:\n  issues:\n    types: [labeled]\n",
            "jobs:\n  sweep:\n    if: github.event.label.name == 'sweep'\n",
            "    permissions:\n      contents: write\n      pull-requests: write\n",
            "    steps:\n      - uses: sweepai/sweep-action@v1\n        with:\n",
            "          github_token: ${{ secrets.GITHUB_TOKEN }}\n"
        )],
    )
}

/// PR-Agent (`qodo-ai/pr-agent`, formerly `Codium-ai/pr-agent`) reviews,
/// describes, and (via `/improve` and its commitable suggestions) edits PRs with
/// the repo's `GITHUB_TOKEN`. Its Action mode has no author-permission check;
/// the vendor examples gate only on `github.event.sender.type != 'Bot'`, which
/// an outside human PR author satisfies. Wired to `pull_request` /
/// `issue_comment` with `contents: write` and no author gate, an attacker's PR
/// body or comment is read as instructions and can drive a push or PR mutation.
/// Anchor on the action use; the fork+write+author-gate post-filter suppresses
/// callers that add a real gate.
fn pr_agent() -> RuleSpec {
    action(
        "fork_triggerable_pr_agent_with_repo_write",
        Severity::High,
        "Fork-triggerable PR-Agent with repository write access in a privileged CI job",
        r#"(?m)(?:Codium-ai|codiumai|qodo-ai)/pr-agent@"#,
        REPO_MUTATION_HIGH,
        REC_GH,
        &[concat!(
            "on:\n  pull_request:\n    types: [opened, reopened]\n  issue_comment:\n",
            "jobs:\n  pr_agent_job:\n    if: ${{ github.event.sender.type != 'Bot' }}\n",
            "    permissions:\n      contents: write\n      pull-requests: write\n",
            "    steps:\n      - uses: qodo-ai/pr-agent@main\n        env:\n",
            "          OPENAI_KEY: ${{ secrets.OPENAI_KEY }}\n",
            "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        )],
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  pr_agent_job:\n",
            "    if: contains(fromJSON('[\"OWNER\", \"MEMBER\", \"COLLABORATOR\"]'), github.event.comment.author_association)\n",
            "    permissions:\n      contents: write\n      pull-requests: write\n",
            "    steps:\n      - uses: Codium-ai/pr-agent@main\n        env:\n",
            "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        )],
    )
}

/// Drop the HIGH `repo_mutating_gh_tools` finding when the CRITICAL
/// `write_or_exec_tools` finding fires on the *same line*: both anchor on the
/// same `allowed_non_write_users: "*"` step, and when the tool grant on that
/// line is an arbitrary shell/write primitive the CRITICAL rule is the precise
/// classification; findings on different lines are left untouched.
///
/// Also drops the generic `bespoke_llm_agent` finding when any named-agent rule
/// already fires in the *same job*: the bespoke rule anchors on a raw
/// completions/messages URL, which a named agent's workflow often also contains
/// (an API smoke-test `curl`, a provider base-URL env). When a precise vendor
/// rule owns the job, the generic one is a duplicate of the same vulnerability.
pub fn suppress_overlaps(findings: Vec<Finding>, lines: &[&str]) -> Vec<Finding> {
    let critical_lines: std::collections::BTreeSet<usize> = findings
        .iter()
        .filter(|f| f.rule_id == "fork_triggerable_ai_agent_with_write_or_exec_tools")
        .map(|f| f.line_number)
        .collect();

    let job = |line: usize| crate::workflow::enclosing_job_start(lines, line.saturating_sub(1));
    let named_agent_jobs: std::collections::BTreeSet<usize> = findings
        .iter()
        .filter(|f| f.rule_id != "fork_triggerable_bespoke_llm_agent_with_repo_write")
        .map(|f| job(f.line_number))
        .collect();

    findings
        .into_iter()
        .filter(|f| {
            f.rule_id != "fork_triggerable_ai_agent_with_repo_mutating_gh_tools"
                || !critical_lines.contains(&f.line_number)
        })
        .filter(|f| {
            f.rule_id != "fork_triggerable_bespoke_llm_agent_with_repo_write"
                || !named_agent_jobs.contains(&job(f.line_number))
        })
        .collect()
}

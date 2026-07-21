//! Installed-agent rules: the agent CLI/action name is the anchor, and a
//! whole-file `proof` keeps a generic binary name from matching unrelated
//! tooling. All share the [`Family::Installed`] post-filter.

use super::metadata::{RCE_CRITICAL, SECRET_EXFIL_HIGH};
use super::{Family, RuleSpec, Severity};
use std::sync::LazyLock;

macro_rules! proof {
    ($name:ident, $re:expr) => {
        static $name: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new($re).unwrap());
    };
}

proof!(
    CURSOR,
    r"(?i)cursor\.com/install|CURSOR_API_?KEY|@cursor/sdk|cursor[_-]sdk"
);
proof!(
    OPENCODE,
    r"(?i)sst/opencode|anomalyco/opencode|opencode\s+run|OPENCODE_API"
);
proof!(
    AMP,
    r"(?i)sourcegraph/amp|ampcode\.com|@sourcegraph/amp|AMP_API_KEY"
);
proof!(
    GOOSE,
    r"(?i)block/goose|goose/releases|download_cli\.sh|GOOSE_(?:PROVIDER|MODEL|MODE)|\.config/goose|configure-goose|block-open-source/goose|goose\s+run\s+--(?:recipe|instructions|with-builtin|with-extension|no-session|text)|goose\s+run\s+-[ti]\b"
);
proof!(
    DROID,
    r"(?i)Factory-AI/droid|factory-ai|app\.factory\.ai|@factory/cli|FACTORY_API_KEY|droid\s+exec\b"
);
proof!(AIDER, r"(?i)aider-chat|(?:^|[^\w-])aider\b");
proof!(
    OPENHANDS,
    r"(?i)All-Hands-AI/OpenHands|all-hands\.dev|openhands-resolver|@openhands-agent|(?:^|[^\w-])openhands\b"
);
proof!(QWEN, r"(?i)qwen-code|@qwen-code|QwenLM/qwen-code");
proof!(
    CRUSH,
    r"(?i)charmbracelet/crush|repo\.charm\.sh|(?:^|[^\w-])crush\s+run\b"
);
proof!(
    COPILOT,
    r#"(?i)@github/copilot|install_copilot_cli|gh\.io/copilot-install|COPILOT_(?:GITHUB|CLI)_TOKEN|COPILOT_ALLOW_ALL|GH_AW_ENGINE\s*[:=]\s*["']?copilot|command\s+-v\s+copilot|copilot\s+--version"#
);
proof!(
    CONTINUE,
    r"(?i)@continuedev/cli|continuedev/|CONTINUE_(?:API_KEY|CLI)"
);
proof!(GPTME, r"(?i)gptme|ErikBjare/gptme");
proof!(
    SWE_AGENT,
    r"(?i)SWE-agent/SWE-agent|princeton-nlp/SWE-agent|python\s+-m\s+sweagent|pip\s+install\s+sweagent|sweagent\s+run\b"
);
proof!(
    WARP,
    r"(?i)releases\.warp\.dev|WARP_API_?KEY|warpdotdev/oz-agent-action|(?:^|[^\w-])warp-cli\b"
);
proof!(
    DEVIN,
    r"(?i)aaronsteers/devin-action|DEVIN_(?:AI_)?API_KEY|devin-token|app\.devin\.ai|cognition-ai/devin"
);
proof!(
    KILOCODE,
    r"(?i)@kilocode/cli|KILOCODE_(?:API_KEY|TOKEN)|kilocode\.ai|Kilo-Org/kilocode|kilocodeModel"
);
proof!(
    CLAUDE_CLI,
    r#"(?i)@anthropic-ai/claude-code|ANTHROPIC_API_?KEY|CLAUDE_CODE|(?:^|[^\w-])claude-code\b|--dangerously-skip-permissions|--permission-mode[\s=]+['"]?(?:bypassPermissions|acceptEdits|auto)\b"#
);
proof!(
    GEMINI_CLI,
    r"(?i)@google/gemini-cli|gemini-cli|google-gemini/gemini|GEMINI_API_?KEY|GOOGLE_API_?KEY|npm\s+install[^\n]*gemini"
);
proof!(
    CODEMIE,
    r"(?i)@codemieai/code|codemie\s+install|CODEMIE_(?:API_KEY|TOKEN|MAX_TURNS)|codemie\.ai"
);
// A bespoke agent has no vendor name to anchor on: the workflow rolls its own
// loop by calling a chat-completions endpoint from a shell step and then pushing
// the result. The proof is the untrusted trigger payload - an issue/PR/comment
// title or body flowing into the same file that hosts the LLM call. Without that
// payload a completions call is a self-authored prompt (release notes, changelog,
// translation of trusted text), which is not the fork-controlled RCE this models.
proof!(
    BESPOKE_LLM,
    r"(?i)github\.event\.(?:comment\.body|issue\.body|issue\.title|pull_request\.body|pull_request\.title|review\.body|discussion\.body|discussion\.title)"
);
// Any of the shell-autonomy CLIs whose invocation the shell-exec rule anchors
// on. Keeps a bare mention of one of these tools from matching unless the file
// really installs/uses that agent. Mirrors the per-vendor proofs and, like
// `CLAUDE_CLI`, treats the shell-autonomy flags themselves as proof: a workflow
// that writes `--dangerously-skip-permissions` / `--allowedTools "...Bash..."` /
// `--yolo` is unambiguously driving an agent, not mentioning one in prose.
proof!(
    SHELL_EXEC_AGENT,
    r#"(?i)@anthropic-ai/claude-code|ANTHROPIC_API_?KEY|CLAUDE_CODE|(?:^|[^\w-])claude-code\b|\.claude/|CLAUDE\.md|@google/gemini-cli|gemini-cli|GEMINI_API_?KEY|GOOGLE_API_?KEY|cursor\.com/install|CURSOR_API_?KEY|@cursor/sdk|sst/opencode|opencode\s+run|OPENCODE_API|aider-chat|(?:^|[^\w-])aider\b|CODEX_API_?KEY|OPENAI_API_?KEY|--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|--allowed-?tools[\s=]+['"][^'"]*\b(?:Bash|Edit|Write|MultiEdit)\b"#
);

/// Shared recommendation for the installed-agent family.
const REC: &str = "Do not run the agent unattended on untrusted PR/issue content in a job that can write to the repository. Keep review jobs at permissions: contents: read with comment scope only and never git push from them. If the agent must make changes, gate the job on repository write access (author_association in OWNER/MEMBER/COLLABORATOR, getCollaboratorPermissionLevel, or a fork-exclusion check) and have it open a PR for human review. Treat PR/issue title, body, and comments as untrusted data.";

#[allow(clippy::too_many_arguments)]
fn installed(
    id: &'static str,
    title: &'static str,
    anchor: &str,
    proof: &'static LazyLock<regex::Regex>,
    openhands_delegation: bool,
    positive_examples: &'static [&'static str],
    negative_examples: &'static [&'static str],
) -> RuleSpec {
    RuleSpec {
        id,
        severity: Severity::Critical,
        title,
        anchor: crate::rules::compile_anchor(anchor),
        family: Family::Installed {
            proof,
            openhands_delegation,
        },
        metadata: RCE_CRITICAL,
        recommendation: REC,
        positive_examples,
        negative_examples,
    }
}

pub fn rules() -> Vec<RuleSpec> {
    vec![
        cursor(),
        opencode(),
        amp(),
        goose(),
        droid(),
        aider(),
        openhands(),
        qwen(),
        crush(),
        copilot_cli(),
        continue_cli(),
        gptme(),
        swe_agent(),
        warp(),
        devin(),
        kilocode(),
        claude_cli(),
        gemini_cli(),
        codemie(),
        bespoke_llm_agent(),
        agent_shell_exec_secret_exposure(),
    ]
}

fn cursor() -> RuleSpec {
    installed(
        "fork_triggerable_cursor_agent_with_repo_write",
        "Fork-triggerable Cursor agent with repository write access in a privileged CI job",
        r"(?<![\w-])(?:cursor-agent|agent)\b(?:[^\n]|\\\r?\n){0,300}?(?:\s(?:-p|--print|--force)\b)|@cursor/sdk|Agent\.(?:prompt|create|resume)\s*\(",
        &CURSOR,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  cursor:\n    permissions:\n      contents: write\n",
            "    steps:\n      - run: curl https://cursor.com/install -fsS | bash\n",
            "      - env:\n          CURSOR_API_KEY: ${{ secrets.CURSOR_API_KEY }}\n",
            "        run: |\n          cursor-agent -p \"$(cat /tmp/prompt.md)\" --model auto\n",
            "          git push origin HEAD\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n      pull-requests: write\n",
            "    steps:\n      - run: curl https://cursor.com/install -fsS | bash\n",
            "      - run: cursor-agent --version\n"
        )],
    )
}

fn opencode() -> RuleSpec {
    installed(
        "fork_triggerable_opencode_agent_with_repo_write",
        "Fork-triggerable OpenCode agent with repository write access in a privileged CI job",
        r"(?:sst|anomalyco)/opencode/github@|(?<![\w-])opencode\s+run\b",
        &OPENCODE,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  opencode:\n    if: contains(github.event.comment.body, '/opencode')\n",
            "    permissions:\n      contents: write\n      issues: write\n",
            "    steps:\n      - uses: sst/opencode/github@latest\n        with:\n          model: opencode/claude-sonnet-4-5\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n      pull-requests: write\n",
            "    steps:\n      - run: npm install -g opencode-ai\n      - run: opencode --version\n"
        )],
    )
}

fn amp() -> RuleSpec {
    installed(
        "fork_triggerable_amp_agent_with_repo_write",
        "Fork-triggerable Amp agent with repository write access in a privileged CI job",
        r"sourcegraph/amp[\w./-]*@|(?<![\w-])amp\b(?:[^\n]|\\\r?\n){0,200}?(?:\s-x\b|--execute\b|--dangerously)|\|\s*amp\b",
        &AMP,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  amp:\n    permissions:\n      contents: write\n",
            "    steps:\n      - env:\n          AMP_API_KEY: ${{ secrets.AMP_API_KEY }}\n",
            "        run: |\n          cat prompt.txt | amp -x\n          git push origin HEAD\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n",
            "    steps:\n      - run: npm install -g @sourcegraph/amp\n      - run: amp --version\n"
        )],
    )
}

fn goose() -> RuleSpec {
    installed(
        "fork_triggerable_goose_agent_with_repo_write",
        "Fork-triggerable Goose agent with repository write access in a privileged CI job",
        r"(?<![\w-])goose\s+(?:run|session)\b",
        &GOOSE,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  goose:\n    permissions:\n      contents: write\n",
            "    steps:\n      - env:\n          GOOSE_PROVIDER: anthropic\n",
            "        run: |\n          goose run -i /tmp/task.md\n          git push origin HEAD\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  migrate:\n    permissions:\n      contents: read\n",
            "    steps:\n      - run: goose up ./migrations\n"
        )],
    )
}

fn droid() -> RuleSpec {
    installed(
        "fork_triggerable_droid_agent_with_repo_write",
        "Fork-triggerable Factory Droid agent with repository write access in a privileged CI job",
        r"Factory-AI/droid[\w./-]*@|(?<![\w-])droid\s+exec\b|@factory/cli",
        &DROID,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  droid:\n    permissions:\n      contents: write\n",
            "    steps:\n      - env:\n          FACTORY_API_KEY: ${{ secrets.FACTORY_API_KEY }}\n",
            "        run: |\n          droid exec \"$(cat /tmp/task.md)\"\n          git push origin HEAD\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n",
            "    steps:\n      - run: npm install -g @factory/cli\n      - run: droid --version\n"
        )],
    )
}

fn aider() -> RuleSpec {
    installed(
        "fork_triggerable_aider_agent_with_repo_write",
        "Fork-triggerable Aider agent with repository write access in a privileged CI job",
        r"(?<![\w-])aider\b(?:[^\n]|\\\r?\n){0,400}?(?:--yes\b|--yes-always\b|--message\b|--message-file\b|--auto-commits\b|\s-m\b)",
        &AIDER,
        false,
        &[
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  aider:\n    permissions:\n      contents: write\n",
                "    steps:\n      - run: pip install aider-chat\n",
                "      - env:\n          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n",
                "        run: |\n          aider --yes --message \"$(cat /tmp/task.md)\"\n          git push origin HEAD\n"
            ),
            concat!(
                "on:\n  pull_request_review:\n    types: [submitted]\n",
                "jobs:\n  fix:\n    permissions:\n      contents: write\n",
                "    steps:\n      - run: |\n          aider \\\n",
                "            --model claude-sonnet-4-6 \\\n            --message \"$(cat /tmp/p.txt)\" \\\n            --yes\n",
                "          git push origin HEAD\n"
            ),
        ],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n",
            "    steps:\n      - run: pip install aider-chat\n      - run: aider --version\n"
        )],
    )
}

fn openhands() -> RuleSpec {
    installed(
        "fork_triggerable_openhands_agent_with_repo_write",
        "Fork-triggerable OpenHands agent with repository write access in a privileged CI job",
        r"All-Hands-AI/OpenHands[\w./-]*|openhands-resolver\.yml|@openhands-agent",
        &OPENHANDS,
        true,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  openhands:\n    permissions:\n      contents: write\n      issues: write\n",
            "    steps:\n      - uses: All-Hands-AI/OpenHands/openhands@main\n",
            "        env:\n          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}\n",
            "      - run: git push origin HEAD\n"
        )],
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  resolve:\n    permissions:\n      contents: write\n      issues: write\n",
            "    uses: All-Hands-AI/OpenHands/.github/workflows/openhands-resolver.yml@main\n"
        )],
    )
}

fn qwen() -> RuleSpec {
    installed(
        "fork_triggerable_qwen_code_agent_with_repo_write",
        "Fork-triggerable Qwen Code agent with repository write access in a privileged CI job",
        r"qwen-code-action|@qwen-code(?![\w/-])|(?<![\w-])qwen\b(?:[^\n]|\\\r?\n){0,160}?--yolo\b",
        &QWEN,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  qwen:\n    permissions:\n      contents: write\n",
            "    steps:\n      - run: npm install -g @qwen-code/cli\n",
            "      - env:\n          DASHSCOPE_API_KEY: ${{ secrets.DASHSCOPE_API_KEY }}\n",
            "        run: |\n          qwen -p \"$(cat /tmp/task.md)\" --yolo\n          git push origin HEAD\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n",
            "    steps:\n      - run: npm install -g @qwen-code/cli\n      - run: qwen --version\n"
        )],
    )
}

fn crush() -> RuleSpec {
    installed(
        "fork_triggerable_crush_agent_with_repo_write",
        "Fork-triggerable Crush agent with repository write access in a privileged CI job",
        r"(?<![\w-])crush\s+run\b",
        &CRUSH,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  crush:\n    permissions:\n      contents: write\n",
            "    steps:\n      - run: curl -fsSL https://repo.charm.sh/install.sh | bash\n",
            "      - env:\n          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n",
            "        run: |\n          crush run \"$(cat /tmp/task.md)\"\n          git push origin HEAD\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n",
            "    steps:\n      - run: charmbracelet/crush --version\n"
        )],
    )
}

fn copilot_cli() -> RuleSpec {
    installed(
        "fork_triggerable_copilot_cli_agent_with_repo_write",
        "Fork-triggerable GitHub Copilot CLI agent granted shell / write tools in a privileged CI job",
        r#"(?m)(?<![\w-])copilot\b(?:(?!^\s*-?\s*(?:uses|name)\s*:)[^\n]|\n){0,240}?(?:--allow-all-tools|--allow-tool[=\s]+['"]?(?:shell|write|edit|all)\b|--yolo\b|--enable-all-github-mcp-tools\b)"#,
        &COPILOT,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  copilot:\n    permissions:\n      contents: write\n",
            "    steps:\n      - run: npm install -g @github/copilot\n",
            "      - env:\n          COPILOT_CLI_TOKEN: ${{ secrets.COPILOT_CLI_TOKEN }}\n",
            "        run: |\n          copilot -p \"$(cat /tmp/task.md)\" --allow-all-tools\n          git push origin HEAD\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n",
            "    steps:\n      - run: npm install -g @github/copilot\n      - run: copilot --version\n"
        )],
    )
}

fn continue_cli() -> RuleSpec {
    installed(
        "fork_triggerable_continue_cli_agent_with_repo_write",
        "Fork-triggerable Continue CLI agent with repository write access in a privileged CI job",
        r"(?<![\w-])cn\s+(?:remote\b|(?:-\S+\s+)*(?:-p\b|--print\b|--agent\b|--config\b|--auto\b))",
        &CONTINUE,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  continue:\n    permissions:\n      contents: write\n",
            "    steps:\n      - run: npm install -g @continuedev/cli\n",
            "      - env:\n          CONTINUE_API_KEY: ${{ secrets.CONTINUE_API_KEY }}\n",
            "        run: |\n          cn -p \"$(cat /tmp/task.md)\" --auto\n          git push origin HEAD\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n",
            "    steps:\n      - run: npm install -g @continuedev/cli\n      - run: cn --version\n"
        )],
    )
}

fn gptme() -> RuleSpec {
    installed(
        "fork_triggerable_gptme_agent_with_repo_write",
        "Fork-triggerable gptme agent with repository write access in a privileged CI job",
        r#"(?<![\w-])gptme\s+(?:(?:-\S+\s+)*(?:--non-interactive|-n)\b|["'])|uses\s*:\s*ErikBjare/gptme"#,
        &GPTME,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  gptme:\n    permissions:\n      contents: write\n",
            "    steps:\n      - run: pip install gptme\n",
            "      - env:\n          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n",
            "        run: |\n          gptme --non-interactive \"$(cat /tmp/task.md)\"\n          git push origin HEAD\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n",
            "    steps:\n      - run: pip install gptme\n      - run: gptme --version\n"
        )],
    )
}

fn swe_agent() -> RuleSpec {
    installed(
        "fork_triggerable_swe_agent_with_repo_write",
        "Fork-triggerable SWE-agent with repository write access in a privileged CI job",
        r"(?<![\w-])sweagent\s+run\b|python\s+-m\s+sweagent\s+run\b",
        &SWE_AGENT,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  swe:\n    permissions:\n      contents: write\n",
            "    steps:\n      - run: pip install sweagent\n",
            "      - env:\n          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n",
            "        run: |\n          sweagent run --problem_statement /tmp/task.md\n          git push origin HEAD\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n",
            "    steps:\n      - run: pip install sweagent\n      - run: sweagent --help\n"
        )],
    )
}

fn warp() -> RuleSpec {
    installed(
        "fork_triggerable_warp_agent_with_repo_write",
        "Fork-triggerable Warp agent with repository write access in a privileged CI job",
        r"(?<![\w-])warp(?:-cli)?\s+agent\s+run\b|uses\s*:\s*[^\n]*?warpdotdev/oz-agent-action",
        &WARP,
        false,
        &[
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  warp:\n    permissions:\n      contents: write\n",
                "    steps:\n      - env:\n          WARP_API_KEY: ${{ secrets.WARP_API_KEY }}\n",
                "        run: |\n          warp-cli agent run \"$(cat /tmp/task.md)\"\n          git push origin HEAD\n"
            ),
            // The Warp cloud agent shipped as a marketplace action, wired to a
            // fork-triggerable event with write scope.
            concat!(
                "on:\n  issues:\n    types: [opened]\n",
                "jobs:\n  triage:\n    permissions:\n      contents: write\n      issues: write\n",
                "    steps:\n      - uses: warpdotdev/oz-agent-action@v1\n        with:\n",
                "          skill: triage\n          warp_api_key: ${{ secrets.WARP_API_KEY }}\n"
            ),
        ],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n",
            "    steps:\n      - run: warp-cli --version\n"
        )],
    )
}

fn devin() -> RuleSpec {
    installed(
        "fork_triggerable_devin_agent_with_repo_write",
        "Fork-triggerable Devin agent with repository write access in a privileged CI job",
        r"uses\s*:\s*[^\n]*?aaronsteers/devin-action|(?im)^\s*(?:devin-token|prompt-text|playbook-macro)\s*:",
        &DEVIN,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  devin:\n    permissions:\n      contents: write\n      issues: write\n",
            "    steps:\n      - uses: aaronsteers/devin-action@main\n        with:\n",
            "          devin-token: ${{ secrets.DEVIN_AI_API_KEY }}\n",
            "          prompt-text: ${{ github.event.comment.body }}\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n",
            "    steps:\n      - uses: aaronsteers/devin-action@main\n        with:\n",
            "          devin-token: ${{ secrets.DEVIN_AI_API_KEY }}\n",
            "          prompt-text: \"Review PR\"\n"
        )],
    )
}

fn kilocode() -> RuleSpec {
    installed(
        "fork_triggerable_kilocode_agent_with_repo_write",
        "Fork-triggerable Kilo Code agent with repository write access in a privileged CI job",
        r#"(?<![\w-])kilocode\b(?:[^\n]|\\\r?\n){0,240}?(?:--auto\b|--yolo\b|--headless\b|--auto-approve\b)|(?<![\w-])kilocode\s+(?:run|code)\b"#,
        &KILOCODE,
        false,
        &[concat!(
            "on:\n  issues:\n    types: [opened, labeled]\n",
            "jobs:\n  kilo:\n    permissions:\n      contents: write\n",
            "    steps:\n      - run: npm install -g @kilocode/cli\n",
            "      - env:\n          KILOCODE_TOKEN: ${{ secrets.KILOCODE_API_KEY }}\n",
            "        run: |\n          kilocode --auto --yolo \"Issue #${{ github.event.issue.number }}: ${{ github.event.issue.title }}\"\n"
        )],
        &[concat!(
            "on:\n  pull_request:\n    types: [opened]\n",
            "jobs:\n  review:\n    permissions:\n      contents: read\n",
            "    steps:\n      - run: npm install -g @kilocode/cli\n",
            "      - run: kilocode --version\n"
        )],
    )
}

fn claude_cli() -> RuleSpec {
    installed(
        "fork_triggerable_claude_cli_agent_with_repo_write",
        "Fork-triggerable Claude CLI agent with repository write access in a privileged CI job",
        r#"(?im)(?<![\w./-])claude(?![\w./-])[ \t]+(?:--dangerously-skip-permissions|--permission-mode[\s=]+['"]?(?:bypassPermissions|acceptEdits|auto)\b|--allowed-?tools[\s=]+['"][^'"]*\b(?:Bash|Edit|Write|MultiEdit)\b|["'$\\-](?:[^\n]|\\\r?\n){0,600}?(?:--dangerously-skip-permissions|--permission-mode[\s=]+['"]?(?:bypassPermissions|acceptEdits|auto)\b|--allowed-?tools[\s=]+['"][^'"]*\b(?:Bash|Edit|Write|MultiEdit)\b))"#,
        &CLAUDE_CLI,
        false,
        &[
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  agent:\n    if: contains(github.event.comment.body, '@claude')\n",
                "    permissions:\n      contents: write\n      pull-requests: write\n",
                "    steps:\n      - uses: actions/checkout@v4\n",
                "      - env:\n          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n          CLAUDE_TASK: ${{ github.event.comment.body }}\n",
                "        run: |\n          claude -p \"Task: $CLAUDE_TASK\" --dangerously-skip-permissions\n          git push origin HEAD\n"
            ),
            // Autonomy granted through --allowedTools (Bash/Edit/Write) in
            // non-interactive mode instead of --permission-mode: those tools run
            // without a prompt, so a fork commenter's instruction reaches a shell.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  fix:\n    if: startsWith(github.event.comment.body, '/fix')\n",
                "    permissions:\n      contents: write\n      pull-requests: write\n",
                "    steps:\n      - uses: actions/checkout@v4\n",
                "      - env:\n          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n          BODY: ${{ github.event.comment.body }}\n",
                "        run: |\n          claude --print \"Fix: $BODY\" --allowedTools \"Edit,Read,Bash\"\n          git push origin HEAD\n"
            ),
        ],
        &[
            concat!(
                "on:\n  pull_request:\n    types: [opened]\n",
                "jobs:\n  review:\n    permissions:\n      contents: read\n      pull-requests: write\n",
                "    steps:\n      - run: npm install -g @anthropic-ai/claude-code\n      - run: claude --version\n"
            ),
            // Read-only tool grant: --allowedTools lists only inspection tools, so
            // the agent cannot edit files or run shell even though it is invoked
            // non-interactively.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  summarize:\n    permissions:\n      contents: write\n",
                "    steps:\n",
                "      - env:\n          BODY: ${{ github.event.comment.body }}\n",
                "        run: |\n          claude --print \"Summarize: $BODY\" --allowedTools \"Read,Glob,Grep\" > out.md\n          git push origin HEAD\n"
            ),
            // Prose "Claude" near an auto-approve flag mentioned in a comment is
            // documentation, not an invocation: the anchor requires claude to be
            // followed by a flag/quoted-prompt/variable, not a word.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  gemini:\n    permissions:\n      contents: write\n",
                "    steps:\n",
                "      - run: |\n",
                "          # --approval-mode yolo is the gemini analogue of Claude's\n",
                "          # --permission-mode bypassPermissions; omit it for review-only runs.\n",
                "          gemini --approval-mode yolo -p \"$(cat task.md)\"\n"
            ),
        ],
    )
}

fn gemini_cli() -> RuleSpec {
    installed(
        "fork_triggerable_gemini_cli_agent_with_repo_write",
        "Fork-triggerable Gemini CLI agent with repository write access in a privileged CI job",
        r#"(?im)(?<![\w./-])gemini(?![\w./-])[ \t]+(?:\\\r?\n[ \t]*)?(?:--yolo\b|--approval-mode[\s=]+['"]?(?:yolo|auto|always)\b|-p\b|--prompt\b|["'$\\-](?:[^\n]|\\\r?\n){0,600}?(?:--yolo\b|--approval-mode[\s=]+['"]?(?:yolo|auto|always)\b|-p\b|--prompt\b))"#,
        &GEMINI_CLI,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  agent:\n    permissions:\n      contents: write\n      pull-requests: write\n",
            "    steps:\n      - uses: actions/checkout@v4\n",
            "      - env:\n          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}\n          TASK: ${{ github.event.comment.body }}\n",
            "        run: |\n          gemini --yolo --prompt \"$TASK\"\n          git push origin HEAD\n"
        )],
        &[
            concat!(
                "on:\n  pull_request:\n    types: [opened]\n",
                "jobs:\n  review:\n    permissions:\n      contents: read\n",
                "    steps:\n      - env:\n          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}\n",
                "        run: gemini --approval-mode yolo -p \"$(cat review.md)\"\n"
            ),
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  agent:\n    if: github.event.sender.login == github.repository_owner\n",
                "    permissions:\n      contents: write\n",
                "    steps:\n      - env:\n          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}\n",
                "        run: gemini --yolo -p \"$PROMPT\"\n"
            ),
            concat!(
                "on:\n  pull_request:\n    types: [opened]\n",
                "jobs:\n  build:\n    permissions:\n      contents: write\n",
                "    steps:\n      - run: gemini --version\n"
            ),
        ],
    )
}

fn codemie() -> RuleSpec {
    installed(
        "fork_triggerable_codemie_agent_with_repo_write",
        "Fork-triggerable CodeMie CLI agent with repository write access in a privileged CI job",
        r#"(?im)(?<![\w./-])codemie[ \t]+(?:install|run|fix|code|exec)\b|npm[ \t]+install[^\n]*@codemieai/code"#,
        &CODEMIE,
        false,
        &[concat!(
            "on:\n  issue_comment:\n    types: [created]\n",
            "jobs:\n  codemie:\n    permissions:\n      contents: write\n      pull-requests: write\n",
            "    steps:\n      - uses: actions/checkout@v4\n",
            "      - run: npm install -g @codemieai/code\n",
            "      - env:\n          CODEMIE_API_KEY: ${{ secrets.CODEMIE_API_KEY }}\n          TASK: ${{ github.event.comment.body }}\n",
            "        run: |\n          codemie install claude\n          codemie run \"$TASK\"\n          git push origin HEAD\n"
        )],
        &[
            concat!(
                "on:\n  pull_request:\n    types: [opened]\n",
                "jobs:\n  review:\n    permissions:\n      contents: read\n",
                "    steps:\n      - run: npm install -g @codemieai/code\n",
                "      - run: codemie review --diff\n"
            ),
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  codemie:\n    if: github.event.comment.author_association == 'OWNER'\n",
                "    permissions:\n      contents: write\n",
                "    steps:\n      - run: codemie run \"$PROMPT\"\n"
            ),
            concat!(
                "on:\n  pull_request:\n    types: [opened]\n",
                "jobs:\n  build:\n    permissions:\n      contents: write\n",
                "    steps:\n      - run: codemie --version\n"
            ),
        ],
    )
}

fn agent_shell_exec_secret_exposure() -> RuleSpec {
    // Anchor: one of the shell-autonomy CLIs invoked with a flag that lets it
    // run arbitrary shell (`--dangerously-skip-permissions`, an autonomous
    // `--permission-mode`, `--allowedTools "...Bash..."`, `--yolo`,
    // `--approval-mode yolo`). The tool name and the flag may sit on the same
    // line or across a `\`-continued multi-line invocation, matching the same
    // window the per-vendor CRITICAL anchors use. This is the repo-write-less
    // complement of those rules: the ForkShellExec post-filter demands a secret
    // in the job and the *absence* of provable write, so a write-capable job is
    // owned by the CRITICAL rule and never double-reported here.
    let shell_flag = r#"(?:--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|--full-auto\b|--permission-mode[\s=]+['"]?(?:bypassPermissions|acceptEdits|auto)\b|--approval-mode[\s=]+['"]?(?:yolo|auto_edit|auto)\b|--allowed-?tools[\s=]+['"][^'"]*\b(?:Bash|Edit|Write|MultiEdit)\b|--allow-all-tools\b)"#;
    let anchor = format!(
        r#"(?im)(?<![\w./-])(?:claude|gemini|cursor-agent|opencode|aider|codex)(?![\w./-])[ \t]+(?:(?:exec|run)[ \t]+)?(?:{flag}|["'$\\-](?:[^\n]|\\\r?\n){{0,600}}?{flag})"#,
        flag = shell_flag
    );
    RuleSpec {
        id: "fork_triggerable_agent_shell_exec_secret_exposure",
        severity: Severity::High,
        title: "Fork-triggerable coding agent given an arbitrary shell on untrusted PR content in a job that exposes a secret",
        anchor: crate::rules::build_bounded(&anchor),
        family: Family::ForkShellExec {
            proof: &SHELL_EXEC_AGENT,
        },
        metadata: SECRET_EXFIL_HIGH,
        recommendation: "This job hands an autonomous coding agent an arbitrary shell (--dangerously-skip-permissions / --allowedTools \"...Bash...\" / --yolo) while a fork PR's code is checked out and a secret (API key, token) is in the job environment. Even without repository write, that shell runs attacker-controlled content and can read and exfiltrate the secret. Drop the shell/write tools for untrusted runs (grant only read-only tools such as Read/Glob/Grep, or Gemini/Claude review-only modes), do not inject long-lived secrets into a job that processes fork content, and gate any autonomous run on repository write access (author_association in OWNER/MEMBER/COLLABORATOR or a collaborator-permission check). Treat PR/issue title, body, and comments as untrusted data.",
        positive_examples: &[
            // pull_request_target-reachable review job: runs on the base ref
            // with secrets, no permissions block (token scope is repo-configured,
            // so grackle cannot prove write), an ANTHROPIC_API_KEY in env, and
            // claude granted Bash on the PR head it checks out. The shell can
            // exfiltrate the key.
            concat!(
                "on:\n  pull_request_target:\n    types: [opened, synchronize]\n",
                "jobs:\n  review:\n    runs-on: ubuntu-latest\n",
                "    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
                "      - run: npm install -g @anthropic-ai/claude-code\n",
                "      - env:\n          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n",
                "        run: |\n          claude -p \"$(cat review-prompt.txt)\" --allowedTools \"Bash,Read,Grep\"\n"
            ),
            // gemini --yolo on an issue-comment-triggered job with a key in env,
            // no write scope.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  audit:\n    runs-on: ubuntu-latest\n",
                "    steps:\n      - uses: actions/checkout@v4\n",
                "      - run: npm install -g @google/gemini-cli\n",
                "      - env:\n          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}\n",
                "        run: gemini --yolo -p \"Analyze the changed files in this PR.\"\n"
            ),
        ],
        negative_examples: &[
            // Write-capable job: this is the CRITICAL repo-write rule's job, so
            // the shell-exec rule must not also fire (no double report).
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  fix:\n    permissions:\n      contents: write\n",
                "    steps:\n      - env:\n          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n",
                "        run: |\n          claude -p \"$(cat p.txt)\" --dangerously-skip-permissions\n          git push origin HEAD\n"
            ),
            // Plain pull_request from a fork receives no secrets, so an arbitrary
            // shell has nothing to exfiltrate - not this class.
            concat!(
                "on:\n  pull_request:\n\njobs:\n  review:\n    runs-on: ubuntu-latest\n",
                "    steps:\n      - uses: actions/checkout@v4\n",
                "      - env:\n          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n",
                "        run: claude -p \"$(cat prompt.txt)\" --allowedTools \"Bash,Read\"\n"
            ),
            // No secret in the job: nothing for the shell to exfiltrate.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  review:\n    runs-on: ubuntu-latest\n",
                "    steps:\n      - uses: actions/checkout@v4\n",
                "      - run: claude -p \"$(cat prompt.txt)\" --allowedTools \"Bash,Read\"\n"
            ),
            // Read-only tool grant: no Bash/Edit/Write and no autonomous flag, so
            // the agent cannot run a shell even with a key present.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  review:\n    runs-on: ubuntu-latest\n",
                "    steps:\n      - env:\n          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n",
                "        run: claude --print \"Summarize\" --allowedTools \"Read,Glob,Grep\" > out.md\n"
            ),
            // Merge-gated: `pull_request_target && action=='closed' && merged==true`
            // is a pure AND-chain that only a maintainer's merge can satisfy, so
            // the fork author never reaches the shell.
            concat!(
                "on:\n  pull_request_target:\n    types: [closed]\n",
                "jobs:\n  index:\n    if: >\n      github.event.action == 'closed' &&\n      github.event.pull_request.merged == true\n",
                "    runs-on: ubuntu-latest\n",
                "    env:\n      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n",
                "    steps:\n      - run: claude --dangerously-skip-permissions -p \"index ${PR_URL}\"\n"
            ),
            // Author-gated: only trusted actors reach the shell.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  agent:\n    if: github.event.comment.author_association == 'OWNER'\n",
                "    runs-on: ubuntu-latest\n",
                "    steps:\n      - env:\n          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n",
                "        run: claude -p \"$BODY\" --dangerously-skip-permissions\n"
            ),
        ],
    }
}

fn bespoke_llm_agent() -> RuleSpec {
    installed(
        "fork_triggerable_bespoke_llm_agent_with_repo_write",
        "Fork-triggerable bespoke LLM agent with repository write access in a privileged CI job",
        // The anchor is the bespoke LLM endpoint the workflow talks to: a
        // chat-completions / messages URL, whether it appears in a `curl` line or
        // as a provider base-URL env value that a local script then POSTs to.
        // Naming the API shape (not a vendor) is what lets an unnamed, roll-your-own
        // agent match. The proof ([`BESPOKE_LLM`]) demands untrusted trigger payload
        // in the file, and the installed-agent post-filter demands the job be
        // fork-reachable, ungated, and write-capable - so a self-prompted call, or
        // one in a read-only review job, never matches.
        r"(?i)(?:/v1/chat/completions|/v1/messages|/v1/completions|/chat/completions|api\.openai\.com/v1|api\.anthropic\.com/v1|generativelanguage\.googleapis\.com|/compatible-mode/v1|/api/paas/v4)",
        &BESPOKE_LLM,
        false,
        &[concat!(
            "on:\n  issues:\n    types: [opened]\n",
            "jobs:\n  agent:\n    permissions:\n      contents: write\n",
            "    steps:\n      - uses: actions/checkout@v4\n",
            "      - env:\n          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}\n          TASK: ${{ github.event.issue.body }}\n",
            "        run: |\n",
            "          RESP=$(curl -s https://api.openai.com/v1/chat/completions \\\n",
            "            -H \"Authorization: Bearer $LLM_API_KEY\" \\\n",
            "            -d \"{\\\"messages\\\":[{\\\"role\\\":\\\"user\\\",\\\"content\\\":\\\"$TASK\\\"}]}\")\n",
            "          echo \"$RESP\" | node apply-ops.js\n",
            "          git add . && git commit -m fix && git push origin HEAD\n"
        )],
        &[
            // Read-only: curls a completions endpoint to post a review comment on a
            // PR, but the job has no write scope and never pushes - not the class.
            concat!(
                "on:\n  pull_request:\n    types: [opened]\n",
                "jobs:\n  review:\n    permissions:\n      contents: read\n      pull-requests: write\n",
                "    steps:\n      - env:\n          KEY: ${{ secrets.OPENAI_API_KEY }}\n          BODY: ${{ github.event.pull_request.body }}\n",
                "        run: |\n",
                "          curl -s https://api.openai.com/v1/chat/completions -d \"{\\\"input\\\":\\\"$BODY\\\"}\" > review.txt\n",
                "          gh pr comment ${{ github.event.number }} -F review.txt\n"
            ),
            // Self-prompted: the completions call summarizes trusted repo content
            // (a changelog), no untrusted event payload flows in, so the proof
            // never matches even though the job can push.
            concat!(
                "on:\n  push:\n    branches: [main]\n",
                "jobs:\n  notes:\n    permissions:\n      contents: write\n",
                "    steps:\n      - run: |\n",
                "          curl -s https://api.openai.com/v1/chat/completions -d @changelog.json > notes.md\n",
                "          git add notes.md && git commit -m notes && git push\n"
            ),
            // Author-gated: the write job that runs the bespoke agent is gated on
            // repository ownership, so a fork contributor cannot reach it.
            concat!(
                "on:\n  issue_comment:\n    types: [created]\n",
                "jobs:\n  agent:\n    if: github.event.comment.author_association == 'OWNER'\n",
                "    permissions:\n      contents: write\n",
                "    steps:\n      - env:\n          TASK: ${{ github.event.comment.body }}\n",
                "        run: |\n",
                "          curl -s https://api.anthropic.com/v1/messages -d \"{\\\"prompt\\\":\\\"$TASK\\\"}\" | apply\n",
                "          git push origin HEAD\n"
            ),
        ],
    )
}

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand-mark.svg">
    <img src="docs/assets/brand-mark-light.svg" alt="Grackle" width="480">
  </picture>
</div>

<!-- BADGES_START - stripped from the Hugo docs build; see .hugo/scripts/build_docs.py -->
<p align="center">
  <a href="https://github.com/cpeoples/grackle/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/cpeoples/grackle/ci.yml?branch=main&label=CI&style=flat-square&logo=github&logoColor=white" alt="CI" /></a>&nbsp;&nbsp;
  <a href="https://scorecard.dev/viewer/?uri=github.com/cpeoples/grackle"><img src="https://img.shields.io/ossf-scorecard/github.com/cpeoples/grackle?style=flat-square&label=OpenSSF%20Scorecard" alt="OpenSSF Scorecard" /></a>&nbsp;&nbsp;
  <a href="https://github.com/cpeoples/grackle/security/code-scanning"><img src="https://img.shields.io/github/actions/workflow/status/cpeoples/grackle/codeql.yml?branch=main&label=CodeQL&style=flat-square&logo=github&logoColor=white" alt="CodeQL" /></a>&nbsp;&nbsp;
  <a href="https://github.com/cpeoples/grackle/actions/workflows/cargo-audit.yml"><img src="https://img.shields.io/github/actions/workflow/status/cpeoples/grackle/cargo-audit.yml?branch=main&label=cargo-audit&style=flat-square&logo=rust&logoColor=white" alt="cargo-audit" /></a>&nbsp;&nbsp;
  <a href="src/rules"><img src="https://img.shields.io/badge/Rules-36-blue?style=flat-square&logo=rust&logoColor=white" alt="Rules" /></a>&nbsp;&nbsp;
  <a href="https://github.com/cpeoples/grackle/releases/latest"><img src="https://img.shields.io/badge/SLSA-Level%203-success?style=flat-square&logo=slsa&logoColor=white" alt="SLSA Build Level 3" /></a>&nbsp;&nbsp;
  <a href="https://github.com/cpeoples/grackle/releases/latest"><img src="https://img.shields.io/badge/SBOM-CycloneDX-success?style=flat-square&logo=cyclonedx&logoColor=white" alt="CycloneDX SBOM" /></a>&nbsp;&nbsp;
  <a href="https://github.com/cpeoples/grackle/releases/latest"><img src="https://img.shields.io/badge/Sigstore-verified-success?style=flat-square&logo=sigstore&logoColor=white" alt="Sigstore verified" /></a>
</p>
<!-- BADGES_END -->

A standalone Rust scanner that detects **fork-triggerable CI coding agents with
repository write access** in GitHub Actions and GitLab CI workflows. When an AI
coding agent runs on untrusted fork input in a job that can write to the repo
and nothing checks who triggered it, prompt injection becomes remote code
execution and repository takeover under the CI token. grackle finds that exact
composition, statically, before it merges.

It is a focused port of the fork-triggerable-agent detection built in
[`ansible-security-scanner`](https://github.com/cpeoples/ansible-security-scanner),
carrying over the same anchors, family proofs, reachability post-filters, and
control-framework metadata so findings match one-to-one.

**<!--RULES-->36<!--/RULES--> rules** across four evaluation families, all
self-validated against a built-in positive and negative example.

### Built with

<div style="display:flex !important;flex-wrap:wrap;align-items:center;gap:1.25rem;margin:0.5rem 0 1rem;">
  <a href="https://www.rust-lang.org/" title="Rust" style="display:inline-flex !important;align-items:center;"><img src="docs/assets/rust.svg" alt="Rust" height="28" style="display:inline-block;" /></a>
  &nbsp;
  <a href="https://doc.rust-lang.org/cargo/" title="Cargo" style="display:inline-flex !important;align-items:center;"><img src="docs/assets/cargo.svg" alt="Cargo" height="28" style="display:inline-block;" /></a>
  &nbsp;
  <a href="https://docs.github.com/actions" title="GitHub Actions" style="display:inline-flex !important;align-items:center;"><img src="docs/assets/githubactions.svg" alt="GitHub Actions" height="28" style="display:inline-block;" /></a>
  &nbsp;
  <a href="https://docs.gitlab.com/ee/ci/" title="GitLab CI" style="display:inline-flex !important;align-items:center;"><img src="docs/assets/gitlab.svg" alt="GitLab CI" height="28" style="display:inline-block;" /></a>
  &nbsp;
  <a href="https://gohugo.io/" title="Hugo" style="display:inline-flex !important;align-items:center;"><img src="docs/assets/hugo.svg" alt="Hugo" height="28" style="display:inline-block;" /></a>
</div>

## What it flags

A workflow is vulnerable when an untrusted fork contributor can reach a job that
runs a coding agent with write access to the repository. All three conditions
must hold for a finding to fire:

1. **Fork-reachable trigger** - `pull_request_target`, `issue_comment`,
   `issues`, `pull_request`, `pull_request_review_comment`,
   `pull_request_review`, `workflow_call`, or a `workflow_run` consumer that
   ingests a fork PR run's data without a same-repo guard, and the agent's job
   is not confined to a non-fork event by its own `if:` (`github.event_name ==
   'push' | 'schedule' | 'workflow_dispatch'`, `pull_request.merged == true`,
   protected-branch ref) or hard-disabled with `if: false`.
2. **No author gate** - no `author_association` /
   `getCollaboratorPermissionLevel` / owner-equality
   (`github.actor == github.repository_owner`) / allowlist
   (`contains(vars.ALLOWED_USERS, ...login)`) / fork-exclusion / maintainer-label
   check restricting who can trigger the agent.
3. **Write-capable agent job** - the agent's job declares `contents: write` /
   `permissions: write-all`, pushes directly (`git push`, `gh pr
   create|merge`), runs the agent in an auto-approve mode
   (`--dangerously-skip-permissions`, `--yolo`,
   `--permission-mode bypassPermissions`), or inherits a workflow-level write
   default it does not narrow.

Review-only agents (`contents: read`, comment scope) and gated agents are not
flagged.

**Secret exfiltration without repository write (HIGH).** A separate rule fires
one tier lower when conditions 1 and 2 hold but the job is *not* provably
write-capable, yet it still hands the agent an arbitrary shell
(`--dangerously-skip-permissions`, `--allowedTools "...Bash..."`, `--yolo`) on
the fork's checked-out code **while a repository secret is in the job
environment** (an API key or `GITHUB_TOKEN`). The shell runs attacker-controlled
content and can read and exfiltrate that secret even without write access. This
variant only fires on secret-bearing fork triggers (`pull_request_target`,
`issue_comment`, `issues`, `workflow_run` escalation); a plain `pull_request`
from a fork receives no secrets, and is suppressed by the same author, merge,
and transitive gates as the CRITICAL rules.

### GitLab CI

GitLab's fork-pipeline model differs from GitHub Actions: a fork merge-request
pipeline runs in the fork with the fork's variables, so the parent's protected
secrets are never injected. A `.gitlab-ci.yml` agent job is flagged (HIGH) when
it runs on merge-request content, is handed write or execute capability
(`--dangerously-skip-permissions` / `--permission-mode acceptEdits` /
`--yolo` / `--full-auto`, a tool grant that includes `Bash`/`Edit`/`Write`, a
`git push`, or a real project/personal access token), and is not self-gated. It
is scored HIGH rather than CRITICAL because final exploitability also depends on
project settings not visible in the file (whether the token is Protected, branch
protection, who may push). Findings are suppressed by a fork-ID guard
(`$CI_MERGE_REQUEST_SOURCE_PROJECT_ID != $CI_PROJECT_ID`), a source-branch-name
gate, a job gated on a project-internal variable, read-only tools,
`--permission-mode plan` with no offsetting write capability, or a fork-scoped
`CI_JOB_TOKEN`.

### Composite / local actions

An agent is sometimes hidden one level down: the workflow step is
`uses: ./.github/actions/foo` and the real agent invocation lives in that
action's `action.yml`. When grackle scans a **directory** (a checked-out repo),
it resolves each `uses: ./<path>` reference from disk and looks for an agent in
the referenced action definition. A hidden agent is attributed to the caller
workflow at the `uses:` line, and only fires when the caller job is
fork-reachable, ungated, and write-capable, since that is where the trust
boundary and token live. Resolution is one level deep. This only applies to
directory scans; a single-file scan cannot resolve a local path off disk.

## Install

Prebuilt binaries for macOS, Linux, and Windows are attached to each
[release](https://github.com/cpeoples/grackle/releases). Download the archive
for your platform, extract it, and put `grackle` on your `PATH`.

To build from source you need the Rust toolchain (`rustup`):

```bash
# macOS / Linux
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

On Windows, install `rustup` with `winget install Rustlang.Rustup` (or run
`rustup-init.exe` from https://rustup.rs) and the MSVC C++ build tools it prompts
for. Then build and install the binary into `~/.cargo/bin` (already on `PATH`):

```bash
cargo install --git https://github.com/cpeoples/grackle.git
```

Or from a local checkout:

```bash
git clone https://github.com/cpeoples/grackle.git
cd grackle
cargo install --path .        # or: cargo build --release
```

`cargo build --release` leaves the binary at `target/release/grackle`
(`target\release\grackle.exe` on Windows).

## Usage

```bash
grackle [PATH]                    # scan a file or directory (default: .)
grackle -f json PATH              # choose an output format
grackle -o report.sarif PATH      # write to a file (format inferred from extension)
grackle --debug PATH              # print per-file scan diagnostics to stderr
grackle --list-rules              # print the rule inventory
grackle --self-test               # validate every rule against its built-in examples
grackle --version                 # print the version
```

Exit code is `1` when any finding is reported, `0` when clean.

### GitHub Actions

Run grackle on every push and pull request and surface findings inline in the
Security tab and on the PR diff:

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  grackle:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cpeoples/grackle@v0.1.0
```

`upload-sarif` is on by default; set `fail-on-findings: false` to report without
failing the build, or `format`/`output` to write a different report. The step
exposes `exit-code` and `report` outputs.

### Pull request and merge request comments

`--github-comment` and `--gitlab-comment` post findings directly onto the PR/MR:
a sticky summary comment (updated in place on re-runs, with a resolved/new
trajectory line) plus inline comments on the offending lines. This needs no
GitHub Advanced Security and works on private repositories.

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  grackle:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install --git https://github.com/cpeoples/grackle.git
      - run: grackle --github-comment .
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Tokens are read from the environment only (`GRACKLE_GITHUB_TOKEN` / `GITHUB_TOKEN`
/ `GH_TOKEN`, or the GitLab equivalents) and redacted from logs. See
[CI/CD integration](docs/ci-cd.md) for GitLab.

### Output formats

`-f/--format` selects the format; `-o/--output` writes to a file and infers the
format from its extension. `--json` is shorthand for `-f json`.

| Format        | Value                     | Notes                                             |
| ------------- | ------------------------- | ------------------------------------------------- |
| Text          | `text` (default)          | Human-readable, with the full remediation.        |
| JSON          | `json`                    | Findings with metadata, snippet, and remediation. |
| Markdown      | `markdown` / `md`         | One section per finding.                          |
| SARIF 2.1.0   | `sarif`                   | Rule catalog + `fixes[]`; GitHub code scanning.   |
| GitLab SAST   | `gitlab-sast`             | `gl-sast-report.json` for `artifacts:reports:sast`. |
| JUnit         | `junit`                   | One failing test case per finding.                |
| CSV           | `csv`                     | Flat table (RFC 4180).                            |
| XML           | `xml`                     | Generic findings document.                        |
| YAML          | `yaml` / `yml`            | Findings with block-scalar snippet/remediation.   |
| HTML          | `html`                    | Self-contained styled report.                     |
| CycloneDX 1.5 | `cyclonedx`               | SBOM `vulnerabilities[]`; Dependency-Track, Snyk. |

Every finding carries a confidence of `high`, `medium`, or `low` alongside its
control-framework references (CWE, OWASP AppSec, OWASP LLM, OWASP ASVS, MITRE
ATT&CK, MITRE ATLAS, CIS Controls, NIST 800-53, PCI-DSS, SOC 2), the offending
workflow block, and a dynamic secure-fix write-up derived from that block: the
vulnerable code, why it is dangerous, and a corrected workflow. Confidence
reflects how much of the finding a static read can prove and is independent of
severity; see [output formats](docs/output-formats.md) for how it is derived.

## Design

| Module               | Responsibility                                                                                     |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| `workflow.rs`        | Structural primitives: GitHub trigger reachability, enclosing job block, workflow-level write default, author gate, per-job write capability; GitLab merge-request reachability, fork/branch/variable gates, and write-capability detection. |
| `rules/mod.rs`       | `RuleSpec` (pure data), `Family` evaluation strategy, `Finding`, and the `Engine` that owns evaluation, post-filters, and overlap suppression. |
| `rules/metadata.rs`  | The three shared compliance profiles (`RCE_CRITICAL`, `REPO_MUTATION_HIGH`, `SECRET_EXFIL_HIGH`). |
| `rules/installed.rs` | The 20 installed-agent rules plus the shell-exec secret-exfiltration rule (anchor + family proof + examples). |
| `rules/action.rs`    | The 14 action-configuration rules and the CRITICAL-over-HIGH overlap suppression.                   |
| `rules/gitlab.rs`    | The GitLab CI agent rule (GitLab-native reachability and gate model).                              |
| `rules/remediation.rs` | Per-rule dynamic secure-fix generation (vulnerable / explanation / corrected workflow).          |
| `localaction.rs`     | Resolves `uses: ./<path>` composite-action references off disk so an agent hidden in an `action.yml` is attributed to its caller. |
| `report.rs`          | The output formats (text, json, markdown, sarif, gitlab-sast, junit, csv, xml, yaml, html, cyclonedx). |
| `scanner.rs`         | Workflow-file discovery and scan orchestration.                                                    |
| `main.rs`            | CLI (`clap`), format selection, and file/stdout output.                                            |

The rule set splits by **evaluation family**, not by vendor: `Installed` agents
(the agent name is the anchor, kept precise by a whole-file proof), `Action`
configurations (the agent is opened to forks via `allowed_non_write_users: "*"`,
a write sandbox, or YOLO/auto approval), `ForkShellExec` (an agent handed an
arbitrary shell on fork content in a secret-bearing job that grackle cannot
prove writes to the repo, a secret-exfiltration risk scored HIGH), and `Gitlab`
agent jobs (GitLab's fork-pipeline reachability, gate, and write model rather
than the GitHub `on:`/`jobs:`/`permissions:` context). The families have
genuinely different reachability semantics, which is the real axis the code
splits on.

Regexes use the `fancy-regex` crate because the ported anchors rely on
lookbehind and lookahead, which the default `regex` crate does not support. They
are compiled once when the `Engine` is built, and cross-cutting reachability /
gate / write facts are computed once per file rather than per rule.

## Detected agents

**Installed agents (CRITICAL):** Cursor, OpenCode, Amp, Goose, Factory Droid,
Aider, OpenHands, Qwen Code, Crush, GitHub Copilot CLI, Continue CLI, gptme,
SWE-agent, Warp (CLI and cloud-agent action), Devin, Kilo Code, Claude
CLI, Gemini CLI.

**Action configurations:** Claude Code action shell/write tools including the
autonomous `claude_args: --permission-mode bypassPermissions` /
`--dangerously-skip-permissions` mode (CRITICAL), Claude Code action
repo-mutating `gh`/MCP tools (HIGH), Gemini / Copilot action with shell or write
access (CRITICAL), OpenAI Codex action with a write / full-access sandbox
(CRITICAL), JetBrains Junie with a custom prompt bypassing its built-in gate
(CRITICAL), Bonk (an OpenCode wrapper) with a writable token and no
maintainer/CODEOWNERS gate (CRITICAL), Cogni AI action with repository write
access (CRITICAL), Letta Code opened to non-write users with shell / commit
access (CRITICAL), the `potproject/code-agent` Claude Code / Codex wrapper with
repository write access (CRITICAL), the `cognitivecomputations` AI-refactor
action with repository write access (CRITICAL), the `a5c` agent router with
repository write access (CRITICAL), the iFlow CLI action driven by an
untrusted prompt (CRITICAL), the Sweep AI agent (`sweepai/sweep`) with
repository write access and no maintainer-label gate (CRITICAL), and PR-Agent
(`qodo-ai/pr-agent`) with repository write access and no author gate (HIGH).

**GitLab CI (HIGH):** a `.gitlab-ci.yml` merge-request job running Claude,
Codex, Aider, Cursor, Qwen, OpenCode, Goose, or Gemini with write/execute
capability and no fork gate.

Every rule is self-validated by `--self-test` against a built-in positive and
negative example.

## Security

Grackle exists to flag write-capable CI agents that untrusted forks can reach,
so the project holds itself to the same bar. Every push and pull request runs:

- **OpenSSF Scorecard** ([`.github/workflows/scorecard.yml`](.github/workflows/scorecard.yml)) -
  weekly supply-chain posture check, published to the code-scanning dashboard.
- **CodeQL** ([`.github/workflows/codeql.yml`](.github/workflows/codeql.yml)) -
  SAST over the Rust in `src/` and the repository's own GitHub Actions
  workflows.
- **cargo-audit** ([`.github/workflows/cargo-audit.yml`](.github/workflows/cargo-audit.yml)) -
  the dependency tree scanned against the RustSec advisory database, weekly and
  on every `Cargo.lock` change.
- **Dependabot** ([`.github/dependabot.yml`](.github/dependabot.yml)) - weekly
  update PRs for the `cargo` and `github-actions` ecosystems.

Every workflow runs on a [`step-security/harden-runner`](https://github.com/step-security/harden-runner)
egress-audited runner, pins third-party actions by commit SHA, and declares the
minimum `permissions` it needs. No workflow grants write to a fork-reachable
trigger.

### Release provenance

Release archives are covered by [SLSA Build Level 3](https://slsa.dev/) provenance
generated by the trusted `slsa-github-generator` reusable workflow. A CycloneDX
SBOM is produced from the Cargo dependency graph, and every archive plus the SBOM
is signed with [Sigstore](https://www.sigstore.dev/). Verify a download with
`slsa-verifier` and `cosign` against the attached `.intoto.jsonl` and
`.sigstore.json` files.

### Privacy

Grackle runs locally and does not phone home. There is no telemetry, no
analytics, no usage pings, and no remote rule fetch. It reads workflow files off
disk and writes a report; it opens no network connections.

### Reporting a vulnerability

Open a private security advisory via the
[Security tab](https://github.com/cpeoples/grackle/security/advisories/new)
rather than a public issue. Vulnerabilities in grackle itself are in scope;
vulnerabilities in the *workflows grackle scans* are not, those belong to the
scanned repository's maintainer.

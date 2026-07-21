# Grackle

Grackle is a standalone Rust scanner that detects **fork-triggerable AI coding
agents with repository write access** in GitHub Actions and GitLab CI workflows.
When an outside contributor can reach a job that runs a coding agent on
untrusted input while that job can write to the repository, prompt injection
turns into remote code execution and repository takeover under the CI token.

**<!--RULES-->36<!--/RULES--> rules** across <!--FAMILIES-->35<!--/FAMILIES--> agent families, on
both GitHub Actions and GitLab CI. Every finding carries control-framework
metadata (CWE, OWASP, MITRE ATT&CK and ATLAS, NIST, CIS, PCI-DSS, SOC 2) and a
dynamic secure-fix write-up.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [What it flags](#what-it-flags)
- [Detection rules](/rules/)
- [Detection model](/detection-model/)
- [Output formats](/output-formats/)
- [CI/CD integration](/ci-cd/)
- [White paper](/whitepaper/)
- [Limitations](/limitations/)

## Install

Prebuilt binaries for macOS, Linux, and Windows are attached to each
[release](https://github.com/cpeoples/grackle/releases). Download the archive
for your platform, extract it, and put `grackle` on your `PATH`.

To build from source you need the Rust toolchain (`rustup`):

```bash
# macOS / Linux
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
cargo install --git https://github.com/cpeoples/grackle.git
```

## Quick start

```bash
grackle                          # scan the current directory
grackle path/to/repo             # scan a checked-out repository
grackle -o report.sarif .        # SARIF for GitHub code scanning
grackle -f gitlab-sast .         # GitLab SAST report
grackle --list-rules             # print the rule inventory
grackle --self-test              # validate every rule against its examples
```

Exit code is `1` when any finding is reported, `0` when clean.

## What it flags

A finding fires only when all three conditions hold at once:

1. **Fork-reachable trigger** such as `pull_request_target`, `issue_comment`,
   `issues`, `pull_request`, `pull_request_review`, `pull_request_review_comment`,
   or a `workflow_call` reached from one of these.
2. **No author gate** restricting who may trigger the agent (no
   `author_association` check, collaborator-permission check, owner-equality
   guard, allowlist, or fork-exclusion).
3. **Write-capable agent job** that declares `contents: write`, pushes directly,
   grants the agent exec/write tools, or runs it in an auto-approve mode.

Review-only agents (`contents: read`, comment scope) and gated agents are not
flagged. See the [detection model](/detection-model/) for the full reasoning.

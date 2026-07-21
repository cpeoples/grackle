# Contributing to Grackle

Thanks for taking the time to contribute. Most pull requests fall into one of
two shapes:

1. **Adding or tuning a detection rule** (the most common kind of PR): a new
   agent family, a new autonomy flag, or a false-positive fix.
2. **Improving the scanner itself**: reachability and gate logic, a new report
   format, remediation text, or performance work.

Before you start, please read [`NOTICE`](./NOTICE). It sets out the attribution
terms for any redistribution or derivative work, including the reserved project
name.

## Set up your dev environment

You need the Rust toolchain (`rustup`) with `rustfmt` and `clippy`:

```bash
git clone --recurse-submodules https://github.com/cpeoples/grackle.git
cd grackle

# If you already cloned without --recurse-submodules, pull the Hugo theme in now:
#   git submodule update --init --recursive

rustup component add rustfmt clippy

# Optional: install the pre-commit hook so formatting and lint run on commit.
pre-commit install
```

## The commands you will use

CI runs `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test`, so
run the same three locally before opening a PR:

| Command | What it does |
| --- | --- |
| `cargo test` | The full test suite, including every rule's self-test. |
| `cargo test <name>` | Filtered test run. |
| `cargo fmt` | Format the tree (CI checks `cargo fmt --check`). |
| `cargo clippy --all-targets -- -D warnings` | Lint; warnings fail CI. |
| `cargo run -- <path>` | Scan a local file or directory. |
| `cargo run -- --self-test` | Validate every rule against its built-in examples. |
| `cargo run -- --list-rules` | Print the rule inventory. |

## Adding a new rule

Rules are plain data. Each is a `RuleSpec` (defined in [`src/rules/mod.rs`](src/rules/mod.rs))
grouped into a module by evaluation family, not by vendor:

- [`src/rules/installed.rs`](src/rules/installed.rs) - agent CLIs and actions
  whose name is the anchor (Claude CLI, Cursor, OpenCode, and so on), plus the
  shell-exec secret-exfiltration rule.
- [`src/rules/action.rs`](src/rules/action.rs) - actions that open themselves to
  forks through configuration (a write sandbox, an allow-all tools grant, an
  auto-approve flag).
- [`src/rules/gitlab.rs`](src/rules/gitlab.rs) - the GitLab CI agent rule, which
  uses GitLab-native reachability and gating.

Add your rule to the module whose family matches how it becomes reachable, and
include it in that module's `rules()` list.

### Rule structure

```rust
RuleSpec {
    id: "fork_reachable_your_agent_with_write",
    severity: Severity::Critical,
    title: "Fork-reachable Your Agent with repository write",
    anchor: compile_anchor(r#"your-agent-cli\b"#),
    family: Family::Installed { proof: &PROOF, openhands_delegation: false },
    metadata: RCE_CRITICAL,
    recommendation: REC,
    positive_examples: POSITIVE,
    negative_examples: NEGATIVE,
}
```

- **`anchor`** locates the invocation. Keep it specific: a bare tool name will
  match prose and unrelated tooling.
- **`family`** decides the post-filter. `Installed` and `Gitlab` also carry a
  whole-file `proof` regex that confirms the match belongs to a real agent
  framework before the finding fires.
- **`metadata`** is one of the shared compliance profiles in
  [`src/rules/metadata.rs`](src/rules/metadata.rs) (`RCE_CRITICAL`,
  `REPO_MUTATION_HIGH`, `SECRET_EXFIL_HIGH`). Reuse one rather than inventing a
  new tag set.
- **`recommendation`** is a plain-text fix hint. The full secure-fix write-up is
  generated per rule in [`src/rules/remediation.rs`](src/rules/remediation.rs).

### Examples are the test

Every rule ships `positive_examples` (workflows that must produce exactly one
finding) and `negative_examples` (workflows that must produce none). These are
not decoration: `--self-test` and the test suite assert both directions on
every rule, so a rule with good examples gets free protection against anchor
drift and false positives.

```bash
cargo run -- --self-test
```

Invent every value in an example. Do not copy a project path, token name, or
prompt from a real repository. A negative example should lock in the exact
shape that motivated it, for example a gated sibling job or a `contents: read`
reviewer.

### Overlap suppression

When a more specific rule and a more general one both fire on the same job, the
CRITICAL-over-HIGH suppression in [`src/rules/action.rs`](src/rules/action.rs)
keeps the report from double-counting. If your new rule describes the same
vulnerability as an existing one at a different severity, add it there; if it is
a genuinely distinct failure mode, leave it out.

## Severity and confidence

Severity is `CRITICAL` (a fork contributor can drive a write-capable agent, so
prompt injection reaches repository write or RCE) or `HIGH` (repository write is
not provable from the file, or GitLab, where exploitability also depends on
project settings). Do not over-tag: downstream pipelines gate on severity.

Confidence (`high` / `medium` / `low`) is derived by the engine from the
reachability, gate, and write signals it already computes; it is not a per-rule
field. See [`docs/output-formats.md`](docs/output-formats.md).

## Improving the scanner

Structural logic (trigger reachability, author gates, write capability) lives in
[`src/workflow.rs`](src/workflow.rs); the engine, post-filters, and overlap
suppression in [`src/rules/mod.rs`](src/rules/mod.rs); report formats in
[`src/report.rs`](src/report.rs); and PR/MR commenting in
[`src/comment/`](src/comment). If you change gate or write logic, add or extend a
rule example that would have regressed without your fix.

## Commit and PR style

- Keep commits focused. A new rule is one PR; a scanner refactor is another.
- Run `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`
  before opening the PR.
- If you add a CLI flag or output format, update `README.md` and the relevant
  file under `docs/`.
- You keep authorship on your commits and are credited in the project history.

## Getting help

Read the existing rules for worked examples, and open an issue if you are unsure
whether a change is in scope.

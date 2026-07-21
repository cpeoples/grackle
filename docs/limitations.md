# Limitations

Grackle is a static, structural scanner. It reads CI YAML and reasons about
reachability, gating, and write capability from the file alone. That is a
deliberate design choice for speed and zero false-positive noise, but it means
some things are out of scope by construction.

## What it reasons from

Only the workflow file (and, for directory scans, one level of local composite
actions). It does not evaluate expressions at runtime, resolve remote reusable
workflows, or inspect repository settings.

## What it cannot see

- **Repository settings.** Whether `GITHUB_TOKEN` write is disabled org-wide,
  whether a branch is protected, or whether a GitLab variable is Protected or
  Masked is not in the file. This is why repo-mutation and GitLab findings are
  scored HIGH rather than CRITICAL.
- **Remote reusable workflows.** A `uses: owner/repo/.github/workflows/x.yml@ref`
  is resolved by the platform, not by grackle. Only local (`./`) composite
  actions are followed, one level deep.
- **Runtime-only gates.** A gate implemented in a separate script the workflow
  calls, or one that depends on a computed value, is invisible to a file-level
  read.
- **Runtime-computed tool grants.** When the agent's autonomy is passed through a
  shell variable rather than named on the invocation - `claude -p - --allowedTools
  "$ALLOWED"`, where `$ALLOWED` is assembled earlier in the step - the literal
  `Bash`/`Edit`/`Write` tokens are not on the agent's command line, so grackle
  cannot tell a write grant from a read-only one. It anchors on tools named at the
  call site; resolving the variable back to its definition would have to guess at
  read-only cases and would trade silence for false positives.
- **Agents hidden inside a custom wrapper.** When an agent CLI is installed and
  then driven by a project script (for example `npm install -g @github/copilot`
  followed by `python -m your_tool`), the autonomy configuration lives inside
  that script, not in the workflow. Grackle anchors on the agent's own
  invocation and flags direct calls that grant shell/write tools; it does not
  flag every install of an agent CLI, because doing so would fire on the many
  workflows that use those CLIs read-only.

## Model runtimes are not agents

A workflow that only calls a model API or a local runtime (an OpenAI, Cohere, or
DeepSeek endpoint, or `ollama run`) is not flagged. A raw model call has no
shell, no filesystem write, and no repository access. The vulnerable primitive
requires an agent framework that hands the model exec/write tools; when such a
framework is backed by any model, the finding anchors on the framework, not the
model.

## Use it as one layer

Grackle catches the fork-triggerable-agent composition well and quietly. Pair it
with the controls you already trust (branch protection, required reviews,
least-privilege tokens, org-level Actions policy) for defense in depth.

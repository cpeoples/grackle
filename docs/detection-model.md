# Detection Model

Grackle does not match on a blocklist of repositories or agent names alone. It
reasons structurally about three properties of a workflow, per job, and only
reports when all three hold at once.

## 1. Fork-reachable trigger

The workflow runs on an event an outside contributor can cause:
`pull_request_target`, `pull_request`, `issue_comment`, `issues`,
`pull_request_review`, `pull_request_review_comment`, a reusable
`workflow_call` reached from one of these, or a `workflow_run` consumer chained
off a fork-PR-triggered producer that ingests the fork run's data (artifact,
`head_sha`, or linked PR) without a same-repo guard.

A job is *not* reachable when its own `if:` confines it to a non-fork event
(`github.event_name == 'push' | 'schedule' | 'workflow_dispatch'`,
`pull_request.merged == true`, a protected-branch ref) or hard-disables it with
`if: false`. A guard on a sibling job never suppresses the agent job.

## 2. No author gate

Nothing restricts who may trigger the agent. Grackle recognizes the common
gates and treats their presence as safe:

- `author_association` in `OWNER` / `MEMBER` / `COLLABORATOR`
- `getCollaboratorPermissionLevel` / `permission.permission` checks
- owner-equality (`github.actor == github.repository_owner`)
- allowlists (`contains(vars.ALLOWED_USERS, ...login)`)
- fork-exclusion checks and maintainer-only label gates

## 3. Write-capable agent job

The job that runs the agent can mutate the repository: it declares
`contents: write` / `permissions: write-all`, inherits a workflow-level write
default it does not narrow, pushes directly (`git push`, `gh pr create|merge`),
grants the agent exec/write tools (`Bash`, `Edit`, `Write`), or runs the agent
in an auto-approve mode (`--dangerously-skip-permissions`, `--yolo`,
`--permission-mode bypassPermissions`).

## How rules are structured

Each rule is pure data: an **anchor** regex that locates an agent invocation, an
evaluation **family** that decides the post-filter, shared compliance
**metadata**, and self-contained positive and negative **examples**. A single
engine owns evaluation, so rules never reach into scanner internals.

- **Installed** rules anchor on an agent CLI or action name and confirm the
  family with a whole-file proof, so a bare binary name does not match unrelated
  tooling.
- **Action** rules anchor on an action configured to open itself to forks (a
  write sandbox, `allowed_non_write_users: "*"`, YOLO/auto approval).
- **GitLab** rules use GitLab-native reachability, gating, and write-capability
  detection rather than the GitHub `on:`/`permissions:` model.

## Composite / local actions

An agent is sometimes hidden one level down: the workflow step is
`uses: ./.github/actions/foo` and the real invocation lives in that action's
`action.yml`. When grackle scans a **directory** it resolves each local
`uses: ./<path>` reference off disk and inspects the referenced action, attributing
any agent it finds to the caller workflow at the `uses:` line. Reachability,
gating, and write capability still come from the caller job, since that is where
the trust boundary and token live. Resolution is one level deep.

## GitLab CI

GitLab's fork-pipeline model differs from GitHub Actions: a fork merge-request
pipeline runs in the fork with the fork's variables, so the parent's protected
secrets are not injected by default. A `.gitlab-ci.yml` agent job is flagged
(HIGH) when it runs on merge-request content, is handed write or execute
capability, and is not self-gated. It is HIGH rather than CRITICAL because final
exploitability also depends on project settings not visible in the file. GitLab
findings are suppressed by a fork-ID guard, a source-branch-name gate, a job
gated on a project-internal variable, read-only tools, `--permission-mode plan`
with no offsetting write capability, or a fork-scoped `CI_JOB_TOKEN`.

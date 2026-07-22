# Fork-Triggerable AI Coding Agents in CI: A Wide-Net Survey

## Abstract

AI coding agents (Claude Code, Cursor, OpenCode, Codex, Gemini, and roughly two
dozen others) are increasingly wired directly into CI pipelines to triage
issues, review pull requests, and land fixes. When such an agent runs on
untrusted input from a fork, in a job that can write to the repository, and
without a check on who triggered it, prompt injection becomes remote code
execution and repository takeover under the CI token.

We built a scanner for this exact primitive and ran it against a large,
opportunistically collected corpus of real-world CI workflows. Across **73,937
workflow files from 16,864 projects**, on both GitHub Actions and GitLab CI, we
found **589 fork-triggerable agent vulnerabilities in 534 of those projects**,
across every major agent family in use today. On a **blind subset
of 3,391 previously unseen files**, its precision was **~98%**, rising to
effectively 100% after several false-positive classes were closed.

This paper describes the vulnerability class, the detection model, and the
aggregate distribution of what we found. In keeping with responsible
disclosure, **no vulnerable project is named**; we report only anonymized
aggregate statistics. Where we name specific popular repositories, it is only
to illustrate that they run an agent in CI *safely* (they did not produce a
finding); no named project is a vulnerable one.

## 1. The vulnerability class

A CI workflow exhibits the vulnerability when **all three** of the following
hold at once:

1. **Fork-reachable trigger.** The workflow runs on an event an outside
   contributor can cause: `pull_request_target`, `pull_request`,
   `issue_comment`, `issues`, `pull_request_review`, `pull_request_review_comment`,
   a reusable `workflow_call` reached from one of these, or a `workflow_run`
   consumer chained off a fork-PR-triggered producer (the privilege-escalation
   pattern described in §2).

2. **No author gate.** Nothing restricts *who* may trigger the agent. There is
   no `author_association` check, no `getCollaboratorPermissionLevel` call, no
   owner-equality guard (`github.actor == github.repository_owner`), no
   allowlist (`contains(vars.ALLOWED_USERS, ...login)`), no fork-exclusion
   check, and no maintainer-only label gate.

3. **Write-capable agent job.** The job that runs the agent can mutate the
   repository, either by declaring `contents: write` / `permissions:
   write-all`, by pushing directly (`git push`, `gh pr create|merge`), by
   granting the agent exec/write tools (`Bash`, `Edit`, `Write`), or by running
   the agent in an auto-approve mode (`--dangerously-skip-permissions`,
   `--yolo`, `--permission-mode bypassPermissions`).

When these coincide, an attacker who opens a pull request or writes an issue
comment controls the text the agent reads. Because agents are instructed to act
on that text and hold a write-scoped token, a crafted prompt can exfiltrate
secrets, push commits, open or merge pull requests, or execute arbitrary shell
commands on the runner. The trust boundary that normally protects a base
repository from fork contributors is erased.

### How the attack works, concretely

An outside contributor opens a pull request. The visible change looks routine,
but its description carries hidden instructions written for the agent, not the
reviewer. A CI job fires automatically on that pull request and passes the
description to an AI coding agent. The job holds a token that can write to the
repository, and the agent is allowed to run shell commands, so it treats the
attacker's text as a task and carries it out under the repository's own identity:
it reads a secret and posts it back as a comment, or edits a build script and
pushes the commit. No maintainer approved the run, and nothing checked that the
person who opened the pull request had any write access. The attacker never
needed credentials of their own; they borrowed the repository's.

The impact escalates along a predictable ladder. Prompt injection first yields
arbitrary command execution on the runner. From there the agent's environment
exposes every secret in scope (`GITHUB_TOKEN`, `ANTHROPIC_API_KEY`,
`GEMINI_API_KEY`, cloud keys) which the agent can be steered to print or post
back through GitHub itself, needing no attacker infrastructure. With
`contents: write` and a privileged token, the same injection can **poison the
repository**: commit malicious code, alter workflow files, or open and merge a
pull request under the repository's own identity. On a widely depended-on
project this is a **supply-chain compromise** reaching every downstream consumer
within the token's validity window, and where a long-lived PAT or app token is
in scope it approaches full **account takeover** of the automation identity.
This is not theoretical severity: the same class was rated CVSS 9.4 (Critical)
by at least one agent vendor during coordinated disclosure.

### What is *not* vulnerable

The model deliberately does not flag review-only agents (`contents: read`,
comment-only scope), agents behind an author or fork-exclusion gate, jobs
confined to non-fork events (`push`, `schedule`, `workflow_dispatch`, merged
pull requests, protected-branch refs), or jobs hard-disabled with `if: false`.
These distinctions are what keep the false-positive rate low.

The model also draws a line between a **model runtime** and an **agent
framework**. A workflow that only calls a model API or a local runtime (an
OpenAI, Cohere, or DeepSeek endpoint, or `ollama run` / `ollama pull` feeding a
prompt) is not flagged. A raw model call has no shell, no filesystem write, and
no repository access; it cannot be steered into repository mutation on its own.
The vulnerable primitive requires an agent framework that hands the model
exec/write tools. When such a framework is *backed by* Ollama or any other model
(Goose, OpenHands, Aider, Continue, and gptme can all run against a local
Ollama), the finding is anchored on the framework, not the model, so the backing
model is irrelevant to detection.

### A note on GitLab

GitLab's fork-pipeline model differs from GitHub's: a fork merge-request
pipeline runs in the fork with the fork's variables, so the parent's protected
secrets are not injected by default. The primitive still exists, but through
different paths (unprotected variables, comment-posting tokens escalated to
write, manual-but-ungated jobs), and it is scored HIGH rather than CRITICAL
because final exploitability depends on project settings not visible in the
file. GitLab findings are gated on GitLab-native signals (fork-ID guards,
source-branch-name gates, project-internal variable gates, `--permission-mode
plan` read-only mode).

## 2. Detection method

The scanner is a standalone tool that parses CI YAML directly and evaluates each
candidate agent invocation against the three conditions above. Detection is
structural, not signature-matching on a blocklist of repos:

- **Anchors** locate an agent invocation (a known CLI or a known action).
- **Family proofs** confirm the match belongs to a real agent framework rather
  than incidental prose or an unrelated tool.
- **Reachability and gating post-filters** apply the trigger, author-gate, and
  write-capability logic per job, so a guard on a sibling job does not suppress
  the agent job and a disabled step does not mask an active one.

Coverage spans **36 rules** across **~32 agent families**: 20 installed-agent
CLIs/actions (Claude Code, Cursor, OpenCode, Amp, Goose, Droid, Aider,
OpenHands, Qwen Code, Crush, Copilot CLI, Continue CLI, gptme, SWE-agent, Warp
(CLI and the Oz cloud-agent action), Gemini CLI, Devin, Kilo Code, CodeMie, and
a name-independent bespoke `run:`-shell LLM agent), 14
action-configuration rules (generic write/exec tools, repo-mutating `gh` tools,
Gemini/Copilot, Codex sandbox, JetBrains Junie, ask-bonk (an OpenCode wrapper),
Cogni AI, Letta Code, potproject/code-agent (a Claude Code/Codex wrapper), the
cognitivecomputations AI-refactor action, the a5c agent router, the iFlow
CLI action, Sweep, and PR-Agent), 1 name-independent shell-exec rule (any of the
common CLIs handed an arbitrary shell on fork content in a secret-bearing job
without provable repository write - a secret-exfiltration risk scored HIGH), and
1 GitLab-native rule.

An agent is sometimes hidden one level below the workflow: the workflow step is
`uses: ./.github/actions/foo` and the real invocation lives in that action's
`action.yml`. When scanning a checked-out repository the tool resolves each local
`uses: ./<path>` reference from disk and inspects the referenced action
definition, attributing any agent it finds to the caller workflow, gated on the
caller job's reachability and write capability. One residual limitation of this
resolution is deliberate: when the agent CLI lives in the composite body but its
auto-approve flag (`--dangerously-skip-permissions`, `--yolo`) is supplied by
the caller's `with:` inputs rather than written literally in the action, the
tool declines to fire, because it cannot prove the agent runs unattended from
the action definition alone. A corpus sweep for this exact shape - a
fork-reachable, ungated caller passing an auto-approve flag into an
agent-invoking composite - found **zero** real instances across all 73,937
files, so we treat it as a documented edge rather than a machinery-justifying
gap.

### The `workflow_run` privilege-escalation trigger

A subtle but real fork-reachable path is the `workflow_run` pattern. A first
workflow runs on a fork's pull request in the *unprivileged* fork context; when
it completes, a second workflow triggered by `on: workflow_run` runs in the
**base repository** with the base repo's write token and secrets. If that second
workflow then ingests data from the triggering run - the fork's uploaded
artifact (`actions/download-artifact` with `run-id: workflow_run.id`), its
`head_sha` (checked out and operated on), or its linked `pull_requests` - and
feeds it to a write-capable agent, an outside contributor drives a privileged
agent exactly as in the direct-trigger case. `workflow_run` is deliberately kept
out of the blanket fork-reachable trigger list because most uses are benign
("comment on my own CI failure"); the scanner isolates only the dangerous subset
with three joint conditions: the consumer (1) ingests triggering-run data, (2)
is **not** guarded to same-repo sources (`workflow_run.head_repository.full_name
== github.repository` or `head_repository.fork == false`), and (3) is not
restricted to non-fork producer events (`workflow_run.event == 'push' |
'schedule' | 'release'`). Write capability and the agent anchor are judged
separately, so a `contents: read` reviewer chained off `workflow_run` never
fires. This pattern accounts for a distinct slice of the findings - most visibly
the "auto-fix on CI failure" family (`fix-ci.yml`, `claude-autofix.yml`,
`cursor_fix_ci_failures.yml`), where a fork PR's failing test run silently
escalates into a write-capable agent editing the checked-out fork branch.

### Autonomous mode via `claude_args`

`anthropics/claude-code-action@v1` grants tool permissions two ways: the legacy
`allowed_tools`/`allowedTools` list, and the newer `claude_args` string that
passes flags straight to the underlying `claude` CLI. A workflow that sets
`claude_args: '... --permission-mode bypassPermissions'` (or
`--dangerously-skip-permissions`, `--permission-mode acceptEdits`) grants the
agent full unattended shell and file-write capability **without any
`allowedTools` list at all**. The scanner recognizes this autonomous-mode shape
in addition to the explicit tool grant; in the corpus, of 3,258
claude-code-action files, 685 used such an auto-approve flag, and the
fork-reachable, write-capable, ungated subset is a substantial fraction of the
generic write/exec-tools findings.


Each finding ships with a **dynamically generated remediation** (the vulnerable
snippet, an explanation, and a corrected workflow) and carries control-framework
metadata (CWE, OWASP, MITRE ATT&CK and ATLAS). Findings can be emitted in eleven
formats including SARIF, GitLab SAST, and CycloneDX for direct ingestion into
existing security tooling.

## 3. Corpus and methodology

Workflow files were collected by content search across public GitHub and GitLab
repositories, targeting `.github/workflows/` and `.gitlab-ci.yml` files that
reference known agent CLIs, agent actions, or autonomy flags. Collection used
multiple axes (family-name queries, invocation-shape queries, newest-first
paginated sweeps, a star-ranked sweep of the most popular agent-in-CI
repositories, and an *unbiased* star-window sweep that enumerated the most-starred
repositories regardless of whether they mention an agent, to avoid selection bias
in the popularity tail, and a broad *shape-and-name* discovery sweep that searched
for autonomy flags and agent tokens across both GitHub Actions and
GitLab-CI-on-GitHub surfaces and fetched only repositories not already collected)
with throttling and exponential backoff to respect API
rate limits. After deduplication the combined corpus was **73,937 workflow files
across 16,864 distinct projects**.

Every file was scanned once, with findings reported one per rule per *job* so a
workflow that names an agent CLI on several lines of one job (an install step
and a run step, say) counts as the single vulnerability it is rather than
several, while the same agent wired into two separate jobs counts as two.
Findings were then triaged: a large blind subset was hand-verified against the
file-visible signals to measure precision, and the full corpus was re-scanned
after each detection change to confirm no regression in recall.

**Limitations.** The corpus is a convenience sample bounded by code-search
recall, not a random sample of all public CI, so counts are a lower bound rather
than a population estimate. Star counts are point-in-time. The scanner reasons
only from the workflow file; final exploitability can depend on repository
settings not visible in the file (token protection, branch protection, whether
an action self-gates), which is why repo-mutation and GitLab findings are scored
HIGH rather than CRITICAL.

## 4. Results

### 4.1 Headline

| Metric | Value |
| --- | --- |
| Workflow files scanned | 73,937 |
| Findings | 589 |
| Distinct affected projects | 534 |
| Platforms affected | GitHub Actions and GitLab CI |
| Agent families implicated | 28 (of 36 rules) |
| Blind-subset precision | ~98% (→ ~100% after several FP classes closed) |
| Scan stability | 0 hangs / 0 timeouts across 73,937 files |

A finding is counted **once per vulnerable job**, not once per line. A single
agent invoked on several lines of one job (an install step and a run step, or
repeated `run:` blocks) is one vulnerability, and the finding records every
invocation line so a reviewer sees each spot the agent is reached. The *same*
agent wired into two *separate* jobs of one workflow counts as two findings,
because those are genuinely distinct vulnerable entry points, each needing its
own fix. This job-scoped counting is what keeps the headline number an honest
count of vulnerabilities rather than an inflated count of pattern matches.

### 4.2 By platform

| Platform | Findings |
| --- | --- |
| GitHub Actions | 571 |
| GitLab CI | 18 |

The primitive is overwhelmingly a GitHub Actions phenomenon, consistent with
`pull_request_target` and comment-triggered agent bots being GitHub-native
patterns. GitLab still contributes a non-trivial tail.

### 4.3 By agent family

| Agent family (rule) | Findings |
| --- | --- |
| PR-Agent (action) | 155 |
| OpenCode | 124 |
| Generic action write/exec tools | 45 |
| Claude Code (raw CLI) | 41 |
| Droid | 34 |
| Cursor | 31 |
| Agent shell-exec (secret exfiltration) | 26 |
| Gemini/Copilot (action) | 22 |
| Bespoke `run:`-shell LLM agent | 19 |
| GitLab CI agent (native) | 18 |
| Codex (write/exec sandbox) | 16 |
| Goose | 7 |
| Aider | 7 |
| Copilot CLI | 6 |
| Cogni AI (action) | 6 |
| Gemini CLI | 5 |
| Warp | 4 |
| CodeMie | 4 |
| Repo-mutating `gh` tools (action) | 4 |
| OpenHands | 3 |
| JetBrains Junie | 3 |
| Sweep (action) | 2 |
| Amp | 2 |
| SWE-agent | 1 |
| gptme | 1 |
| code-agent (Claude/Codex wrapper) | 1 |
| AI-refactor / AI GitHub action | 1 |
| a5c agent router (action) | 1 |

ask-bonk (Bonk) has a dedicated rule but produced **zero findings**: every
Bonk deployment in the corpus sets `permissions: CODEOWNERS`/`write` or
`token_permissions: NO_PUSH`, so its rule stays armed for the misconfiguration
while the ecosystem uses it safely - a precision-first outcome worth stating
explicitly. JetBrains **Junie**, by contrast, moved from zero to three findings
once the discovery net widened: Junie self-gates on write access by default, but
three deployments - including one in **the vendor's own example workflow** -
bypass that default by supplying a custom `prompt:` on a fork-reachable trigger,
exactly the documented gate-bypass its rule is written to catch (see §5).

The distribution has a long tail: PR-Agent and OpenCode together account for
roughly half of all findings, but the pattern recurs across every agent
ecosystem we have rules for. **PR-Agent** (`qodo-ai/pr-agent`) is now the
single largest family: it has no built-in author gate, processes untrusted PR
and issue text, and is frequently wired with repository write, so a fork-
reachable deployment is exploitable out of the box. Raw
`claude ... --dangerously-skip-permissions` invocations remain a major family
once the anchor was made tolerant of shell line-continuations (agents are
frequently invoked as a multi-line command with the bypass flag on a
`\`-continued line), a purely mechanical detection improvement that surfaced a
cluster of previously-invisible true positives. The newest family - **agent
shell-exec with secret exfiltration** - captures a distinct risk shape: a
fork-reachable, secret-bearing job hands an agent an arbitrary shell on the
fork's checked-out code without any provable repository write, so the exposure
is credential theft rather than a repo push (scored HIGH, one tier below the
write-capable CRITICAL rules). This is a class-wide problem, not a single
vendor's bug.

### 4.4 By project popularity

Affected projects span the full popularity spectrum, from experiments to
widely-starred repositories:

| Star tier | Affected projects |
| --- | --- |
| 100,000+ | 1 |
| 20,000 - 49,999 | 2 |
| 10,000 - 19,999 | 2 |
| 1,000 - 9,999 | 15 |
| 100 - 999 | 21 |
| 10 - 99 | 37 |
| 0 - 9 | 445 |

The popularity and owner breakdowns below were enriched on an earlier
523-project snapshot; the headline total of 534 reflects the final scan. The
11-project difference sits in the 0-9 star tail and does not change any tier
above 100 stars or the owner-class proportions.

The bulk of findings sit in small and early-stage projects, which is expected:
those repos adopt agent-in-CI wiring fastest and harden it least. But the
vulnerability is **not confined to hobby projects**. **41 affected projects
have 100+ stars, 20 have 1,000+, and five exceed 10,000** - the most-starred
exceeding **185,000 stars**, with others in the 28,000, 20,000, 12,000, and
10,000 star ranges. Popular, actively-used repositories are exposed too.
(Specific project identities are withheld pending coordinated disclosure.)

**The adoption ceiling far exceeds the vulnerability ceiling - but the top of
the curve is not immune.** Agent-in-CI wiring itself reaches the very top of the
popularity curve: among the repositories we searched, projects as large as
`microsoft/vscode` (187k★), `google-gemini/gemini-cli` (106k★), `keras-team/
keras` (64k★) and dozens more in the 10k-100k band run an AI coding agent in
their pipelines. To test the top of the curve without any selection bias, we ran
a separate **unbiased star-window sweep** that enumerated the most-starred
repositories on GitHub *regardless of whether they mention an agent* and fetched
**every workflow file** of each: **6,330 repositories at 8,000+ stars, of which
5,331 exceed 10,000 stars, 2,176 exceed 20,000, 461 exceed 50,000, and 117
exceed 100,000** (topping out at 527,970★). The overwhelming majority of that
mega-star tail is clean - where these repositories run an agent at all, they
gate it behind an author-association or non-fork check, run it read-only, or
restrict it to trusted events. But "overwhelming majority" is not "all": the
agent-targeted hunt surfaced a finding in a **185k-star flagship project** - a
`workflow_run`-triggered "auto fix CI failures" workflow that checks out the
failed PR's `head_branch` under `contents: write` and runs `claude-code-action`
with `Edit`/`Write`/`Bash(git:*)`/`Bash(gh:*)` tools, then pushes a fix branch.
A fork PR that fails CI can therefore steer an autonomous, write-capable agent
over its own branch. That the exploitable recipe reaches a 185k-star flagship
shows the mistake is not confined to the long tail; it is just *rarer* at the
top, and grackle's job-scoped gating is what lets it find the rare exception
without drowning the thousands of correctly-gated mega-star workflows in false
positives. (The affected project is identified only in a private,
coordinated-disclosure dossier, not here.)

### 4.5 By repository owner

Stars measure attention; they do not measure who is on the hook when a repo is
compromised. Classifying each affected project by the GitHub account that owns
it - an organization versus an individual, and for organizations a rough proxy
for reach (public follower count) - reframes the blast radius around
responsibility rather than popularity.

| Owner class | Affected projects |
| --- | --- |
| Organization (1,000+ followers) | 9 |
| Organization (100-999 followers) | 21 |
| Organization (<100 followers) | 120 |
| Individual / personal account | 373 |

**150 of 523 affected projects (29%) are owned by an organization, not an
individual**, and several are funded companies or established
institutions with thousands of followers rather than hobby orgs. Most strikingly,
the widened discovery sweep surfaced two **major agent vendors' own repositories**
in the top follower tier (13,000+ and 3,900+ followers respectively): one ships a
`workflow_run`-triggered "fix failed checks" example that checks out a fork PR's
branch under `contents: write` with no author gate, and the other publishes a
reusable comment-driven agent template that runs its agent on untrusted comment
text and then `git commit && git push`. That the vendors *demonstrating* the
pattern also demonstrate its insecure form is the clearest evidence that this is a
copy-the-recipe problem, not a downstream misunderstanding. An exposed repository
under a company or foundation account is a materially sharper supply-chain point
than an equally-starred solo project: it typically has more downstream consumers,
more contributors whose comments can trigger the agent, and shared credentials
whose compromise reaches further. The individual long tail still dominates in raw
count, but the organizational slice is where the consequences concentrate. (To
respect responsible disclosure, no owner in this table is a *vulnerable* named
project; owner classes are reported in aggregate.)

## 5. Discussion

Three findings stand out.

**The pattern is ecosystem-wide.** It appears across 28 distinct agent families
and both major CI platforms. Teams are copying the same insecure recipe ("run
the agent on the PR, let it push") regardless of which agent they picked. The
root cause is not any one tool; it is the composition of a fork-reachable
trigger, a write token, and no author check.

**Popularity is not protection.** While most findings are in small repos, a
meaningful fraction are in projects with real user bases. A compromised popular
repository is a supply-chain risk to everyone downstream.

**Detection is tractable with low noise.** Structural, per-job reasoning about
reachability, gating, and write capability distinguishes true exposure from safe
usage well enough to hold ~98-100% precision on unseen code, while remaining
stable and fast at corpus scale. Reaching that precision is an ongoing
discipline of closing false-positive classes as the corpus widens: the write-
capability check, for example, was hardened to ignore YAML and shell comments
after a workflow whose only "write" token was the string `git push` *inside a
security-note comment* (`# a stray git push here would use base creds`) was
briefly mis-flagged. That single fix removed the corpus's highest-starred
"finding," which was in fact a correctly-hardened, read-only review bot -
a reminder that at the very top of the popularity curve the safe cases must be
read as carefully as the dangerous ones. A second class was closed as the
corpus widened to include GitHub-Next's *Agentic Workflows* (`gh-aw`) framework,
which compiles an agent spec into a `.lock.yml` whose agent job is gated
transitively - through a `pre_activation` team-membership job two `needs` hops
away from the invocation - rather than by an inline `author_association` check.
The gate is real but invisible to a per-job scan, so grackle now recognizes the
compiled-file signature together with its membership-check wiring and treats the
whole family as gated. This matters at scale: the corpus contains **1,606**
`gh-aw` compiled workflows, and after the fix all of them are correctly read as
safe.

A third class was closed around reusable workflows. A `workflow_call`-only file
is not itself fork-reachable - its reachability is decided by whichever caller
`uses:` it - so a reusable definition whose agent consumes only in-repo prompt
files (no `github.event.*` untrusted field, no issue/PR/comment identifier
input) cannot be judged exploitable in isolation and is suppressed; a reusable
workflow that *does* take an untrusted body/title or an issue/PR number it will
dereference still fires. Closing this class removed a run of reusable-workflow
"findings" (repositories named `*/reusable-workflows`, `*/shared-workflows`,
`*/actions`) that were library definitions rather than live vulnerable
endpoints, and is the main reason the headline count is lower than an earlier,
pre-suppression snapshot even though the corpus roughly tripled in size.

Precision work also has an offensive complement: to guard against *missing*
agents rather than mis-flagging safe ones, the corpus was swept
**agent-agnostically** - searching for the vulnerability *shape* (a fork-
reachable trigger installing or invoking an arbitrary tool that ingests
untrusted input in a write-capable job) and extracting every tool name that was
not already one of the covered families. That pass surfaced three genuine
net-new agent actions - JetBrains **Junie**, **ask-bonk** (an OpenCode wrapper
used by, among others, Cloudflare), and **Cogni AI** - which were added as
rules. Two of the three self-gate on write access by default (Junie via a
built-in permission check that only a custom `prompt:` input bypasses; Bonk via
its `permissions: admin/write/CODEOWNERS` input), so their rules are written to
fire only on the documented gate-bypass and produce zero findings against the
safe deployments actually present in the corpus.

Two further **recall** gaps were closed after auditing the corpus for
under-detection (the mirror image of the precision work above). First, the
`workflow_run` privilege-escalation trigger (§2): grackle now treats a
`workflow_run` consumer as fork-reachable when it ingests the triggering run's
data, is not same-repo-guarded, and is not restricted to non-fork producer
events. This surfaced a distinct "auto-fix on CI failure" family that direct-
trigger reachability had missed, while the same-repo-guarded and push-only
variants - the majority - correctly stay silent. Second, the
`anthropics/claude-code-action@v1` autonomous mode via
`claude_args: --permission-mode bypassPermissions` /
`--dangerously-skip-permissions` (§2), a full write/exec grant that uses no
`allowedTools` list and was therefore invisible to the earlier tool-grant anchor.
Both closes were validated against the full corpus with no new false positives
in an audit of the affected findings; together they account for the increase
from a pre-audit 252 to 315 findings, entirely from genuine
previously-missed exposures rather than any loosening of the gate logic.

A final precision refinement came from the unbiased star-window sweep. Adding
its ~7,000 net-new most-starred workflow files (growing the corpus to 46,484
files across 13,053 projects) produced exactly one new candidate - a reusable
workflow whose agent job was reached only after a separate `check-permission`
job verified the commenter against an explicit allow-list, exposed transitively
as `if: needs.check-permission.outputs.allowed == 'true'`. The scanner now
recognizes this multi-job authorization gate (a job-output guard on the
agent-bearing job combined with permission-check wiring elsewhere in the file)
as the equivalent of the inline author gate, so the candidate correctly does
not fire. The finding and project totals therefore held at 315/265 even as the
denominator grew, which is the intended behavior for an unbiased popularity
sweep: it strengthens the base rate without inflating the numerator.

Two further refinements closed the numerator from 315/265 to the final
**313/264**. First, a GitLab-specific author gate: a job whose only
merge-request rule carries `when: manual` is not started automatically - in a
GitLab MR pipeline a manual job requires a project member with pipeline access
to press "play," so an outside fork contributor who merely opens an MR cannot
drive it. The scanner now treats such a job as gated (the GitLab analogue of
GitHub's manual-dispatch guard), but *only* when every merge-request rule is
manual and the job carries no other rule that auto-runs on fork-controllable
input (a `$CI_COMMIT_MESSAGE`/title regex, a `@agent` comment webhook, or a bare
MR rule that defaults to `on_success`). This suppressed two candidates - a
manual-only `claude -p` review job in the widely-used PETSc scientific-computing
library's mirror, and the manual review job in an autonomous-driving lab's
pipeline - while leaving their auto-triggered siblings and every mixed
manual+comment job (which a fork commit message still fires) correctly firing.

Second, we validated the GitLab surface through an independent collection path.
GitLab CI is frequently mirrored onto GitHub, where the pipeline lives in a
root `.gitlab-ci.yml` that `include:`s fragments under `.gitlab/`, `.workflows/`,
or `ci/` - files our GitHub collection, scoped to `.github/workflows/**`, never
saw. A dedicated probe searched GitHub for `.gitlab-ci.yml` (and its split
fragments) invoking an agent CLI, then fetched each hit's root file plus all
included fragments so the scanner could reason across the split pipeline. It
surfaced 14 firing projects - **every one of which was already in the corpus**
via the direct gitlab.com collection, and zero net-new - an encouraging
cross-method agreement that the GitLab findings are neither a collection artifact
nor undercounted. Notably, high-collaboration mirrors of major projects that
merely *mention* an agent (e.g. Datadog's `dd-trace-py`/`dd-trace-php`, 500+ and
180+ forks) did **not** fire: their agent references sit in benign, non-fork-
reachable contexts, exactly the true negatives a precision-first scanner must
produce.

Finally, the numerator grew from 313/264 to 358/306 in a broad *shape-and-name*
discovery sweep that deliberately looked past the families and repositories
already in hand. It
searched GitHub for autonomy shapes (`--dangerously-skip-permissions`,
`bypassPermissions`, `--yolo`, `--full-auto`) and the full agent-token vocabulary
across both GitHub Actions and GitLab-CI-on-GitHub surfaces, then fetched *only*
repositories not already collected - 3,630 net-new repos, 27,459 files, growing
the corpus to 73,937 files across 16,864 projects. Scanning that net-new slice
with the frozen ruleset produced **45 findings across 42 net-new projects**, and
a hand audit of all 42 confirmed every one is genuinely fork-reachable, ungated,
and write-capable - zero false positives, and, notably, zero *new rule gaps*:
every finding was caught by an existing rule, which is the strongest signal yet
that the family coverage is saturated. The pass added the two vendor-owned cases
discussed in §4.5 and a cluster of the `workflow_run`
"auto-fix on CI failure" family (`cursor_fix_ci_failures.yml`, `fix-ci.yml`,
`fix-failed-checks.yml`) that the earlier `workflow_run` recall work had predicted
would exist and this sweep confirmed in the wild. That a 59%-larger corpus moved
precision not at all - every net-new candidate survived audit - is the reassuring
counterpart to the recall story: widening the net finds more real exposures
without manufacturing false ones.

As a final independent check, we re-scanned the entire corpus with a *separate,
grackle-agnostic* detector that keys on the vulnerability's shape - a
fork-reachable trigger, an autonomy/write signal, and a generic "agent" hint -
while explicitly excluding every agent grackle already knows, so that only
genuinely unknown families could surface. After triaging the resulting
candidate actions (the large majority are review/comment-only bots or CI-infra
name collisions, both out of scope) and hand-auditing every ungated,
fork-reachable, write-capable hit, the sweep surfaced no novel *vulnerability
shape* - only three new agent *products* not yet named by a rule: the
`potproject/code-agent` Claude/Codex wrapper, the `cognitivecomputations`
AI-refactor action, and the `a5c` agent router. Adding those three rules moved
the totals to **361 findings across 309 projects** with zero regressions and no
collateral false positives, confirming that grackle's detection *model* was
already complete and only its family vocabulary needed extending.

A subsequent, deliberately adversarial pass hardened this conclusion. Rather
than key on action names at all, we re-ran the grackle-agnostic detector over
every fork-reachable, write-capable job that carries *any* LLM runtime signal
(a provider API key, a model runtime, an MCP server, or an autonomy flag),
subtracted every agent and review-only bot already accounted for, and
hand-audited the residue - including bespoke agents invoked through `run:` shell
(`bun run cli.ts --yolo`, `node implement-with-glm.mjs`, `python agent.py`),
local/composite-action wrappers (`uses: ./.github/actions/...`), and GitLab-CI
files hosted on GitHub. Every genuinely ungated, fork-reachable hit resolved to
either an agent grackle already covers or a bespoke, repo-local LLM script with
no named CLI/action to anchor on - an inherent, documented boundary of a
signature-based model, not a missed vulnerability class. The one *actionable*
gap the pass surfaced was an anchor omission, not a model omission: GitHub
Copilot CLI's autonomous `--yolo` / `--enable-all-github-mcp-tools` invocation
form, which the existing Copilot rule (anchored on `--allow-all-tools` /
`--allow-tool`) did not recognize. Extending the anchor to the `--yolo` form -
and, in the same pass, teaching the write-capability check to ignore `git push`
/ `gh pr` verbs that appear only as *quoted string data* in a test/eval workflow
(a false-positive class the broader anchor would otherwise have introduced) -
moved the totals to **365 findings across 313 projects** with zero regressions
and no collateral false positives.

A final, still-more-adversarial sweep converted the one documented *boundary* of
the signature model into a detector. Auditing the ~24 grackle-silent, ungated,
fork-reachable, write-capable jobs that invoke an LLM through inline `run:` shell
rather than a named CLI, we found their common anchor is not a vendor name but
the **completions/messages endpoint the workflow talks to** - an
`api.openai.com/v1`, `/v1/chat/completions`, `api.anthropic.com/v1`, or
compatible base-URL, whether it appears in a `curl` line or a provider base-URL
env that a local script then POSTs to. A tight behavioral rule anchored on that
API *shape*, gated on untrusted trigger payload flowing into the prompt and on
the job being fork-reachable, ungated, and write-capable, promotes this class
from "inherent boundary" to a firing detector (20 findings) without naming any
vendor. The same sweep surfaced one more named product - CodeMie
(`@codemieai/code`) - added as its own rule. Hand-auditing every new hit then
exposed two *false-positive* classes the broad anchor would otherwise admit,
both closed with precise gates rather than by narrowing the rule: (i) a
**same-job allow-list step gate**, where every privileged step is guarded by
`if: steps.<check>.outputs.authorized == 'true'` fed by a hardcoded maintainer
whitelist (observed across 12 projects), and (ii) an
**indirect author-association gate**, where `github.event.*.author_association`
is captured to an env var and an inline script rejects everyone but
`OWNER`/`MEMBER`. With the generic rule
also suppressed wherever a precise vendor rule already owns the same job, and
after several mechanical detection refinements - making the raw-`claude` anchor
tolerant of shell line-continuations (agents are routinely invoked as a
`\`-continued multi-line command with `--dangerously-skip-permissions` on a
later line); correctly handling **OR-gate bypasses**, where a job's `if:`
ORs an author-gated disjunct with an *ungated* fork-reachable one (e.g.
`pull_request_review` + `changes_requested`) so the coarse whole-file author
gate must not suppress it; recognizing Claude Code's `--permission-mode auto`
as an autonomous mode (it auto-approves every tool with only a background
classifier, unlike the lockdown `dontAsk` mode, which is correctly *not*
treated as a bypass); treating `discussion` and `discussion_comment` as
fork-reachable triggers (anyone can open or comment on a discussion, exactly
like an issue); and recognizing `github.event.pull_request.user.login ==
'<bot>'` (e.g. `dependabot[bot]`) as a sound trust gate, since such PRs always
branch inside the base repository and never a fork - the totals settled at
**589 findings across 534 projects** across **36 rules**, with zero
regressions and no collateral false positives. The net effect reinforces
the central claim: the vulnerability *shape* grackle models is saturated, and
continued digging now yields anchor refinements and gate precision rather than
new detection categories.

## 6. Related work

The exploitability of AI agents in GitHub Actions has been demonstrated in
prior disclosures. The most directly related is "Comment and Control" (Guan,
Liu, and Zhong, disclosed April 2026), which showed that a single crafted pull
request title or issue body can hijack three widely deployed agents (Anthropic
Claude Code, Google Gemini CLI, and GitHub Copilot) into executing shell
commands and exfiltrating CI secrets back through GitHub, with Anthropic rating
its variant CVSS 9.4. Cloud Security Alliance and Rescana published concurrent
advisories framing the same pattern as a software supply-chain risk and mapping
it to CWE-1427 (improper neutralization of untrusted input used for LLM
prompting).

Those works are **vulnerability demonstrations**: they prove the exploit deeply
on a small set of named agents and drive vendor fixes. This paper is
complementary and **measurement-oriented**. Rather than proving one exploit, it
asks how widespread the composed primitive is across the whole ecosystem, and
whether it can be detected statically at scale with low noise. Where prior work
covers roughly three agents, the scanner here reasons about ~32 agent families
across both GitHub Actions and GitLab CI, reports anonymized prevalence over a
seventy-four-thousand-file corpus, and ships a reproducible detection model rather
than a proof-of-concept. The two lines of work reinforce each other: the
disclosures establish that the primitive is critical, and this survey
establishes that it is common.

A parallel thread targets agent tool servers rather than CI workflows. Invariant
Labs (May 2025) showed that a public issue could steer an agent using the GitHub
MCP server into reading a private repository and leaking it back through a pull
request, and a July 2026 disclosure against a vendor Azure DevOps MCP server
showed a hidden pull-request comment steering a reviewer's agent across projects
it should not reach. Both are instances of the same trifecta named by Willison:
private-data access, untrusted content, and an exfiltration path in one agent.
These are runtime exploits of a specific integration and depend on an agent
already running with broad credentials. This paper addresses the configuration
that makes such an agent reachable from untrusted input in the first place, and
detects it statically in the workflow definition before any agent runs.

## 7. Recommendations

For teams running AI agents in CI:

1. **Gate on who triggered the run.** Require `author_association` in
   `OWNER`/`MEMBER`/`COLLABORATOR`, or a collaborator-permission check, before
   the agent step.
2. **Separate read from write.** Keep review/triage agents at `contents: read`
   with comment-only scope. Never `git push` from a fork-reachable job.
3. **If the agent must make changes,** have it open a pull request for human
   review rather than committing directly, and run it only after a maintainer
   check.
4. **Treat PR/issue title, body, and comments as untrusted input** to the agent,
   never as trusted instructions.
5. **Scan CI configuration in CI.** This class is detectable statically; catch
   it before it merges.

## 8. Responsible disclosure

No affected project is identified in this document. Statistics are aggregated
and anonymized. Where individual maintainers are notified, they receive the
specific finding and remediation privately, with a reasonable window to fix
before any further discussion.

## Appendix: reproducibility

The scanner, its rule definitions, and its detection logic are open source.
Findings are deterministic given a workflow file; each carries the matched line,
the rule, a severity, control-framework metadata, and a generated fix, and can
be exported as SARIF, GitLab SAST, or CycloneDX for independent verification.

Rather than enumerate every agent's homepage here, the canonical and always-current list of covered families is the rule set itself. Each rule names the family, the exact CLI or action it anchors on, and the invocation shape that makes it dangerous, so a reader can map any finding back to a concrete, distributable tool.

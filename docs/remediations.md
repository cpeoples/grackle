# Remediations

Every finding grackle reports carries a remediation. A finding is not just "this
is wrong" - it is "here is the vulnerable block, here is why it is exploitable,
and here is a safe rewrite you can adapt." The remediation is derived from the
matched rule and the offending snippet, so it names the specific action and pin
in front of you rather than a generic template.

## The three parts

Each finding renders as three blocks, cued by an icon:

- **❌ Vulnerable pattern** - the exact lines that matched, quoted from the
  workflow, so the report points at real code rather than describing it.
- **🔍 Why it is exploitable** - one plain-language sentence tying the pattern to
  its consequence: what an outside contributor gains (secret exfiltration, repo
  RCE, a push or merge under the project's token) and through what mechanism
  (prompt injection on untrusted PR/issue text).
- **✅ Secure fix example** - a self-contained YAML rewrite that closes the hole:
  an author gate, read-only tools, a maintainer-controlled label trigger, or a
  fork-exclusion guard, whichever fits the rule.

## Why the fix is dynamic, not canned

The fix is assembled per finding, not copied from a fixed string. Two things
make it specific:

1. **The pin is lifted from your file.** If the finding is on
   `sweepai/sweep@main` or `anthropics/claude-code-action@v1`, the secure
   example reuses that exact `uses:` reference, so you can paste it back without
   re-pinning.
2. **The gate matches the rule's threat.** A repo-mutating `gh` finding is fixed
   by scoping the agent to the single `gh` command it needs; a Sweep finding is
   fixed with its documented maintainer-`sweep`-label trigger; a Gemini shell
   finding is fixed by disabling `run_shell_command` and manual approval. Each
   family maps to the remediation that actually neutralizes it, falling back to a
   generic write-access gate only for rules without a more specific fix.

## How the fixes stay in sync with the rules

Remediations live beside the rules and are keyed by rule id, so adding or
changing a rule surfaces its fix in both the CLI output and the generated
documentation without a second source of truth. When no tailored fix exists for
a rule id, grackle emits the generic hardening block (gate the job on write
access, keep the agent's tools read-only) rather than leaving the finding
unexplained.

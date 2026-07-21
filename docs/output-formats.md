# Output Formats

`-f`/`--format` selects the format; `-o`/`--output` writes to a file and infers
the format from its extension. `--json` is shorthand for `-f json`.

| Format | Value | Notes |
|---|---|---|
| Text | `text` (default) | Human-readable, with the full remediation. |
| JSON | `json` | Findings with metadata, snippet, and remediation. |
| Markdown | `markdown` / `md` | One section per finding. |
| SARIF 2.1.0 | `sarif` | Rule catalog + `fixes[]`; GitHub code scanning. |
| GitLab SAST | `gitlab-sast` | `gl-sast-report.json` for `artifacts:reports:sast`. |
| JUnit | `junit` | One failing test case per finding. |
| CSV | `csv` | Flat table (RFC 4180). |
| XML | `xml` | Generic findings document. |
| YAML | `yaml` / `yml` | Findings with block-scalar snippet/remediation. |
| HTML | `html` | Self-contained styled report. |
| CycloneDX 1.5 | `cyclonedx` | SBOM `vulnerabilities[]`; Dependency-Track, Snyk. |

Every finding carries its control-framework references (CWE, OWASP AppSec, OWASP
LLM, OWASP ASVS, MITRE ATT&CK, MITRE ATLAS, CIS Controls, NIST 800-53, PCI-DSS,
SOC 2), the offending workflow block, and a dynamic secure-fix write-up derived
from that block: the vulnerable code, why it is dangerous, and a corrected
workflow.

## Confidence

Every finding also carries a confidence of `high`, `medium`, or `low`. It is
derived from the same reachability, gate, and write signals the scanner already
computes, so it needs no per-rule tuning:

- `high` when the job is directly fork-reachable, ungated, and can write to the
  repo or run an autonomous shell. The whole exposure is provable from the file.
- `medium` when the worst case depends on repository state a static read cannot
  see (a fork pull request's provider-secret scope), or when the only path in is
  a narrower OR-gate bypass rather than a plainly ungated trigger.
- `low` is reserved for the weakest reachability still worth reporting.

Confidence measures how much of the finding a static read can prove, not how
severe the outcome is; severity and confidence are independent. The machine
formats also expose a banded numeric (`0.9` / `0.7` / `0.4`) for consumers that
prefer a scalar, but the ordinal is the source of truth. It surfaces in the text
report, `json`, `sarif` (result `properties`), `gitlab-sast` (native
`confidence`), `csv`, `xml`, `yaml`, `markdown`, and `html`.

## Dynamic remediation

Rather than a static string, each finding's remediation is generated from the
matched workflow block. It shows the vulnerable snippet, explains why the
composition is dangerous, and prints a corrected workflow that keeps the agent
useful while closing the fork-reachable write path (an author gate, a read-only
scope, or a maintainer-reviewed pull request instead of a direct push).

# Security policy

## Reporting a vulnerability

Please open a private security advisory via the
[Security tab](https://github.com/cpeoples/grackle/security/advisories/new)
rather than a public issue.

## Scope

In scope:

- Vulnerabilities in grackle itself, e.g. a parser bug that lets a crafted
  workflow file execute code in the scanner process, or a report path that
  leaks a token grackle read out of a scanned file.
- Issues in the published distribution (GitHub release archives, SLSA
  provenance, CycloneDX SBOM, Sigstore signatures).

Out of scope:

- Vulnerabilities in the *CI workflows grackle scans*. A fork-triggerable
  agent that grackle flags is the scanned repository maintainer's issue to
  fix, not a vulnerability in grackle.
- Findings grackle produces against this repository's own rule examples,
  those are deliberate positive fixtures used by `--self-test`.

## Supported versions

Only the latest minor release line is supported. See
[Releases](https://github.com/cpeoples/grackle/releases) for the current
version.

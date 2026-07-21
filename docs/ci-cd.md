# CI/CD Integration

Grackle is a single static binary with no runtime dependencies, so it drops into
any pipeline. It scans a checked-out repository and exits `1` when it finds a
fork-triggerable agent, which fails the job.

## GitHub Actions

```yaml
name: grackle
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # only needed to upload SARIF

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install grackle
        run: cargo install --git https://github.com/cpeoples/grackle.git
      - name: Scan workflows
        run: grackle -o grackle.sarif .
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: grackle.sarif
```

## GitLab CI

```yaml
grackle:
  stage: test
  image: rust:latest
  script:
    - cargo install --git https://github.com/cpeoples/grackle.git
    - grackle -f gitlab-sast -o gl-sast-report.json .
  artifacts:
    reports:
      sast: gl-sast-report.json
```

The GitLab SAST report auto-populates the Security Dashboard.

## Pull request and merge request comments

Beyond the report formats above, grackle can post its findings straight onto the
pull request or merge request it is running against. This works on any repository
(public or private) without GitHub Advanced Security, and gives GitLab true
per-line comments the SAST widget cannot.

Two things get posted:

- A **sticky summary comment**: findings grouped by rule, with the offending
  workflow block and a link to each spot. It is updated in place on later runs
  rather than duplicated, and carries a "resolved / new / still open" line so a
  reviewer sees the trajectory across pushes.
- **Inline comments** on the offending lines, for findings whose line is part of
  the diff. Each is posted once and not repeated on re-runs.

Comments are scoped to the files the PR/MR touched, so grackle does not complain
about pre-existing issues on untouched workflows. If a posting call fails, the
scan's exit code is unaffected; the failure is logged and the run continues.

### GitHub

Add `--github-comment` to a `pull_request` workflow. Grackle reads the PR from
the standard Actions environment and the token from `GRACKLE_GITHUB_TOKEN`,
`GITHUB_TOKEN`, or `GH_TOKEN`.

```yaml
name: grackle
on: pull_request

permissions:
  contents: read
  pull-requests: write   # post the summary and inline comments

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install --git https://github.com/cpeoples/grackle.git
      - run: grackle --github-comment .
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### GitLab

Add `--gitlab-comment` to a `merge_request_event` pipeline. Grackle reads the MR
from the CI environment and the token from `GRACKLE_GITLAB_TOKEN`,
`GITLAB_TOKEN`, or `CI_JOB_TOKEN`. Posting notes and discussions needs a token
with `api` scope; the default `CI_JOB_TOKEN` cannot always write MR notes, so a
project or group access token in `GITLAB_TOKEN` is the reliable choice.

```yaml
grackle:
  stage: test
  image: rust:latest
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - cargo install --git https://github.com/cpeoples/grackle.git
    - grackle --gitlab-comment .
```

Tokens are read from the environment only, never from a flag, and are redacted
from every log line grackle writes.

## Pre-commit / local

Run it against a checkout before pushing:

```bash
grackle .
```

Scanning a directory also resolves local composite actions, so an agent hidden
in `.github/actions/*/action.yml` is caught. A single-file scan cannot resolve a
local path off disk, so prefer a directory scan in CI.

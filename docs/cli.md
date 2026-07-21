# CLI Reference

```bash
grackle [PATH]                    # scan a file or directory (default: .)
grackle -f json PATH              # choose an output format
grackle -o report.sarif PATH      # write to a file (format inferred from extension)
grackle --json PATH               # shorthand for -f json
grackle --debug PATH              # print per-file scan diagnostics to stderr
grackle --list-rules              # print the rule inventory
grackle --rules-json              # print the full rule catalog with metadata as JSON
grackle --self-test               # validate every rule against its built-in examples
grackle --github-comment PATH     # post PR comments (inside a GitHub Actions PR)
grackle --gitlab-comment PATH     # post MR comments (inside a GitLab CI pipeline)
grackle --version                 # print the version
```

## Arguments

| Argument | Description |
|---|---|
| `PATH` | File or directory to scan. Defaults to the current directory. A directory scan also resolves local composite actions off disk. |

## Options

| Option | Description |
|---|---|
| `-f`, `--format <FORMAT>` | Output format: `text`, `json`, `markdown`, `sarif`, `gitlab-sast`, `junit`, `csv`, `xml`, `yaml`, `html`, `cyclonedx`. |
| `-o`, `--output <FILE>` | Write the report to a file. The format is inferred from the extension unless `--format` is set. |
| `--json` | Shorthand for `--format json`. |
| `--debug` | Print per-file scan diagnostics (candidates, findings, totals) to stderr. |
| `--list-rules` | Print every built-in rule (id, severity, title) and exit. |
| `--rules-json` | Print the full rule catalog with compliance metadata as JSON and exit. This is the source the documentation site is generated from. |
| `--self-test` | Validate every built-in rule against its own positive and negative examples and exit. |
| `--github-comment` | Post a sticky summary comment and inline comments on the current GitHub pull request. See [CI/CD integration](/ci-cd/). |
| `--gitlab-comment` | Post a sticky summary comment and inline comments on the current GitLab merge request. See [CI/CD integration](/ci-cd/). |
| `--version` | Print the version. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no findings. |
| `1` | Scan completed, at least one finding reported. |
| `2` | Usage or I/O error (bad path, unwritable output, invalid format). |

## Format inference

When `--output` is given without `--format`, the format is inferred from the
file extension (`.sarif`, `.json`, `.md`, `.html`, `.xml`, `.yaml`/`.yml`,
`.csv`). An explicit `--format` always wins.

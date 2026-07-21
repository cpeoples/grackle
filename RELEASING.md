# Releasing Grackle

Releases are cut from a git tag and a published GitHub Release. Publishing the
release triggers [`.github/workflows/release.yml`](.github/workflows/release.yml),
which builds the platform binaries, generates provenance and an SBOM, signs
everything, publishes the crate, and opens the Homebrew tap bump.

## One-time setup

The release workflow reads three things. Confirm they exist before the first
release:

| Secret / environment | Where | Purpose |
| --- | --- | --- |
| `CARGO_REGISTRY_TOKEN` | repo Actions secret | `cargo publish` to crates.io. Scope it to `publish-new` + `publish-update`. |
| `HOMEBREW_TAP_TOKEN` | repo Actions secret | A PAT with `contents` and `pull-requests` write on `cpeoples/homebrew-tap`, used to open and auto-merge the formula bump. |
| `homebrew-tap` | repo environment | Referenced by the tap-bump job; must exist even if it has no protection rules. |

`GITHUB_TOKEN` is injected automatically and needs no setup.

The tap repository must already contain `Formula/grackle.rb`. The bump job
rewrites the version and checksums in an existing formula; it does not create
one.

## Cutting a release

1. Land everything on `main` and confirm CI, CodeQL, and Scorecard are green.
2. Bump `version` in [`Cargo.toml`](Cargo.toml), commit, and let CI pass. The
   tag must match this version.
3. Tag and push:

   ```bash
   git tag -a v0.1.0 -m "Release 0.1.0"
   git push origin v0.1.0
   ```

4. On GitHub, draft a release for the tag and publish it. Publishing is what
   triggers the pipeline; pushing the tag alone does not.

## What the pipeline does

On a published release, the jobs run in this order:

- **build** - compiles and smoke-tests (`--self-test`, `--list-rules`) the
  binary for Linux (x86_64, aarch64), macOS (x86_64, aarch64), and Windows
  (x86_64), then packages and checksums each archive.
- **provenance** - SLSA Build Level 3 attestation over every archive, via the
  trusted `slsa-github-generator` reusable workflow.
- **sign-and-attest** - generates a CycloneDX SBOM from the Cargo dependency
  graph, signs the archives and SBOM with Sigstore, and attaches all of it to
  the release.
- **publish-crate** - `cargo publish --locked` to crates.io.
- **bump-tap** - opens a pull request on `cpeoples/homebrew-tap` with the new
  version and checksums and enables auto-merge.

`workflow_dispatch` runs only the build job, so you can smoke-test the build on
any branch without publishing anything.

## First release

Crate versions on crates.io are permanent and cannot be overwritten, only
yanked. Before the first tag, dry-run the publish locally to catch packaging
problems:

```bash
cargo publish --dry-run --locked
```

Confirm the crate name `grackle` is available on crates.io. If it is taken,
change `name` in `Cargo.toml`; the binary can stay `grackle`.

## Verifying a release

Downloads carry SLSA provenance and a Sigstore signature. Verify an archive
against the attached `.intoto.jsonl` and `.sigstore.json` with `slsa-verifier`
and `cosign`.

## If a release job fails

- **publish-crate fails with "already exists"** - the version was published
  before. Bump `version`, tag again, and cut a new release; you cannot reuse a
  version.
- **bump-tap fails** - check that `Formula/grackle.rb` exists in the tap and
  that `HOMEBREW_TAP_TOKEN` still has write access. The binaries, provenance,
  and crate are already published at that point; you can re-run just the tap
  bump.

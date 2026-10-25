# Immutable Dependency Inputs

This reference is for maintainers connecting dependency admission to PR source.
`scripts/dependency_inputs.py` reads source files by their Git object identities
through `scripts/dependency_git_objects.py`. It compares declared input families
without trusting a PR's generated inventory or executing its code.
Run the reader from a trusted checkout; the requested source revisions supply
data, never the reader implementation.

A successful source check is not dependency admission. The report keeps
`dependency_coverage_verified: false`: component extraction, artifact/license/
advisory verification, trusted policy selection and the hosted verdict belong
to the [combined caller](dependency-review.md), not this input reader alone.

## Source Families

The code-owned catalog covers these existing repository inputs:

| Family | Inputs |
| --- | --- |
| Go | Application and QA `go.mod`/`go.sum`, plus custom `release/tools/syft.go.mod` and `.sum`. |
| Node | Marketing `package.json` and `package-lock.json`. |
| Python | The pinned QA requirements file. |
| Downloaded/build tools | Support matrix, standalone Go catalog, Makefile and installation workflow. |
| Actions | Repository/example workflows and local/documented `action.yml`/`action.yaml` metadata. |
| Images | Both Dockerfiles, Compose definitions, air-gap manifest, Helm templates/values and Docker ignore rules. |
| Fixtures | Catalog, corpus, payloads, notices, source notes and project license. |
| Controls/tooling | Dependency update/config files, collector sources and shell recipes. |

New conventional manifests outside these families, tracked vendor directories
and gitlinks are reported as unclassified. Missing required inputs also remain
explicit. Selected documents must be regular Git blobs; symlinks and gitlinks
cannot stand in for a manifest or fixture source. Generated inventory outputs
and untracked working-tree files are not accepted as source evidence.

Every selected file records its path, roles, mode, Git blob ID, byte count and
SHA-256. Source contents remain private to the reader and are omitted from
reports. Comparisons preserve additions, removals, byte changes and mode changes.
Source hashes expose changed build recipes but do not analyze every dynamically
computed download or establish its dependency/license coverage.

The reader additionally checks npm lock structure, Python pin syntax, standalone
Go installation bindings and fixture file coverage/declared byte hashes using
trusted parsers. This is not full fixture upstream-equivalence, Go graph,
license, artifact or advisory verification. Those checks must consume the verified
inputs before admission can pass.

## Git Byte Verification

The authenticated reader permits only the fixed repository's
[Git blob GET endpoint](https://docs.github.com/en/rest/git/blobs#get-a-blob).
It checks the requested ID, base64 encoding, declared size, canonical decoded
bytes and Git object identity. Wrapped base64 line feeds are supported; other
whitespace, inconsistent sizes, invalid padding or mismatched bytes fail.
Identical verified blobs are fetched once across both revisions.

The local reader uses only read operations on Git objects. Global/system config,
replacement refs, hooks, fsmonitor and lazy fetch are disabled for those commands.
It reads committed blobs rather than working-tree files and never checks out,
restores or rewrites source. Git's structured NUL-delimited tree output is checked
against reconstructed tree identities. A missing local object fails instead of
being fetched. The tested host Git supports `--no-lazy-fetch`.

Objects are limited to 1 MiB and the decoded blob cache to 32 MiB. Each revision
selects at most 256 inputs; local Git operations are capped at 1,024. The explicit
provider source-input profile permits at most 768 API reads and 64 MiB of JSON
responses, retaining the 4 MiB per-response bound. The default PR observation
profile remains 48 reads/32 MiB. Requests and blob reads stay serial.

Reports are written atomically with the matching schema and explicit replacement.
Unrelated files, symlink outputs and concurrent output edits are protected.
Neither input bytes nor provider credentials, CLI diagnostics or raw responses
are exported into source reports.

## Checks And Observations

```sh
"$HOME/.local/bin/codex-ramgate" 1 -- make dependency-inputs-check
```

This runs isolated tests and checks the committed `HEAD` source catalog without
writing a report. It does not inspect uncommitted/untracked changes or turn source
coverage into a dependency-policy verdict. `make docs-check` includes it and
also compiles Go tools, so that broader gate needs a suitable RAM reservation.

The CLI can compare two full commit IDs with `--local-repository`, `--base`,
`--head`, `--output` and optional `--replace`. Without `--local-repository`, add
`--pull-request` and `--head-repository` to bind the read to a live PR using the
[provider reader](dependency-review-provider.md). The PR is checked again after
source collection. The input comparison uses the effective merge base; trusted
policy must separately come from the current target base, not PR head or an
older merge base.

Exit codes are 0 for verified selected bytes with no head catalog gaps, 1 for a
source observation with missing/unclassified inputs, and 2 for invalid bytes,
provider/command failure or unsafe output. Neither a saved report nor exit 0
proves complete license/advisory admission or an authenticated workflow decision.

The local comparison from `4fe7ef6b357d10b14e6e9cb6d7ca0aa5bccacb24` to
`7f3d4071a1c557c0317f955ba9df4d221fbbffdd` verified 159/160 selected inputs with
no head gaps. The older public PR #30 source verified 111/122 inputs through
157 authenticated requests but returned 1: the head lacks the fixture catalog,
scanner lock pair, pinned Python requirements and standalone Go catalog required
by the current input catalog. Those are observed older-source gaps, not passing
coverage or current local `master` CI qualification.

The [trusted classifier builder](dependency-classifier.md) consumes base Git
objects for executable code and its QA lock files. Proposed head sources remain
dependency data. The caller must select the current reviewed target base rather
than letting proposed code or policy authorize its own execution.
The [Git collection caller](dependency-collection.md) exports verified inputs
into a private data directory, uses that base-built helper and trusted Python,
and rechecks source/tooling identities before returning observations.

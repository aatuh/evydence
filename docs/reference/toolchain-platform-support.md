# Toolchain And Platform Support

This reference defines source-build and unreleased release targets for maintainers
and operators. The machine-readable policy is
[`release/support-matrix.json`](../../release/support-matrix.json).
`make support-matrix-check` checks build selections and this generated table;
a declared target is not a passed qualification receipt. The check requires
Python 3 with PyYAML, alongside the existing project tools.

<!-- BEGIN GENERATED SUPPORT MATRIX -->
| Go role | Exact version |
| --- | --- |
| Minimum | `1.26.9` |
| Current | `1.27.2` |

| Platform | CLI target | Server target | Runtime target |
| --- | --- | --- | --- |
| `linux/amd64` | `evydence` | API, worker, migrations | yes |
| `linux/arm64` | `evydence` | none | cross-build only |
| `darwin/amd64` | `evydence` | none | cross-build only |
| `darwin/arm64` | `evydence` | none | cross-build only |
| `windows/amd64` | `evydence` | none | cross-build only |

| QA tool | Exact version | Linux amd64 archive SHA-256 |
| --- | --- | --- |
| `golangci_lint` | `v2.15.0` | `Go module checksum database` |
| `gosec` | `v2.29.0` | `Go module checksum database` |
| `govulncheck` | `v1.9.0` | `Go module checksum database` |
| `helm` | `v4.3.0` | `86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb` |
| `oasdiff` | `1.29.1` | `541f7c66c933495fceef24eaf5c48aa66c19069f366f7bd0a60a6a4820c5e533` |

| QA build dependency | Exact version |
| --- | --- |
| `golang.org/x/tools` | `v0.52.0` |

| SDK language | Delivery |
| --- | --- |
| go | `source-wrapper` |
| python | `source-wrapper` |
| typescript | `source-wrapper` |
<!-- END GENERATED SUPPORT MATRIX -->

## Release build plan

Inspect the current command plan without starting builds or reading signing
material:

```sh
scripts/release_candidate_package.sh --plan
```

This emits JSON from the validated policy without Git, Go, Make, database or
provider calls. Normal packaging requires the declared current compiler and
keeps the full production gate, live dependency configuration, signing and
checksum checks. It rechecks the initial commit and clean worktree after that
gate, before replacing artifact files; a changed source or failed Git check stops
packaging. Normal packaging uses a Linux amd64 build host for its signing
CLI. Container builders serialize Go packages and bound compiler parallelism.
Only the Linux amd64 archive contains the API, worker and
migration commands; the other declared archives contain the CLI. Their existing
archive and CLI filenames remain stable. The pre-build manifest also commits
the support policy digest. Release packaging/qualification is still required;
plan inspection alone does not prove binary builds or runtime support.

## Version selection

The module's `go` directive is the minimum compiler; `toolchain` selects the
preferred current compiler. Make defaults to that exact current patch, and
Docker uses the same current patch in a digest-pinned builder. CI derives its
current compiler from `go.mod`; a separate compatibility job explicitly selects
each declared version with `GOTOOLCHAIN=local` so the minimum cannot silently
upgrade. Current version-file setup leaves the incoming toolchain setting unset;
the pinned action reads the preferred directive before setting `local` for
subsequent commands. Operators evaluating an override must use an installed supported
compiler and retain its actual `go version` with their validation evidence.

The minimum retains the patched older supported Go branch because dependency
floors require Go 1.26. Current qualification targets the patched Go 1.27 branch.
The [Go release history](https://go.dev/doc/devel/release) owns patch/security
status; [toolchain selection](https://go.dev/doc/toolchain) and
[setup-go version-file behavior](https://github.com/actions/setup-go/blob/main/docs/advanced-usage.md#using-the-go-version-file-input)
explain compiler selection. A newer unlisted version has no implied support.

The server target is Linux amd64, with one API writer and the existing
PostgreSQL/object-store deployment boundaries. Other CLI targets are
cross-build targets, not native runtime, service-manager or server qualification.
Go, Python and TypeScript SDKs remain repository source wrappers; see
[SDK delivery and limits](../sdk/README.md). This repository supplies no SDK
publishing manifests or additional OS/runtime qualification for those examples.

## Updating the policy

Change policy data and its checked build/CI/documentation inputs in the same
reviewed change. `tools/go.mod` and `tools/go.sum` isolate the QA dependency graph
from application dependencies; `make tools` installs from that graph with
workspace overrides disabled and module edits forbidden. Update both lock files
alongside the declared tool versions and build-dependency pin. Keep exact QA tool versions; Go tools use module/checksum-db
verification. The shared `golang.org/x/tools` pin lets standalone gosec read
current Go export data; its released isolated dependency graph cannot read
Go 1.27.2 exports. The same engine with this parser already runs in the pinned
golangci-lint graph. Downloaded Helm/oasdiff archives require their declared
SHA-256. Inspect official release notes, dependency floors and security fixes.
Review Docker Official Image manifest digests, retaining immutable pins and the
matching builder/runtime Alpine release. Weekly Dependabot updates cover Go
modules (including `/tools`), Actions and Docker; manually review QA tool pins at least monthly and
when a relevant security fix is released. Never switch a tool to `latest`.

Run focused drift, source-review and regression checks during the change. Before
closing the support-matrix ticket, run the complete minimum/current Go tests,
`make docs-check`, and the required release gate with its real live dependencies.
New native input semantics require explicit source review and compatibility notes;
[the configuration ADR](../adr/0005-validated-runtime-configuration.md) records
TLS-root and path-list differences. Refresh the generated block with
`python3 scripts/support_matrix.py --render` and preserve the surrounding policy.

Version/platform changes apply to new source builds. Historical release artifacts,
checksums, signatures and source evidence retain their original commitments.
The [backlog](../../.EVYDENCE_CODEX_BACKLOG.md) owns EVY-1401 completion evidence;
local checks do not prove hosted CI, publication or native tests on another OS.
Support targets do not establish legal compliance, certification or release security.

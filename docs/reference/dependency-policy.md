# Dependency Policy

This reference is for contributors selecting dependencies and maintainers
reviewing their admission. **EVY-1407 is in progress.** The offline admission
rules and their regression tests exist. A bounded Go license-classification
helper passes focused tests on both supported compilers. The dependency
collector produces source-bound observations; complete scope, live PR
review and the final release gate are not yet integrated.
Passing these tests does not establish that the current dependency set has been
audited or that a real dependency addition would be rejected by hosted CI.

## Selection And Removal

Before adding a dependency, explain the concrete behavior it supplies and why
the standard library or an existing dependency is insufficient. Preserve the
required API toolkit foundation. Keep SDK wrappers minimal; a server or build
dependency is not automatically an SDK requirement.

Review the pinned source/version, release activity, archived status, security
advisories, license and redistribution requirements, platform/toolchain support,
transitive graph and replacement cost. An old release is a review signal, not
proof that a project is abandoned or vulnerable. Pin build tools and fixtures
as deliberately as runtime libraries. Do not automatically merge an update
without the required tests and review.

Remove unused dependencies when their imports or build steps disappear. Recheck
the graph and supported API/SDK behavior; do not retain a dependency solely for
an obsolete fixture or silently break a published interface to remove it.

## Update Review

[`.github/dependabot.yml`](../../.github/dependabot.yml) configures weekly
version updates with at most five open version PRs per scope:

| Ecosystem | Directory |
| --- | --- |
| Go modules | `/`, `/tools` |
| npm | `/site/marketing` |
| pip | `/tools` (`requirements-qa.txt`) |
| GitHub Actions | `/` |
| Dockerfiles | `/`, `/deploy/local-dependencies` |

Each scope groups minor/patch version updates and leaves major version updates
for separate review. SemVer grouping is a review aid, not evidence of safety.
Separate security groups have no version or development-dependency restriction:
a major fix must remain eligible. Security updates use the provider's separate
queue and do not wait for the weekly version schedule, where supported and
active. See GitHub's [group and queue options](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference)
and [ecosystem limits](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories).

Every update still needs normal tests and maintainer review; this configuration
adds no automatic merge or check bypass. Pinned toolchain selections, QA tool
versions and checksums, Python artifact hashes and generated inventory inputs
must be updated consistently in the reviewed PR. Drift-check failures require
those related updates, not weaker assertions. Follow the
[toolchain update procedure](toolchain-platform-support.md) and
[scanner dependency review](release-supply-chain.md#scanner-dependency-review).
The custom `release/tools/syft.go.mod` lock, downloaded QA tools, embedded
source revisions, service-image references and redistributed fixtures still
require explicit maintainer updates; these scopes do not imply complete bot
coverage or vulnerability scanning of container contents.

`make dependency-updates-check`, also in `make docs-check`, checks local scope
coverage, bounded version queues and separate routine/security groups offline.
It does not run Dependabot. A read-only GitHub observation on 2026-10-21 returned
`enabled: true, paused: true` for automated security fixes. Recheck the live
state and update results after approved integration; local configuration tests
do not prove active hosted automation. GitHub documents qualifying activity for
[resuming paused updates](https://docs.github.com/en/code-security/reference/supply-chain-security/troubleshoot-dependabot/dependabot-updates-stopped).

## Python QA Dependency

[`tools/requirements-qa.txt`](../../tools/requirements-qa.txt) pins PyYAML 6.0.3
and its published artifact SHA-256 values. CI production checks and release
packaging install binary wheels into a dedicated virtual environment using
pip's isolated configuration and `--require-hashes --only-binary=:all:`.
They no longer use the runner's unpinned `python3-yaml` OS package. A missing
compatible wheel or mismatched hash fails installation; source builds and their
implicit build dependencies are disabled. See [pip's hash-checking guidance](https://pip.pypa.io/en/stable/topics/secure-installs/#hash-checking-mode).

For local setup, create a virtual environment outside the checkout, install
that requirements file with the same flags, and place its `bin` directory first
on `PATH`. Use the host RAM coordinator for environment creation/installation
and the subsequent Go-backed gates. Existing environments with the exact
version can run `make python-qa-check` directly.

That check rejects version drift and new transitive package requirements and
checks that the Python SDK's static imports stay in the standard library or
the wrapper directory. Installed OS-package bytes and dynamic imports are
outside that check.

The separate inventory collector reads the release-specific
[PyPI JSON endpoint](https://docs.pypi.org/api/json/) and requires every artifact
hash in the pin to have one exact distribution record. Registry declarations
do not substitute for artifact contents. Each pinned source archive and wheel
is checked against its SHA-256 before bounded reads of root `PKG-INFO` or wheel
`METADATA` and license/notice files. It verifies name/version, rejects new
package requirements and preserves disagreements across distributions. No
package setup, native extension or install hook runs during this inspection.
Unsupported license prose remains unknown; text classification stays separate
from declarations and admission. See Python's [core metadata specification](https://packaging.python.org/en/latest/specifications/core-metadata/).

## Build Tool Sources

The inventory observes the Linux amd64 Helm and oasdiff release archives pinned
in [`release/support-matrix.json`](../../release/support-matrix.json). The
collector checks each compressed archive's SHA-256 before bounded tar/gzip
inspection, checks the gzip trailer and records the expected binary's digest
plus root license/notice bytes. It does not extract files or run the binaries.
See the upstream [Helm release installation procedure](https://helm.sh/docs/intro/install/)
and [oasdiff releases](https://github.com/oasdiff/oasdiff/releases).

Downloads disable ambient proxies and credentials. Only the fixed official
archive endpoints are used. GitHub's release endpoint may redirect once to its
HTTPS release-assets host; arbitrary hosts, ports and redirect chains fail.
Signed redirect URLs remain outside public reports. Compressed bytes, expanded
bytes, file sizes, member counts and transfer time all have explicit limits.
Verified archives remain in fresh private scratch work; existing files are not
overwritten.

The QA Go graph already includes the pinned golangci-lint, gosec and
govulncheck modules. Syft is the main module in its scanner graph and therefore
needs a separate source observation: the collector downloads it as a dependency
in an isolated bootstrap module with the release recipe's exact checksum pair,
requires the proxy's source revision to match the recorded recipe and runs
`go mod verify` before reading root license bytes. The bootstrap does not build
or execute Syft or change the application/scanner locks.

The container-signing workflow installs Cosign as a separate versioned Go
command. [`release/tools/standalone-go.json`](../../release/tools/standalone-go.json)
records its source checksum pair and revision, along with the local
MinIO/client source builds. The catalog is checked against the workflow and
Dockerfile installation lines before provider/tool work; changing one without
its matching pin fails validation.

Each standalone root is downloaded as a checksum-pinned dependency in private
scratch work and checked with `go mod verify`. Only bounded root `go.mod` and
`go.sum` bytes are read from the verified source ZIP. Go's structured manifest
parser checks module identity and rejects replacements, exclusions and explicit
self-requirements. The collector resolves each original upstream graph in a
separate directory, verifies the downloaded dependencies and includes the root
module itself. The upstream `go.mod` must remain byte-identical. No command is
built or installed by this collection. See Go's
[versioned install rules](https://go.dev/ref/mod#go-install) and
[module verification](https://go.dev/ref/mod#go-mod-verify).

The report records installation locations, checksum/revision pins, upstream
manifest digests and per-profile module counts separately from merged component
origins. These are available-module graphs, not proof of code linked into a
particular binary. The MinIO profiles remain disposable fixtures with the
documented upstream security limits; inventorying them does not recommend them
for production or grant license approval.

These records cover selected tool archives and module sources, not all linked
binary dependencies, nested notices, the compiler/interpreter, runner image or
installer bootstrap. Archive integrity and root text candidates are separate
from producer authenticity, complete SBOMs, license approval and redistribution
obligations. Artifact-bound release evidence has its own
[supply-chain profile](release-supply-chain.md).

## GitHub Action Sources

The inventory parses `.github/workflows/` and the copyable workflows under
`docs/github-actions/` as YAML. External references must use full commit IDs;
local reusable calls must refer to a covered workflow. Unsupported local step
actions, mutable top-level references, invalid mappings and symlinked inputs
fail before tool/provider work. Input hashes bind every workflow, and a final
coverage check detects added workflows or concurrent edits.

Read-only GitHub calls require public repository metadata and the exact pinned
commit/tree identities. Generation needs an authenticated GitHub CLI with
public repository read access; the offline tests do not need credentials.
The collector walks action directories, reads ancestor
license/notice files and the Action manifest, and checks blob IDs, sizes and
independent SHA-256 values before storing bytes in private scratch work. Tree
truncation, selected symlinks, duplicate paths, oversized responses, excessive
requests/reference counts and conflicting existing files fail. Alias reuse
cannot bypass the reference-count budget. No Action code is executed.
Private Action repositories are unsupported. See GitHub's
[tree](https://docs.github.com/en/rest/git/trees#get-a-tree),
[blob](https://docs.github.com/en/rest/git/blobs#get-a-blob) and
[Action metadata](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax)
references.

Runtime records describe declared entrypoints, nested Action references and
container references. Nested external Actions are collected at resolved commit
IDs; their declared tags remain marked mutable, with the observed resolution
recorded separately. This is not a guarantee of the code a mutable reference
will execute later. A container reference is input to the remaining image scope,
not proof of its contents. Shell commands and input defaults are not copied into
the public report. Bundled JavaScript/native libraries, entrypoint bodies,
runtime downloads and runner software are outside these source observations;
they do not constitute a complete artifact SBOM or license approval.

## Implemented Admission Rules

Fixture coverage and source declarations use a
[provenance catalog and checks](fixture-provenance.md). Its local gate is part
of `make docs-check`; the upstream gate checks pinned files and notices through
read-only GitHub API calls. The general dependency snapshot includes fixture
records and separately classified notice bytes. License admission remains
separate from source equivalence and recorded license declarations.

`scripts/dependency_policy.py` is an offline library without network, subprocess
or filesystem effects. Its caller must provide trusted policy and verified
component metadata. `assess_component` requires explicit ecosystem, name,
version, license and vulnerability records. Missing or malformed records do
not become an empty, passing assessment.

- A license must satisfy the policy's explicit identifier list. Unknown values,
  including `NOASSERTION`, `UNKNOWN` and missing metadata, fail admission.
- Compound expressions preserve `WITH`, `AND`, `OR` and parenthesis precedence.
  An `OR` alternative can satisfy the license policy; every `AND` obligation
  must satisfy it. License identifiers ignore case; operators remain uppercase.
  A `WITH` permission applies only to the named license/exception pair. See
  [SPDX expression semantics](https://spdx.github.io/spdx-spec/v2.3.1/SPDX-license-expressions/).
- Expressions are limited to 2,048 ASCII characters, 128 tokens and 16 nested
  groups. Unsupported syntax and unresolved document-qualified references are
  rejected. The evaluator does not fetch or infer the terms behind a custom
  license reference, nor independently validate the SPDX license registry.
- Known high/critical advisories and unknown-severity advisories block admission
  for runtime, development and fixture components alike. Low/moderate findings
  still need triage; their admission is not a claim of safety.
- The JSON parser rejects duplicate keys, nonfinite numbers, invalid UTF-8 and
  documents over 4 MiB. Public errors omit raw manifest/provider content.

These are automated review rules, not a determination of legal compatibility
or fulfillment of attribution, source-offer or other license obligations.

## Exceptions

An exception must name one exact ecosystem/name/version and one license
expression or advisory ID. It cannot use wildcards, waive a different version,
or turn a license exception into an advisory waiver. Missing-license exceptions
must explicitly target `NOASSERTION` for that dependency.

Every entry requires an ID, owner, public reason, review date, expiration date
and a review URL in `aatuh/evydence`. Expiration is exclusive at the start of
that UTC date and cannot exceed 90 days after review. Future-dated reviews,
expired entries, duplicate identities/scopes and unknown fields fail validation.
Renewal requires another review; it is not automatic.

A syntactically valid review URL or owner field does not prove approval.
Enforcement must load policy from a trusted reviewed source and bind provider
data to the actual comparison. That integration remains incomplete. Test
exceptions are synthetic and do not approve any real dependency or advisory.

## License Classification Helper

The build-tool helper under `tools/cmd/license-inventory/` uses the checksum-pinned
`github.com/google/licensecheck v0.3.1` already selected by the release scanner.
It adds no runtime or SDK dependency. It accepts license bytes through stdin;
it does not open supplied paths, run package code, access the network or read
credentials.

The v1 scan protocol accepts a JSON array of unique `sha256` and
`content_base64` string pairs, with canonical base64 matching the exact digest.
Batches are limited to 64 files and 8 MiB of JSON; each UTF-8 license text is
limited to 1 MiB. Unknown/duplicate fields, digest mismatches, malformed input
and a late invalid record must fail without emitting a partial result.

Results distinguish a single text-match **candidate** at at least 95% coverage,
**ambiguous** multiple license IDs, and **unknown** text or URL-only matches.
Multiple detected terms do not imply an `OR` choice. Candidate classification
does not grant policy admission, establish legal rights or replace a reviewed
source/license record. The file digest binds the observed bytes; it is not a
publisher-authentication or artifact-signing claim.

The [upstream repository](https://github.com/google/licensecheck) was not archived when checked on 2026-10-21, with its
last recorded push on 2024-04-14. This is a maintenance-review signal, not proof
of abandonment. The complete inventory and maintenance report remain pending.

## Collect Source Observations

`scripts/dependency_inventory.py` resolves the application, QA and scanner
module graphs from isolated copies of their manifests and locks. It downloads
their selected module ZIPs through the Go proxy/checksum database and requires
`go mod verify` before reading root license/notice bytes from those archives.
Inspection does not run dependency install scripts or package executables.
Temporary work and bounded tool diagnostics are retained in a private directory
under the configured work root; cache paths and raw diagnostics are omitted from
the report.

The collector requires the current compiler from the support matrix, disables
automatic switching and workspace overrides, and serializes downloads. It
omits provider credentials from the tool environment. ZIP reads never extract
files, reject escaping/symlink paths and enforce entry/file limits. Fixture
payloads, notices, corpus and source notes are read into one bounded input
snapshot before provider work. Notice bytes are classified separately from the
catalog's declarations. Input hashes and fixture coverage are checked again
before writing a report; edits or newly unclassified files abort collection
without overwriting the owner's changes.

The marketing lock contributes all package locations, exact versions, registry
URLs, SHA-512 integrity declarations and declared license expressions. The
collector fetches each exact HTTPS registry archive serially, without inherited
proxy credentials or redirects. It verifies compressed bytes against the lock
before bounded gzip/tar inspection, without extracting files. The archive's
root `package.json` must match the locked name/version; its digest, license
declaration and root license/notice observations are recorded.

`artifact-declared` means the archive and lock declare the same expression.
`license_text_status` and `license_text_candidate` describe the separately
classified root text. They do not override the declaration or grant approval;
disagreements and unknown results require review. Declaration mismatches set
the effective license to unknown/ambiguous and preserve both observations.
Legacy or unsupported declarations are not silently converted into SPDX.
See npm's [license declaration reference](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/#license).
The collector does not invent empty vulnerability lists.

Use the host RAM coordinator for this command; downloading, verifying and
classifying the complete graphs is a memory-intensive operation:

```sh
make dependency-inventory-generate
```

The target writes `docs/reference/dependency-inventory.json` atomically and
replaces only an existing inventory of the same schema. It refuses unrelated
files and unsafe paths. Configure `DEPENDENCY_INVENTORY_WORK_ROOT` to an existing
scratch directory, preferably on the build-storage volume. The CLI also accepts
`--output` as a path relative to the checkout for a private qualification report.

This stage sets `complete: false`. Image and maintenance/live
review evidence remain to be integrated before EVY-1407 can close. Go graph
observations cover available modules, not only dependencies linked into a
particular binary; they are separate from artifact-bound release SBOMs.

The [2026-10-21 snapshot](dependency-inventory.json) contains 2,880 records:
2,501 Go module/versions, 327 Node packages, one PyYAML component with 73 pinned
distributions, 34 fixture records, two build-tool archives and 15 Action sources. Go and registry
source artifacts passed their download/checksum verification. Go license
observations include 2,328 candidates,
105 ambiguous results, 53 unknown and 15 with no root license file. None of
those classifications grants approval. All 327 npm manifest declarations match
the lock. Their separate root-text observations are 241 candidates, three
ambiguous, 17 unknown and 66 with no root license file. A candidate for one
license does not discharge a compound declaration's additional obligations;
bundled native dependencies and nested notices still require review.
The PyYAML component records all 72 pinned wheels and one source distribution:
every artifact declares MIT and contains the same root/dist-info license bytes,
classified as an MIT candidate. This is an observation, not license approval or
verification of the Python interpreter, installer bootstrap or all bundled
third-party obligations. The report includes the Python and Go collector
runtime versions alongside source/input hashes.
The fixture records cover the catalog's 34 logical records, 56 payload files
and ten notice records. `local-digests-checked` describes the generation-time
verification; the pinned upstream references have a separate live verification
target. Recorded license declarations remain intact when text classification
is unknown or ambiguous. All 34 fixture entries have a primary text candidate;
one secondary attribution notice is unknown and remains in the evidence. No
classification becomes an approval.
Helm and oasdiff record their pinned archive SHA-256 values and observed binary
digests. Their root license texts and the separately verified Syft main source
are Apache-2.0 candidates. This does not inventory all dependencies bundled
in those binaries or grant license approval.
The standalone Cosign, MinIO client and MinIO profiles contain 888, 317 and 600
module records respectively, including each root. Shared component identities
merge graph origins while retaining matching source and license observations.
The report preserves the exact checksum/revision pins and upstream manifest
digests for these profiles; no tools were installed by inventory generation.
The 14 direct Action references and one nested Action have 30 manifest/notice
observations across 22 unique blobs. Root texts classify as 14 MIT candidates
and one Apache-2.0 candidate. The nested `actions/upload-artifact@v4` remains
mutable even though its observed commit is recorded; Scorecard's tagged GHCR
image is still part of the pending image scope. These records do not approve
licenses, prove complete bundled dependency coverage or verify later execution.
The snapshot binds generator/input
hashes and records the missing scopes; the unit tests reject a stale snapshot
after those inputs change. The missing scopes and policy enforcement are still
required, so this does not complete EVY-1407 or enforce live PR policy.

## Verify This Unit

```sh
make dependency-policy-test
make dependency-inventory-test
```

The first target is offline Python. The inventory target compiles and runs Go
tests; it and `make docs-check` must use the host RAM coordinator. Neither test
requires provider credentials. `make docs-check` includes both. Regression evidence covers expression semantics,
unknown metadata, exact and expiring exceptions, advisory severity, resource
bounds and safe error handling. It does not replace the remaining ticket gates.

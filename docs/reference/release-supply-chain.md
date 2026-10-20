# Release SBOM and Provenance Profile

This reference is for release maintainers and artifact verifiers. It defines
`evydence-release-evidence.v1`, implemented by the release evidence scripts.
The [2026-10-20 local qualification](release-supply-chain-2026-10-20-local.json)
records source commit `af20e46a52ea95580bd24a780940dbd4d0e4c575` and fixture tag
`v0.0.0-rc.1403`. It covers local candidate and image builds; it does
not establish that existing public releases contain this profile.

## Artifact identities

The supported binary and archive set comes from
[`release/support-matrix.json`](../../release/support-matrix.json). It currently
contains eight binaries in five archives. Binary identities use the archive
directory and executable name; archive identities use the archive filename.
Both identities carry SHA-256 digests computed from actual bytes.

`scripts/release_subjects.py` reads each archive through the standard library's
structured TAR or ZIP parser. It permits the exact supported executables and
`LICENSE`, `README.md`, and `CHANGELOG.md` under one canonical directory. Links,
traversal, duplicate or missing entries, special files and excessive declared
sizes fail. It extracts executables into a private temporary directory without
executing them. Archives and expanded payloads are limited to 512 MiB each;
the entry limit is 16.

Each subject has a CycloneDX 1.6 JSON SBOM. Its metadata component contains the
subject name and exact SHA-256 digest. The filename is
`evydence-sbom-<SHA256(subject-name)>.cdx.json`.

The package inventory is deliberately flat. It retains public package names,
versions and package URLs from pinned Syft output. Identical coordinates from
multiple binaries merge; conflicting coordinates fail. Scanner file records,
paths, arbitrary properties, CPE guesses, relationships and licenses are
omitted. This reduction protects private build paths and narrows the exported
claims. It does not establish package completeness or vulnerability coverage.
The tool list identifies Syft and the Evydence adapter; provenance binds the
adapter's exact source files.

## Provenance and index

`evydence-release-provenance.intoto.jsonl` contains one
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
with the [SLSA build provenance v1 predicate](https://slsa.dev/spec/v1.2/build-provenance).
Its subjects are the actual binary and archive digests. The predicate identifies
the source commit, pre-build manifest digest, source-relative material digests,
tag, platform set, build recipe and producer invocation.

The build type URI ends in `release-supply-chain.md#build-v1`. The local profile
uses closed, canonical JSON documents and requires the exact supported subjects;
it is narrower than a general-purpose SLSA consumer. Unknown local profile
fields or noncanonical bytes require a profile change rather than an implicit
compatibility fallback.

`evydence-release-provenance.json` is the `evydence-release-provenance.v2`
summary containing the same statement and explicit limitations.
`evydence-release-evidence-index.json` maps each binary and archive to its
SBOM and shared provenance file, including the evidence file digests.
The source-module inventory `evydence-release-sbom.cdx.json` is a separate
catalog; it does not replace the individual artifact SBOMs.

### Build v1

The producer uses the shared recipe described in
[reproducible builds](reproducible-builds.md). External parameters are the
release tag, exact source commit, ordered supported platform list and recipe
version. Resolved dependencies identify that commit, the actual pre-build
manifest and its source-relative materials. Builder versions record the Go,
Syft and evidence-profile versions.

A local invocation names the source-commit version of
`scripts/release_candidate_package.sh`. A hosted invocation names
`.github/workflows/release-artifacts.yml` at `GITHUB_WORKFLOW_SHA` and the
validated numeric GitHub Actions run URL. The checked-out source commit is
recorded separately. Neither field independently proves
that a provider executed the build. Subject integrity, producer assertions,
signature verification and independently verified signing identity remain
separate trust decisions. This is not a SLSA level claim.

The read-only verifier is:

```sh
python3 scripts/release_evidence_verify.py \
  --dist dist/<tag> --tag <tag> --expected-commit <full-source-commit>
```

It reopens the archive bytes, derives every binary subject, checks the complete
index and compares each SBOM and provenance subject against the actual digests.
Missing evidence, unsafe paths, ambiguous JSON and consistently rehashed
metadata for substituted bytes fail. It does not execute a downloaded binary
or need scanner, registry, signing or provider credentials.

The checksum stage also limits entries to regular release files or canonical
`migrations/<name>.sql` paths. Absolute paths, traversal, links, duplicate names
and oversized lists fail before a downloaded CLI is executed.

Historical `v0.1.0-rc.7` assets use the older provenance/module catalog format.
They have no verified per-artifact SBOM binding. Explicit compatibility is
limited to the repository, tag and commit in
[`release/legacy-evidence.json`](../../release/legacy-evidence.json):

```sh
EVYDENCE_RELEASE_ALLOW_LEGACY_EVIDENCE=1 make public-release-verify TAG=v0.1.0-rc.7
```

This verifies the historical checksums, manifest and legacy provenance shape;
it does not grant the new subject-binding assurance. New or retargeted tags
cannot use this compatibility path. The default public verifier requires the
artifact profile.

## Container build v1

`scripts/container_evidence.py` defines `evydence-container-evidence.v1` for
the supported Linux amd64 image. The index maps the immutable OCI manifest
digest to `evydence-container-sbom.cdx.json` and
`evydence-container-provenance.intoto.jsonl`, including their SHA-256 digests.
The SLSA-style predicate records the image reference, platform, Dockerfile,
source commit, source/tool lock digests, Buildx version and invocation.
Hosted builder identity uses `container-image.yml` at the workflow definition's
commit; it can differ from the source ref selected for the image build.

The OCI reader verifies one manifest, its configuration and every referenced
blob. It checks compressed blob hashes, expanded layer hashes (`diff_ids`),
declared sizes, source/version labels and Linux amd64 configuration. It rejects
links or unsafe paths in the outer layout, duplicate or unreferenced members,
unsupported media types and excessive expansion. Layout archives are limited
to 512 MiB, each expanded layer to 512 MiB and total expansion to 1 GiB.
Layer filesystem contents are read by the pinned scanner; they are not
extracted by the verifier onto the host filesystem.

Image inventories include recognized Go modules and Alpine APK coordinates,
including the optional bounded `upstream` package name for Alpine split
packages, plus the vetted Alpine operating-system descriptor. File paths, arbitrary
scanner metadata, licenses and relationships are omitted. Both Go and APK
inventory must be present. The scanner receives the OCI archive directly and
does not need registry credentials or network access.

The image workflow exports matching OCI media types to a local archive and
stages content-addressed blobs in GHCR with `push-by-digest=true`. It verifies
the image evidence before creating the requested tag, then checks that tag's
registry digest. Staged blobs can exist before the requested tag is created.
The signing job checks out the exact built source, verifies the downloaded
evidence again and performs the existing cosign signature checks. Signing
identity and provider protections remain separate controls.

Generation is qualified on a Linux amd64 host; the five binary target platforms
remain unchanged. For an already-built archive, replace the bracketed values
with its identities and use the pinned `release_scanner` path prepared by the
[candidate setup](release-candidate.md#required-commands):

```sh
python3 scripts/container_evidence.py generate \
  --oci image.oci.tar --image ghcr.io/aatuh/evydence:<tag> \
  --digest sha256:<manifest-sha256> --expected-commit <source-commit> \
  --out <evidence-directory> --syft "$release_scanner" --buildx-version <vN.N.N>
python3 scripts/container_evidence.py verify \
  --oci image.oci.tar --image ghcr.io/aatuh/evydence:<tag> \
  --digest sha256:<manifest-sha256> --expected-commit <source-commit> \
  --out <evidence-directory>
```

Buildx/BuildKit 0.13 or later supports the required
[multiple exporters](https://docs.docker.com/build/exporters/#multiple-exporters).
The workflow pins BuildKit to
`moby/buildkit:v0.34.0@sha256:b059f8d7226d0b326bc871af489a5dddf65e36af4d20d14251b072974d9ee87c`
and limits the builder to one worker and 6 GiB. The builder stops after export.
The digest and source labels identify image bytes and producer assertions;
they do not independently authenticate a publisher.

## Scanner dependency review

Observed on 2026-10-19; the patched local tool was checked on 2026-10-20.

| Item | Evidence and decision |
| --- | --- |
| Source | [Anchore Syft v1.54.1](https://github.com/anchore/syft/releases/tag/v1.54.1), commit `b254e6d92f28c3868a755f62fb3ca8f26e9fee76`; Go module sum `h1:IdNS5Ha7WfatXHDL0qzjdf7DBVnfb8OI3FpSbltv0nc=`. |
| License | [Apache-2.0](https://github.com/anchore/syft/blob/v1.54.1/LICENSE). |
| Activity and cadence | Upstream releases observed on August 10/27, September 17 and October 1/6, 2026. The latest observed release was October 6. This is historical activity, not a maintenance guarantee. |
| Why this tool | The standard library supplies archive parsers and hashing but does not catalog cross-platform Go binaries and container package ecosystems or generate those inventories in CycloneDX. |
| Footprint | The patched isolated tool module declares 100 direct and 241 indirect requirements. They are tooling dependencies, not additions to Evydence's application module. |
| Patched upstream advisories | [Binary parsing memory exhaustion](https://github.com/anchore/syft/security/advisories/GHSA-mw2c-m758-9v5q) fixed in 1.52.0; [temporary-file cleanup](https://github.com/anchore/syft/security/advisories/GHSA-rjcw-vg7j-m9rc) fixed in 1.42.3; [attestation credential disclosure](https://github.com/anchore/syft/security/advisories/GHSA-jp7v-3587-2956) affected 0.69.0 through versions before 0.70.0. |
| Toolchain correction | The upstream Linux binary used Go 1.26.8. Its binary vulnerability scan found 13 advisories. The local source build uses the current compiler from `release/support-matrix.json` (Go 1.27.2 at observation) and pins `golang.org/x/net` to 0.60.0; its scan leaves one advisory. |
| Remaining advisory | [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) concerns bundled, unmaintained `golang.org/x/crypto/openpgp`, with no fixed version. The full CLI's binary scan still reports it. This wrapper requests no OpenPGP signing, authentication or verification and exposes only fixed offline scan/version commands. This is a limited-use assessment, not a vulnerability-free tool claim. |
| Replacement | Upgrade the pinned source and isolated tool lock when reviewed, or replace the scanner adapter while retaining the subject/index verification contract. Failure to obtain a qualified scanner must fail generation rather than emit an empty inventory. |

The scanner child receives a private HOME/configuration directory, bounded
output, a deadline, one cataloger worker and no ambient credentials, database
configuration or operator Go flags. Go binary/archive scans explicitly select
the Go binary cataloger and disable local-cache, vendor and remote license
discovery. Image scans select the same Go cataloger and the Alpine APK cataloger.
The selected upstream
[Go cataloger](https://github.com/anchore/syft/blob/v1.54.1/syft/pkg/cataloger/golang/cataloger.go)
and [APK cataloger](https://github.com/anchore/syft/blob/v1.54.1/syft/pkg/cataloger/alpine/cataloger.go)
read build information and installed-package records. No OpenPGP operation is
requested by this adapter. Reassess the remaining advisory whenever command,
cataloger, transport or output selection changes. The full Syft CLI remains
outside this restricted-use claim.

`make release-evidence-tools` verifies the upstream module as a dependency
before copying its cached source. It then applies the checked tool module locks,
verifies those dependencies and builds with the current Go compiler. Completed
installations bind the executable hash to the tool recipe; changed binaries or
recipes fail preflight. Failed isolated builds are preserved for diagnosis.

SBOMs and provenance organize technical evidence. They do not certify a
release, establish legal compliance, prove complete SBOM coverage, make scanner
results authoritative, or guarantee release security.

# Release Evidence Index

The release-style binary gate also writes
`tmp/black-box-release-artifact/lifecycle/summary.json`, per-case durable receipts
and Go events for four real-SIGTERM API/worker scenarios. See the
[release validation contract](release-validation.md#production-readiness-gate)
for required counts, artifact hash binding and scope limits.

This reference maps each release-candidate evidence artifact to the command
that creates or verifies it. Keep it with
[Release candidate checklist](release-candidate.md) and
[Release validation](release-validation.md) when preparing a controlled
self-hosted release candidate.

Release evidence supports reproducible engineering and operator review. It is
not legal compliance proof, certification, complete SBOM proof, authoritative
vulnerability coverage, a secure-release guarantee, regulator acceptance, or
auditor acceptance.

## Artifact Map

`scripts/release_candidate_package.sh <tag>` writes the release evidence set
under `dist/<tag>/` after `make production-check` passes.

| Artifact | Created By | Verification Use |
| --- | --- | --- |
| `evydence_<tag>_<os>_<arch>.tar.gz` or `.zip` | `scripts/release_candidate_package.sh` | Verify the commands declared in the [platform policy](toolchain-platform-support.md#release-build-plan): the CLI for each declared target, plus API, worker and migration commands for Linux amd64. |
| `SHA256SUMS` | `scripts/release_candidate_package.sh` | Verify every release archive byte-for-byte before extraction or redistribution. |
| `openapi.yaml` | `cmd/openapi` through the release package script | Preserve the exact public API contract shipped with the release. |
| `openapi.sha256` | `scripts/release_candidate_package.sh` | Verify the shipped OpenAPI contract has not drifted from the release evidence set. |
| `migrations.sha256` | `scripts/release_candidate_package.sh` | Verify the migration directory that the release was checked against. |
| `release-build-manifest.json` | `scripts/release_candidate_package.sh` | Bind the tag, commit, build time, Go version, OpenAPI input, and migration inputs used to inject the API build identity. Its SHA-256 digest is reported by `GET /v1/version`; it is also included in the final signed manifest. |
| `coverage.out` | `make production-check` | Preserve the coverage input used by the release gate. |
| `release-check-summary.txt` | `make release-check` inside `make production-check` | Record whether formatting, unit tests, OpenAPI, docs, deployment, SDK, lint, gosec, govulncheck, race, and live PostgreSQL checks passed. |
| `evydence-release-manifest.json` | `./evydence release manifest` through the package script | List release artifacts, hashes, OpenAPI checksum, migration checksum, and release metadata. |
| `evydence-release-manifest.sig.json` | `./evydence release sign` through the package script | Verify the release manifest signature with the release public key. |
| `evydence-release-manifest.sig` | Copied from `evydence-release-manifest.sig.json` by the package script | Scorecard-compatible alias for the signed manifest metadata. Use the `.sig.json` file with the Evydence CLI verifier. |
| `evydence-release-attestations.sigstore.json` | Protected Release Artifacts attestation job, after packaging | Authenticate the manifest and signature using the exact issuer/workflow/ref/source policy before any downloaded CLI executes. Historical RC.7 has pinned legacy content instead. |
| `evydence-release-sbom.cdx.json` | `scripts/release_evidence_metadata.py` | Source-module catalog with coverage limits; individual artifact SBOMs provide the byte bindings. |
| `evydence-sbom-<subject-name-sha256>.cdx.json` | `scripts/release_evidence_metadata.py` and pinned Syft | One CycloneDX 1.6 inventory for each supported binary/archive, bound to its actual SHA-256 digest. |
| `evydence-release-evidence-index.json` | `scripts/release_evidence_metadata.py` | Map all eight binaries and five archives to their SBOM and provenance file digests. |
| `evydence-release-provenance.json` | `scripts/release_evidence_metadata.py` | Version 2 summary of the source, shared SLSA-style statement and limitations; provider identity is a separate verification decision. |
| `evydence-release-provenance.intoto.jsonl` | `scripts/release_evidence_metadata.py` | In-toto Statement v1 with SLSA provenance v1 predicate and actual artifact digests. This is not a SLSA level claim. |
| `release-notes.md` | Tag-specific release notes or `docs/reference/release-notes-template.md` | State supported profile, upgrade notes, assumptions, limitations, and unresolved hardening work. |
| `ghcr.io/aatuh/evydence:<tag>` | `.github/workflows/container-image.yml` | Optional project-owned image publication path for a release tag. Verify by digest and cosign workflow identity; do not deploy by mutable tag alone. |
| `evydence-container-image-manifest.json` | `.github/workflows/container-image.yml` | Records the image digest, source commit, cosign verification file, assumptions, and limitations for the image workflow run. |
| `image.oci.tar` | Container workflow's OCI exporter | Transport the supported image's manifest/config/layers for offline digest and source-label checks. |
| `evydence-container-sbom.cdx.json` | `scripts/container_evidence.py` and pinned Syft | Bind recognized Go/APK components and the Alpine OS descriptor to the immutable image manifest digest. |
| `evydence-container-provenance.intoto.jsonl` | `scripts/container_evidence.py` | Record the image subject, workflow/source commits, Dockerfile and tool locks, parameters and limitations. |
| `evydence-container-evidence-index.json` | `scripts/container_evidence.py` | Map the image subject to its SBOM and provenance digests; verification reopens the actual OCI layout. |

The [SBOM and provenance profile](release-supply-chain.md) defines the exact
formats, tool versions, coverage limits and verification commands. Historical
public assets listed below retain their original metadata format.

## Current Public Release Candidate

The current public release candidate is
[`v0.1.0-rc.7`](https://github.com/aatuh/evydence/releases/tag/v0.1.0-rc.7).
It was built from tag `v0.1.0-rc.7` at commit
`2f759100e723554e4e68e3ada712c923e391a17a`; the public Release Artifacts
workflow run is
[`26769039974`](https://github.com/aatuh/evydence/actions/runs/26769039974).
The release commit also has a public CI `Production Check` run
[`26767778491`](https://github.com/aatuh/evydence/actions/runs/26767778491)
and CodeQL run
[`26767778487`](https://github.com/aatuh/evydence/actions/runs/26767778487).

The public prerelease includes release archives for Linux, macOS, and Windows;
`SHA256SUMS`; `openapi.yaml`; `openapi.sha256`; `migrations.sha256`;
`coverage.out`; `release-check-summary.txt`; `evydence-release-sbom.cdx.json`;
`evydence-release-provenance.json`;
`evydence-release-provenance.intoto.jsonl`; `release-notes.md`;
`evydence-release-manifest.json`; `evydence-release-manifest.sig.json`; and
`evydence-release-manifest.sig`.

`release-build-manifest.json` is included by release packages produced after
the build-identity addition. Its presence has not been verified for the
historical public `v0.1.0-rc.7` artifact set.

The latest repository-local source snapshot recorded in
[`release/current.json`](../../release/current.json) is commit
`266ec32bb4bc8857a2bafc8c2be0db06bfb01131` on `master`, recorded on
2026-07-22. It is intentionally distinct from the `v0.1.0-rc.7` public release
and from container image verification; a source snapshot alone has no public
release artifacts.

Project-owned container images are separate release evidence. At the time this
index was updated, the latest verified project-owned container image evidence
for the release-candidate line was
`ghcr.io/aatuh/evydence:v0.1.0-rc.5@sha256:38188044a3e5ded3c6094564ab39ce989185f65e22cf4296985ec19ba0eb1888`.
It was produced by the Container Image workflow run
[`26752805538`](https://github.com/aatuh/evydence/actions/runs/26752805538)
from release source commit `d5098c635ee7b171dac3a449ba7ca2e30d8b0c16`.
That image is not an `v0.1.0-rc.7` image. For `v0.1.0-rc.7`, use release
archives or publish and verify a tag-specific image before treating it as
deployment evidence. A tag-specific image workflow run should attach
`evydence-container-image-manifest.json` and
`evydence-container-image-cosign-verify.json` when available.

## Local Verification

After packaging, verify the evidence directory before publishing:

```sh
gh release download v0.1.0-rc.7 --repo aatuh/evydence --dir dist/v0.1.0-rc.7
(cd dist/v0.1.0-rc.7 && sha256sum -c SHA256SUMS)
(cd dist/v0.1.0-rc.7 && sha256sum -c openapi.sha256)
sha256sum -c dist/v0.1.0-rc.7/migrations.sha256
tar -C dist/v0.1.0-rc.7 -xzf dist/v0.1.0-rc.7/evydence_v0.1.0-rc.7_linux_amd64.tar.gz
./dist/v0.1.0-rc.7/evydence_v0.1.0-rc.7_linux_amd64/evydence release verify \
  --manifest dist/v0.1.0-rc.7/evydence-release-manifest.json \
  --signature dist/v0.1.0-rc.7/evydence-release-manifest.sig.json
```

Use the platform-specific `evydence` binary from the release archive whenever
possible so the verifier matches the released toolchain. If you verify from a
source checkout instead, record that limitation in the release notes.

To verify the already-published public release from a clean temporary directory,
run:

```sh
EVYDENCE_RELEASE_ALLOW_LEGACY_EVIDENCE=1 make public-release-verify TAG=v0.1.0-rc.7
```

The explicit legacy profile is restricted to the recorded repository/tag/commit.
The helper downloads assets with `gh`, requires the pinned manifest/public-key
fingerprints, checks manifest-bound files and bounded release/migration checksum
paths, and validates the old in-toto shape and signature. It does not grant
artifact-bound SBOM or protected keyless workflow assurance. The default public
verifier requires the new identity/profile and checks actual subjects before
executing a downloaded CLI. See [publisher identity and custody](../release-signing.md).

For local release asset smoke validation without live GitHub Releases or full
release-candidate packaging, run:

```sh
make release-asset-smoke-check
```

The smoke check verifies a synthetic release asset set, checksum mismatch
failure, missing-asset failure, signed manifest verification, tampered manifest failure,
sample customer package verification output, and wrong expected package ID failure.

To inspect the last checked historical public container image digest, run:

```sh
docker buildx imagetools inspect ghcr.io/aatuh/evydence:v0.1.0-rc.5 \
  --format '{{json .Manifest.Digest}}'
```

This historical digest predates the new exact workflow/ref/source profile;
inspection alone does not authenticate its publisher. Use the canonical
[`cosign verify` command for new containers](../release-signing.md#verify-new-container-identities)
with an independently selected digest and source commit. Historical signatures
need their own reviewed identity profile, without granting new protected-workflow
assurance through a wildcard.

Expected digest:
`sha256:38188044a3e5ded3c6094564ab39ce989185f65e22cf4296985ec19ba0eb1888`.
The cosign verification proves the configured workflow identity signed the
image digest; it is not legal compliance proof, certification, complete SBOM
proof, authoritative vulnerability coverage, or a secure-release guarantee.

## Publication Status

The first public release candidate is published. GitHub Releases are now the
operator evaluation source for release-candidate binaries and release evidence.
Source checkout remains the development path.

Project-owned container images are published separately from the release archive
workflow through `.github/workflows/container-image.yml` as
`ghcr.io/aatuh/evydence:<tag>`. Treat an image as release evidence only when the
workflow has produced an immutable digest and
`evydence-container-image-manifest.json` for that tag. Operators who mirror or
rebuild images for Kubernetes or air-gapped workflows must record the resulting
digest with their deployment evidence.

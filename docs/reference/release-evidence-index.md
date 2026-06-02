# Release Evidence Index

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
| `evydence_<os>_<arch>.tar.gz` or `.zip` | `scripts/release_candidate_package.sh` | Operator installs the API, worker, migration command, and CLI from the release archive for the matching platform. |
| `SHA256SUMS` | `scripts/release_candidate_package.sh` | Verify every release archive byte-for-byte before extraction or redistribution. |
| `openapi.yaml` | `cmd/openapi` through the release package script | Preserve the exact public API contract shipped with the release. |
| `openapi.sha256` | `scripts/release_candidate_package.sh` | Verify the shipped OpenAPI contract has not drifted from the release evidence set. |
| `migrations.sha256` | `scripts/release_candidate_package.sh` | Verify the migration directory that the release was checked against. |
| `coverage.out` | `make production-check` | Preserve the coverage input used by the release gate. |
| `release-check-summary.txt` | `make release-check` inside `make production-check` | Record whether formatting, unit tests, OpenAPI, docs, deployment, SDK, lint, gosec, govulncheck, race, and live PostgreSQL checks passed. |
| `evydence-release-manifest.json` | `./evydence release manifest` through the package script | List release artifacts, hashes, OpenAPI checksum, migration checksum, and release metadata. |
| `evydence-release-manifest.sig.json` | `./evydence release sign` through the package script | Verify the release manifest signature with the release public key. |
| `evydence-release-manifest.sig` | Copied from `evydence-release-manifest.sig.json` by the package script | Scorecard-compatible alias for the signed manifest metadata. Use the `.sig.json` file with the Evydence CLI verifier. |
| `evydence-release-sbom.cdx.json` | `scripts/release_evidence_metadata.py` | Record release SBOM metadata and limitations; this does not prove SBOM completeness. |
| `evydence-release-provenance.json` | `scripts/release_evidence_metadata.py` | Record build/release provenance metadata and limitations; this does not prove provider trust by itself. |
| `evydence-release-provenance.intoto.jsonl` | `scripts/release_evidence_metadata.py` | Scorecard-compatible in-toto statement with the same Evydence release provenance limitations. This is not a SLSA level claim. |
| `release-notes.md` | Tag-specific release notes or `docs/reference/release-notes-template.md` | State supported profile, upgrade notes, assumptions, limitations, and unresolved hardening work. |
| `ghcr.io/aatuh/evydence:<tag>` | `.github/workflows/container-image.yml` | Optional project-owned image publication path for a release tag. Verify by digest and cosign workflow identity; do not deploy by mutable tag alone. |
| `evydence-container-image-manifest.json` | `.github/workflows/container-image.yml` | Records the image digest, source commit, cosign verification file, assumptions, and limitations for the image workflow run. |

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
make public-release-verify TAG=v0.1.0-rc.7
```

The helper downloads the release assets with `gh`, checks the public checksums,
validates the in-toto statement shape, extracts the released Linux amd64 CLI,
and verifies the signed manifest with that released binary.

For local release asset smoke validation without live GitHub Releases or full
release-candidate packaging, run:

```sh
make release-asset-smoke-check
```

The smoke check verifies a synthetic release asset set, checksum mismatch
failure, missing-asset failure, signed manifest verification, tampered manifest failure,
sample customer package verification output, and wrong expected package ID failure.

To verify the last checked public container image digest and workflow identity,
run:

```sh
docker buildx imagetools inspect ghcr.io/aatuh/evydence:v0.1.0-rc.5 \
  --format '{{json .Manifest.Digest}}'
cosign verify \
  --certificate-identity-regexp 'https://github.com/aatuh/evydence/.github/workflows/container-image.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/aatuh/evydence@sha256:38188044a3e5ded3c6094564ab39ce989185f65e22cf4296985ec19ba0eb1888
```

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

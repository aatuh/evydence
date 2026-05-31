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
| `evydence-release-sbom.cdx.json` | `scripts/release_evidence_metadata.py` | Record release SBOM metadata and limitations; this does not prove SBOM completeness. |
| `evydence-release-provenance.json` | `scripts/release_evidence_metadata.py` | Record build/release provenance metadata and limitations; this does not prove provider trust by itself. |
| `release-notes.md` | Tag-specific release notes or `docs/reference/release-notes-template.md` | State supported profile, upgrade notes, assumptions, limitations, and unresolved hardening work. |

## Current Public Release Candidate

The current public release candidate is
[`v0.1.0-rc.4`](https://github.com/aatuh/evydence/releases/tag/v0.1.0-rc.4).
It was built from tag `v0.1.0-rc.4` at commit
`944c4c6694535f6fc23a2b272e58347217321672`; the public Release Artifacts
workflow run is
[`26719422897`](https://github.com/aatuh/evydence/actions/runs/26719422897).
The release commit also has a public CI `Production Check` run
[`26719406847`](https://github.com/aatuh/evydence/actions/runs/26719406847)
and CodeQL run
[`26719406836`](https://github.com/aatuh/evydence/actions/runs/26719406836).

The public prerelease includes release archives for Linux, macOS, and Windows;
`SHA256SUMS`; `openapi.yaml`; `openapi.sha256`; `migrations.sha256`;
`coverage.out`; `release-check-summary.txt`; `evydence-release-sbom.cdx.json`;
`evydence-release-provenance.json`; `release-notes.md`;
`evydence-release-manifest.json`; and
`evydence-release-manifest.sig.json`.

## Local Verification

After packaging, verify the evidence directory before publishing:

```sh
gh release download v0.1.0-rc.4 --repo aatuh/evydence --dir dist/v0.1.0-rc.4
(cd dist/v0.1.0-rc.4 && sha256sum -c SHA256SUMS)
(cd dist/v0.1.0-rc.4 && sha256sum -c openapi.sha256)
sha256sum -c dist/v0.1.0-rc.4/migrations.sha256
tar -C dist/v0.1.0-rc.4 -xzf dist/v0.1.0-rc.4/evydence_v0.1.0-rc.4_linux_amd64.tar.gz
./dist/v0.1.0-rc.4/evydence_v0.1.0-rc.4_linux_amd64/evydence release verify \
  --manifest dist/v0.1.0-rc.4/evydence-release-manifest.json \
  --signature dist/v0.1.0-rc.4/evydence-release-manifest.sig.json
```

Use the platform-specific `evydence` binary from the release archive whenever
possible so the verifier matches the released toolchain. If you verify from a
source checkout instead, record that limitation in the release notes.

## Publication Status

The first public release candidate is published. GitHub Releases are now the
operator evaluation source for release-candidate binaries and release evidence.
Source checkout remains the development path.

The current release line does not publish a project-owned container image.
Operators who need Kubernetes or air-gapped image workflows must build, sign,
and publish an image into their own registry from the release archive or source
checkout, then record the image digest with their deployment evidence.

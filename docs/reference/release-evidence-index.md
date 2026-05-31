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
| `release-sbom-metadata.json` | `scripts/release_evidence_metadata.py` | Record release SBOM metadata and limitations; this does not prove SBOM completeness. |
| `release-provenance-metadata.json` | `scripts/release_evidence_metadata.py` | Record build/release provenance metadata and limitations; this does not prove provider trust by itself. |
| `release-notes.md` | Tag-specific release notes or `docs/reference/release-notes-template.md` | State supported profile, upgrade notes, assumptions, limitations, and unresolved hardening work. |

## Local Verification

After packaging, verify the evidence directory before publishing:

```sh
sha256sum -c dist/<tag>/SHA256SUMS
./dist/<tag>/<platform>/evydence release verify \
  --manifest dist/<tag>/evydence-release-manifest.json \
  --signature dist/<tag>/evydence-release-manifest.sig.json \
  --public-key evydence-release-public.key
```

Use the platform-specific `evydence` binary from the release archive whenever
possible so the verifier matches the released toolchain. If you verify from a
source checkout instead, record that limitation in the release notes.

## Publication Status

Before the first public release, source checkout remains the development and
evaluation path. After a public release candidate is published, GitHub Releases
must be the install source for operator evaluation, and the README, getting
started tutorial, and install guide should link to the release artifacts and
this index.

Public publication is not proven by this file. It requires a pushed tag, a
completed release-artifacts workflow run, uploaded release assets, and any
repository or registry settings required by the operator.

# Release Candidate Checklist

This reference defines the minimum evidence for a controlled self-hosted
Evydence release candidate such as `v0.1.0-rc.1` or `v0.9.0-rc.1`.

Release-candidate evidence supports reproducible engineering and operator
review. It is not a certification, legal compliance conclusion, complete SBOM
claim, authoritative vulnerability result, secure-release guarantee, regulator
acceptance, or auditor acceptance.

## Required Evidence

Before creating a release-candidate tag, collect:

- passing `make production-check` output with live PostgreSQL configured;
- `tmp/release-check-summary.txt` from the same run;
- `coverage.out` and the total coverage summary;
- `openapi.yaml` plus an OpenAPI checksum;
- migration checksum output for the directory or per-file migration checksums;
- per-binary/archive SBOMs, SLSA-style provenance and their evidence index;
- signed release artifact manifest and manifest signature;
- checksums for every published binary, container image digest, chart package,
  and release archive;
- release notes with supported profile, upgrade notes, assumptions,
  limitations, and unresolved hardening work.

The artifact map and verification commands are maintained in
[Release evidence index](release-evidence-index.md).

## Required Commands

Run from a clean checkout with a disposable PostgreSQL database:

```sh
set -a; . ./.test.env; set +a
release_scanner="$(make --silent --no-print-directory release-evidence-tools RELEASE_EVIDENCE_TOOLS_ROOT="${TMPDIR:-/tmp}/evydence-release-tools")"
EVYDENCE_RELEASE_SYFT="$release_scanner" \
EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64="$(cat evydence-release-private.key)" \
  make release-candidate-check TAG=<vX.Y.Z-rc.N>
```

The target runs `scripts/release_candidate_package.sh`, which requires a clean
worktree, a release-candidate tag such as `v0.1.0-rc.1`, no existing local tag
unless the protected master publication workflow explicitly allows it, live PostgreSQL through
`EVYDENCE_TEST_DATABASE_URL`, a verified pinned scanner installation selected
by `EVYDENCE_RELEASE_SYFT`, and release signing material. It runs
`make production-check`, builds the release archive matrix, writes checksums,
generates and checks artifact-bound SBOM/provenance metadata, signs the complete evidence set,
verifies the manifest signature, and validates the release-note language.

The scanner setting is consumed before production validation and passed only to
the metadata generator. It is not an application configuration variable. See
[the SBOM and provenance profile](release-supply-chain.md) for tool locks,
coverage limits, container verification and historical compatibility.

Do not tag from a run where live PostgreSQL checks, migration compatibility,
coverage threshold enforcement, OpenAPI checks, docs checks, deployment checks,
SDK checks, lint, gosec, govulncheck, race tests, artifact checksums, or
manifest signature verification were skipped.

## Supported Profile Statement

Release notes must use this status unless the production exit review has
explicitly changed it:

> Controlled self-hosted production candidate for evaluation, pilots, and
> controlled internal production after operator review.

The notes must also state that broad production for most uses, regulated
production, and hosted SaaS production require additional review and controls.

## Public Publication

The current public release candidate,
[`v0.1.0-rc.7`](https://github.com/aatuh/evydence/releases/tag/v0.1.0-rc.7),
is published as a prerelease. Public release readiness requires a pushed tag, a
completed release-artifacts workflow run, uploaded release archives, checksums,
signed manifest files, release notes, and any configured repository or registry
trust settings.

Release archives and release evidence are published by the Release Artifacts
workflow. Project-owned container images are published by the separate Container
Image workflow to `ghcr.io/aatuh/evydence:<tag>` when that workflow is run for a
release tag. Operators should pin the resulting digest, verify the cosign
evidence, and record that image digest with deployment evidence. If no image
workflow evidence exists for a tag, operators must build and publish images into
their own registry for Helm or air-gapped deployment flows.

The release packaging workflow keeps `GITHUB_TOKEN` contents access read-only and
separates package generation from draft-release publication. Creating or
updating the draft GitHub release happens in a separate job and requires the
`EVYDENCE_RELEASE_PUBLISH_TOKEN` secret with only the release-publication scope
the maintainer account approves for that workflow. The container image workflow
also keeps `GITHUB_TOKEN` from receiving package-write permissions; publishing
to GHCR requires `EVYDENCE_GHCR_PUBLISH_TOKEN`, and only the separate signing
job receives `id-token: write` for keyless cosign signing. Artifact publication
also has a separate keyless attestation job with the narrowly scoped token
permissions described in [release signing](../release-signing.md). Publishing
tokens belong in the reviewed `release-production` environment, with no
repository-scoped signing key. Provider migration is required before this
profile can run; secret values must not be printed, committed or included in
release evidence. Dispatch from protected `master`, with a reviewed existing
RC tag at that exact commit; tag-push signing is no longer supported.

## Deployment Constraints

- Use one API writer replica for the current production profile.
- Worker replicas may be scaled when PostgreSQL outbox locking is enabled.
- Use external PostgreSQL, external object storage, TLS ingress, non-default
  API-key pepper, externalized secrets, backup and restore rehearsal,
  monitoring, and documented incident response.
- Keep service decomposition, HA/multi-writer operation, native PKCS#11/HSM
  modules, provider-specific management API/group synchronization, and broader
  object-lock proof beyond configured bucket/sample-object checks listed as
  unresolved hardening work until they are implemented and verified.

# Production Exit Review

This review records the current release-positioning decision. It is a product
and operations review, not legal compliance proof, certification, complete SBOM
proof, an authoritative vulnerability result, or a secure-release guarantee.

## Verdict

Evydence remains a controlled self-hosted production candidate. Do not change
the public status to broad production-ready, regulated production-ready, hosted
SaaS-ready, legally compliant, certified, or secure-release-guaranteed.

## Repo-Verified Strengths

- API contract has 186 precise `/v1` operations and zero broad operations.
- `make production-check` is available and requires live PostgreSQL, coverage,
  migration compatibility, release validation, race tests, security scans, and
  release-signing smoke checks.
- `make coverage-check` now fails early without `EVYDENCE_TEST_DATABASE_URL` so
  local no-database coverage cannot be mistaken for production release
  evidence.
- Production API startup rejects in-process state, default pepper, unsupported
  writer modes, writer replicas above one, local plaintext signing-key mode,
  and bootstrap secret printing.
- Release-candidate packaging generates checksums, OpenAPI checksum, migration
  checksum, release SBOM metadata, release provenance metadata, release notes,
  signed manifest, and manifest signature.
- Public prerelease `v0.1.0-rc.7` is published with signed release archives,
  checksums, OpenAPI and migration checksums, coverage output,
  production-check summary, SBOM/provenance metadata, release notes, and signed
  release manifest.
- PostgreSQL relational-only production loading and focused critical plus
  release-ledger write paths are implemented for the current candidate profile.
- Security, support, governance, contribution, code of conduct, issue
  templates, Dependabot, and Scorecard workflow files exist.
- CODEOWNERS and the maintainer review policy document expected review
  ownership for high-risk code, release, deployment, and public-claim surfaces.
- The release-artifacts workflow keeps `GITHUB_TOKEN` read-only and separates
  signed package generation from draft GitHub release publication. Draft
  publication uses `EVYDENCE_RELEASE_PUBLISH_TOKEN` only in the publication job.
- The container-image workflow keeps `GITHUB_TOKEN` read-only, uses
  `EVYDENCE_GHCR_PUBLISH_TOKEN` for GHCR publication, and scopes GitHub OIDC
  `id-token: write` to the keyless cosign signing job.
- `make release-acceptance` and
  `make public-release-verify TAG=v0.1.0-rc.7` have passed against the current
  repository state.

## Remaining Exit Blockers

- Project-owned container images count as release evidence only after the
  maintainer Container Image workflow has run for the tag and produced digest
  plus cosign evidence. Operators who mirror or rebuild images for Helm or
  air-gapped workflows must record their own image digest and verification
  evidence.
- GitHub private vulnerability reporting, secret scanning, push protection,
  Dependabot security updates, public CI, CodeQL, Scorecard, Scorecard SARIF,
  and zero open code-scanning alerts have been verified for the current public
  `master` state. Branch protection admin bypass state, repository secret
  values, and workflow publication credentials remain provider/account checks.
- Native PKCS#11/HSM module custody requires operator hardware, drivers, and
  provider-specific validation.
- Broad WORM/object-lock proof requires object-store policy, IAM, lifecycle,
  backup, and provider audit evidence.
- Direct provider management APIs and external group synchronization remain
  outside the current bring-your-own-evidence posture.
- Multi-writer API HA remains unsupported. The current reviewed stance is one
  API writer replica.
- Target-environment backup/restore, incident-response, monitoring, and
  capacity tests must be run by each operator.

## Decision

The current repository can support controlled self-hosted evaluation, pilots,
and internal production after operator review. The tracked
[production readiness audit closeout](production-readiness-audit-closeout.md)
and [highest achievable internal score](production-internal-score.md) support
keeping this controlled candidate status, not strengthening it. It should not
be marketed as broad production-ready for most uses until the external controls
above are closed, the
[Stable v0.1.0 exit criteria](stable-v0.1.0-exit-criteria.md) pass for a
concrete candidate, and a fresh product, codebase, security, documentation, and
test audit confirms the change.

# Production Exit Review

This review records the current release-positioning decision. It is a product
and operations review, not legal compliance proof, certification, complete SBOM
proof, an authoritative vulnerability result, or a secure-release guarantee.

## Verdict

Evydence remains a controlled self-hosted production candidate. Do not change
the public status to broad production-ready, regulated production-ready, hosted
SaaS-ready, legally compliant, certified, or secure-release-guaranteed.

## Repo-Verified Strengths

- API contract has 166 precise `/v1` operations and zero broad operations.
- `make production-check` is available and requires live PostgreSQL, coverage,
  migration compatibility, release validation, race tests, security scans, and
  release-signing smoke checks.
- Production API startup rejects in-process state, default pepper, unsupported
  writer modes, writer replicas above one, local plaintext signing-key mode,
  and bootstrap secret printing.
- Release-candidate packaging generates checksums, OpenAPI checksum, migration
  checksum, release SBOM metadata, release provenance metadata, release notes,
  signed manifest, and manifest signature.
- PostgreSQL relational-only production loading and focused critical plus
  release-ledger write paths are implemented for the current candidate profile.
- Security, support, governance, contribution, code of conduct, issue
  templates, Dependabot, and Scorecard workflow files exist.

## Remaining Exit Blockers

- Public release publication and branch protection require GitHub/operator
  settings outside repository files.
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
and internal production after operator review. It should not be marketed as
broad production-ready for most uses until the external controls above are
closed and a fresh product, codebase, security, documentation, and test audit
confirms the change.

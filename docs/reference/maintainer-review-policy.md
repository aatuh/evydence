# Maintainer Review Policy

This reference documents the repository review expectations for Evydence
changes that affect high-trust release evidence, tenant isolation, credentials,
signing, storage, deployment, or public product claims.

The policy supports engineering review. It is not legal compliance proof,
certification, complete vulnerability coverage, or a secure-release guarantee.

## Current Enforcement Status

`CODEOWNERS` is committed at the repository root and names the expected
maintainer owner for high-risk paths. GitHub branch protection or repository
rules must enforce CODEOWNERS and required checks before it becomes a merge
gate. Until those GitHub settings are enabled, this file is a public review
policy and not a technical enforcement guarantee.

## High-Risk Paths

Changes in these areas require maintainer review before merge or release:

- `internal/app/`, `internal/domain/`, and `internal/adapters/httpapi/` for
  tenant isolation, authorization, idempotency, evidence immutability, report
  wording, and API behavior;
- `internal/adapters/postgres/`, `internal/adapters/objectstore/`, and
  `migrations/` for persistence, object payload references, transaction
  behavior, durability, and recovery;
- `cmd/`, `scripts/`, `.github/workflows/`, and `Makefile` for CLI/operator
  behavior, release packaging, CI gates, and secret-handling surfaces;
- `deploy/`, `Dockerfile`, `docker-compose.yml`, and
  `compose.production-like.yml` for production startup, probes, resources,
  ingress, object storage, and database wiring;
- `openapi.yaml`, `docs/api.md`, and `docs/reference/api-contract-matrix.md`
  for public API contract changes;
- `SECURITY.md`, `RELEASE_EVIDENCE.md`, `README.md`, and production/release
  references for public security intake, release evidence, production status,
  and product claim boundaries.

## Required Review Questions

Reviewers should explicitly check:

- tenant-scoped resources cannot cross tenant boundaries;
- evidence core fields, audit-chain entries, release bundles, decisions,
  approvals, exceptions, and lifecycle records remain append-only where
  required;
- create/action endpoints preserve idempotency replay and conflict behavior;
- uploaded objects, release artifacts, and imported bundles are checked by
  digest before trust is assigned;
- errors, logs, reports, release evidence, and examples do not expose API keys,
  bearer tokens, session tokens, portal tokens, private keys, database URLs,
  provider credentials, raw evidence payloads, or customer data;
- public wording stays limited to compliance readiness, technical evidence
  organization, reproducibility, gaps, assumptions, exceptions, and
  limitations.

## Required Checks

For routine changes, run the narrowest affected tests plus the relevant
project-owned gate. For release, production, deployment, API, persistence, or
security-sensitive changes, reviewers should require evidence from:

```sh
make docs-check
make fast-check
```

Release-candidate and production-readiness changes should also require:

```sh
make production-check
make release-candidate-check TAG=<vX.Y.Z-rc.N>
```

Those stronger commands require live PostgreSQL and release signing material;
skips or unavailable external dependencies must be recorded in release notes or
the release evidence index.

Repository CI and SAST workflows should keep third-party Actions pinned by
commit SHA and service/container images pinned by digest. If an Action or image
pin is updated, reviewers should verify the upstream tag or digest source and
record the reason in the pull request or release evidence.

Branch protection requires the live `Production Check` and `CodeQL Analyze`
checks because they run on pushes and pull requests and directly gate runtime
correctness and security analysis. OpenSSF Scorecard and Scorecard SARIF remain
scheduled/manual advisory checks for the current release-candidate line. Do not
make them required branch-protection checks unless their workflows also run on
the same pull request events without introducing circular or non-deterministic
merge blocking.

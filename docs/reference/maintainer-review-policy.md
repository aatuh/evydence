# Maintainer Review Policy

This reference documents the repository review expectations for Evydence
changes that affect high-trust release evidence, tenant isolation, credentials,
signing, storage, deployment, or public product claims.

The policy supports engineering review. It is not legal compliance proof,
certification, complete vulnerability coverage, or a secure-release guarantee.

## Current Enforcement Status

The [repository controls reference](repository-controls.md) owns the required
GitHub profile, live-verification command, refresh cadence, and dated evidence.
Provider reads on 2026-10-19 verified required pull requests, administrator
enforcement, strict app-bound CI checks, resolved conversations, and protected
release tags. The verified maintainer model has one human writer, so independent
approvals and CODEOWNERS approvals are not required. `CODEOWNERS` remains an
ownership reference for high-risk paths.

The solo model requires maintainer self-review before merging a pull request.
It does not provide independent review. When another human maintainer gains
write access, require at least one non-author approval and approval of the latest
push, then rerun the live verifier. Settings can change after observation;
refresh the report before relying on them.

EVY-1105 implementation `57cb91a95bbf` is included in published commit
`d77b612bc721`. Its hosted [Production Check and Race and Stress run](https://github.com/aatuh/evydence/actions/runs/38765165262)
and [CodeQL run](https://github.com/aatuh/evydence/actions/runs/38765165260)
passed on that same commit. These historical results do not establish CI success
for other commits or release artifacts.

## Administrator Enforcement

The verified profile applies the configured branch checks to administrators and
has no review-bypass allowance. Maintainers must use the normal pull-request
path and wait for every required check. Do not weaken protection or bypass checks
to publish local implementation work. Keep any necessary settings changes
explicit, record their reason, and collect a fresh provider report afterward.
Administrators can still edit repository settings; this is not an immutable
governance boundary or a claim of independent review.

## High-Risk Paths

Changes in these areas require maintainer self-review before merge or release,
without a mandatory second-person approval:

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

Branch protection requires `Production Check`, `CodeQL Analyze`, and
`Race and Stress` for runtime correctness, security analysis, and deterministic
contention validation on protected updates, including administrator updates.
Their workflows run on pushes and pull requests.

OpenSSF Scorecard and Scorecard SARIF remain scheduled/manual advisory checks for
the current release-candidate line. Do not make them required branch-protection
checks unless their workflows also run on the same pull request events without
introducing circular or non-deterministic merge blocking.

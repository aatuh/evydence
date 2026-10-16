# Maintainer Review Policy

This reference documents the repository review expectations for Evydence
changes that affect high-trust release evidence, tenant isolation, credentials,
signing, storage, deployment, or public product claims.

The policy supports engineering review. It is not legal compliance proof,
certification, complete vulnerability coverage, or a secure-release guarantee.

## Current Enforcement Status

The live GitHub API settings for `master` were verified on 2026-10-16:

- `Production Check`, `CodeQL Analyze`, and `Race and Stress` are required,
  bound to GitHub Actions (app ID `15368`), with the branch required to be up
  to date;
- pull-request approvals and CODEOWNERS approvals are not required;
- linear history and conversation resolution are not required;
- force pushes and branch deletion remain disabled;
- administrator enforcement remains disabled, so administrators can bypass
  these protections.

`CODEOWNERS` remains committed at the repository root as an ownership reference
for high-risk paths, not an enforced approval gate. This solo-maintainer setup
does not require an independent reviewer. The settings snapshot is not proof
that CI passed on any particular commit, and settings can change after the
verification date.

EVY-1105 implementation `57cb91a95bbf` is included in published commit
`d77b612bc721`. Its hosted [Production Check and Race and Stress run](https://github.com/aatuh/evydence/actions/runs/38765165262)
and [CodeQL run](https://github.com/aatuh/evydence/actions/runs/38765165260)
passed on that same commit. With explicit maintainer approval, `Race and Stress`
was added to required checks on 2026-10-16; a subsequent API read verified all
three Actions bindings and the retained up-to-date requirement. These
observations establish that commit's hosted results and the dated settings;
they do not establish CI success for other commits or release artifacts.

## Maintainer Bypass Posture

The verified configuration does not enforce branch protection for
administrators. Required checks apply to non-bypass updates, but Evydence does
not claim that every change is technically forced through CI or pull-request
review. Maintainer self-review remains expected for high-risk changes; a second
person's approval is not a prerequisite in this solo-maintainer workflow.

When a maintainer bypass is used for an urgent or operational change, the
maintainer should record the reason in the pull request, release evidence, or a
follow-up audit note as appropriate. The compensating controls are:

- required `Production Check`, `CodeQL Analyze`, and `Race and Stress` CI jobs
  on normal push and pull-request paths;
- project-owned `make production-check`, `make release-acceptance`, and
  release-candidate validation gates for release-affecting changes;
- signed release artifacts, checksums, OpenAPI checksums, migration checksums,
  and release evidence manifests before candidate tags are treated as operator
  evaluation inputs;
- `CODEOWNERS` coverage for high-risk paths, which states expected maintainer
  ownership without requiring a CODEOWNERS approval;
- public release evidence and audit visibility for candidate releases.

These controls support review and reproducibility. They do not prove that a
specific live GitHub setting prevented maintainer bypass, and they are not legal
compliance proof, certification, complete vulnerability coverage, or a
secure-release guarantee.

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
contention validation on non-bypass updates. Their workflows run on pushes and
pull requests.

OpenSSF Scorecard and Scorecard SARIF remain scheduled/manual advisory checks for
the current release-candidate line. Do not make them required branch-protection
checks unless their workflows also run on the same pull request events without
introducing circular or non-deterministic merge blocking.

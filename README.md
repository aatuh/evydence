# Evydence

Evydence is a self-hosted, API-first evidence ledger for software release evidence. It supports compliance readiness by organizing and verifying technical evidence, producing tamper-evident records, and showing gaps, assumptions, exceptions, and limitations.

It does not make legal compliance conclusions, grant certification, prove SBOM completeness, treat scanner findings as authoritative, or guarantee release security.

## Current Implementation

This repository contains a Go implementation under module `github.com/aatuh/evydence`. The current status is controlled self-hosted production candidate hardening: useful for evaluation, pilots, and controlled internal production after operator review, with a stricter production gate and release-candidate checklist tracking the remaining work before any broader production claim.

### API And Contracts

- HTTP API under `/v1` using `github.com/aatuh/api-toolkit/v3` route contracts, OpenAPI generation, response helpers, and Problem Details.
- Generated OpenAPI contract committed at `openapi.yaml` and served at `/v1/openapi.json`.
- Request idempotency for create/action endpoints and tenant-scoped Problem Details responses.

### Identity And Tenant Boundaries

- Multi-tenant scoped API keys with one-time secret output, HMAC-SHA256 storage, and server-side scope checks.
- Organizations, users, role bindings, admin-managed SSO provider/session records, collector keys, and customer portal package tokens.
- Instance diagnostics require explicit `instance:admin` scope.

### Evidence And Release Records

- Products, projects, releases, release candidates, artifacts, container images, artifact signatures, evidence search, evidence lifecycle events, SBOM and VEX upload, vulnerability scans, vulnerability decisions, exceptions, waivers, approvals, incidents, remediation tasks, source records, deployment events, controls, reports, policies, release bundles, evidence bundles, backup manifests, and retention records.
- Immutable or append-only behavior for evidence core fields, release bundles, approvals, exceptions, audit entries, chain entries, and related transition records.
- Release-readiness, control-coverage, CRA-readiness, vulnerability-posture, incident-package, security-review-package, evidence-summary, questionnaire-draft, graph-snapshot, PDF-package, anomaly, retention, and backup-manifest reports with assumptions and limitations.

### Persistence, Object Storage, And Workers

- In-process store for local demos and unit-test execution when `EVYDENCE_DATABASE_URL` is unset.
- PostgreSQL-backed durable ledger state, tenant-scoped relational projections, migrations, and persisted outbox jobs when `EVYDENCE_DATABASE_URL` is set.
- Filesystem or S3/MinIO-compatible object storage for raw upload payload bytes under tenant-prefixed paths.
- Polling `cmd/evydence-worker` process that claims persisted outbox jobs with PostgreSQL row locking and records retry or terminal status.
- Optional worker-owned parser side effects through `EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS=true`, including OpenVEX-derived vulnerability decisions created idempotently by the `parse_vex` worker.

### Tooling, Deployment, And Examples

- `cmd/evydence` helper for hashing, manifest verification, GitHub Actions build provenance upload, release artifact manifest signing/verification, bulk upload manifests, and air-gapped evidence bundle import.
- Docker Compose dependencies for PostgreSQL and MinIO.
- Kubernetes Helm chart under `deploy/helm/evydence`.
- Air-gapped package manifest under `deploy/airgap/manifest.yaml`.
- Lightweight Go, TypeScript, and Python SDK wrappers.
- GitHub Actions and GitLab CI workflow examples.
- Documentation portal under `docs/`.
- AGPL license, commercial licensing, governance, contribution, security,
  support, trademark, release-evidence, and changelog metadata.

Implemented-but-partial areas are documented explicitly: signing-provider operation receipts do not replace direct production KMS/HSM SDK adapters, SSO credential exchange uses configured local OIDC/SAML trust material and session-scoped OIDC group-role mappings but does not replace live provider API validation or external group synchronization, and public transparency records can verify operator-supplied or fetched inclusion proof material without replacing provider-specific trust review.

## License, Security, Support, And Governance

Evydence is licensed under `AGPL-3.0-only`; see [LICENSE](LICENSE).
Commercial license exceptions and paid support are described in
[COMMERCIAL.md](COMMERCIAL.md). Project governance, contribution expectations,
security reporting, support paths, trademark guidance, release-evidence
expectations, and release notes are documented in [GOVERNANCE.md](GOVERNANCE.md),
[CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
[SUPPORT.md](SUPPORT.md), [TRADEMARKS.md](TRADEMARKS.md),
[RELEASE_EVIDENCE.md](RELEASE_EVIDENCE.md), and [CHANGELOG.md](CHANGELOG.md).

These files preserve the same product boundary as the rest of the repository:
Evydence supports compliance readiness and technical evidence organization, but
does not make legal compliance conclusions, grant certification, prove SBOM
completeness, treat scanner output as authoritative, or guarantee release
security.

## Local API

```sh
cp .api.env.example .api.env
set -a; . ./.api.env; set +a
EVYDENCE_PRINT_BOOTSTRAP_SECRET=true go run ./cmd/evydence-api
```

The API listens on `EVYDENCE_ADDR`, defaulting to `:8080`. Local bootstrap output includes a one-time admin API key secret. Leave `EVYDENCE_DATABASE_URL` unset for in-process local demos, or set it to use PostgreSQL-backed durable state.

Use the secret as:

```http
Authorization: Bearer <secret>
Idempotency-Key: <stable-create-key>
```

For a runnable first evidence flow, use [Getting started](docs/tutorials/getting-started.md).

## Validation

The canonical release validation reference is [docs/reference/release-validation.md](docs/reference/release-validation.md).
The self-hosted production-readiness profile is [docs/reference/production-readiness.md](docs/reference/production-readiness.md).
The release-candidate checklist is [docs/reference/release-candidate.md](docs/reference/release-candidate.md).

Common local checks:

```sh
make test
make openapi-check
make fast-check
```

PostgreSQL checks are opt-in so unit tests stay fast:

```sh
make compose-up
set -a; . ./.test.env; set +a
make live-postgres-check
make postgres-integration-test
```

`make finalize` runs the project-owned formatting, unit, OpenAPI, docs, deployment, and SDK gates. `make release-check` extends that with lint, gosec, govulncheck, race tests, and live PostgreSQL gates when `EVYDENCE_TEST_DATABASE_URL` is configured.

`make production-check` is stricter: it requires `EVYDENCE_TEST_DATABASE_URL`, enforces the configured coverage threshold, and runs a release artifact signing smoke test. Passing the gate is required release-candidate evidence, but it does not by itself close the remaining focused repository-write, direct KMS/HSM SDK, provider API/group validation, object-lock enforcement, HA, and exit-review work. Production API and worker processes default to relational-only PostgreSQL loads and skip compatibility snapshot writes; the compatibility snapshot remains for migration, recovery, and local workflows. Current self-hosted production guidance uses a single API writer replica and allows worker replicas to scale through PostgreSQL outbox row locking.

# Evydence

Evydence is a self-hosted, API-first evidence ledger for software release evidence. It supports compliance readiness by organizing and verifying technical evidence, producing tamper-evident records, and showing gaps, assumptions, exceptions, and limitations.

It does not make legal compliance conclusions, grant certification, prove SBOM completeness, treat scanner findings as authoritative, or guarantee release security.

## Current Implementation

This repository contains a Go release-ledger MVP scaffold under module `github.com/aatuh/evydence`.

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

### Tooling, Deployment, And Examples

- `cmd/evydence` helper for hashing, manifest verification, GitHub Actions build provenance upload, release artifact manifest signing/verification, bulk upload manifests, and air-gapped evidence bundle import.
- Docker Compose dependencies for PostgreSQL and MinIO.
- Kubernetes Helm chart under `deploy/helm/evydence`.
- Air-gapped package manifest under `deploy/airgap/manifest.yaml`.
- Lightweight Go, TypeScript, and Python SDK wrappers.
- GitHub Actions and GitLab CI workflow examples.
- Documentation portal under `docs/`.

Implemented-but-partial areas are documented explicitly: signing-provider operation receipts do not replace production KMS/HSM adapters, stored provider identity checks do not verify live OIDC/SAML tokens, and public transparency records do not prove external log inclusion without the configured operator workflow.

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

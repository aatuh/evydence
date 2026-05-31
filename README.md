# Evydence

[![CI](https://github.com/aatuh/evydence/actions/workflows/ci.yml/badge.svg)](https://github.com/aatuh/evydence/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://github.com/aatuh/evydence/actions/workflows/scorecard.yml/badge.svg)](https://github.com/aatuh/evydence/actions/workflows/scorecard.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)
![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8.svg)
![OpenAPI](https://img.shields.io/badge/OpenAPI-166%20precise%20operations-brightgreen.svg)
![Coverage Gate](https://img.shields.io/badge/coverage%20gate-80%25+-brightgreen.svg)

Evydence is a self-hosted release evidence ledger that helps software teams
collect, verify, and share tamper-evident technical evidence for each release.

It is for security, platform, AppSec, and compliance-readiness teams at B2B
software companies that need customer-reviewable release evidence without
handing all release trust data to a SaaS GRC platform.

Before shipping a release, Evydence can collect SBOMs, vulnerability scans, VEX
decisions, build/source/deployment evidence, controls, exceptions, release
bundles, and customer-safe packages, then show readiness gaps, assumptions, and
limitations.

It does not make legal compliance conclusions, grant certification, prove SBOM
completeness, treat scanner findings as authoritative, or guarantee release
security.

## Current Limitations

- Current status is a controlled self-hosted production candidate for
  evaluation, pilots, and controlled internal production after operator review.
- Production API deployments use one API writer replica; workers may scale
  through PostgreSQL outbox locking.
- Public release publication, branch protection, private vulnerability
  reporting settings, and public CI status are GitHub/operator controls, not
  guarantees made by repository files alone.
- Native PKCS#11/HSM module handling, broad WORM/object-lock proof, direct
  provider-specific management API clients, external group synchronization,
  regulated production, and hosted SaaS production remain outside the current
  supported profile unless a deployment review closes those gaps.

## Current Implementation

This repository contains a Go implementation under module
`github.com/aatuh/evydence`. A local signed `v0.1.0-rc.3` evidence package has
been generated from this checkout; public release publication remains a
separate operator action.

Until a public release candidate is published, source checkout is the
development and evaluation path. After the first public release candidate is
available, GitHub Releases and the checked release evidence artifacts should be
the operator install source.

## Fastest Proof Path

For a first local API flow, follow [Getting started](docs/tutorials/getting-started.md).
For durable local evaluation, run the production-like Compose rehearsal in
[Install and operate](docs/how-to/install-and-operate.md).
For the release-evidence path to inspect first, use the
[end-to-end release evidence example](examples/end-to-end-release-evidence/README.md).
For concrete JSON outputs to inspect without running a full stack, open the
sample readiness report, customer-package manifest, and audit-chain
verification fixtures in that example or load the bundled package in the
[local package viewer](docs/how-to/view-packages.md).

Release-candidate artifacts and their verification commands are indexed in
[Release evidence index](docs/reference/release-evidence-index.md). Before a
public release exists, that index describes the evidence contract rather than a
published install guarantee.

The end-to-end evidence flow to evaluate first is:

1. Create a product, release, and artifact.
2. Upload SBOM and vulnerability scan evidence.
3. Record a VEX decision or exception for an intentionally blocking finding.
4. Generate a release bundle and readiness report.
5. Export a customer-safe package or evidence bundle for review.

## Why Evydence Instead Of Existing Tools?

- Dependency-Track and vulnerability-management tools are strong for SBOM and
  finding workflows; Evydence focuses on release-level evidence, decisions,
  bundles, audit chains, controls, customer packages, and review limitations.
- Vanta, Drata, and similar SaaS GRC tools are broad compliance platforms;
  Evydence is a self-hosted technical evidence ledger and does not claim legal
  compliance or certification.
- Building this in-house with object storage, scripts, spreadsheets, and ad hoc
  Postgres tables is possible; Evydence provides a versioned API, OpenAPI
  contract, tenant scoping, idempotency, audit chains, release evidence, and
  checked non-claim language from the start.

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
- Production-like Docker Compose rehearsal with API, worker, migrations,
  PostgreSQL, and MinIO.
- Kubernetes Helm chart under `deploy/helm/evydence`.
- Air-gapped package manifest under `deploy/airgap/manifest.yaml`.
- Lightweight Go, TypeScript, and Python SDK wrappers.
- GitHub Actions and GitLab CI workflow examples.
- Documentation portal under `docs/`.
- AGPL license, commercial licensing, governance, contribution, security,
  support, code of conduct, trademark, release-evidence, and changelog metadata.

Implemented-but-partial areas are documented explicitly: signing-provider operation receipts can use an HTTPS signing gateway, built-in AWS KMS, GCP Cloud KMS, or Azure Key Vault executors, and `pkcs11-hsm` remains gateway-backed because native HSM modules are deployment-specific; deployment-specific custody review remains operator work. SSO credential exchange uses configured local OIDC/SAML trust material and session-scoped OIDC group-role mappings, and provider verification can optionally call OIDC UserInfo or an operator-controlled provider validation gateway when a caller supplies an access token, but the gateway receives only non-secret metadata and this does not replace direct provider-specific management API clients or external group synchronization. Public transparency records can verify operator-supplied proof material, fetch from configured endpoints, or use an operator-controlled transparency proof gateway without replacing provider-specific trust review.

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
The release evidence artifact map is [docs/reference/release-evidence-index.md](docs/reference/release-evidence-index.md).
The maintainer review policy for high-risk paths is [docs/reference/maintainer-review-policy.md](docs/reference/maintainer-review-policy.md).
The public roadmap and release cadence are [docs/reference/roadmap.md](docs/reference/roadmap.md).

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

`make production-check` is stricter: it requires `EVYDENCE_TEST_DATABASE_URL`, enforces the configured coverage threshold, and runs a release artifact signing smoke test. Passing the gate is required release-candidate evidence, but it does not by itself close the remaining service decomposition, PKCS#11/native HSM custody, direct provider-specific management API/group synchronization, broader object-lock enforcement beyond configured bucket/sample-object checks, HA, and exit-review work. Production API and worker processes default to relational-only PostgreSQL loads and skip compatibility snapshot writes; the compatibility snapshot remains for migration, recovery, and local workflows. Critical runtime mutations for tenants, credential hashes, idempotency, audit-chain entries, release bundles, signatures, verification results, vulnerability decisions, and outbox jobs use focused PostgreSQL write paths when available. Release-ledger and evidence-core mutations for products, projects, releases, artifacts, evidence items, evidence lifecycle events, SBOMs, vulnerability scans, OpenAPI contracts, VEX documents, audit-chain entries, and parser outbox jobs also use focused PostgreSQL write paths when available. Remaining aggregate persistence calls use PostgreSQL relational synchronization without writing the compatibility snapshot when that store is configured. Current self-hosted production guidance still uses a single API writer replica; production API startup rejects unsupported writer modes and declared replica counts above one, then enforces that stance with a PostgreSQL advisory writer lease. Worker replicas may scale through PostgreSQL outbox row locking.

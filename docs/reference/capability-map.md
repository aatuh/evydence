# Capability Map

This reference keeps the broad implementation inventory out of the README
first screen while preserving a discoverable map for operators, reviewers, and
contributors.

The map describes repository capabilities that are backed by source code,
OpenAPI, tests, deployment files, examples, or checked documentation. It is not
legal compliance proof, certification, complete SBOM proof, authoritative
vulnerability coverage, or a secure-release guarantee.

## API And Contracts

- HTTP API under `/v1` using `github.com/aatuh/api-toolkit/v3` route contracts,
  OpenAPI generation, response helpers, and Problem Details.
- Generated OpenAPI contract committed at `openapi.yaml` and served at
  `/v1/openapi.json`.
- Request idempotency for create/action endpoints and tenant-scoped Problem
  Details responses.

## Identity And Tenant Boundaries

- Multi-tenant scoped API keys with one-time secret output, HMAC-SHA256
  storage, and server-side scope checks.
- Organizations, users, role bindings, admin-managed SSO provider/session
  records, collector keys, and customer portal package tokens.
- Instance diagnostics require explicit `instance:admin` scope.

## Release Evidence Core

- Products, projects, releases, release candidates, artifacts, container
  images, artifact signatures, SBOM and VEX upload, vulnerability scans,
  vulnerability decisions, exceptions, waivers, approvals, policies, release
  bundles, evidence bundles, and customer packages.
- Immutable or append-only behavior for evidence core fields, release bundles,
  approvals, exceptions, audit entries, chain entries, and related transition
  records.
- Release-readiness, vulnerability-decision-summary, missing-evidence,
  security-summary, package, retention, and backup-manifest reports with
  assumptions and limitations.

## Extended Evidence Families

- Evidence search, evidence lifecycle events, controls, CRA/control coverage,
  source records, deployment events, incidents, remediation tasks, audit log
  querying, object retention records, transparency records, backup manifests,
  and customer package access records.
- Control-coverage, CRA-readiness, vulnerability-posture, incident-package,
  security-review-package, evidence-summary, questionnaire-draft,
  graph-snapshot, PDF-package, anomaly, retention, and backup reports.
- Customer package manifests and static report exports are redaction-aware and
  exclude raw payload bytes, bearer tokens, private keys, API key hashes, SSO or
  session token hashes, and internal notes by default.

## Persistence, Object Storage, And Workers

- In-process store for local demos and unit-test execution when
  `EVYDENCE_DATABASE_URL` is unset.
- PostgreSQL-backed durable ledger state, tenant-scoped relational projections,
  migrations, and persisted outbox jobs when `EVYDENCE_DATABASE_URL` is set.
- Production API and worker processes default to relational-only PostgreSQL
  loads and skip compatibility snapshot writes; the compatibility snapshot
  remains for migration, recovery, and local workflows.
- Filesystem or S3/MinIO-compatible object storage for raw upload payload bytes
  under tenant-prefixed paths.
- Polling `cmd/evydence-worker` process that claims persisted outbox jobs with
  PostgreSQL row locking and records retry or terminal status.
- Optional worker-owned parser side effects through
  `EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS=true`, including OpenVEX-derived
  vulnerability decisions created idempotently by the `parse_vex` worker.

## Tooling, Deployment, And Examples

- `cmd/evydence` helper for hashing, one-shot release evidence upload,
  manifest verification, GitHub Actions build provenance upload, release
  artifact manifest signing/verification, bulk upload manifests, and air-gapped
  evidence bundle import.
- Docker Compose dependencies for PostgreSQL and MinIO.
- Production-like Docker Compose rehearsal with API, worker, migrations,
  PostgreSQL, and MinIO.
- Kubernetes Helm chart under `deploy/helm/evydence`.
- Air-gapped package manifest under `deploy/airgap/manifest.yaml`.
- Lightweight Go, TypeScript, and Python SDK wrappers.
- GitHub Actions and GitLab CI workflow examples.
- Documentation portal under `docs/`.
- AGPL license, commercial licensing, governance, contribution, security,
  support, code of conduct, trademark, release-evidence, and changelog
  metadata.

## Implemented-But-Partial Areas

- Signing-provider operation receipts can use an HTTPS signing gateway, built-in
  AWS KMS, GCP Cloud KMS, or Azure Key Vault executors.
- `pkcs11-hsm` remains gateway-backed because native HSM modules are
  deployment-specific.
- `native_pkcs11_hsm` provider records and custody-review reports capture
  operator-supplied HSM profile evidence without loading modules or proving
  custody.
- SSO credential exchange uses configured local OIDC/SAML trust material and
  session-scoped OIDC group-role mappings.
- Provider verification can optionally call OIDC UserInfo or an
  operator-controlled provider validation gateway when a caller supplies an
  access token. The gateway receives only non-secret metadata and does not
  replace direct provider-specific management API clients or external group
  synchronization.
- Public transparency records can verify operator-supplied proof material,
  fetch from configured endpoints, or use an operator-controlled transparency
  proof gateway without replacing provider-specific trust review.
- Production API deployments remain intentionally single-writer until
  multi-writer API concurrency is reviewed across every write family. Worker
  replicas may scale through PostgreSQL outbox locking.

## Where To Go Next

- Start with [Evaluate Evydence in 10 minutes](../tutorials/evaluate-in-10-minutes.md).
- Run the local API path in [Getting started](../tutorials/getting-started.md).
- Review production limits in [Production readiness](production-readiness.md).
- Inspect public release artifacts in [Release evidence index](release-evidence-index.md).

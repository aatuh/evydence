# Architecture

Evydence follows a ports-and-adapters shape:

- `internal/domain` defines release-ledger resource types and schema version constants.
- `internal/app` owns tenant isolation, API key authorization, evidence immutability, canonical hashes, audit-chain entries, signing, release bundles, deterministic policy and control checks, report generation, and storage ports.
- `internal/adapters/httpapi` adapts the application service to HTTP and OpenAPI.
- `internal/adapters/postgres` provides the durable ledger-state store, migration runner, tenant-scoped relational resource projection, and persisted outbox.
- `internal/adapters/objectstore/filesystem` stores raw uploaded payload bytes under tenant-prefixed object keys for local and self-hosted deployments.
- `cmd/*` contains process entry points.

Core logic does not depend on HTTP routers, SQL drivers, object storage SDKs, queues, KMS providers, provider clients, or UI frameworks. PostgreSQL persistence currently stores a versioned ledger snapshot and also rebuilds tenant-scoped relational projection rows plus forward-compatible per-resource tables for the implemented release, evidence, source, deployment, and control resources. The projection supports operational querying and migration discipline while keeping the application store contract small.

## Security Boundaries

Tenant isolation is enforced in application methods before reads and writes return data. API keys are scoped, revocable, and stored as HMAC-SHA256 hashes with `EVYDENCE_API_KEY_PEPPER`. Collector identity is server-derived from the API key binding and is not trusted from build upload request bodies. Evidence, evidence lifecycle events, incidents, remediation tasks, security scans, manual security documents, SBOM diffs, VEX documents, vulnerability decisions/workflow records, waivers, approvals, customer packages, report templates, evidence bundles, exceptions, build runs, build attestations, release candidates, artifact signatures, source-control records, deployment events, contract diffs, custom policy evaluations, control evidence links, and release bundle records are append-only in behavior; changes are represented by supersession, lifecycle events, approval transitions, package access records, links, verification receipts, rollback-as-new-event records, or new audit-chain entries.

When `EVYDENCE_DATABASE_URL` is set, mutations are saved to PostgreSQL before successful responses return. Upload payload bytes, including raw SBOM, vulnerability scan, OpenAPI, OpenVEX, and DSSE build-attestation payloads, are written to the configured filesystem object store with tenant-prefixed keys and SHA-256 digest checks before metadata is accepted. Outbox jobs are persisted in PostgreSQL and claimed by workers with `FOR UPDATE SKIP LOCKED`.

Release readiness is deterministic and evidence-scoped. Open critical vulnerability findings block readiness unless the latest decision marks the finding `not_affected` or `fixed`, or an approved unexpired exception applies to the release/finding. Passed build provenance and a structurally valid build attestation must link to release artifact digests. Source snapshots, deployment records, incident packages, security scans, manual reviews, SBOM diffs, contract diffs, API security checks, customer packages, evidence bundles, and custom policies add traceability and reproducible decisions but do not prove provider truth, scanner authority, runtime security, legal sufficiency, or secure releases. Control coverage and CRA-readiness reports use versioned tenant-created controls, explicit evidence links, and approved unexpired control exceptions. GitHub OIDC subject metadata can be captured, but OIDC token verification, live provider API verification, and artifact-signature cryptographic verification are roadmap work. DSSE attestation signatures can be verified against configured Ed25519 trust roots when raw attestation bytes are available. Reports include gaps, assumptions, and limitations and do not make legal compliance or secure-release claims.

## Limitations

The in-process store remains available only when `EVYDENCE_DATABASE_URL` is unset. S3/MinIO runtime object storage, external signing-key providers, KMS/HSM support, and hand-tuned per-resource repository implementations remain roadmap work. `ENV=production` rejects the in-process store, default API-key pepper, and local plaintext signing-key mode.

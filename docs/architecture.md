# Architecture

Evydence follows a ports-and-adapters shape:

- `internal/domain` defines release-ledger resource types and schema version constants.
- `internal/app` owns tenant isolation, API key authorization, evidence immutability, canonical hashes, audit-chain entries, signing, release bundles, deterministic policy and control checks, report generation, and storage ports.
- `internal/adapters/httpapi` adapts the application service to HTTP and OpenAPI.
- `internal/adapters/postgres` provides the durable ledger-state store, migration runner, tenant-scoped relational resource projection, and persisted outbox.
- `internal/adapters/objectstore/filesystem` stores raw uploaded payload bytes under tenant-prefixed object keys for local and self-hosted deployments.
- `internal/adapters/objectstore/s3` stores the same tenant-prefixed object keys in S3/MinIO-compatible buckets.
- `cmd/*` contains process entry points.

Core logic does not depend on HTTP routers, SQL drivers, object storage SDKs, queues, KMS providers, provider clients, or UI frameworks. PostgreSQL persistence currently stores a versioned ledger snapshot and rebuilds tenant-scoped relational projection rows plus forward-compatible per-resource tables for implemented release, evidence, source, deployment, and control resources. Identity, idempotency, and customer portal token records are synchronized into relational rows with non-secret hashes and tenant-scoped constraints. Release-ledger core rows are also synchronized for products, projects, releases, artifacts, evidence, audit-chain entries, signing keys, signatures, SBOMs, vulnerability scans, OpenAPI contracts, policy evaluations, release bundles, and verification receipts. Collector/build provenance, source/deployment, incident, security evidence, SBOM diff, vulnerability workflow, contract diff, custom policy, waiver, approval, DSSE trust-root, collector release, Cosign verification, signing provider, Merkle batch, transparency checkpoint, evidence lifecycle, release candidate, VEX/risk decision, control, package, report, retention, provider verification, signing operation, and future-extension records are synchronized into their migration-backed relational tables. Production API and worker startup defaults to relational-only reconstruction and disables compatibility snapshot writes; local development defaults to snapshot-preferred compatibility. If the snapshot row is absent, the Postgres store can rebuild identity, SSO session, customer portal token, release-ledger core, build provenance, source/deployment, incident, security evidence, SBOM diff, vulnerability workflow, contract diff, custom policy, waiver, approval, DSSE trust-root, collector release, Cosign verification, signing provider, Merkle batch, transparency checkpoint, evidence lifecycle, release candidate, VEX/risk decision, control, package, report, retention, provider verification, signing operation, and future-extension families from relational rows. Moving all canonical production writes to dependency-ordered relational repositories is tracked as production hardening, not as a completed production maturity claim.

## Tenant And Auth Boundaries

Tenant isolation is enforced in application methods before reads and writes return data. API keys are scoped, revocable, and stored as HMAC-SHA256 hashes with `EVYDENCE_API_KEY_PEPPER`.

Human SSO session tokens and customer portal package tokens are also stored as hashes and returned only once. Human actors derive scopes from tenant role bindings. Collector identity is server-derived from the API key binding and is not trusted from build upload request bodies.

Instance diagnostics require explicit `instance:admin` scope. Tenant admin and ordinary wildcard tenant keys do not satisfy that instance-wide scope by themselves.

## Storage And Append-Only Behavior

When `EVYDENCE_DATABASE_URL` is set, mutations are saved to PostgreSQL before successful responses return. Upload payload bytes, including raw SBOM, vulnerability scan, OpenAPI, OpenVEX, and DSSE build-attestation payloads, are written to the configured object store with tenant-prefixed keys and SHA-256 digest checks before metadata is accepted.

Evidence, evidence lifecycle events, incidents, remediation tasks, security scans, manual security documents, SBOM diffs, VEX documents, vulnerability decisions/workflow records, organizations, users, role bindings, SSO providers, SSO sessions, legal holds, retention overrides, customer portal access records, questionnaire packages and drafts, evidence summaries, evidence graph snapshots, commercial and marketplace collector definitions, waivers, approvals, customer packages, report templates, evidence bundles, exceptions, build runs, build attestations, release candidates, artifact signatures, source-control records, deployment events, contract diffs, custom policy evaluations, provider verifications, signing operations, control evidence links, public transparency log entries, and release bundle records are append-only in behavior. Changes are represented by supersession, lifecycle events, approval transitions, session revocation, package access records, links, verification receipts, rollback-as-new-event records, or new audit-chain entries.

Outbox jobs are persisted in PostgreSQL and claimed by workers with `FOR UPDATE SKIP LOCKED`. Parser jobs re-read tenant-prefixed object-store payloads, verify size and digest, validate durable state, persist missing parser-derived normalized fields, and fail closed on mismatches. Upload endpoints still create initial accepted records, so moving every parser-owned side effect fully out of the API request path remains production hardening work.

## Verification And Trust

Release readiness is deterministic and evidence-scoped. Open critical vulnerability findings block readiness unless the latest decision marks the finding `not_affected` or `fixed`, or an approved unexpired exception applies to the release or finding. Passed build provenance and a structurally valid build attestation must link to release artifact digests.

DSSE attestation signatures can be verified against configured Ed25519 trust roots when raw attestation bytes are available. Cosign-style artifact verification records digest binding, signature presence, and optional Rekor metadata without overstating full Sigstore trust-chain validation. Signing keys support revocation and valid-at-signing semantics for historical signatures.

Merkle batches, signed checkpoints, optional transparency checkpoint/public transparency records with operator-supplied or fetched inclusion proof verification, backup manifests, object-retention policy records with verification hashes, legal holds, retention overrides, readiness, metrics, instance admin diagnostics, external signing gateway receipts, and admin audit queries provide operational integrity and review surfaces.

## Reports And Customer-Facing Packages

Control coverage and CRA-readiness reports use versioned tenant-created controls, explicit evidence links, approved unexpired control exceptions, and built-in starter packs for CRA-readiness, NIST SSDF-lite, SOC 2-style technical evidence, and ISO 27001-style technical evidence.

Source snapshots, deployment records, signed incident webhook events, incident packages, security scans, manual reviews, SBOM diffs, contract diffs, API security checks, customer packages, customer portal package access, questionnaire packages, evidence bundles, and custom policies add traceability and reproducible decisions. Reports include gaps, assumptions, and limitations.

Evidence summaries, questionnaire drafts, graph snapshots, PDF packages, and anomaly reports are generated from stored records with citations, assumptions, and limitations. Customer-facing packages require explicit package scope, redaction profile, expiry, and access auditing. Customer package JSON and ZIP download paths return scoped manifest metadata and verification guidance; raw tenant evidence payload bytes are not returned.

## Provider And Deployment Boundaries

GitHub OIDC subject metadata can be captured, and stored OIDC/SAML identity links can be verified against tenant metadata. OIDC provider records can include public JWKS material for local EdDSA or RS256 ID-token signature and claim verification, and SAML provider records can include PEM signing certificates for local assertion signature and claim verification. Trust material can be rotated without recreating the provider. Live provider API verification, discovery, browser login callbacks, and group synchronization remain trust boundaries outside those records. Collector supply-chain records track pinned collector versions with signature, SBOM, and scan evidence where available; commercial and marketplace collector definitions add extension metadata without granting provider trust.

Air-gapped import-bundle workflows preserve the same tenant-scoped import path after controlled transfer. Object-retention policy APIs record tenant-scoped retention intent and, when the S3/MinIO object-store adapter is configured, verify bucket versioning plus default object-lock mode and duration. Policies can also name a tenant-prefixed sample object key for object-level retention checks where the provider supports them. Those checks are evidence for the configured bucket and sample object only; WORM/object-lock enforcement, IAM policy, lifecycle rules, and deployment-specific retention review remain operator responsibilities.

## Limitations

The in-process store remains available only when `EVYDENCE_DATABASE_URL` is unset. S3/MinIO runtime object storage is available through the object-store port. Signing-provider operation receipts, an optional HTTPS signing gateway executor, OIDC discovery refresh, SSO credential exchange, and public-transparency proof fetching are implemented, but direct cloud KMS/HSM SDK adapters, live Sigstore verification, live provider API validation, and group synchronization remain deployment hardening work. Hand-tuned per-resource repository implementations and moving parser side effects fully out of request paths remain production-readiness work. `ENV=production` rejects the in-process store, default API-key pepper, local plaintext signing-key mode, and bootstrap secret printing.

Evydence does not prove provider truth, scanner authority, runtime security, legal compliance, or release security by itself.

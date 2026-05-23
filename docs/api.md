# API Reference

The public API base path is `/v1`.

Common headers:

```http
Authorization: Bearer <api_key>
Idempotency-Key: <stable-create-key>
Content-Type: application/json
Accept: application/json
```

Create and action endpoints require `Idempotency-Key`. Reusing the same key with the same request returns the original response. Reusing it with different request content returns `409` with `IDEMPOTENCY_KEY_REUSED`.

Errors use RFC 9457 Problem Details and include stable `code` and `request_id` fields. Clients may send `X-Request-ID`; otherwise the API generates one and returns it in the response header and Problem Details body.

The generated OpenAPI document is committed at `openapi.yaml` and served at `/v1/openapi.json`.

## Enterprise Identity And Administration

`POST /v1/organizations` creates a tenant-scoped organization. `POST /v1/users` creates a human user with normalized email, and `POST /v1/users/{id}/deactivate` records a deactivation transition.

`POST /v1/role-bindings` assigns a role to a user or collector. Current roles are `tenant_admin`, `security_engineer`, `release_manager`, `customer_verifier`, and `collector`. Human SSO session actors derive API scopes from role bindings and enforce `resource_type`/`resource_id` constraints for product, project, release, customer package, evidence bundle, build, control evidence, source, deployment, incident, security scan, report, export, read, and write operations where those resources are part of the request. API key and collector API key scopes remain tenant-scoped. `GET /v1/role-bindings` lists tenant-scoped bindings.

`POST /v1/sso/providers` records OIDC or SAML provider metadata. `POST /v1/sso/identity-links` links a verified provider subject to an existing user. `POST /v1/sso/sessions` issues an expiring one-time session token response; the token hash is stored server-side and is not returned by list/read paths. `POST /v1/sso/sessions/{id}/revoke` revokes the session. These endpoints model admin-managed identity/session records; they do not perform live OIDC discovery, JWKS validation, SAML assertion verification, browser redirects, or provider login callbacks.

`GET /v1/admin/instance` returns low-detail instance diagnostics only for actors explicitly granted `instance:admin`. Tenant `admin` and ordinary wildcard `*` tenant keys remain tenant-scoped and do not satisfy this instance-wide scope unless `instance:admin` is also present. The endpoint exposes operational counts only, not raw evidence payloads, API keys, session hashes, or customer portal tokens.

## Controls And Reports

`POST /v1/control-frameworks` creates a tenant-scoped framework version such as an internal CRA-readiness or SSDF-lite mapping. `GET /v1/control-frameworks` lists framework versions for the tenant.

`POST /v1/controls` creates a framework-owned control with evidence requirements. Supported requirement types currently match implemented evidence resources: `sbom`, `vulnerability_scan`, `vex`, `vulnerability_decision`, `artifact`, `build`, `build_attestation`, `openapi_contract`, `release_bundle`, and `exception`. `GET /v1/controls/{id}` reads a tenant-scoped control.

`POST /v1/controls/{id}/evidence` appends a control evidence link to an existing subject and confidence value of `high`, `medium`, `low`, or `unsupported`. Duplicate links return the existing link. `GET /v1/control-evidence` lists links by optional control, product, or release filters.

`GET /v1/reports/control-coverage?framework_id=...&product_id=...&release_id=...` returns deterministic coverage statuses per control: `satisfied`, `partial`, `missing`, `waived`, `not_applicable`, or `unknown`. Approved, unexpired exceptions with a matching `control_id` may waive a control.

`GET /v1/reports/cra-readiness?product_id=...&release_id=...` returns a CRA-oriented technical evidence report built from the same control coverage engine. It includes assumptions and limitations and does not make legal compliance, certification, complete-SBOM, or secure-release claims.

`GET /v1/control-framework-template-packs` lists built-in starter packs for CRA-readiness, NIST SSDF-lite, SOC 2-style technical evidence, and ISO 27001-style technical evidence. `POST /v1/control-framework-template-packs/{slug}/install` copies a pack into tenant-owned framework/control records.

`POST /v1/waivers` creates a first-class waiver for a release, finding, control, or custom policy. `POST /v1/waivers/{id}/approve` records the append-only approval transition. Waivers are separate from exceptions and carry owner, risk, reason, expiry, supersession, and audit-chain entries.

`POST /v1/approvals` creates immutable approval records for releases, contract diffs, waivers, security reviews, and customer packages.

## CI Provenance

Collectors are tenant-scoped automated ingesters. `POST /v1/collectors` creates a `github_actions`, `gitlab_ci`, or `generic_ci` collector and returns a one-time API key secret scoped for build/evidence upload. `GET /v1/collectors` lists collectors without key hashes or secrets. The server binds collector identity from the API key; clients must not submit `collector_id` for build attribution.

`import_bundle` collectors are also supported for air-gapped workflows that move evidence bundles through controlled media before upload. `POST /v1/collectors/{id}/releases` records collector release supply-chain evidence such as version, artifact digest, signature, SBOM, scan, and pinning. `GET /v1/collectors/{id}/health` returns a tenant-scoped collector health report with checks and limitations.

`POST /v1/builds` records an immutable build run. For `provider=github_actions`, the request must include `project_id`, `release_id`, `commit_sha`, `status`, `started_at`, `repository`, `workflow_ref`, `run_id`, and `run_attempt`. Supported statuses are `queued`, `running`, `passed`, `failed`, and `cancelled`. `GET /v1/builds/{id}` requires `build:read`.

`POST /v1/builds/{id}/attestations` accepts raw DSSE JSON containing `payloadType`, base64 `payload`, and `signatures`. Evydence decodes the in-toto Statement, records subjects, predicate type, SLSA builder/build metadata when present, stores raw bytes as tenant-prefixed evidence, and marks the record structurally valid. This slice does not perform cryptographic trust-root verification.

## Evidence Lifecycle And Search

`GET /v1/evidence/search` filters tenant evidence by product, project, release, build, deployment, type, subtype, source system, collector, verification status, subject ref, tag, created time, and limit. Results are tenant-scoped and sorted newest first.

`POST /v1/evidence/{id}/lifecycle-events` appends lifecycle records for `amendment`, `redaction`, `tombstone`, or `retention_marker`. These records do not mutate the immutable evidence core fields. `GET /v1/evidence/{id}/lifecycle-events` returns the timeline for one evidence item.

## Release Candidates And Artifacts

`POST /v1/release-candidates` records an immutable release-candidate snapshot over explicit builds, artifacts, SBOMs, scans, VEX documents, OpenAPI contracts, and bundles. `POST /v1/release-candidates/{id}/promote` and `/reject` append the terminal transition; a candidate cannot be transitioned twice.

`POST /v1/container-images` records OCI-style image repository, tag, digest, platform, and optional artifact binding. `POST /v1/artifact-signatures` records detached artifact signature metadata and optional raw signature payload bytes in object storage. `POST /v1/verify` supports `subject_type=artifact_signature` for digest binding and signature-presence verification.

`POST /v1/artifact-signatures/{id}/verify-cosign` records cosign-style digest-bound verification metadata, including optional Rekor UUID/log index and certificate identity/issuer. The check verifies the stored artifact digest binding and signature presence, and captures transparency metadata when supplied. It does not claim full Sigstore trust-chain verification unless a later trust-root integration proves it.

## Source And Deployment Evidence

`POST /v1/source/repositories`, `/v1/source/commits`, `/v1/source/branches`, and `/v1/source/pull-requests` record source-control evidence without replacing the source provider as the source of truth. Commit messages are represented by hashes, not stored as raw report text.

`POST /v1/collectors/github/source-snapshots` and `/v1/collectors/gitlab/source-snapshots` accept strict JSON snapshots containing repository, commit, branch-protection, and pull-request metadata. No live provider API calls or OIDC token verification are performed by these endpoints.

`POST /v1/environments` creates deployment environments for a product. `POST /v1/deployments` records deployment events linking an environment, release, artifacts, status, timing, and optional rollback reference. Rollbacks are recorded as new deployment events, not destructive edits.

## Release Risk Decisions

OpenVEX ingestion is available at `POST /v1/vex` with a request body containing `release_id`, optional `artifact_id`, and `payload`. The payload must be OpenVEX JSON with author, timestamp, and one or more statements. Raw VEX bytes are stored as tenant-prefixed object payloads and represented as immutable `vex` evidence.

CycloneDX VEX ingestion is available at `POST /v1/vex/cyclonedx` for CycloneDX JSON with `vulnerabilities[].analysis`. It preserves raw payload bytes, records a `vex` evidence item, and normalizes matching finding decisions when a release finding has the same vulnerability ID.

Vulnerability findings from `POST /v1/vulnerability-scans` can be resolved with `POST /v1/vulnerability-findings/{id}/decisions`. Supported statuses are `affected`, `not_affected`, `fixed`, and `under_investigation`. New decisions supersede earlier decisions for the same finding.

`POST /v1/vulnerability-findings/{id}/workflow` appends workflow records such as scanner metadata, SLA notes, scanner disagreement, supersession, or re-open markers. `GET /v1/reports/vulnerability-posture?release_id=...` summarizes uploaded findings. These records organize scanner evidence and do not make scanner findings authoritative.

Scoped exceptions are created with `POST /v1/exceptions` and approved separately with `POST /v1/exceptions/{id}/approve`. Only approved, unexpired exceptions can affect release readiness.

`GET /v1/reports/release-readiness?release_id=...` returns deterministic readiness JSON with checks, blocking findings, accepted exceptions, gaps, assumptions, and limitations. Readiness requires SBOM, vulnerability scan, artifact digest evidence, signed bundle, passed build provenance, build attestation subject matching a release artifact digest, and no unhandled open critical finding. It supports compliance readiness only and is not a legal compliance or secure-release conclusion.

## Incidents And Remediation

`POST /v1/incidents` creates an incident linked to a product and optional release. `POST /v1/incidents/{id}/timeline` appends timeline events, optionally linked to evidence. `POST /v1/remediation-tasks` creates remediation tasks linked to an incident or release.

`GET /v1/reports/incident-package?incident_id=...` returns a deterministic incident package with timeline events, remediation tasks, linked evidence IDs, assumptions, and limitations. It is an evidence organization report and does not prove root cause completeness or remediation sufficiency.

## Security Evidence And SBOM Expansion

`POST /v1/security-scans` uploads normalized SAST, DAST, secret scan, license scan, or API-security scan JSON. `POST /v1/api-security-scans` is a convenience route for API security scan evidence. Generic payloads use `findings[].severity`; SARIF payloads use `runs[].results[].level`. Secret scan evidence is marked redacted and quarantined when findings are present.

`POST /v1/security-documents` uploads sensitive manual security documents with type `threat_model`, `security_review`, or `pen_test_report` and sensitivity `internal`, `confidential`, or `restricted`. Raw bytes are stored as object payloads and the API response exposes metadata, not payload contents.

`POST /v1/sboms/spdx` ingests SPDX JSON as first-class SBOM evidence. `POST /v1/sbom-diffs` compares two stored SBOMs and records added, removed, and unchanged component counts. SBOM handling does not prove SBOM completeness.

## Packages, Templates, And Bundles

`POST /v1/redaction-profiles` creates an explicit package redaction profile. `POST /v1/customer-packages` creates a scoped customer security package manifest with expiry and access auditing. `GET /v1/customer-packages/{id}` reads the manifest and records an access event; raw payload bytes are not returned.

`POST /v1/customer-portal/access` creates an expiring customer portal access token for one package and returns the token once. `POST /v1/customer-portal/package` accepts that token and returns the scoped package manifest without exposing the token or raw tenant evidence. Failed portal token attempts that match a known token prefix record a safe audit-chain signal without storing or returning the supplied token. After repeated failed attempts for one active access record, Evydence revokes that access record and reports only tenant-safe counters.

`POST /v1/questionnaire-templates` creates tenant-defined customer questionnaire templates with question-to-evidence hints. `POST /v1/questionnaire-packages` generates deterministic evidence-backed responses for a package, product, and release scope. Responses cite linked evidence IDs and include limitations for human review.

`GET /v1/reports/security-review-package?package_id=...` returns a redaction-aware security review package report. `GET /v1/reports/cra-readiness-html?product_id=...&release_id=...` returns deterministic HTML content for CRA-readiness review with limitations and no compliance conclusion.

`POST /v1/report-templates` creates a tenant report template with explicit allowed fields. `POST /v1/report-templates/{id}/render` renders only those allowed fields into a deterministic JSON report.

`POST /v1/evidence-bundles` exports a portable evidence bundle manifest with evidence IDs, manifest hash, signature references, and verification instructions. `POST /v1/evidence-bundles/import` verifies and records an imported bundle manifest. The CLI command `evydence verify-evidence-bundle <bundle.json>` verifies bundle manifest hashes offline.

`POST /v1/dsse-trust-roots` configures an Ed25519 DSSE verification trust root. `POST /v1/build-attestations/{id}/verify-signature` verifies stored DSSE attestation signatures against configured trust roots and records a verification result.

## Integrity, Audit, And Operations

`POST /v1/signing-keys/{id}/revoke` revokes a tenant signing key. Historical signatures created before revocation remain valid-at-signing when their cryptographic signature still verifies; revoked keys are not used for new signatures.

`POST /v1/signing-providers` records a signing-provider configuration reference such as `local_encrypted_dev`, `aws_kms`, `gcp_kms`, `azure_key_vault`, or `pkcs11_hsm`. The API stores provider metadata and key references, not private key material. Production still requires an external signing mode.

`POST /v1/merkle-batches` creates a signed Merkle batch over a tenant audit-chain sequence range. `GET /v1/merkle-batches/{id}/verify` recomputes the Merkle root and verifies the checkpoint signature.

`POST /v1/transparency-checkpoints` records optional external timestamp/transparency anchoring metadata for a Merkle batch. Public transparency is optional and not required for local trust.

`POST /v1/object-retention-policies` records tenant-prefixed object-retention policy intent. `POST /v1/object-retention-policies/{id}/verify` records a verification transition for the policy record. Object-lock enforcement depends on the configured object store.

`POST /v1/backup-manifests` generates a backup manifest with a state hash, resource counts, audit-chain consistency checks, and limitations. `GET /v1/backup-manifests/{id}/verify` verifies the recorded manifest checks. The manifest intentionally excludes raw payload bytes and private keys; restore requires matched database and object-store backups.

`GET /v1/ready` returns a low-detail readiness response. `GET /v1/metrics` returns tenant-scoped safe resource counts and requires admin scope.

`GET /v1/audit-log` lists tenant audit-chain entries with optional `subject_type`, `subject_id`, `since`, and `limit` filters. It requires admin scope and returns tenant-scoped audit fields only.

`POST /v1/legal-holds` records a legal hold for tenant, product, project, release, or evidence scope. `POST /v1/retention-overrides` records an expiring retention override. `GET /v1/reports/retention` lists tenant-scoped legal hold and retention override records with limitations.

`POST /v1/commercial-collectors` records a commercial collector definition with provider, version, manifest digest, allowed scopes, and status. `GET /v1/commercial-collectors` lists tenant-scoped definitions. These records define extension metadata and do not grant provider trust by themselves.

## Contracts And Policy V2

`POST /v1/openapi-diffs` compares two uploaded OpenAPI contracts by stored contract metadata and classifies the result as unchanged, changed, or breaking when target path count decreases. Rich operation-level diffing remains future work.

`POST /v1/custom-policies` creates a versioned deterministic policy with simple required evidence rules. `POST /v1/custom-policies/{id}/evaluate` stores a replayable evaluation with input hash and policy checks for one release.

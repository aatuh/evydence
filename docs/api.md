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

Errors use RFC 9457 Problem Details and include a stable `code` field.

The generated OpenAPI document is committed at `openapi.yaml` and served at `/v1/openapi.json`.

## Controls And Reports

`POST /v1/control-frameworks` creates a tenant-scoped framework version such as an internal CRA-readiness or SSDF-lite mapping. `GET /v1/control-frameworks` lists framework versions for the tenant.

`POST /v1/controls` creates a framework-owned control with evidence requirements. Supported requirement types currently match implemented evidence resources: `sbom`, `vulnerability_scan`, `vex`, `vulnerability_decision`, `artifact`, `build`, `build_attestation`, `openapi_contract`, `release_bundle`, and `exception`. `GET /v1/controls/{id}` reads a tenant-scoped control.

`POST /v1/controls/{id}/evidence` appends a control evidence link to an existing subject and confidence value of `high`, `medium`, `low`, or `unsupported`. Duplicate links return the existing link. `GET /v1/control-evidence` lists links by optional control, product, or release filters.

`GET /v1/reports/control-coverage?framework_id=...&product_id=...&release_id=...` returns deterministic coverage statuses per control: `satisfied`, `partial`, `missing`, `waived`, `not_applicable`, or `unknown`. Approved, unexpired exceptions with a matching `control_id` may waive a control.

`GET /v1/reports/cra-readiness?product_id=...&release_id=...` returns a CRA-oriented technical evidence report built from the same control coverage engine. It includes assumptions and limitations and does not make legal compliance, certification, complete-SBOM, or secure-release claims.

## CI Provenance

Collectors are tenant-scoped automated ingesters. `POST /v1/collectors` creates a `github_actions`, `gitlab_ci`, or `generic_ci` collector and returns a one-time API key secret scoped for build/evidence upload. `GET /v1/collectors` lists collectors without key hashes or secrets. The server binds collector identity from the API key; clients must not submit `collector_id` for build attribution.

`POST /v1/builds` records an immutable build run. For `provider=github_actions`, the request must include `project_id`, `release_id`, `commit_sha`, `status`, `started_at`, `repository`, `workflow_ref`, `run_id`, and `run_attempt`. Supported statuses are `queued`, `running`, `passed`, `failed`, and `cancelled`. `GET /v1/builds/{id}` requires `build:read`.

`POST /v1/builds/{id}/attestations` accepts raw DSSE JSON containing `payloadType`, base64 `payload`, and `signatures`. Evydence decodes the in-toto Statement, records subjects, predicate type, SLSA builder/build metadata when present, stores raw bytes as tenant-prefixed evidence, and marks the record structurally valid. This slice does not perform cryptographic trust-root verification.

## Evidence Lifecycle And Search

`GET /v1/evidence/search` filters tenant evidence by product, project, release, build, deployment, type, subtype, source system, collector, verification status, subject ref, tag, created time, and limit. Results are tenant-scoped and sorted newest first.

`POST /v1/evidence/{id}/lifecycle-events` appends lifecycle records for `amendment`, `redaction`, `tombstone`, or `retention_marker`. These records do not mutate the immutable evidence core fields. `GET /v1/evidence/{id}/lifecycle-events` returns the timeline for one evidence item.

## Release Candidates And Artifacts

`POST /v1/release-candidates` records an immutable release-candidate snapshot over explicit builds, artifacts, SBOMs, scans, VEX documents, OpenAPI contracts, and bundles. `POST /v1/release-candidates/{id}/promote` and `/reject` append the terminal transition; a candidate cannot be transitioned twice.

`POST /v1/container-images` records OCI-style image repository, tag, digest, platform, and optional artifact binding. `POST /v1/artifact-signatures` records detached artifact signature metadata and optional raw signature payload bytes in object storage. `POST /v1/verify` supports `subject_type=artifact_signature` for digest binding and signature-presence verification; cryptographic trust-root verification remains future work.

## Source And Deployment Evidence

`POST /v1/source/repositories`, `/v1/source/commits`, `/v1/source/branches`, and `/v1/source/pull-requests` record source-control evidence without replacing the source provider as the source of truth. Commit messages are represented by hashes, not stored as raw report text.

`POST /v1/collectors/github/source-snapshots` and `/v1/collectors/gitlab/source-snapshots` accept strict JSON snapshots containing repository, commit, branch-protection, and pull-request metadata. No live provider API calls or OIDC token verification are performed by these endpoints.

`POST /v1/environments` creates deployment environments for a product. `POST /v1/deployments` records deployment events linking an environment, release, artifacts, status, timing, and optional rollback reference. Rollbacks are recorded as new deployment events, not destructive edits.

## Release Risk Decisions

OpenVEX ingestion is available at `POST /v1/vex` with a request body containing `release_id`, optional `artifact_id`, and `payload`. The payload must be OpenVEX JSON with author, timestamp, and one or more statements. Raw VEX bytes are stored as tenant-prefixed object payloads and represented as immutable `vex` evidence.

Vulnerability findings from `POST /v1/vulnerability-scans` can be resolved with `POST /v1/vulnerability-findings/{id}/decisions`. Supported statuses are `affected`, `not_affected`, `fixed`, and `under_investigation`. New decisions supersede earlier decisions for the same finding.

Scoped exceptions are created with `POST /v1/exceptions` and approved separately with `POST /v1/exceptions/{id}/approve`. Only approved, unexpired exceptions can affect release readiness.

`GET /v1/reports/release-readiness?release_id=...` returns deterministic readiness JSON with checks, blocking findings, accepted exceptions, gaps, assumptions, and limitations. Readiness requires SBOM, vulnerability scan, artifact digest evidence, signed bundle, passed build provenance, build attestation subject matching a release artifact digest, and no unhandled open critical finding. It supports compliance readiness only and is not a legal compliance or secure-release conclusion.

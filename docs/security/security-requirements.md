# Security Requirements Matrix

Document type: reference. This matrix is the canonical security-requirements
map for the threat model. Each public trust claim made by Evydence documentation
or API descriptions must map to at least one requirement below before it is
published. A requirement may state a limitation; it must not upgrade a local
record into a provider, legal, or security conclusion.

The threat rationale is in the [threat model](threat-model.md). Current API
operations, scopes, auth modes, and idempotency requirements are generated in
the [API inventory](../reference/api-inventory.md).

| ID | Requirement and public claim boundary | Current repository control and evidence | Required test evidence | External/operator control | Residual risk and owner |
| --- | --- | --- | --- | --- |
| SEC-001 | A tenant-scoped request must not read, link, export, verify, package, or mutate another tenant's resource. UI visibility is not authorization. | Application and persistence use tenant IDs; object identity is tenant-prefixed; the API inventory records route auth/scopes. | `internal/adapters/httpapi/router_test.go`; `internal/app/object_identity_test.go`; `internal/adapters/postgres/object_payloads_test.go`. | Credential issuance, tenant membership, network exposure, and database roles. | Distributed authorization is not exhaustive proof; Codex owns P0 EVY-1002. |
| SEC-002 | API, collector, SSO-session, and portal secrets are returned only when the contract permits, stored as non-secret hashes where implemented, scoped, revocable, and not replayed in stored idempotency responses. | Identity and idempotency repositories; one-time-secret API descriptions; portal/session lifecycle behaviour. | `internal/app/identity_uow_test.go`; `internal/app/enterprise_test.go`; `internal/app/idempotency_test.go`; `internal/adapters/httpapi/router_test.go`. | MFA, credential distribution, key rotation schedule, secret manager, and identity-provider policy. | Complete lifecycle/CSRF/protocol vectors: Codex owns P0 EVY-1005. |
| SEC-003 | HTTP ingress must have finite header/read/write/idle limits, bounded client/tenant limiter state, safe retry responses, and trusted-proxy-only forwarding. | EVY-1003 listener/limiter implementation and documented configuration. | `internal/adapters/httpapi/ingress_test.go`; `internal/adapters/httpapi/router_test.go`. | TLS termination, WAF/DDoS controls, ingress rate limits, and trusted proxy sanitization. | Non-HTTP resource paths remain under SEC-006; Codex owns P0 EVY-1006. |
| SEC-004 | Outbound provider, signing, identity, and transparency HTTP calls must use an allowlisted, bounded destination policy that rejects prohibited resolved addresses and unsafe redirects. | No repository-wide control currently satisfies this requirement. | EVY-1004 must add metadata/private-network, redirect, DNS-rebinding, and header-origin tests. | Egress firewall, DNS policy, proxy configuration, and approved provider endpoints. | Unresolved; Codex owns P0 EVY-1004. No SSRF-resistance claim may be made before it completes. |
| SEC-005 | A payload becomes trusted only after its bytes, canonical digest, tenant, media type, size, and staged/finalized lifecycle state match durable metadata. | Versioned tenant object keys, staged/finalized lifecycle, object-store read verification, and worker revalidation. | `internal/app/object_identity_test.go`; `internal/app/object_ingestion_test.go`; `internal/adapters/postgres/object_payloads_test.go`; `cmd/evydence-worker/main_test.go`. | Bucket IAM, encryption, versioning/object lock, backup consistency, and object-store incident response. | Provider durability and retention are not established by local metadata; operator/provider owns them. |
| SEC-006 | Parsers, archives, templates, graphs, reports, and uploads must reject malformed or resource-exhausting input within documented resource limits; raw inputs are not automatically trusted. | Streaming/native upload limits, worker payload limits, supported parser matrices, and hardened release/package archive verification. | `internal/adapters/httpapi/ingestion_handlers_test.go`; `cmd/evydence-worker/main_test.go`; `cmd/evydence/main_test.go`; parser fuzz/corpus tests. | Process/container CPU, memory, disk, and ingress limits; malware handling policy. | Comprehensive depth/count/compression/template/graph limits and security regression gate: Codex owns P0 EVY-1006; broader fuzzing: EVY-1104. |
| SEC-007 | Signed inbound incident webhooks must bind a permitted key, event identity, timestamp, and payload before an incident timeline change; provider input is evidence until verified. | Incident webhook receiver and verification paths; provider verification records. | `internal/app/risk_workflows_test.go`; `internal/app/provider_verification_uow_test.go`; HTTP operation contract tests. | Sender key custody, webhook endpoint routing, provider-side replay controls, and incident process. | Provider truth and destination security are not implied; EVY-1004 and EVY-1005 own related gaps. |
| SEC-008 | A verification receipt must name its profile and checked inputs. `passed` means all required checks passed; it does not mean secure, compliant, complete, or provider-authoritative. | ADR 0002, verification profiles, trust-root/key lifecycle, DSSE/Cosign/Merkle/archive verification paths. | `internal/app/dsse_verification_uow_test.go`; `internal/app/cosign_verification_uow_test.go`; `internal/app/merkle_verification_uow_test.go`; `cmd/evydence/main_test.go`. | Trust-root source, KMS/HSM policy, revocation source, transparency operator, and independent signing review. | Profile-specific online, revocation, and provider limitations remain explicit; Verification/signing context owns profile changes. |
| SEC-009 | Audit-chain and checkpoint verification must expose local inconsistency, while documentation must not claim protection from a privileged operator who can rewrite all stores and keys. | Append-only audit-chain model, canonical hashes, checkpoints, restore/recovery evidence. | `internal/adapters/postgres/failure_atomicity_test.go`; `internal/adapters/postgres/paired_backup_restore_test.go`; audit/verification tests. | Separate administrative roles, immutable/independent checkpoints, backup custody, storage/database audit, and restore testing. | This is an external-control residual, not a repo-owned claim of administrator-proof history. |
| SEC-010 | Collector, CI, registry, bundle, and release evidence must retain declared source/digest/signature limitations. Release verification rejects identity and archive-manifest mismatch. | Collector release records, release manifests, and verification commands. | `internal/app/collector_supply_chain_test.go`; `cmd/evydence/main_test.go`. | Branch protection, CI runner trust, registry controls, release permissions, provider audit logs, and deployment-digest evidence. | Evidence does not prove CI/runtime or provider truth; operator/provider owns those controls. |
| SEC-011 | External responses, logs, metrics, packages, reports, and rendered portal content must avoid secrets, raw payloads, and unauthorized customer data; package scope/redaction is explicit. | Redaction profiles, scoped packages, safe diagnostics, and portal HTML safety controls. | `internal/app/redaction_leakage_test.go`; `internal/adapters/httpapi/router_test.go`; `cmd/evydence/main_test.go`. | Package recipient authorization, NDA/sharing approval, log retention/access, and customer privacy review. | Central classification and canary coverage are unresolved; Codex owns P0 EVY-1006 and P0 EVY-1202 follows it. |
| SEC-012 | Instance-only diagnostics and outbox operations require explicit instance authorization and return bounded, sanitized detail. | `instance:admin` route contracts and safe OpenAPI descriptions. | `internal/adapters/httpapi/router_test.go`; `internal/adapters/httpapi/system_handlers_reconciliation_test.go`. | Protected metrics/admin network path, authenticated scrape, operator role review. | Central action/resource policy coverage is unresolved; Codex owns P0 EVY-1002. |
| SEC-013 | Reusing an idempotency key with equivalent content returns the original durable result; different content conflicts; a one-time secret is not replayed. | Transactional idempotency reservation/completion and safe replay records. | `internal/app/idempotency_test.go`; `internal/app/idempotency_concurrency_test.go`; `internal/adapters/httpapi/idempotency_concurrency_test.go`; `internal/adapters/postgres/idempotency_concurrency_test.go`. | Clients must protect keys and retry according to documented contract. | Route-wide proof belongs with EVY-1002 and the critical-behaviour matrix in EVY-1101. |
| SEC-014 | A command's domain mutation, audit, idempotency, and outbox effects commit or roll back together; workers fail safely and remain replayable. | ADR 0001, transaction-scoped ports, persisted outbox, staged object protocol, and worker checks. | `internal/adapters/postgres/failure_atomicity_test.go`; `internal/adapters/postgres/recovery_killpoints_test.go`; `internal/adapters/postgres/outbox_lifecycle_test.go`; `cmd/evydence-worker/main_test.go`. | Database availability, migration process, worker deployment/lifecycle, alerting, and recovery ownership. | Operational lifecycle and deployment proof remain EVY-1201, EVY-1203, and EVY-1206 work. |
| SEC-015 | Product and report language must describe evidence, checks, gaps, assumptions, and limitations without claiming legal compliance, certification, complete SBOMs, authoritative scanning, or guaranteed release security. | Product-boundary docs, ADR 0002, generated API descriptions, and documentation review rules. | `make docs-check`; `make quality-scorecard-check`; source-of-truth review. | Legal/audit/customer review of suitability and claims. | External review is required for those conclusions; no repository check can establish them. |

### Control-evidence command migration evidence

For `SEC-001`, `SEC-006`, `SEC-011`, `SEC-013`, and `SEC-014`,
`internal/risk/app/control_evidence_commands_test.go` covers the focused command
core's tenant/subject identity checks, subject-derived authorization requests,
duplicate disclosure ordering, bounded input, and link/audit rollback.
Those tests use transaction fakes. Live database evidence is in
`internal/platform/wiring/control_evidence_commands_test.go`: every supported
subject and focused-list visibility, foreign/broken references, typed source
and artifact-parent checks, scope-matching artifact grants, bounded duplicate
metadata, pending-row reads, replay, rollback, and competing duplicate writes.
Private storage errors map to the safe error catalog. The grant policy and its
query budgets are tested in `internal/risk/app/control_evidence_authorizer_test.go`.
PostgreSQL HTTP binding evidence is in
`internal/platform/wiring/control_evidence_http_test.go`: fresh-server creation
and replay for all supported subjects, current-grant checks on command
execution, natural-duplicate preservation, cross-tenant and invalid-input
rejection, exact durable list DTOs, safe Problem Details, and link/audit rollback.
Local-memory mode keeps its explicit compatibility command. This evidence does
not establish deployment, route-wide authorization, or grant revalidation of
already completed idempotency replay records; those records remain actor-bound.

## Change and release rules

- A code, OpenAPI, provider, deployment, or public-copy change that affects a
  `SEC-*` requirement must update this matrix, the threat model, and the
  relevant focused test evidence in the same change.
- An unmet high-risk repository requirement must retain a P0/P1 backlog item;
  operator/provider/review controls must be labelled external rather than
  counted as implementation evidence.
- Before a release, maintainers review this matrix against the release commit
  and record any changed residual risk in release evidence. This repository can
  require and document the review, but cannot fabricate that external action.
- A passing local check establishes only the listed repository evidence. It does
  not prove a deployment's IAM, network, key custody, provider state, or legal
  suitability.

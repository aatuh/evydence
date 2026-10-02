# Threat Model

Document type: explanation. This model describes the current repository
boundary and the security requirements that guide its implementation. It is
versioned with the repository and must be reviewed when a release changes a
trust boundary, public trust claim, authentication method, provider, storage
profile, parser, package format, or deployment topology.

Evydence organizes and verifies technical evidence. It does not establish legal
compliance, certification, scanner completeness or authority, provider truth,
or that a release is secure.

## Scope and assets

The model covers the API client, collector, customer portal user, tenant and
instance administrator, PostgreSQL, object storage, worker, signing key or
KMS/HSM, identity provider, transparency provider, CI/release workflow, and
malicious evidence input. It applies to the supported self-hosted topology,
not to an assumed managed service.

Assets needing protection include tenant-scoped records and relationships; API,
collector, session, and portal credentials; raw evidence payloads; canonical
digests; audit-chain and outbox records; signing and trust-root material;
verification receipts; customer package contents; release manifests; and
operator diagnostics.

The main data path is:

```text
client / collector / portal user
              |
              v
      authenticated HTTP API
              |
              v
  command transaction (tenant, audit, idempotency, outbox)
       |                         |
       v                         v
 PostgreSQL                   object storage
                                  |
                                  v
                           worker/parser/signer
                                  |
                                  v
                     packages, reports, verification receipts
```

The PostgreSQL transaction boundary is defined by
[ADR 0001](../adr/0001-database-authoritative-transactions.md). The intended
ownership and post-commit context-event boundary is defined by
[ADR 0003](../adr/0003-bounded-contexts.md). Cryptographic receipt meaning is
defined by [ADR 0002](../adr/0002-cryptographic-trust-model.md).

## Security objectives and non-objectives

Evydence aims to ensure that a tenant-scoped caller cannot read or mutate
another tenant's resources; evidence core fields and audit history remain
immutable or append-only; payload bytes are checked before they become trusted;
and verification/package results state their scope and limitations.

It does not defend, by repository code alone, against a privileged operator who
can alter PostgreSQL, object storage, all signing keys, and every checkpoint;
an identity provider, KMS, registry, or transparency service that is
misconfigured or compromised; or a customer who authorizes disclosure of an
overly broad package. Those are operator, provider, and review boundaries
described in the [external controls matrix](../reference/external-controls-matrix.md).

## Threats and required treatment

`SEC-*` entries refer to the normative
[security requirements matrix](security-requirements.md). "Repository evidence"
identifies an implemented boundary or committed test; it does not imply that an
external control has been observed in a particular deployment.

| ID | Threat and affected boundary | Required treatment | Repository evidence | Residual risk and owner |
| --- | --- | --- | --- | --- |
| TM-01 | Tenant escape or confused deputy through an ID, link, export, report, package, or worker input. | `SEC-001`, `SEC-012` | Tenant-scoped route and storage tests include `internal/adapters/httpapi/router_test.go`, `internal/app/object_identity_test.go`, and `internal/adapters/postgres/object_payloads_test.go`. | Authorization remains distributed in the transition aggregate; EVY-1002 is P0 repository work. Tenant role design and deployment identity lifecycle are operator-owned. |
| TM-02 | Credential theft, reuse, or session/portal replay at the API, SSO, collector, or portal boundary. | `SEC-002`, `SEC-013` | One-time secret replay protection and session/portal tests include `internal/app/idempotency_test.go`, `internal/app/identity_uow_test.go`, `internal/app/enterprise_test.go`, and `internal/adapters/httpapi/router_test.go`. | Cookie, CSRF, OIDC/SAML negative-vector, and lifecycle coverage are incomplete; EVY-1005 is P0. Credential issuance, MFA, and key storage are operator/provider-owned. |
| TM-03 | Request flooding, slow headers, or oversized inbound requests exhaust API resources. | `SEC-003` | Bounded ingress and proxy tests are in `internal/adapters/httpapi/ingress_test.go`; configuration is documented in `docs/reference/configuration.md`. | Existing HTTP limits do not prove every parser, report, graph, template, or archive path is bounded; EVY-1006 is P0. Edge DDoS protection is operator-owned. |
| TM-04 | Outbound SSRF reaches metadata, private, loopback, redirected, or rebinding destinations through identity, signing, or transparency integrations. | `SEC-004` | Current adapters have bounded provider-specific behaviour, but no single repository-wide destination policy is established. | This is unresolved P0 work: EVY-1004. Network egress policy and provider allowlists are operator-owned until code enforces a compatible policy. |
| TM-05 | A raw object differs from its declared digest, tenant, media type, or lifecycle state. | `SEC-005` | Object identity and staged/finalized lifecycle tests are in `internal/app/object_identity_test.go`, `internal/app/object_ingestion_test.go`, `internal/adapters/postgres/object_payloads_test.go`, and `cmd/evydence-worker/main_test.go`. | Storage IAM, encryption, replication, object lock, and recovery-point consistency are operator/provider-owned. |
| TM-06 | Malicious SBOM, VEX, scan, OpenAPI, archive, template, or graph input consumes unbounded CPU/memory or traverses a path. | `SEC-006` | Native upload and worker oversize tests are in `internal/adapters/httpapi/ingestion_handlers_test.go` and `cmd/evydence-worker/main_test.go`; release/package archive negative tests are in `cmd/evydence/main_test.go`. | Recursive JSON, archive, report/template, graph, and parser-wide resource bounds are incomplete; EVY-1006 is P0 and EVY-1104 supplies broader fuzz/vector evidence. |
| TM-07 | Webhook/provider replay, altered timestamp, or signature substitution causes a false incident or provider assertion. | `SEC-007`, `SEC-008` | Incident-webhook, provider-verification, DSSE, and Cosign flows have focused application and adapter tests, including `internal/app/dsse_verification_uow_test.go` and `internal/app/cosign_verification_uow_test.go`. | Outbound destination policy remains EVY-1004; complete identity/session protocol hardening remains EVY-1005. Provider configuration and signing-key custody are external controls. |
| TM-08 | A signature, certificate identity, trust root, checkpoint, or verification receipt is replayed for a different subject or interpreted as stronger evidence than it is. | `SEC-008` | ADR 0002 and `docs/reference/verification-results.md` define named profiles and fail-closed requirements; release/archive negative tests are in `cmd/evydence/main_test.go`. | External transparency, certificate revocation, historical key validity, and provider truth are profile-specific limitations, not repository guarantees. |
| TM-09 | A privileged database or storage administrator rewrites history, deletes checkpoints, or substitutes keys. | `SEC-009` | Audit-chain and verification checks detect inconsistencies within the retained local records; restore and failure tests include `internal/adapters/postgres/failure_atomicity_test.go` and `internal/adapters/postgres/paired_backup_restore_test.go`. | Independent checkpoint retention, database/object access control, backups, and key separation are operator/provider-owned. This residual cannot be closed by an application-only change. |
| TM-10 | CI, collector, registry, dependency, or release artifact compromise inserts misleading provenance or changes a published artifact. | `SEC-010` | Collector supply-chain evidence is exercised in `internal/app/collector_supply_chain_test.go`; release artifact verification is covered by `cmd/evydence/main_test.go`. | Branch protection, runner trust, registry policy, provider audit logs, and independent deployment digest evidence are external controls. |
| TM-11 | Logs, errors, metrics, packages, reports, or portal rendering disclose a secret, raw payload, or customer data. | `SEC-011` | Package redaction and HTML safety tests include `internal/app/redaction_leakage_test.go` and `internal/adapters/httpapi/router_test.go`; safe diagnostics are described in `docs/reference/observability.md`. | Central sensitive-field handling and exhaustive canary coverage are unresolved P0 work in EVY-1006; structured redacted logging follows in EVY-1202. Customer-specific sharing approval is operator/review-owned. |
| TM-12 | Instance diagnostics, metrics, or outbox administration leaks another tenant's data or grants instance power to tenant administration. | `SEC-012` | Route descriptions and tests require explicit `instance:admin`; see `internal/adapters/httpapi/openapi_operations.go` and `internal/adapters/httpapi/router_test.go`. | A centralized route-to-policy proof is unresolved P0 work in EVY-1002. Network exposure and scrape authentication are operator-owned. |
| TM-13 | A lost response or retried create duplicates a durable action or replays a one-time secret. | `SEC-013` | Application, HTTP, and PostgreSQL concurrency tests are in `internal/app/idempotency_concurrency_test.go`, `internal/adapters/httpapi/idempotency_concurrency_test.go`, and `internal/adapters/postgres/idempotency_concurrency_test.go`. | EVY-1002 must prove route coverage; callers must preserve and protect idempotency keys. |
| TM-14 | Worker crash, poisoned job, migration race, or incomplete recovery changes durable state or hides a failed side effect. | `SEC-014` | Fault-injection, recovery, and outbox tests are in `internal/adapters/postgres/failure_atomicity_test.go`, `internal/adapters/postgres/recovery_killpoints_test.go`, and `internal/adapters/postgres/outbox_lifecycle_test.go`. | Lifecycle, telemetry, migration-job, and deployment hardening remain EVY-1201, EVY-1203, and EVY-1206 work. |
| TM-15 | Product language or a report is mistaken for legal compliance, complete SBOM coverage, authoritative vulnerability detection, or a secure-release conclusion. | `SEC-015` | Claim limits are maintained in `README.md`, `docs/reference/product-boundary.md`, ADR 0002, and the documentation checks. | Legal, audit, customer, and regulator acceptance are review-owned; no repository check can establish them. |

For the control-evidence linking migration (`TM-01`, `TM-06`, `TM-13`, and
`TM-14`), the focused risk command core treats supplied scopes as filters rather
than ownership proof, reauthorizes before duplicate disclosure, bounds text and
the duplicate key, and appends one link/audit pair atomically. Its transaction-fake
tests are `internal/risk/app/control_evidence_commands_test.go`. A durable reader
must check current control/framework and subject/parent ownership; artifact
authorization must find a permitted current association matching the requested
scope. PostgreSQL concurrency and HTTP migration remain unproven pending work,
not security guarantees established by these core tests.

## Attacker capabilities

This model assumes an attacker can obtain a low-privilege tenant credential,
send arbitrary HTTP requests and structured documents, retry/reorder requests,
submit malformed parser inputs, control a public webhook payload, and operate a
public internet endpoint for outbound integration tests. It also assumes a
customer portal token can be mishandled by a recipient and a provider can
return incomplete or deceptive metadata.

It treats a host/root, PostgreSQL, object-storage, KMS, or identity-provider
administrator as outside the application's unilateral trust boundary. The
application must limit what it exposes and record trustworthy local evidence,
but an operator must supply host hardening, IAM, encryption, network policy,
backups, monitoring, and independent review.

## Release review rule

Before a release, maintainers must review this model and the requirements
matrix against the exact release commit. The review must identify changed trust
boundaries, update affected `SEC-*` entries and tests, and distinguish
repository evidence from any deployment/provider evidence. A local documentation
check does not prove that a maintainer, operator, provider, or external reviewer
performed that review.

## High-priority open risk register

The following high-risk repository gaps already have P0/P1 backlog ownership;
they are not silently accepted by this model.

| Risk | Backlog disposition |
| --- | --- |
| Centralized tenant/resource authorization and route coverage | P0 EVY-1002. |
| Outbound SSRF and redirect/DNS policy | P0 EVY-1004. |
| SSO, session, cookie, bearer, and credential lifecycle hardening | P0 EVY-1005. |
| Complete secret redaction and resource-exhaustion controls | P0 EVY-1006. |
| Machine-checked critical behaviour and coverage policy | P0 EVY-1101. |
| Parser/archive fuzz and cryptographic vector breadth | EVY-1104. |
| Structured, correlated, redacted logging | P0 EVY-1202 after EVY-1006. |
| Validated configuration/secret source and migration/deployment hardening | P0 EVY-1205 and P0 EVY-1206. |

External residuals—such as privileged infrastructure access, provider truth,
and legal sufficiency—remain explicitly operator, provider, or review-owned.
They need deployment evidence and review rather than a fabricated
repository-only completion claim.

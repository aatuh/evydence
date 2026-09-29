# ADR 0003: Bounded Context Ownership And Dependency Rules

Status: accepted. EVY-902 implemented the context-owned model layer described
below. EVY-903 implemented focused Identity, Release, and Evidence command
services. EVY-904 has added focused Decision, Package, and Verification
services and moved their migrated HTTP workflows behind context-specific
interfaces. The composition-root and database-backed query migration and
legacy-facade retirement remain assigned to EVY-905 and EVY-906.

## Context

The implementation has useful transaction-scoped repository ports, but the
commands and queries not yet migrated to focused services remain behind
`internal/app.Ledger`. The legacy `internal/domain` package also remains the
JSON and persistence compatibility surface while callers migrate. Without
explicit context-owned models and checked adapters, those transition paths make
ownership hard to see and permit accidental broad access to unrelated state.

[ADR 0001](0001-database-authoritative-transactions.md) remains the transaction
contract: one production command owns one PostgreSQL unit of work, including
its durable domain mutation, audit entry, idempotency record when supplied, and
outbox job. Bounded contexts must preserve that contract; they are not a reason
to introduce distributed writes or publish an event before its transaction
commits.

## Decision

Evydence will use the contexts below. A context owns its business rules,
domain types, command service, query model, migration stewardship, and
repository port. A route may call only its owning context's application
service. Contexts exchange identifiers and committed, versioned integration
events rather than importing each other's aggregates or writing each other's
repositories.

### Implemented model and command boundaries

EVY-902 created tag-free, standard-library-only domain packages at
`internal/{identity,release,evidence,risk,package,verification,operations,integration,experimental}/domain`.
Together they own all 142 models assigned in the table below. Schema and policy
constants now originate in those packages; `internal/domain/schema_context.go`
re-exports them only for source compatibility.

Stable lifecycle behavior uses validated named values in the context model for
release and release-candidate state, evidence lifecycle action, vulnerability
decision status, release-bundle state, verification result and signing-key
status, incident status, and collector status. Normal constructors and parsers
reject empty or unknown values, and release transitions reject invalid order.
Verification profile normalization, conservative result aggregation, profile
policy definitions, and signing-key historical-validity evaluation are owned by
the verification context. Signing-key core metadata deliberately excludes
private key bytes.

EVY-903 added transport-neutral command services under
`internal/{identity,release,evidence}/app`. They depend on focused reader,
repository, transaction, authorization, clock, identifier, object-ingestion,
audit, and outbox ports. The HTTP handlers for the 15 Identity, 21 Release, and
27 Evidence operations now depend on context-specific interfaces rather than
on `*app.Ledger`. Temporary Ledger-backed adapters map the legacy DTOs and
preserve the existing idempotent command scope until the EVY-905 composition
root migration. EVY-904 added focused `internal/{risk,package,verification}/app`
services for decisions, policy readiness, customer and release packages,
evidence bundles, CRA HTML and custom report materialization, signing-key
lifecycle, and verification receipts. Committed
read snapshots and transaction ports keep these services independent of the
legacy Ledger maps; the compatibility adapters still translate persisted and
HTTP DTOs.

EVY-905 is in progress. PostgreSQL-backed point reads for products, projects,
releases, builds, artifacts, and release candidates use release-catalog queries. The
API's read dependencies are now assembled by `internal/platform/wiring.BuildAPIReadServices`
from the same validated runtime that opens API and worker infrastructure; the
API entry point supplies HTTP limits and bootstrap configuration separately.
This centralizes the durable read ports but does not yet remove the production
Ledger compatibility surface or finish all database-backed queries. Release
candidate pages filter current product/release grants before the SQL limit;
artifact point reads resolve current evidence/build associations in the same
tenant-filtered statement before granting scoped human access;
deployment point and list reads use operations-owned queries. Deployment list
visibility and keyset limits are applied in PostgreSQL; release and environment
joins must resolve to one tenant-owned product before grant evaluation.
Ordinary evidence point reads use a tenant-scoped, snapshot-consistent query.
Ordinary evidence lifecycle-event lists use one tenant-scoped snapshot for the
evidence authorization point and bounded SQL keyset page; worker-owned evidence
retains the provenance-checked Ledger projection. Response redaction remains
at the API boundary.
OpenAPI contract point reads verify their source evidence, product, and optional
release in one tenant-filtered statement before applying human resource grants;
local-memory mode retains the Ledger reader.
Parsed SBOM point reads also verify current source evidence, release, and
artifact parentage and require sole artifact/source-evidence subject agreement in
one tenant-filtered statement before applying human
resource grants. They preserve accepted, not-yet-parsed rows and return one
document with its stored components when available, not a
tenant-wide projection; local-memory mode retains the Ledger reader.
Vulnerability-scan point reads now use a repeatable-read tenant snapshot to
validate the scan's source evidence, current release/product ownership,
parsed finding identities, and human resource grants. Accepted pending scans
retain their empty parser fields; local-memory mode retains the Ledger reader.
SBOM component pages now expand tenant-owned JSONB component arrays in a
repeatable-read PostgreSQL snapshot, apply current resource grants before the
keyset limit, and transfer only a bounded page to the API. This removes the
production Ledger's 500-component preselection cap, but does not provide a
component-level search index; local-memory mode retains the cap. The page
query applies the same source-type, release, artifact-subject, and optional
build/deployment parent checks as the parsed SBOM point read before expansion.
Control-evidence lists now use a risk-owned query service in PostgreSQL mode:
one SQL statement resolves current control/framework/subject ownership and
applies actor grants before keyset pagination. Broken parent relationships are
excluded. The local-memory profile retains the Ledger compatibility reader;
the remaining production Ledger reads still belong to EVY-905.
Exception lists also use a risk-owned PostgreSQL query. One repeatable-read
snapshot resolves an optional release filter and applies current tenant,
product, and release grants before the bounded keyset page. Local-memory mode
retains the compatibility reader.
Vulnerability-decision history also uses a risk-owned PostgreSQL query. It
validates filtered product/release coordinates in one snapshot, applies current
evidence-read grants and filters before keyset pagination, and never selects
tenant-internal notes. Local-memory mode retains its compatibility reader.
The customer-safe vulnerability-decision summary uses a separate risk-owned
read snapshot: it checks the release and `report:read` grant before loading
only active, customer-visible decisions for that release. The versioned report
wording and field redaction are shared with the local-memory compatibility
path.
Worker-owned evidence types still use the Ledger projection so their parser,
document, and audit provenance checks are not bypassed. Source-repository
pages use an integration-owned query that validates current project/product
parentage and filters grants before the keyset limit. Collector inventory
pages use an integration-owned tenant-scoped query; human sessions
need a current tenant-level `collector:read` grant, while issued credentials
remain scope-bound. The query does not select credential secrets or hashes.
Commercial collector-definition pages use the same integration-owned tenant
authorization boundary and a SQL-side keyset limit.
Experimental marketplace collector metadata pages and health points now use
tenant-filtered PostgreSQL reads, with current evidence-reference ownership
resolved in one statement. Human sessions need a current tenant-level
`collector:read` grant in both runtime profiles. These presence checks do not
prove package safety, marketplace trust, or provider endorsement.
Governance framework pages and control points use a risk-owned query; a
control must resolve to a framework in the same tenant before it is returned.
Signing-key pages use a verification-owned tenant-scoped query that selects
only public lifecycle metadata and applies a keyset limit in PostgreSQL;
human sessions need a current tenant-level `verify:read` grant.
Local-memory mode and other unmigrated handlers still use the Ledger
compatibility model.

`internal/domain` remains a compatibility DTO boundary at the HTTP,
persistence, and legacy-facade edges while remaining callers migrate in EVY-904
through EVY-906. It retains the existing JSON tags and public field shapes,
uses aliases where exact identity is safe, and uses explicit copying mappers
where validated values or local report projections differ.
`make domain-context-check` verifies unique ADR ownership, package import/tag
boundaries, field-by-field compatibility, stable field types, schema ownership,
and the required mappers. JSON round-trip tests and the unchanged public field
shapes cover the current API/persistence representation. No database migration
was required for the EVY-902 model split.

### Context ownership

The type lists are exhaustive for the exported production types currently in
`internal/domain/domain.go`. Supporting types and schema-version constants
belong to the row that owns the resource they support.

| Context | Owns these current domain types | Current implementation and port ownership |
| --- | --- | --- |
| Identity and access | `Actor`, `ResourceGrant`, `Tenant`, `Organization`, `HumanUser`, `RoleBinding`, `SSOProvider`, `UserIdentityLink`, `SSOSession`, `APIKey`, `ProviderVerification` | `internal/identity/app.Service`; `IdentityRepository`; identity portions of `EnterpriseRepository` and the Ledger DTO adapter are temporary. |
| Release catalog | `Product`, `Project`, `Release`, `ReleaseEvidenceFlow`, `ReleaseEvidenceFlowStep`, `Artifact`, `BuildRun`, `BuildOutput`, `BuildAttestation`, `ReleaseCandidate`, `ContainerImage` | `internal/release/app.Service`; `ReleaseCatalogRepository`, `BuildRepository`, and `SupplyChainRepository` except artifact-signature writes. Ledger query and DTO adapters remain transitional. |
| Evidence ingestion | `EvidenceItem`, `SubjectRef`, `EvidenceRef`, `EvidenceNotice`, `EvidenceLifecycleEvent`, `SBOM`, `SBOMComponent`, `SBOMComponentRecord`, `VulnerabilityScan`, `VulnerabilityFinding`, `VulnerabilityIdentity`, `VEXDocument`, `VEXImportIssue`, `VEXImportReport`, `VEXImportPreview`, `OpenAPIContract`, `OpenAPIOperation`, `SecurityScan`, `ManualSecurityDocument`, `SBOMDiff`, `DependencyChange`, `ContractDiff` | `internal/evidence/app.Service`; `EvidenceRepository` and `ObjectPayloadRepository`. Ledger query and DTO adapters and the evidence-facing methods of `RiskRepository` remain transitional. |
| Vulnerability decisions and governance | `VulnerabilityDecision`, `VulnerabilityDecisionCustomerSummary`, `VulnerabilityDecisionSummaryReport`, `Exception`, `PolicyEvaluation`, `PolicyCheck`, `CustomPolicy`, `PolicyRule`, `CustomPolicyEvaluation`, `Waiver`, `ApprovalRecord`, `ControlFramework`, `SecurityControl`, `ControlEvidenceRequirement`, `ControlEvidence`, `ControlFrameworkTemplatePack`, `VulnerabilityWorkflowRecord`, `ReleaseSecuritySummary`, `ReleaseSecurityProductSummary`, `ReleaseSecurityReleaseSummary`, `ReleaseSecurityMissingDecision`, `ReleaseSecurityApprovalSummary`, `ReleaseSecurityExceptionSummary` | `internal/risk/app.Service` owns decision, exception, waiver, approval, and readiness commands; `DecisionRepository`, `ControlRepository`, and remaining policy/query methods of `GovernanceRepository` and `RiskRepository` are compatibility paths. |
| Package and reporting | `CustomerPortalAccess`, `QuestionnaireTemplate`, `QuestionnaireQuestion`, `QuestionnairePackage`, `QuestionnaireResponse`, `QuestionnaireAnswerLibraryEntry`, `RedactionProfile`, `CustomerSecurityPackage`, `SecurityReviewPackageReport`, `HTMLReportPackage`, `PDFReportPackage`, `CustomReportTemplate`, `RenderedCustomReport`, `EvidenceBundle`, `EvidenceBundleImport`, `ReleaseBundle`, `EvidenceCitation`, `EvidenceSummary`, `QuestionnaireDraft`, `GraphNode`, `GraphEdge`, `EvidenceGraphSnapshot`, `ControlCoverageReport`, `ControlCoverageItem`, `CRAReadinessReport`, `CRAVulnerabilityHandlingReport`, `SecurityUpdateEvidenceReport`, `ReleaseReadinessReport`, `ReadinessSummary`, `ReadinessSection`, `ReadinessQuestion`, `BlockingFinding`, `IncidentReport`, `VulnerabilityPostureReport` | `internal/package/app.Service` owns redaction, customer-package, release-bundle, evidence-bundle, release-readiness, CRA HTML, and custom report-template workflows; `internal/package/query.AnswerLibrary` owns grant-filtered questionnaire draft reads, `internal/package/query.ReleaseBundles` owns bounded bundle and manifest reads, `internal/package/query.PortalAccess` owns grant-filtered portal-access pages, and `internal/package/query.VulnerabilityPosture` owns tenant/release-authorized scan aggregates in the PostgreSQL profile. Other `packageReportService`, `PackageRepository`, and specialized report/questionnaire paths remain compatibility paths. |
| Verification and signing | `AuditChainEntry`, `SigningKey`, `SigningProvider`, `Signature`, `ArtifactSignature`, `CosignVerification`, `MerkleBatch`, `TransparencyCheckpoint`, `ObjectRetentionPolicy`, `SigningCustodyReviewReport`, `BackupManifest`, `DSSETrustRoot`, `SigningOperation`, `VerificationResult`, `VerifyCheck` | `internal/verification/app.Service` owns signing-key lifecycle, verification receipts, DSSE/Cosign, Merkle/checkpoints, retention, custody, and backup workflows; `internal/verification/query.ArtifactSignatures` owns the PostgreSQL artifact-signature point read. `SignatureRepository`, `IntegrityRepository`, `VerificationRepository`, and remaining audit/query paths are compatibility adapters. Audit append is a required transaction side effect, not an authority to change another context's record. |
| Operations and incidents | `InstanceAdminSnapshot`, `LegalHold`, `RetentionOverride`, `RetentionReport`, `DeploymentEnvironment`, `DeploymentEvent`, `Incident`, `IncidentTimelineEvent`, `IncidentWebhookReceiver`, `IncidentWebhookEvent`, `RemediationTask` | `risk_workflows.go`, runtime/readiness, outbox administration and object reconciliation; `DeploymentRepository`. `AuditRepository`, `IdempotencyRepository`, and `OutboxRepository` are platform services owned here and used inside the caller's unit of work. |
| Integration ingestion | `Collector`, `CollectorRelease`, `CollectorHealthReport`, `SourceRepository`, `SourceCommit`, `SourceBranch`, `PullRequest`, `CommercialCollectorDefinition` | Collector, source-snapshot, and commercial-collector paths; `SourceRepository` and the collector methods of `BuildRepository`. |
| Experimental peripherals | `SaaSEditionProfile`, `PublicTransparencyLog`, `PublicTransparencyLogEntry`, `MarketplaceCollector`, `MarketplaceCollectorHealthReport`, `AnomalySignal`, `AnomalyReport` | `FutureExtensionsRepository` is a temporary quarantine port. These surfaces remain experimental until a named owning context accepts them; no new production dependency may target this port. |

`GovernanceRepository`, `RiskRepository`, `EnterpriseRepository`, and
`FutureExtensionsRepository` are explicitly transitional mixed ports. Their
row above assigns one accountable owner today. EVY-903 moved the Identity,
Release, and Evidence command capabilities it required. EVY-904 added focused
decision, package, and verification transaction ports while the legacy mixed
repository interfaces remain for compatibility. No new method may be added to
a mixed port.

### Public operations and internal work

`docs/reference/api-inventory.md` is the generated, exhaustive current
operation inventory. It contains 189 operations, each with one OpenAPI
`Owner` value. This table maps every possible current owner value to exactly
one target context; it is the route and public command/query assignment until
the generated OpenAPI owner labels are changed atomically with their handlers.

| Current OpenAPI owner (operation count) | Target context | Transition rule |
| --- | --- | --- |
| `identity-access` (15) | Identity and access | Direct mapping. |
| `release-catalog` (21) | Release catalog | Direct mapping introduced with the EVY-903 handler migration. |
| `evidence-ingestion` (27) | Evidence ingestion | Direct mapping introduced with the EVY-903 handler migration. |
| `release-ledger` (7) | Package and reporting, Vulnerability decisions and governance, or Operations and incidents | Remaining transitional query and operations label. Bundle reads, summaries, and graph/report creation go to Package and reporting; vulnerability workflow records go to Vulnerability decisions and governance; remediation tasks go to Operations and incidents. The route's resource selects the future service. |
| `integration-ingestion` (17) | Integration ingestion | Direct mapping. |
| `governance` (28) | Vulnerability decisions and governance | Direct mapping, except redaction and customer-package rendering, which move to Package and reporting. |
| `customer-delivery` (15) | Package and reporting | Direct mapping. |
| `reporting` (17) | Package and reporting | Direct mapping. |
| `integrity-verification` (24) | Verification and signing | Direct mapping. |
| `operations-incidents` (9) | Operations and incidents | Direct mapping. |
| `platform-operations` (9) | Operations and incidents | Direct mapping. |

The table above is intentionally a mapping, not a second handwritten route
catalog. The generated inventory remains the source of individual operation
IDs, paths, methods, auth, idempotency, and current labels. Its eleven counts
sum to 189. Later migration tickets must update a route's OpenAPI owner and
handler in the same compatible change; no handler may be silently re-owned.

Current non-HTTP commands and queries are assigned by the same owner rule:

| Current source surface | Owner | Required split outcome |
| --- | --- | --- |
| `internal/identity/app` with adapters in `internal/app/identity_service.go` and `identity_context_adapter.go` | Identity and access | Focused service owns commands; the old facade forwards and still supplies compatibility queries and DTO mapping. |
| `internal/release/app` with adapters in `internal/app/release_evidence_service.go`, `release_context_adapter.go`, and build paths | Release catalog | Focused service owns release/catalog/build commands; the old facade forwards during migration. |
| `internal/evidence/app` with adapters in `internal/app/evidence_context_adapter.go`, parser adapters, and remaining `vex.go` compatibility | Evidence ingestion, with decision effects emitted after commit | Focused service owns evidence/document commands and normalization; decision creation remains a separate decision command. |
| `internal/app/governance_packages.go`, `controls.go`, and policy paths | Vulnerability decisions and governance; Package and reporting for output/rendering | Policy mutation and read-only package rendering separate. |
| `internal/app/integrity_runtime.go`, audit chain, and verification profiles | Verification and signing | Provider adapters remain outside the application package. |
| `internal/app/risk_workflows.go` | Operations and incidents, Evidence ingestion, and Vulnerability decisions and governance | Split incidents, raw security evidence, and policy workflow methods. |
| `internal/app/package_report_service.go` and package/report portions of `enterprise.go` | Package and reporting | Use committed, tenant-scoped snapshots only. |
| `internal/app/outbox_admin.go`, runtime diagnostics, and reconciliation administration | Operations and incidents | Platform-only operator surface. |
| `internal/app/future_extensions.go` | Experimental peripherals | Keep isolated; graduate or remove each feature before it becomes stable. |

The persisted worker job kinds currently are assigned as follows:

| Job kind | Owner | Post-commit effect |
| --- | --- | --- |
| `finalize_payload`, `parse_sbom`, `parse_vulnerability_scan`, `parse_openapi_contract` | Evidence ingestion | Validate staged bytes and finalize or normalize evidence. |
| `parse_vex` | Evidence ingestion | Normalize VEX; it may request an idempotent Vulnerability decisions command after parsing. |
| `sign_bundle` | Verification and signing | Attach a signing receipt to an immutable package/bundle subject. |
| `verify_subject`, `verify_attestation` | Verification and signing | Append a verification receipt; never mutate the verified subject's core fields. |

### Repository and migration stewardship

Every field of `app.Repositories` has one accountable context. A caller may
use only its own business port plus the platform `Audit`, `Idempotency`, and
`Outbox` ports in the same unit of work.

| Repository field | Owner | Transitional note |
| --- | --- | --- |
| `WorkerProjection` | Operations and incidents — shared transaction/query platform | Temporary read-only bridge for worker-owned records needed by the Ledger compatibility model; it grants no mutation authority. |
| `Identity` | Identity and access | — |
| `Idempotency` | Operations and incidents | The platform owns expiry and replay mechanics; callers use it within their own transaction. |
| `ReleaseCatalog`, `Builds`, `SupplyChain` | Release catalog | `ArtifactSignature` moves from `SupplyChain` to Verification and signing. |
| `Evidence`, `Payloads` | Evidence ingestion | — |
| `Decisions`, `Controls`, `Governance` | Vulnerability decisions and governance | Redaction, legal-hold, retention, and DSSE methods leave `Governance`. |
| `Packages`, `Enterprise` | Package and reporting | Commercial-collector methods leave `Enterprise` for Integration ingestion. |
| `Signatures`, `Integrity`, `Verification` | Verification and signing | — |
| `Deployments`, `Audit`, `Outbox` | Operations and incidents | Audit and outbox are mandatory cross-cutting transaction effects. |
| `Source` | Integration ingestion | — |
| `Risk` | Vulnerability decisions and governance | Incident methods move to Operations; raw document/diff methods move to Evidence ingestion. |
| `Future` | Experimental peripherals | Split or delete before any stable API commitment. |

Migration ownership below is stewardship of the forward-only schema change,
not a claim that every table touched by an early aggregate migration belongs
to its steward. This makes each current `.up.sql` migration accountable to
exactly one context while preserving existing data and migration history.

| Migration | Steward context |
| --- | --- |
| `20260527000100_initial_ledger`, `20260527000200_runtime_foundation`, `20260528000200_increment_6_15`, `20260528000300_increment_16_25`, `20260528000400_increment_26_35`, `20260528000500_increment_36_45`, `20260528000600_increment_46_55`, `20260528000700_increment_56_65`, `20260528001600_remaining_relational_recovery_columns` | Operations and incidents — historical platform transition. |
| `20260527000300_vex_decisions_exceptions`, `20260528000100_controls_reports`, `20260601000100_vulnerability_decision_customer_fields`, `20260601000200_vulnerability_decision_evidence_ids`, `20260601000300_vex_import_reports`, `20260601000600_vulnerability_decision_review_times`, `20260601000700_vulnerability_decision_sbom_context`, `20260601000800_vulnerability_decision_supporting_refs`, `20260601000900_vex_import_report_failures`, `20260904000100_vulnerability_decision_active_unique`, `20260929000600_vulnerability_decision_query_indexes` | Vulnerability decisions and governance. |
| `20260527000400_collectors_builds_attestations`, `20260528001400_release_core_relational_columns` | Release catalog. |
| `20260815000100_vulnerability_scan_adapter_identity` | Evidence ingestion. |
| `20260528000800_customer_portal_access_counters`, `20260528001500_package_retention_relational_columns`, `20260601000400_customer_portal_nda_answer_library`, `20260601000500_customer_portal_reviewers` | Package and reporting. |
| `20260528001000_signed_incident_webhooks` | Operations and incidents. |
| `20260528001100_static_oidc_jwks`, `20260528001200_saml_provider_certificates`, `20260528001300_sso_trust_material_timestamp`, `20260529000200_sso_session_groups` | Identity and access. |
| `20260528000900_future_extensions_and_partial_closures` | Experimental peripherals. |
| `20260529000100_object_retention_object_key`, `20260531000100_object_retention_legal_hold`, `20260722000100_verification_assurance_taxonomy`, `20260722000200_object_retention_verification_truth`, `20260724000100_audit_chain_integrity_v2`, `20260726000100_provider_signature_receipts`, `20260815000100_dsse_attestation_verification_profiles`, `20260815000200_cosign_verification_receipts`, `20260815000300_signing_operation_canonical_receipts`, `20260815000400_signing_key_lifecycle` | Verification and signing. |
| `20260726000200_idempotency_state_machine`, `20260726000300_idempotency_safe_replay_responses`, `20260727000400_audit_sequences_and_resource_revisions`, `20260727000500_outbox_dead_letter_controls`, `20260728000100_object_payload_lifecycle`, `20260728000200_object_reconciliation_receipts`, `20260728000300_object_reconciliation_receipt_schema_version`, `20260822000100_cursor_pagination_indexes` | Operations and incidents — shared transaction/query platform. |

### Dependency, event, and transaction rules

The only allowed business dependency direction is:

```text
Identity and access ────────► all context entry points (actor and grant checks)
Release catalog ────────────► Evidence ingestion
Evidence ingestion ─────────► Vulnerability decisions and governance
Release catalog + decisions ─► Package and reporting
Evidence/catalog/package ───► Verification and signing
Any committed context event ─► Operations and incidents
Integration ingestion ──────► Release catalog or Evidence ingestion
Experimental peripherals ───► no production context
```

An arrow permits a tenant-scoped ID reference, a read-only query through an
explicit port, or a committed versioned event. It does not permit importing a
foreign aggregate, mutating its repository, or calling back from the target.
Package/report generation reads a committed snapshot and may persist only its
own package/report/receipt record. Verification appends a receipt and cannot
edit the subject it verified. Operations consumes diagnostics and events; it
does not become an alternate business-write path.

The target event vocabulary is `EvidenceAccepted`, `PayloadFinalized`,
`SBOMParsed`, `VulnerabilityScanParsed`, `OpenAPIContractParsed`, `VEXParsed`,
`VulnerabilityDecisionRecorded`, `ReleaseStateChanged`, `PackageGenerated`,
`BundleGenerated`, `VerificationRecorded`, and `IncidentRecorded`. These are
design names, not a claim that a stable event schema already exists. Until the
schema is introduced, the persisted outbox job kinds in the prior table are the
only implementation truth. Every event must contain schema version, event ID,
tenant ID, subject type/ID, occurrence time, causation ID, and canonical
request or subject digest as applicable.

Every command performs its required scope and tenant preflight before opening a
unit of work. Resource coordinates already resolved at that point are also
authorized during preflight. When a uniqueness lookup or concurrent row read
discovers the exact existing resource inside the transaction, the command
revalidates tenant ownership, relationships, and resource authorization against
that transaction-local record before returning it or writing dependent state.
This transaction-local revalidation does not replace the earlier scope
preflight. The owner validates its invariants, writes its data plus the required
audit/idempotency/outbox effects, commits, then publishes. Cross-context effects
are requested by an outbox event after commit. A command requiring an atomic
change to two business owners must be redesigned around one owning record or a
durable saga; it must not create a cross-context repository write.

`Repositories.WorkerProjection` is a temporary read-only compatibility port for
records that an outbox worker may commit after an API process built its local
Ledger read model. A PostgreSQL unit of work binds this port to the same
transaction as the command repositories. The adapter constrains every
projection query by tenant and coordinates a stable snapshot with a per-tenant
advisory fence: standalone read-only refreshes use a repeatable-read transaction
and shared fence, while transaction-bound projection reads, worker projection
mutations, and audit appends use the exclusive fence. Audit append takes the
projection fence before its audit-chain sequencing lock. This prevents a
worker/API mutation from interleaving between a transaction-local projection
read and the command's dependent write or audit append. It protects the legacy
read bridge; it does not replace the EVY-904 decision/package/verification
service split or complete the EVY-905 database-backed query migration. The detailed
runtime contract is in [Worker Outbox Contract](../reference/worker-outbox.md).

The EVY-903 focused command-service migration has exactly three temporary
synchronous cross-context write exceptions. Tenant bootstrap is the first:
the focused Identity service owns tenant and initial API-key preparation and
writes, while the composition adapter invokes Verification-owned initial
signing-key preparation and commit in the same unit of work. This preserves
the existing all-or-nothing bootstrap and bearer-secret issuance contract;
Identity has no signing-key repository capability.

Build-attestation upload is the second exception. The public compatibility
contract atomically creates a release-owned `BuildAttestation` and its
evidence-owned `EvidenceItem`; the attestation repository requires the evidence
identifier to resolve in the same transaction. Splitting the operation during
EVY-903 would either expose a partially created upload, violate ADR 0001, or
require a new saga and API/persistence state model. The focused Release service
therefore receives only a transaction-scoped,
`BuildAttestationEvidenceWriter` capability for this one evidence shape. It
does not receive `EvidenceRepository`, evidence aggregates, or any other
evidence mutation. EVY-906 must replace this bridge with a durable
`BuildAttestationAccepted` ingestion saga (including an explicit pending state
and compatible API transition), then remove the capability before the
architecture boundary check becomes mandatory. No other release command may
use this exception.

Deployment recording is the third exception. Its existing public contract
returns a deployment event whose evidence identifier is immediately readable,
and persistence validates both sides of that deployment/evidence back-reference
inside one transaction. The operations-owned command may therefore create only
the fixed `deployment/event` evidence shape and insert it with the deployment
event in the shared compatibility unit of work. This bridge does not permit an
operations command to accept arbitrary evidence fields or mutate existing
evidence. EVY-906 must replace it with a durable `DeploymentRecorded` ingestion
saga, an explicit pending-evidence state, and a compatible API transition before
the architecture boundary check becomes mandatory. No other operations command
may use this exception.

Go dependency cycles are prohibited. A context domain package may depend only
on standard library and small shared value/event packages. An application
package may depend on its own domain and inward-facing ports. Adapters and
`cmd/*` depend inward only. Neither domain nor application may import HTTP,
PostgreSQL, object-store, worker, or provider adapters. The future
`architecture-check` from EVY-906 will enforce these rules.

### Migration and retirement sequence

Each step is additive and must leave the repository buildable, testable, and
API-compatible.

1. EVY-902 created context-owned packages and adapters/types at the new paths.
   Old `internal/domain` names remain type aliases or compatibility mappers;
   persisted and OpenAPI DTOs remain at adapter boundaries.
2. EVY-903 moved identity, release, and evidence commands to focused services
   and their handlers behind context-specific interfaces. `Ledger` is now a
   deprecated forwarding facade; no new command behaviour is added to it.
3. EVY-904 moves decision, package, and verification workflows, splits mixed
   repository methods, and makes package reads transaction-consistent.
4. EVY-905 installs one composition root and database-backed context query
   services. HTTP and worker wiring then receive only focused services.
   Collector health now reads the tenant-owned collector and latest/pinned
   release records under one PostgreSQL snapshot. Instance-admin counts now
   come from a single aggregate database snapshot guarded by an explicit
   instance scope; other Ledger-compatible reads remain transitional until
   their focused queries are installed.
5. EVY-906 removes production `Ledger` construction and its forwarding
   methods, deletes obsolete aliases only after every caller has moved, and
   makes an import-graph violation fail the build gate.

Schema changes stay forward-only. A context adds new columns/tables and maps
old records before a later release removes obsolete compatibility reads. A
commit moving a route changes its handler, generated OpenAPI ownership,
contract tests, and compatibility notes together. No commit may require a
consumer to import both a new aggregate and its legacy `internal/domain`
implementation.

## Consequences

This decision gives each existing type, operation, repository field, migration,
and worker job a current accountable owner without pretending that the code has
already reached the target package tree. It also makes mixed ports and
experimental surfaces visible technical debt with a removal or graduation path.

EVY-902 and EVY-903 implemented the model boundary and the first three focused
command-service boundaries. Until the later tickets land, `internal/domain`,
the compatibility portions of `internal/app`, and `*app.Ledger` remain
transition paths, not examples for new production dependencies.

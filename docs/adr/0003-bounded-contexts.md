# ADR 0003: Bounded Context Ownership And Dependency Rules

Status: accepted as the incremental transition plan for EVY-902 through
EVY-906. It describes target ownership; it does not claim that the current
`internal/domain` package or `*app.Ledger` facade has already been split.

## Context

The current implementation has useful transaction-scoped repository ports, but
the production model still collects its types in `internal/domain` and much of
its command/query behaviour behind `internal/app.Ledger`. That makes ownership
hard to see and permits accidental broad access to unrelated state.

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

### Context ownership

The type lists are exhaustive for the exported production types currently in
`internal/domain/domain.go`. Supporting types and schema-version constants
belong to the row that owns the resource they support.

| Context | Owns these current domain types | Current implementation and port ownership |
| --- | --- | --- |
| Identity and access | `Actor`, `ResourceGrant`, `Tenant`, `Organization`, `HumanUser`, `RoleBinding`, `SSOProvider`, `UserIdentityLink`, `SSOSession`, `APIKey`, `ProviderVerification` | `identityService`; `IdentityRepository`; identity portions of `EnterpriseRepository` are temporary. |
| Release catalog | `Product`, `Project`, `Release`, `ReleaseEvidenceFlow`, `ReleaseEvidenceFlowStep`, `Artifact`, `BuildRun`, `BuildOutput`, `BuildAttestation`, `ReleaseCandidate`, `ContainerImage` | `Ledger`, `releaseEvidenceService`, and build handling; `ReleaseCatalogRepository`, `BuildRepository`, and `SupplyChainRepository` except artifact-signature writes. |
| Evidence ingestion | `EvidenceItem`, `SubjectRef`, `EvidenceRef`, `EvidenceNotice`, `EvidenceLifecycleEvent`, `SBOM`, `SBOMComponent`, `SBOMComponentRecord`, `VulnerabilityScan`, `VulnerabilityFinding`, `VulnerabilityIdentity`, `VEXDocument`, `VEXImportIssue`, `VEXImportReport`, `VEXImportPreview`, `OpenAPIContract`, `OpenAPIOperation`, `SecurityScan`, `ManualSecurityDocument`, `SBOMDiff`, `DependencyChange`, `ContractDiff` | Ingestion and parser paths in `Ledger`; `EvidenceRepository`, `ObjectPayloadRepository`; the evidence-facing methods of `RiskRepository` are transitional. |
| Vulnerability decisions and governance | `VulnerabilityDecision`, `VulnerabilityDecisionCustomerSummary`, `VulnerabilityDecisionSummaryReport`, `Exception`, `PolicyEvaluation`, `PolicyCheck`, `CustomPolicy`, `PolicyRule`, `CustomPolicyEvaluation`, `Waiver`, `ApprovalRecord`, `ControlFramework`, `SecurityControl`, `ControlEvidenceRequirement`, `ControlEvidence`, `ControlFrameworkTemplatePack`, `VulnerabilityWorkflowRecord`, `ReleaseSecuritySummary`, `ReleaseSecurityProductSummary`, `ReleaseSecurityReleaseSummary`, `ReleaseSecurityMissingDecision`, `ReleaseSecurityApprovalSummary`, `ReleaseSecurityExceptionSummary` | `vex.go`, governance paths, and policy paths; `DecisionRepository`, `ControlRepository`, and the decision methods of `GovernanceRepository` and `RiskRepository`. |
| Package and reporting | `CustomerPortalAccess`, `QuestionnaireTemplate`, `QuestionnaireQuestion`, `QuestionnairePackage`, `QuestionnaireResponse`, `QuestionnaireAnswerLibraryEntry`, `RedactionProfile`, `CustomerSecurityPackage`, `SecurityReviewPackageReport`, `HTMLReportPackage`, `PDFReportPackage`, `CustomReportTemplate`, `RenderedCustomReport`, `EvidenceBundle`, `EvidenceBundleImport`, `ReleaseBundle`, `EvidenceCitation`, `EvidenceSummary`, `QuestionnaireDraft`, `GraphNode`, `GraphEdge`, `EvidenceGraphSnapshot`, `ControlCoverageReport`, `ControlCoverageItem`, `CRAReadinessReport`, `CRAVulnerabilityHandlingReport`, `SecurityUpdateEvidenceReport`, `ReleaseReadinessReport`, `ReadinessSummary`, `ReadinessSection`, `ReadinessQuestion`, `BlockingFinding`, `IncidentReport`, `VulnerabilityPostureReport` | `packageReportService` and package/report portions of `enterprise.go`, `governance_packages.go`, and `risk_workflows.go`; `PackageRepository`. |
| Verification and signing | `AuditChainEntry`, `SigningKey`, `SigningProvider`, `Signature`, `ArtifactSignature`, `CosignVerification`, `MerkleBatch`, `TransparencyCheckpoint`, `ObjectRetentionPolicy`, `SigningCustodyReviewReport`, `BackupManifest`, `DSSETrustRoot`, `SigningOperation`, `VerificationResult`, `VerifyCheck` | `integrity_runtime.go`, audit-chain and verification paths; `SignatureRepository`, `IntegrityRepository`, and `VerificationRepository`. Audit append is a required transaction side effect, not an authority to change another context's record. |
| Operations and incidents | `InstanceAdminSnapshot`, `LegalHold`, `RetentionOverride`, `RetentionReport`, `DeploymentEnvironment`, `DeploymentEvent`, `Incident`, `IncidentTimelineEvent`, `IncidentWebhookReceiver`, `IncidentWebhookEvent`, `RemediationTask` | `risk_workflows.go`, runtime/readiness, outbox administration and object reconciliation; `DeploymentRepository`. `AuditRepository`, `IdempotencyRepository`, and `OutboxRepository` are platform services owned here and used inside the caller's unit of work. |
| Integration ingestion | `Collector`, `CollectorRelease`, `CollectorHealthReport`, `SourceRepository`, `SourceCommit`, `SourceBranch`, `PullRequest`, `CommercialCollectorDefinition` | Collector, source-snapshot, and commercial-collector paths; `SourceRepository` and the collector methods of `BuildRepository`. |
| Experimental peripherals | `SaaSEditionProfile`, `PublicTransparencyLog`, `PublicTransparencyLogEntry`, `MarketplaceCollector`, `MarketplaceCollectorHealthReport`, `AnomalySignal`, `AnomalyReport` | `FutureExtensionsRepository` is a temporary quarantine port. These surfaces remain experimental until a named owning context accepts them; no new production dependency may target this port. |

`GovernanceRepository`, `RiskRepository`, `EnterpriseRepository`, and
`FutureExtensionsRepository` are explicitly transitional mixed ports. Their
row above assigns one accountable owner today, while the named exception
methods move to their target context in EVY-903 and EVY-904. No new method may
be added to a mixed port.

### Public operations and internal work

`docs/reference/api-inventory.md` is the generated, exhaustive current
operation inventory. It contains 189 operations, each with one OpenAPI
`Owner` value. This table maps every possible current owner value to exactly
one target context; it is the route and public command/query assignment until
the generated OpenAPI owner labels are changed atomically with their handlers.

| Current OpenAPI owner (operation count) | Target context | Transition rule |
| --- | --- | --- |
| `identity-access` (15) | Identity and access | Direct mapping. |
| `release-ledger` (63) | Release catalog, Evidence ingestion, Vulnerability decisions and governance, or Package and reporting | Transitional aggregate label. Catalog resources (`products`, `projects`, `releases`, `artifacts`, `builds`, `release-candidates`, and `container-images`) go to Release catalog; evidence and document resources go to Evidence ingestion; decision/policy resources go to Vulnerability decisions and governance; bundle, summary, graph, and report resources go to Package and reporting. The route's resource, not the old label, selects the service. |
| `integration-ingestion` (17) | Integration ingestion | Direct mapping. |
| `governance` (25) | Vulnerability decisions and governance | Direct mapping, except redaction and customer-package rendering, which move to Package and reporting. |
| `customer-delivery` (12) | Package and reporting | Direct mapping. |
| `reporting` (17) | Package and reporting | Direct mapping. |
| `integrity-verification` (22) | Verification and signing | Direct mapping. |
| `operations-incidents` (9) | Operations and incidents | Direct mapping. |
| `platform-operations` (9) | Operations and incidents | Direct mapping. |

The table above is intentionally a mapping, not a second handwritten route
catalog. The generated inventory remains the source of individual operation
IDs, paths, methods, auth, idempotency, and current labels. Its nine counts
sum to 189. EVY-903 through EVY-905 must update a route's OpenAPI owner and
handler in the same compatible change; no handler may be silently re-owned.

Current non-HTTP commands and queries are assigned by the same owner rule:

| Current source surface | Owner | Required split outcome |
| --- | --- | --- |
| `internal/app/identity_service.go` and identity operations in `enterprise.go` | Identity and access | Focused identity service. |
| `internal/app/ledger.go`, `release_evidence_service.go`, and build paths | Release catalog and Evidence ingestion | Two focused services; the old facade only forwards during migration. |
| `internal/app/vex.go`, document parsers, object ingestion, and reconciliation | Evidence ingestion, with decision effects emitted after commit | Parsing owns normalized evidence; decision creation is a separate decision command. |
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
| `20260527000300_vex_decisions_exceptions`, `20260528000100_controls_reports`, `20260601000100_vulnerability_decision_customer_fields`, `20260601000200_vulnerability_decision_evidence_ids`, `20260601000300_vex_import_reports`, `20260601000600_vulnerability_decision_review_times`, `20260601000700_vulnerability_decision_sbom_context`, `20260601000800_vulnerability_decision_supporting_refs`, `20260601000900_vex_import_report_failures` | Vulnerability decisions and governance. |
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

For every command, authorization and tenant validation occur before the unit
of work. The owner validates its invariants, writes its data plus the required
audit/idempotency/outbox effects, commits, then publishes. Cross-context
effects are requested by an outbox event after commit. A command requiring an
atomic change to two business owners must be redesigned around one owning
record or a durable saga; it must not create a cross-context repository write.

Go dependency cycles are prohibited. A context domain package may depend only
on standard library and small shared value/event packages. An application
package may depend on its own domain and inward-facing ports. Adapters and
`cmd/*` depend inward only. Neither domain nor application may import HTTP,
PostgreSQL, object-store, worker, or provider adapters. The future
`architecture-check` from EVY-906 will enforce these rules.

### Migration and retirement sequence

Each step is additive and must leave the repository buildable, testable, and
API-compatible.

1. EVY-902 creates context-owned packages and adapters/types at the new paths.
   Old `internal/domain` names remain type aliases or compatibility mappers;
   persisted and OpenAPI DTOs remain at adapter boundaries.
2. EVY-903 moves identity, release, and evidence commands to focused services.
   `Ledger` becomes a deprecated forwarding facade; no new behaviour is added
   to it.
3. EVY-904 moves decision, package, and verification workflows, splits mixed
   repository methods, and makes package reads transaction-consistent.
4. EVY-905 installs one composition root and database-backed context query
   services. HTTP and worker wiring then receive only focused services.
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

The first implementation work is EVY-902. Until the later tickets land,
`internal/domain`, `internal/app`, and `*app.Ledger` remain transition paths,
not examples for new production dependencies.

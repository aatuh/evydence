package domain

const ContractDiffSchemaVersion = "contract-diff.v1.0.0"
const DependencyChangeSchemaVersion = "dependency-change.v1.0.0"
const EvidenceItemSchemaVersion = "evidence-item.v1.0.0"
const LegacyEvidenceCanonicalizationProfileVersion = "canonicalization-profile.v1.0.0"
const LegacyCanonicalOriginDetailKey = "evydence_canonical_origin_v1"

// EvidenceCanonicalizationProfileVersion hashes immutable evidence content and
// origin subject references while relationship projections remain append-only
// audited metadata outside the signed/hash-bound core.
const EvidenceCanonicalizationProfileVersion = "evidence-canonicalization-profile.v2.0.0"
const EvidenceLifecycleSchemaVersion = "evidence-lifecycle-event.v1.0.0"
const EvidenceRelationshipLifecycleSchemaVersion = "evidence-relationship-lifecycle-event.v2.0.0"
const ManualSecurityDocSchemaVersion = "manual-security-document.v1.0.0"
const SBOMDiffSchemaVersion = "sbom-diff.v1.0.0"
const SecurityScanSchemaVersion = "security-scan.v1.0.0"
const VEXDocumentSchemaVersion = "vex-document.v1.0.0"
const VEXImportPreviewSchemaVersion = "vex-import-preview.v1.0.0"
const VEXImportReportSchemaVersion = "vex-import-report.v1.0.0"

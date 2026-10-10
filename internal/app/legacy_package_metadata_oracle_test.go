package app

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Unchanged aggregate metadata builders are retained only for historical tests.
func redactionProfileToPackageContext(value domain.RedactionProfile) packagedomain.RedactionProfile {
	return packagedomain.RedactionProfile{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Description: value.Description,
		AllowedTypes: append([]string(nil), value.AllowedTypes...), ExcludedFields: append([]string(nil), value.ExcludedFields...),
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func (l *Ledger) packageTenantMetadataLocked(tenantID string) map[string]any {
	tenant := l.tenants[tenantID]
	return map[string]any{"id": tenant.ID, "name": tenant.Name}
}

func (l *Ledger) packageOrganizationMetadataLocked(tenantID string) map[string]any {
	organizations := []map[string]any{}
	for _, organization := range l.organizations {
		if organization.TenantID != tenantID {
			continue
		}
		organizations = append(organizations, map[string]any{
			"id":      organization.ID,
			"name":    organization.Name,
			"slug":    organization.Slug,
			"status":  organization.Status,
			"created": organization.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(organizations, func(i, j int) bool { return organizations[i]["id"].(string) < organizations[j]["id"].(string) })
	return map[string]any{
		"records": organizations,
		"limitations": []string{
			"Organization records are included only as tenant metadata; product-to-organization ownership is not inferred by this package schema.",
		},
	}
}

func packageProductMetadata(product domain.Product) map[string]any {
	if product.ID == "" {
		return map[string]any{}
	}
	return map[string]any{
		"id":         product.ID,
		"name":       product.Name,
		"slug":       product.Slug,
		"created_at": product.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func packageReleaseMetadata(release domain.Release) map[string]any {
	if release.ID == "" {
		return map[string]any{}
	}
	out := map[string]any{
		"id":         release.ID,
		"product_id": release.ProductID,
		"version":    release.Version,
		"state":      release.State,
		"created_at": release.CreatedAt.UTC().Format(time.RFC3339),
	}
	if release.FrozenAt != nil {
		out["frozen_at"] = release.FrozenAt.UTC().Format(time.RFC3339)
	}
	if release.ApprovedAt != nil {
		out["approved_at"] = release.ApprovedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func (l *Ledger) packageArtifactMetadataLocked(tenantID, releaseID string) []map[string]any {
	ids := l.packageReleaseArtifactIDsLocked(tenantID, releaseID)
	out := []map[string]any{}
	for _, id := range ids {
		artifact := l.artifacts[id]
		out = append(out, map[string]any{
			"id":         artifact.ID,
			"name":       artifact.Name,
			"media_type": artifact.MediaType,
			"size":       artifact.Size,
			"digest":     artifact.Digest,
			"created_at": artifact.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	return out
}

func (l *Ledger) packageReleaseArtifactIDsLocked(tenantID, releaseID string) []string {
	ids := map[string]bool{}
	if releaseID == "" {
		return nil
	}
	for _, item := range l.evidence {
		if item.TenantID != tenantID || item.ReleaseID != releaseID {
			continue
		}
		for _, ref := range item.SubjectRefs {
			if ref.Type == "artifact" && ref.ID != "" {
				ids[ref.ID] = true
			}
		}
	}
	for _, sbom := range l.sboms {
		if sbom.TenantID == tenantID && sbom.ReleaseID == releaseID && sbom.ArtifactID != "" {
			ids[sbom.ArtifactID] = true
		}
	}
	for _, vex := range l.vexDocuments {
		if vex.TenantID == tenantID && vex.ReleaseID == releaseID && vex.ArtifactID != "" {
			ids[vex.ArtifactID] = true
		}
	}
	for _, build := range l.buildRuns {
		if build.TenantID != tenantID || build.ReleaseID != releaseID {
			continue
		}
		for _, output := range build.Outputs {
			if output.ArtifactID != "" {
				ids[output.ArtifactID] = true
			}
		}
	}
	return sortedStringSet(ids)
}

func (l *Ledger) packageSBOMMetadataLocked(tenantID, releaseID string) []map[string]any {
	out := []map[string]any{}
	for _, sbom := range l.sboms {
		if sbom.TenantID != tenantID || sbom.ReleaseID != releaseID {
			continue
		}
		out = append(out, map[string]any{
			"id":              sbom.ID,
			"evidence_id":     sbom.EvidenceID,
			"release_id":      sbom.ReleaseID,
			"artifact_id":     sbom.ArtifactID,
			"format":          sbom.Format,
			"spec_version":    sbom.SpecVersion,
			"component_count": sbom.ComponentCount,
			"created_at":      sbom.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	sortManifestMapsByID(out)
	return out
}

func (l *Ledger) packageVulnerabilityScanMetadataLocked(tenantID, releaseID string) []map[string]any {
	out := []map[string]any{}
	for _, scan := range l.scans {
		if scan.TenantID != tenantID || scan.ReleaseID != releaseID {
			continue
		}
		out = append(out, map[string]any{
			"id":            scan.ID,
			"evidence_id":   scan.EvidenceID,
			"release_id":    scan.ReleaseID,
			"scanner":       scan.Scanner,
			"target_ref":    scan.TargetRef,
			"summary":       cloneIntMap(scan.Summary),
			"finding_count": len(scan.Findings),
			"created_at":    scan.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	sortManifestMapsByID(out)
	return out
}

func (l *Ledger) packageVEXMetadataLocked(tenantID, releaseID string) []map[string]any {
	out := []map[string]any{}
	for _, vex := range l.vexDocuments {
		if vex.TenantID != tenantID || vex.ReleaseID != releaseID {
			continue
		}
		out = append(out, map[string]any{
			"id":              vex.ID,
			"evidence_id":     vex.EvidenceID,
			"release_id":      vex.ReleaseID,
			"artifact_id":     vex.ArtifactID,
			"format":          vex.Format,
			"version":         vex.Version,
			"statement_count": vex.StatementCount,
			"status_summary":  cloneIntMap(vex.StatusSummary),
			"schema_version":  vex.SchemaVersion,
			"created_at":      vex.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	sortManifestMapsByID(out)
	return out
}

func (l *Ledger) packageAPIContractMetadataLocked(tenantID, releaseID string) map[string]any {
	contracts := []map[string]any{}
	for _, contract := range l.contracts {
		if contract.TenantID != tenantID || contract.ReleaseID != releaseID {
			continue
		}
		contracts = append(contracts, map[string]any{
			"id":              contract.ID,
			"evidence_id":     contract.EvidenceID,
			"product_id":      contract.ProductID,
			"release_id":      contract.ReleaseID,
			"version":         contract.Version,
			"hash":            contract.Hash,
			"path_count":      contract.PathCount,
			"operation_count": len(contract.Operations),
			"operations":      packageOpenAPIOperations(contract.Operations),
			"created_at":      contract.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	sortManifestMapsByID(contracts)
	diffs := []map[string]any{}
	for _, diff := range l.contractDiffs {
		if diff.TenantID != tenantID || diff.ReleaseID != releaseID {
			continue
		}
		diffs = append(diffs, map[string]any{
			"id":                   diff.ID,
			"base_contract_id":     diff.BaseContractID,
			"target_contract_id":   diff.TargetContractID,
			"product_id":           diff.ProductID,
			"release_id":           diff.ReleaseID,
			"result":               diff.Result,
			"breaking_changes":     append([]string(nil), diff.BreakingChanges...),
			"non_breaking_changes": append([]string(nil), diff.NonBreakingChanges...),
			"schema_version":       diff.SchemaVersion,
			"created_at":           diff.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	sortManifestMapsByID(diffs)
	return map[string]any{
		"openapi_contracts": contracts,
		"contract_diffs":    diffs,
		"limitations": []string{
			"OpenAPI contract evidence includes stored metadata, hashes, and normalized operation summaries only.",
			"Raw OpenAPI document bytes, object-store payload references, and private/internal extensions are not included.",
			"Diff results summarize recorded contract evidence and do not make this package an API governance approval.",
		},
	}
}

func packageOpenAPIOperations(operations []domain.OpenAPIOperation) []map[string]any {
	inputs := make([]packageapp.CustomerPackageAPIOperation, 0, len(operations))
	for _, operation := range operations {
		inputs = append(inputs, packageapp.CustomerPackageAPIOperation{
			Path: operation.Path, Method: operation.Method, OperationID: operation.OperationID,
			Deprecated: operation.Deprecated, RequestBodyRequired: operation.RequestBodyRequired,
			RequiredRequestFields: operation.RequiredRequestFields, ResponseStatuses: operation.ResponseStatuses,
		})
	}
	return packageapp.CustomerPackageOperationSummaries(inputs)
}

func (l *Ledger) packageApprovalSummariesLocked(tenantID, productID, releaseID string) []map[string]any {
	out := []map[string]any{}
	for _, approval := range l.approvals {
		if approval.TenantID != tenantID || !approvalBelongsToPackage(approval, productID, releaseID) {
			continue
		}
		out = append(out, map[string]any{
			"id":           approval.ID,
			"subject_type": approval.SubjectType,
			"subject_id":   approval.SubjectID,
			"decision":     approval.Decision,
			"reason":       approval.Reason,
			"evidence_id":  approval.EvidenceID,
			"created_at":   approval.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	sortManifestMapsByID(out)
	return out
}

func approvalBelongsToPackage(approval domain.ApprovalRecord, productID, releaseID string) bool {
	switch approval.SubjectType {
	case "release":
		return releaseID != "" && approval.SubjectID == releaseID
	case "product":
		return approval.SubjectID == productID
	default:
		return false
	}
}

func (l *Ledger) packageExceptionSummariesLocked(tenantID, releaseID string) []map[string]any {
	out := []map[string]any{}
	now := l.now()
	for _, exception := range l.exceptions {
		if exception.TenantID != tenantID || exception.ReleaseID != releaseID || !exception.Approved || !exception.ExpiresAt.After(now) {
			continue
		}
		summary := map[string]any{
			"id":         exception.ID,
			"release_id": exception.ReleaseID,
			"finding_id": exception.FindingID,
			"control_id": exception.ControlID,
			"reason":     exception.Reason,
			"owner":      exception.Owner,
			"expires_at": exception.ExpiresAt.UTC().Format(time.RFC3339),
			"approved":   exception.Approved,
			"created_at": exception.CreatedAt.UTC().Format(time.RFC3339),
		}
		if exception.ApprovedAt != nil {
			summary["approved_at"] = exception.ApprovedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, summary)
	}
	sortManifestMapsByID(out)
	return out
}

func (l *Ledger) packageWaiverSummariesLocked(tenantID, productID, releaseID string) []map[string]any {
	out := []map[string]any{}
	now := l.now()
	for _, waiver := range l.waivers {
		if waiver.TenantID != tenantID || !waiver.Approved || !waiver.ExpiresAt.After(now) || !waiverBelongsToPackage(waiver, productID, releaseID) {
			continue
		}
		summary := map[string]any{
			"id":         waiver.ID,
			"scope_type": waiver.ScopeType,
			"scope_id":   waiver.ScopeID,
			"control_id": waiver.ControlID,
			"policy_id":  waiver.PolicyID,
			"owner":      waiver.Owner,
			"risk":       waiver.Risk,
			"reason":     waiver.Reason,
			"expires_at": waiver.ExpiresAt.UTC().Format(time.RFC3339),
			"approved":   waiver.Approved,
			"created_at": waiver.CreatedAt.UTC().Format(time.RFC3339),
		}
		if waiver.ApprovedAt != nil {
			summary["approved_at"] = waiver.ApprovedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, summary)
	}
	sortManifestMapsByID(out)
	return out
}

func (l *Ledger) packageAnswerLibraryMetadataLocked(tenantID, productID, releaseID string) []map[string]any {
	out := []map[string]any{}
	for _, entry := range l.answerLibrary {
		if entry.TenantID != tenantID {
			continue
		}
		if entry.ProductID != "" && entry.ProductID != productID {
			continue
		}
		if entry.ReleaseID != "" && entry.ReleaseID != releaseID {
			continue
		}
		out = append(out, map[string]any{
			"id":            entry.ID,
			"question_id":   entry.QuestionID,
			"evidence_type": entry.EvidenceType,
			"control_id":    entry.ControlID,
			"product_id":    entry.ProductID,
			"release_id":    entry.ReleaseID,
			"answer":        entry.Answer,
			"evidence_ids":  append([]string(nil), entry.EvidenceIDs...),
			"limitations":   append([]string(nil), entry.Limitations...),
			"created_at":    entry.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	sortManifestMapsByID(out)
	return out
}

func (l *Ledger) packageObjectLockProofsLocked(tenantID string) []map[string]any {
	policies := make([]verificationdomain.ObjectRetentionPolicy, 0)
	for _, policy := range l.retentionPolicies {
		if policy.TenantID != tenantID {
			continue
		}
		policies = append(policies, objectRetentionPolicyToVerificationContext(policy))
	}
	return verificationapp.ObjectLockProofs(policies, l.now())
}

func packageVerifyChecks(checks []domain.VerifyCheck) []map[string]any {
	values := make([]packageapp.CustomerPackageVerificationCheck, 0, len(checks))
	for _, check := range checks {
		values = append(values, packageapp.CustomerPackageVerificationCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
	}
	return packageapp.CustomerPackageVerificationCheckSummaries(values)
}

func (l *Ledger) packageProvenanceMetadataLocked(tenantID, releaseID string, profile domain.RedactionProfile) map[string]any {
	builds := []map[string]any{}
	buildIDs := map[string]bool{}
	if profileAllowsPackageType(profile, "build") {
		for _, build := range l.buildRuns {
			if build.TenantID != tenantID || build.ReleaseID != releaseID {
				continue
			}
			buildIDs[build.ID] = true
			builds = append(builds, map[string]any{
				"id":               build.ID,
				"project_id":       build.ProjectID,
				"collector_id":     build.CollectorID,
				"provider":         build.Provider,
				"commit_sha":       build.CommitSHA,
				"repository":       build.Repository,
				"workflow_ref":     build.WorkflowRef,
				"run_id":           build.RunID,
				"run_attempt":      build.RunAttempt,
				"status":           build.Status,
				"started_at":       build.StartedAt.UTC().Format(time.RFC3339),
				"finished_at":      packageOptionalTime(build.FinishedAt),
				"parameters_hash":  build.ParametersHash,
				"environment_hash": build.EnvironmentHash,
				"outputs":          packageBuildOutputs(build.Outputs),
				"schema_version":   build.SchemaVersion,
				"created_at":       build.CreatedAt.UTC().Format(time.RFC3339),
			})
		}
	}
	sortManifestMapsByID(builds)
	attestations := []map[string]any{}
	if profileAllowsPackageType(profile, "build_attestation") {
		for _, attestation := range l.attestations {
			if attestation.TenantID != tenantID || !buildIDs[attestation.BuildID] {
				continue
			}
			attestations = append(attestations, map[string]any{
				"id":                  attestation.ID,
				"build_id":            attestation.BuildID,
				"evidence_id":         attestation.EvidenceID,
				"payload_hash":        attestation.PayloadHash,
				"payload_size":        attestation.PayloadSize,
				"payload_type":        attestation.PayloadType,
				"predicate_type":      attestation.PredicateType,
				"subject_digests":     append([]string(nil), attestation.SubjectDigests...),
				"signature_count":     attestation.SignatureCount,
				"verification_status": attestation.VerificationStatus,
				"schema_version":      attestation.SchemaVersion,
				"created_at":          attestation.CreatedAt.UTC().Format(time.RFC3339),
			})
		}
	}
	sortManifestMapsByID(attestations)
	return map[string]any{"builds": builds, "build_attestations": attestations}
}

func packageBuildOutputs(outputs []domain.BuildOutput) []map[string]any {
	values := make([]packageapp.CustomerPackageBuildOutput, 0, len(outputs))
	for _, output := range outputs {
		values = append(values, packageapp.CustomerPackageBuildOutput{ArtifactID: output.ArtifactID, Digest: output.Digest})
	}
	return packageapp.CustomerPackageBuildOutputSummaries(values)
}

func packageOptionalTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func (l *Ledger) packageVerificationMaterialLocked(tenantID, releaseID string) map[string]any {
	releaseArtifactIDs := map[string]bool{}
	for _, artifactID := range l.packageReleaseArtifactIDsLocked(tenantID, releaseID) {
		releaseArtifactIDs[artifactID] = true
	}
	bundles := []map[string]any{}
	for _, bundle := range l.bundles {
		if bundle.TenantID != tenantID || bundle.ReleaseID != releaseID {
			continue
		}
		bundles = append(bundles, map[string]any{
			"id":             bundle.ID,
			"state":          bundle.State,
			"manifest_hash":  bundle.ManifestHash,
			"signature_refs": append([]string(nil), bundle.SignatureRefs...),
			"created_at":     bundle.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	sortManifestMapsByID(bundles)
	results := []map[string]any{}
	for _, verification := range l.verifications {
		if verification.TenantID != tenantID || !l.verificationMatchesReleaseLocked(verification, releaseID, releaseArtifactIDs) {
			continue
		}
		results = append(results, map[string]any{
			"id":             verification.ID,
			"subject_type":   verification.SubjectType,
			"subject_id":     verification.SubjectID,
			"result":         verification.Result,
			"checks":         packageVerifyChecks(verification.Checks),
			"profile":        verification.Profile,
			"limitations":    append([]string(nil), verification.Limitations...),
			"schema_version": verification.SchemaVersion,
			"verified_at":    verification.VerifiedAt.UTC().Format(time.RFC3339),
		})
	}
	sortManifestMapsByID(results)
	cosignAssessments := []map[string]any{}
	for _, verification := range l.cosignVerifs {
		artifact, ok := l.artifacts[verification.ArtifactID]
		if !ok || artifact.TenantID != tenantID || !releaseArtifactIDs[artifact.ID] {
			continue
		}
		cosignAssessments = append(cosignAssessments, map[string]any{
			"id":             verification.ID,
			"artifact_id":    verification.ArtifactID,
			"result":         verification.Result,
			"checks":         packageVerifyChecks(verification.Checks),
			"profile":        verification.Profile,
			"limitations":    append([]string(nil), verification.Limitations...),
			"schema_version": verification.SchemaVersion,
			"created_at":     verification.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	sortManifestMapsByID(cosignAssessments)
	return map[string]any{
		"hash_algorithm":       "sha256",
		"canonicalization":     domain.CanonicalizationProfileVersion,
		"manifest_hash_field":  "manifest_hash",
		"release_bundles":      bundles,
		"verification_results": results,
		"cosign_assessments":   cosignAssessments,
		"audit_chain":          l.packageAuditChainSummaryLocked(tenantID),
	}
}

func (l *Ledger) verificationMatchesReleaseLocked(verification domain.VerificationResult, releaseID string, releaseArtifactIDs map[string]bool) bool {
	switch verification.SubjectType {
	case "release_bundle":
		bundle, ok := l.bundles[verification.SubjectID]
		return ok && bundle.ReleaseID == releaseID
	case "evidence_item":
		item, ok := l.evidence[verification.SubjectID]
		return ok && item.ReleaseID == releaseID
	case "artifact_signature":
		signature, ok := l.artifactSigs[verification.SubjectID]
		if !ok {
			return false
		}
		artifact, ok := l.artifacts[signature.ArtifactID]
		return ok && releaseArtifactIDs[artifact.ID]
	case "build_attestation":
		attestation, ok := l.attestations[verification.SubjectID]
		if !ok {
			return false
		}
		build, ok := l.buildRuns[attestation.BuildID]
		return ok && build.ReleaseID == releaseID
	default:
		return false
	}
}

func (l *Ledger) packageAuditChainSummaryLocked(tenantID string) map[string]any {
	checks := l.verifyChainLocked(tenantID)
	result := "passed"
	for _, check := range checks {
		if check.Result == "failed" {
			result = "failed"
			break
		}
	}
	entries := l.chain[tenantID]
	head := ""
	if len(entries) > 0 {
		head = entries[len(entries)-1].EntryHash
	}
	return map[string]any{
		"result":          result,
		"latest_sequence": len(entries),
		"head_hash":       head,
		// Customer packages intentionally expose the aggregate integrity state,
		// not internal audit verification check names or entry identifiers.
		"checks": []map[string]any{{"name": "audit_chain_integrity", "result": result}},
	}
}

func sortedStringSet(in map[string]bool) []string {
	out := make([]string, 0, len(in))
	for value := range in {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func sortManifestMapsByID(items []map[string]any) {
	sort.Slice(items, func(i, j int) bool {
		left, _ := items[i]["id"].(string)
		right, _ := items[j]["id"].(string)
		return left < right
	})
}

func cleanExternalLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	runes := make([]rune, 0, len(value))
	for _, r := range value {
		if r < 32 || r == 127 {
			continue
		}
		runes = append(runes, r)
		if len(runes) >= 160 {
			break
		}
	}
	return strings.TrimSpace(string(runes))
}

func (l *Ledger) ListControlFrameworkTemplatePacks(ctx context.Context, actor domain.Actor) ([]domain.ControlFrameworkTemplatePack, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeControlsRead); err != nil {
		return nil, err
	}
	return builtinTemplatePacks(), nil
}

func (l *Ledger) packageDecisionSummariesLocked(tenantID, releaseID string, profile domain.RedactionProfile) []map[string]any {
	if !profileAllowsPackageType(profile, "vulnerability_decision") {
		return nil
	}
	values := []packagedomain.VulnerabilityDecisionSnapshot{}
	for _, decision := range l.decisions {
		if decision.TenantID != tenantID || decision.ReleaseID != releaseID || decision.SupersededBy != "" || !decision.CustomerVisible {
			continue
		}
		value := packagedomain.VulnerabilityDecisionSnapshot{
			ID: decision.ID, FindingID: decision.FindingID, ScanID: decision.ScanID, ReleaseID: decision.ReleaseID,
			Vulnerability: decision.Vulnerability, Component: decision.Component, SBOMID: decision.SBOMID,
			SBOMComponentPURL: decision.SBOMComponentPURL, SBOMComponentName: decision.SBOMComponentName,
			Status: string(decision.Status), Justification: decision.Justification, ImpactStatement: decision.ImpactStatement,
			ActionStatement: decision.ActionStatement, Source: decision.Source, EvidenceID: decision.EvidenceID,
			EvidenceIDs: decision.EvidenceIDs, VEXDocumentID: decision.VEXDocumentID,
			ReviewedAt: decision.ReviewedAt, ReviewDueAt: decision.ReviewDueAt, CreatedAt: decision.CreatedAt,
		}
		for _, ref := range decision.SupportingRefs {
			value.SupportingRefs = append(value.SupportingRefs, packagedomain.SupportingReference{Type: ref.Type, ID: ref.ID, Digest: ref.Digest})
		}
		values = append(values, value)
	}
	return packageapp.CustomerPackageDecisionSummaries(values, redactionProfileToPackageContext(profile))
}

func profileAllowsPackageType(profile domain.RedactionProfile, typ string) bool {
	for _, allowed := range profile.AllowedTypes {
		if strings.TrimSpace(allowed) == typ {
			return true
		}
	}
	return false
}

func builtinTemplatePacks() []domain.ControlFrameworkTemplatePack {
	owned := riskdomain.BuiltinTemplatePacks()
	packs := make([]domain.ControlFrameworkTemplatePack, 0, len(owned))
	for _, pack := range owned {
		converted := domain.ControlFrameworkTemplatePack{ID: pack.ID, Name: pack.Name, Slug: pack.Slug, Version: pack.Version, Description: pack.Description, SchemaVersion: pack.SchemaVersion}
		for _, control := range pack.Controls {
			item := domain.SecurityControl{ID: control.ID, TenantID: control.TenantID, FrameworkID: control.FrameworkID, Code: control.Code, Title: control.Title, Objective: control.Objective, Applicability: append([]string(nil), control.Applicability...), Limitations: append([]string(nil), control.Limitations...), SchemaVersion: control.SchemaVersion, CreatedAt: control.CreatedAt}
			for _, requirement := range control.EvidenceRequirements {
				item.EvidenceRequirements = append(item.EvidenceRequirements, domain.ControlEvidenceRequirement{Type: requirement.Type, FreshnessDays: requirement.FreshnessDays, Required: requirement.Required})
			}
			converted.Controls = append(converted.Controls, item)
		}
		packs = append(packs, converted)
	}
	return packs
}

func validWaiverScope(scope string) bool {
	switch scope {
	case "release", "finding", "control", "policy":
		return true
	default:
		return false
	}
}

func validApprovalSubject(subject string) bool {
	switch subject {
	case "release", "contract_diff", "waiver", "security_review", "customer_package":
		return true
	default:
		return false
	}
}

func validApprovalDecision(decision string) bool {
	switch decision {
	case "approved", "rejected":
		return true
	default:
		return false
	}
}

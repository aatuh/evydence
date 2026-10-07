package app

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type CreateWaiverInput struct {
	ScopeType  string
	ScopeID    string
	ControlID  string
	PolicyID   string
	Owner      string
	Risk       string
	Reason     string
	ExpiresAt  time.Time
	Supersedes string
}

type CreateApprovalInput struct {
	SubjectType string
	SubjectID   string
	Decision    string
	Reason      string
	EvidenceID  string
}

type CreateRedactionProfileInput struct {
	Name           string
	Description    string
	Preset         string
	AllowedTypes   []string
	ExcludedFields []string
}

type CreateCustomerPackageInput struct {
	ProductID          string
	ReleaseID          string
	RedactionProfileID string
	Title              string
	ExpiresAt          time.Time
}

type CustomerPackageArchive struct {
	PackageID string
	Filename  string
	MediaType string
	Bytes     []byte
	Hash      string
	Size      int64
}

const (
	customerDecisionExportFile    = "vulnerability-decisions.json"
	customerDecisionExportVersion = "customer-vulnerability-decisions.v1.0.0"
)

type CreateReportTemplateInput struct {
	Name          string
	Version       string
	ReportType    string
	AllowedFields []string
	Template      string
}

type RenderReportInput struct {
	TemplateID  string
	SubjectType string
	SubjectID   string
}

type CreateDSSETrustRootInput struct {
	Name                  string
	KeyID                 string
	Algorithm             string
	PublicKey             string
	AllowedPredicateTypes []string
	ExpectedBuilderIDs    []string
	RequiredClaims        []string
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

func waiverBelongsToPackage(waiver domain.Waiver, productID, releaseID string) bool {
	switch waiver.ScopeType {
	case "release":
		return releaseID != "" && waiver.ScopeID == releaseID
	case "product":
		return waiver.ScopeID == productID
	default:
		return false
	}
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

func cloneIntMap(in map[string]int) map[string]int {
	if len(in) == 0 {
		return map[string]int{}
	}
	out := make(map[string]int, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func sortManifestMapsByID(items []map[string]any) {
	sort.Slice(items, func(i, j int) bool {
		left, _ := items[i]["id"].(string)
		right, _ := items[j]["id"].(string)
		return left < right
	})
}

func (l *Ledger) ExportCustomerSecurityPackageArchive(ctx context.Context, actor domain.Actor, id string) (CustomerPackageArchive, error) {
	pkg, err := l.AccessCustomerSecurityPackage(ctx, actor, id)
	if err != nil {
		return CustomerPackageArchive{}, err
	}
	return customerPackageArchive(pkg)
}

func (l *Ledger) ExportCustomerPortalPackageArchive(ctx context.Context, token string) (CustomerPackageArchive, error) {
	return l.ExportCustomerPortalPackageArchiveWithAcceptance(ctx, token, CustomerPortalAcceptanceInput{})
}

func (l *Ledger) ExportCustomerPortalPackageArchiveWithAcceptance(ctx context.Context, token string, in CustomerPortalAcceptanceInput) (CustomerPackageArchive, error) {
	pkg, err := l.accessCustomerPortalPackage(ctx, token, in, "customer_portal_package.downloaded")
	if err != nil {
		return CustomerPackageArchive{}, err
	}
	return customerPackageArchive(pkg)
}

func (l *Ledger) SecurityReviewPackageReport(ctx context.Context, actor domain.Actor, packageID string) (domain.SecurityReviewPackageReport, error) {
	report, err := l.packageCommands.SecurityReviewPackageReport(ctx, actor, packageID)
	if err != nil {
		return domain.SecurityReviewPackageReport{}, fromPackageContextError(err)
	}
	return domain.SecurityReviewPackageReport{ReportType: report.ReportType, TemplateVersion: report.TemplateVersion, PackageID: report.PackageID, ProductID: report.ProductID, ReleaseID: report.ReleaseID, EvidenceIDs: report.EvidenceIDs, Assumptions: report.Assumptions, Limitations: report.Limitations, GeneratedAt: report.GeneratedAt}, nil
}

func packageWithDistributionWatermark(pkg domain.CustomerSecurityPackage, access domain.CustomerPortalAccess) domain.CustomerSecurityPackage {
	pkg.DistributionWatermark = packageDistributionWatermark(pkg, portalReviewerLabel(access.CustomerName, access.ReviewerName, access.ReviewerEmail), access.ID)
	if access.Watermark != "" {
		pkg.DistributionWatermark = access.Watermark
	}
	return pkg
}

func portalReviewerLabel(customerName, reviewerName, reviewerEmail string) string {
	if reviewerName != "" && reviewerEmail != "" {
		return reviewerName + " <" + reviewerEmail + ">"
	}
	if reviewerEmail != "" {
		return reviewerEmail
	}
	if reviewerName != "" {
		return reviewerName
	}
	return customerName
}

func packageDistributionWatermark(pkg domain.CustomerSecurityPackage, customerName, accessID string) string {
	customerName = cleanExternalLabel(customerName)
	accessID = strings.TrimSpace(accessID)
	if customerName == "" && accessID == "" {
		return "Evydence package " + pkg.ID + " exported for scoped review."
	}
	return cleanExternalLabel("Evydence package " + pkg.ID + " for " + customerName + " via access " + accessID + ".")
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

func customerPackageArchive(pkg domain.CustomerSecurityPackage) (CustomerPackageArchive, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var expandedSize int64
	decisionExport := customerPackageDecisionExport(pkg)
	metadata := map[string]any{
		"id":                   pkg.ID,
		"product_id":           pkg.ProductID,
		"release_id":           pkg.ReleaseID,
		"redaction_profile_id": pkg.RedactionProfileID,
		"title":                pkg.Title,
		"state":                pkg.State,
		"manifest_hash":        pkg.ManifestHash,
		"html_report_file":     "report.html",
		"expires_at":           pkg.ExpiresAt.UTC().Format(time.RFC3339),
		"schema_version":       pkg.SchemaVersion,
		"created_at":           pkg.CreatedAt.UTC().Format(time.RFC3339),
	}
	if decisionExport != nil {
		metadata["decision_export_file"] = customerDecisionExportFile
	}
	if pkg.DistributionWatermark != "" {
		metadata["distribution_watermark"] = pkg.DistributionWatermark
	}
	verification := map[string]any{
		"package_id":        pkg.ID,
		"manifest_hash":     pkg.ManifestHash,
		"manifest_file":     "manifest.json",
		"metadata_file":     "package.json",
		"html_report_file":  "report.html",
		"hash_algorithm":    "sha256",
		"verification_note": "Verify the package manifest hash against the Evydence API or a signed bundle before relying on contents.",
		"limitations": []string{
			"Archive contents are scoped and redacted.",
			"Raw tenant evidence payload bytes are not included.",
			"This package supports technical evidence review and does not prove legal compliance, certification, or release security status.",
		},
	}
	if decisionExport != nil {
		verification["decision_export_file"] = customerDecisionExportFile
	}
	readme := "Evydence customer security package\n\n" +
		"This ZIP contains a scoped package manifest, package metadata, verification guidance, and customer-safe decision export when present.\n" +
		"It intentionally excludes raw tenant evidence payload bytes and bearer tokens.\n" +
		"Use the manifest hash with Evydence verification records or signed bundles before relying on package contents.\n"
	for _, entry := range []struct {
		name string
		body any
	}{
		{name: "manifest.json", body: pkg.Manifest},
		{name: "package.json", body: metadata},
		{name: "verification.json", body: verification},
	} {
		body, err := marshalCustomerPackageJSON(entry.body)
		if err != nil {
			_ = zw.Close()
			return CustomerPackageArchive{}, fmt.Errorf("serialize customer package %s: %w", entry.name, err)
		}
		body = append(body, '\n')
		if err := addCustomerPackageZIPFile(zw, &expandedSize, entry.name, body); err != nil {
			_ = zw.Close()
			return CustomerPackageArchive{}, err
		}
	}
	if decisionExport != nil {
		body, err := marshalCustomerPackageJSON(decisionExport)
		if err != nil {
			_ = zw.Close()
			return CustomerPackageArchive{}, err
		}
		body = append(body, '\n')
		if err := addCustomerPackageZIPFile(zw, &expandedSize, customerDecisionExportFile, body); err != nil {
			_ = zw.Close()
			return CustomerPackageArchive{}, err
		}
	}
	if err := addCustomerPackageZIPFile(zw, &expandedSize, "README.txt", []byte(readme)); err != nil {
		_ = zw.Close()
		return CustomerPackageArchive{}, err
	}
	if pkg.DistributionWatermark != "" {
		if err := addCustomerPackageZIPFile(zw, &expandedSize, "WATERMARK.txt", []byte(pkg.DistributionWatermark+"\n")); err != nil {
			_ = zw.Close()
			return CustomerPackageArchive{}, err
		}
	}
	report := customerPackageHTMLReport(pkg, metadata, verification)
	if len(report) > MaxGeneratedReportBytes {
		_ = zw.Close()
		return CustomerPackageArchive{}, ErrValidation
	}
	if err := addCustomerPackageZIPFile(zw, &expandedSize, "report.html", report); err != nil {
		_ = zw.Close()
		return CustomerPackageArchive{}, err
	}
	if err := zw.Close(); err != nil {
		return CustomerPackageArchive{}, err
	}
	body := buf.Bytes()
	if len(body) > MaxCustomerPackageArchiveBytes {
		return CustomerPackageArchive{}, ErrValidation
	}
	return CustomerPackageArchive{PackageID: pkg.ID, Filename: "evydence-customer-package-" + pkg.ID + ".zip", MediaType: "application/zip", Bytes: body, Hash: hashBytes(body), Size: int64(len(body))}, nil
}

// RenderCustomerPackageArchive is a bounded, record-only compatibility utility.
// Durable package/portal commands supply the authorized committed package; rendering
// performs no Ledger lookup, transaction, token verification, or state mutation.
func RenderCustomerPackageArchive(pkg domain.CustomerSecurityPackage) (CustomerPackageArchive, error) {
	return customerPackageArchive(pkg)
}

func customerPackageDecisionExport(pkg domain.CustomerSecurityPackage) map[string]any {
	decisions := packageHTMLRecords(pkg.Manifest["vulnerability_decisions"])
	if len(decisions) == 0 {
		return nil
	}
	return map[string]any{
		"schema_version":       customerDecisionExportVersion,
		"package_id":           pkg.ID,
		"product_id":           pkg.ProductID,
		"release_id":           pkg.ReleaseID,
		"source_manifest_hash": pkg.ManifestHash,
		"decision_count":       len(decisions),
		"decisions":            decisions,
		"assumptions": []string{
			"This file contains only active vulnerability decisions included by the package redaction profile.",
			"Supporting links are Evydence record type/id pairs scoped by the package manifest.",
		},
		"limitations": []string{
			"This export supports technical evidence review and compliance readiness only; it is not legal compliance proof, certification, complete SBOM proof, authoritative vulnerability coverage, or a secure-release guarantee.",
			"Decision accuracy depends on tenant-supplied scanner, VEX, SBOM, exception, waiver, approval, and review evidence.",
		},
		"generated_at": pkg.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func customerPackageHTMLReport(pkg domain.CustomerSecurityPackage, metadata, verification map[string]any) []byte {
	manifest := pkg.Manifest
	product := packageHTMLMap(manifest["product"])
	release := packageHTMLMap(manifest["release"])
	readiness := packageHTMLMap(manifest["readiness_summary"])
	apiContracts := packageHTMLMap(manifest["api_contracts"])
	vexDocuments := packageHTMLRecords(manifest["vex_documents"])
	decisions := packageHTMLRecords(manifest["vulnerability_decisions"])
	answerLibrary := packageHTMLRecords(manifest["answer_library"])
	objectLockProofs := packageHTMLRecords(manifest["object_lock_proofs"])
	limitations := packageHTMLStrings(manifest["limitations"])
	nonClaims := packageHTMLStrings(manifest["non_claims"])

	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'\"><title>")
	b.WriteString(packageHTMLEscape(pkg.Title))
	b.WriteString("</title><style>body{font-family:Arial,sans-serif;margin:2rem;line-height:1.5;color:#17202a;background:#fff}main{max-width:980px}h1,h2{line-height:1.2}table{border-collapse:collapse;width:100%;margin:0.75rem 0 1.5rem}th,td{border:1px solid #ccd3db;padding:0.45rem;text-align:left;vertical-align:top}th{background:#f3f6f8}.muted{color:#59636e}.notice{border-left:4px solid #5b6f82;background:#f6f8fa;padding:0.75rem 1rem}.badge{display:inline-block;border:1px solid #ccd3db;padding:0.1rem 0.45rem;border-radius:4px}</style></head><body><main>")
	b.WriteString("<h1>")
	b.WriteString(packageHTMLEscape(pkg.Title))
	b.WriteString("</h1><p class=\"notice\">This static report is generated from the redacted customer package manifest. It supports technical evidence review and compliance readiness only; it is not legal compliance proof, certification, complete SBOM proof, an authoritative vulnerability result, regulator acceptance, or a secure-release guarantee.</p>")
	if watermark := packageHTMLString(metadata["distribution_watermark"]); watermark != "" {
		b.WriteString("<p class=\"notice\"><strong>Distribution watermark:</strong> ")
		b.WriteString(packageHTMLEscape(watermark))
		b.WriteString("</p>")
	}

	b.WriteString("<h2>Release Summary</h2><table><tbody>")
	packageHTMLRow(&b, "Package ID", pkg.ID)
	packageHTMLRow(&b, "Product", packageHTMLFirst(product, "name", "id"))
	packageHTMLRow(&b, "Release", packageHTMLFirst(release, "version", "id"))
	packageHTMLRow(&b, "Package State", pkg.State)
	packageHTMLRow(&b, "Readiness", packageHTMLString(readiness["result"]))
	packageHTMLRow(&b, "Manifest Hash", packageHTMLString(metadata["manifest_hash"]))
	b.WriteString("</tbody></table>")

	b.WriteString("<h2>VEX And Vulnerability Decisions</h2>")
	if len(vexDocuments) == 0 && len(decisions) == 0 {
		b.WriteString("<p class=\"muted\">No customer-visible VEX documents or vulnerability decisions are included by this package profile.</p>")
	} else {
		if len(vexDocuments) > 0 {
			b.WriteString("<h3>VEX Documents</h3><table><thead><tr><th>ID</th><th>Format</th><th>Statements</th><th>Status Summary</th></tr></thead><tbody>")
			for _, record := range vexDocuments {
				b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(record["id"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["format"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["statement_count"])) + "</td><td>" + packageHTMLEscape(packageHTMLJSON(record["status_summary"])) + "</td></tr>")
			}
			b.WriteString("</tbody></table>")
		}
		if len(decisions) > 0 {
			b.WriteString("<h3>Vulnerability Decisions</h3><table><thead><tr><th>Vulnerability</th><th>Component</th><th>SBOM</th><th>Status</th><th>Impact Statement</th><th>Reviewed</th><th>Review Due</th><th>Supporting Links</th><th>Source</th></tr></thead><tbody>")
			for _, record := range decisions {
				b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(record["vulnerability"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["component"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["sbom_id"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["status"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["impact_statement"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["reviewed_at"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["review_due_at"])) + "</td><td>" + packageHTMLEscape(packageHTMLJSON(record["supporting_refs"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["source"])) + "</td></tr>")
			}
			b.WriteString("</tbody></table>")
		}
	}

	b.WriteString("<h2>Questionnaire Answer Library</h2>")
	if len(answerLibrary) == 0 {
		b.WriteString("<p class=\"muted\">No customer-visible questionnaire answer library entries are included by this package profile.</p>")
	} else {
		b.WriteString("<table><thead><tr><th>Question</th><th>Evidence Type</th><th>Answer</th><th>Evidence IDs</th></tr></thead><tbody>")
		for _, record := range answerLibrary {
			b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(record["question_id"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["evidence_type"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["answer"])) + "</td><td>" + packageHTMLEscape(packageHTMLJSON(record["evidence_ids"])) + "</td></tr>")
		}
		b.WriteString("</tbody></table>")
	}

	b.WriteString("<h2>Object-Lock Proofs</h2>")
	if len(objectLockProofs) == 0 {
		b.WriteString("<p class=\"muted\">No customer-visible object-lock proof records are included by this package profile.</p>")
	} else {
		b.WriteString("<table><thead><tr><th>ID</th><th>Status</th><th>Mode</th><th>Retention Days</th><th>Verification Hash</th></tr></thead><tbody>")
		for _, record := range objectLockProofs {
			b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(record["id"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["status"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["mode"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["retention_days"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["verification_hash"])) + "</td></tr>")
		}
		b.WriteString("</tbody></table>")
	}

	b.WriteString("<h2>API Contract Evidence</h2>")
	contractRecords := packageHTMLRecords(apiContracts["openapi_contracts"])
	diffRecords := packageHTMLRecords(apiContracts["contract_diffs"])
	if len(contractRecords) == 0 && len(diffRecords) == 0 {
		b.WriteString("<p class=\"muted\">No customer-visible OpenAPI contract evidence is included by this package profile.</p>")
	} else {
		if len(contractRecords) > 0 {
			b.WriteString("<h3>OpenAPI Contracts</h3><table><thead><tr><th>ID</th><th>Version</th><th>Hash</th><th>Paths</th><th>Operations</th></tr></thead><tbody>")
			for _, record := range contractRecords {
				b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(record["id"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["version"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["hash"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["path_count"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["operation_count"])) + "</td></tr>")
			}
			b.WriteString("</tbody></table>")
		}
		if len(diffRecords) > 0 {
			b.WriteString("<h3>Contract Diffs</h3><table><thead><tr><th>ID</th><th>Result</th><th>Breaking Changes</th><th>Non-breaking Changes</th></tr></thead><tbody>")
			for _, record := range diffRecords {
				b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(record["id"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["result"])) + "</td><td>" + packageHTMLEscape(packageHTMLJSON(record["breaking_changes"])) + "</td><td>" + packageHTMLEscape(packageHTMLJSON(record["non_breaking_changes"])) + "</td></tr>")
			}
			b.WriteString("</tbody></table>")
		}
	}

	b.WriteString("<h2>Readiness</h2>")
	packageHTMLReadiness(&b, readiness)
	b.WriteString("<h2>Verification</h2><table><tbody>")
	packageHTMLRow(&b, "Manifest File", packageHTMLString(verification["manifest_file"]))
	packageHTMLRow(&b, "Manifest Hash", packageHTMLString(verification["manifest_hash"]))
	packageHTMLRow(&b, "Decision Export", packageHTMLString(verification["decision_export_file"]))
	packageHTMLRow(&b, "Hash Algorithm", packageHTMLString(verification["hash_algorithm"]))
	packageHTMLRow(&b, "Verification Note", packageHTMLString(verification["verification_note"]))
	b.WriteString("</tbody></table>")
	b.WriteString("<h2>Limitations</h2>")
	packageHTMLList(&b, limitations)
	b.WriteString("<h2>Non-Claims</h2>")
	packageHTMLList(&b, nonClaims)
	b.WriteString("</main></body></html>")
	return []byte(b.String())
}

func packageHTMLReadiness(b *strings.Builder, readiness map[string]any) {
	result := packageHTMLString(readiness["result"])
	if result == "" {
		b.WriteString("<p class=\"muted\">No release readiness summary is included in this package.</p>")
		return
	}
	b.WriteString("<p>Result: <span class=\"badge\">" + packageHTMLEscape(result) + "</span></p>")
	checks := packageHTMLRecords(readiness["checks"])
	if len(checks) > 0 {
		b.WriteString("<table><thead><tr><th>Check</th><th>Result</th><th>Severity</th><th>Missing</th><th>Explanation</th></tr></thead><tbody>")
		for _, check := range checks {
			b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(check["name"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(check["result"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(check["severity"])) + "</td><td>" + packageHTMLEscape(packageHTMLJSON(check["missing"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(check["explanation"])) + "</td></tr>")
		}
		b.WriteString("</tbody></table>")
	}
	if gaps := packageHTMLStrings(readiness["gaps"]); len(gaps) > 0 {
		b.WriteString("<h3>Gaps</h3>")
		packageHTMLList(b, gaps)
	}
}

func packageHTMLRow(b *strings.Builder, label, value string) {
	b.WriteString("<tr><th>")
	b.WriteString(packageHTMLEscape(label))
	b.WriteString("</th><td>")
	b.WriteString(packageHTMLEscape(value))
	b.WriteString("</td></tr>")
}

func packageHTMLList(b *strings.Builder, items []string) {
	if len(items) == 0 {
		b.WriteString("<p class=\"muted\">None included.</p>")
		return
	}
	b.WriteString("<ul>")
	for _, item := range items {
		b.WriteString("<li>")
		b.WriteString(packageHTMLEscape(item))
		b.WriteString("</li>")
	}
	b.WriteString("</ul>")
}

func packageHTMLMap(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if record, ok := value.(map[string]any); ok {
		return record
	}
	return map[string]any{}
}

func packageHTMLRecords(value any) []map[string]any {
	switch records := value.(type) {
	case []map[string]any:
		return records
	case []any:
		out := make([]map[string]any, 0, len(records))
		for _, record := range records {
			if mapped, ok := record.(map[string]any); ok {
				out = append(out, mapped)
			}
		}
		return out
	default:
		return nil
	}
}

func packageHTMLStrings(value any) []string {
	switch records := value.(type) {
	case []string:
		return append([]string(nil), records...)
	case []any:
		out := make([]string, 0, len(records))
		for _, record := range records {
			if s := packageHTMLString(record); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func packageHTMLFirst(record map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := packageHTMLString(record[key]); value != "" {
			return value
		}
	}
	return ""
}

func packageHTMLString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func packageHTMLJSON(value any) string {
	if value == nil {
		return ""
	}
	body, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(body)
}

func packageHTMLEscape(value string) string {
	return html.EscapeString(value)
}

func addCustomerPackageZIPFile(zw *zip.Writer, expandedSize *int64, name string, body []byte) error {
	if expandedSize == nil || len(body) > MaxCustomerPackageFileBytes || *expandedSize > MaxCustomerPackageExpandedBytes-int64(len(body)) {
		return ErrValidation
	}
	*expandedSize += int64(len(body))
	return addZIPFile(zw, name, body)
}

func addZIPFile(zw *zip.Writer, name string, body []byte) error {
	// Customer packages are generated with stored entries. This keeps their
	// advertised uncompressed bytes equal to on-disk bytes and guarantees the
	// generated package cannot trip the verifier's compression-ratio defense.
	header := &zip.FileHeader{Name: name, Method: zip.Store}
	header.SetMode(0o644)
	header.Modified = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	writer, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = writer.Write(body)
	return err
}

// marshalCustomerPackageJSON is the final output boundary for customer
// artifacts. The profile builders must already have removed sensitive fields;
// this guard rejects rather than silently mutates the immutable manifest.
func marshalCustomerPackageJSON(value any) ([]byte, error) {
	if _, changed := redaction.RemoveSensitive(value); changed {
		path, _ := redaction.FirstSensitivePath(value)
		return nil, fmt.Errorf("%w: customer package contains sensitive field %s", ErrValidation, path)
	}
	return json.MarshalIndent(value, "", "  ")
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

func (l *Ledger) InstallControlFrameworkTemplatePack(ctx context.Context, actor domain.Actor, slug string) (domain.ControlFramework, error) {
	if err := l.AuthorizeControlTemplateInstallation(ctx, actor, slug); err != nil {
		return domain.ControlFramework{}, err
	}
	var selected domain.ControlFrameworkTemplatePack
	for _, pack := range builtinTemplatePacks() {
		if pack.Slug == strings.TrimSpace(slug) {
			selected = pack
			break
		}
	}
	if selected.ID == "" {
		return domain.ControlFramework{}, ErrNotFound
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	framework := domain.ControlFramework{ID: newID("cf"), TenantID: actor.TenantID, Name: selected.Name, Slug: selected.Slug, Version: selected.Version, Description: selected.Description, Status: "active", SchemaVersion: domain.ControlFrameworkSchemaVersion, CreatedAt: l.now()}
	controls := make([]domain.SecurityControl, 0, len(selected.Controls))
	for _, templateControl := range selected.Controls {
		control := templateControl
		control.ID = newID("ctrl")
		control.TenantID = actor.TenantID
		control.FrameworkID = framework.ID
		control.SchemaVersion = domain.SecurityControlSchemaVersion
		control.CreatedAt = l.now()
		controls = append(controls, control)
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Controls.InsertControlFramework(ctx, framework); err != nil {
				return err
			}
			for _, control := range controls {
				if err := repos.Controls.InsertSecurityControl(ctx, control); err != nil {
					return err
				}
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(framework.CreatedAt, actor.TenantID, "control_framework_template.installed", "control_framework", framework.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.ControlFramework{}, err
		}
		l.frameworks[framework.ID] = framework
		for _, control := range controls {
			l.controls[control.ID] = control
		}
		l.publishCommittedAuditEntryLocked(entry)
		return framework, nil
	}
	l.frameworks[framework.ID] = framework
	for _, control := range controls {
		l.controls[control.ID] = control
	}
	_, _ = l.appendChainLocked(actor.TenantID, "control_framework_template.installed", "control_framework", framework.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ControlFramework{}, err
	}
	return framework, nil
}

func validDSSETrustRoot(root domain.DSSETrustRoot) bool {
	return verificationapp.ValidDSSETrustRoot(domain.DSSETrustRootToContextModel(root))
}

func (l *Ledger) registeredReleaseBuildOutputDigestsLocked(tenantID string, build domain.BuildRun) []string {
	releaseDigests := l.releaseArtifactDigestsLocked(tenantID, build.ReleaseID)
	digests := []string{}
	for _, output := range build.Outputs {
		artifact, ok := l.artifacts[output.ArtifactID]
		if !ok || artifact.TenantID != tenantID || artifact.Digest != output.Digest {
			continue
		}
		if _, ok := releaseDigests[output.Digest]; ok {
			digests = append(digests, output.Digest)
		}
	}
	return sortedStrings(digests)
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

func (l *Ledger) ensureWaiverScopeLocked(tenantID, scope, id string) error {
	switch scope {
	case "release":
		item, ok := l.releases[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	case "control":
		item, ok := l.controls[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	case "policy":
		item, ok := l.customPolicies[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	case "finding":
		if _, _, ok := l.findFindingLocked(tenantID, id); !ok {
			return ErrNotFound
		}
	}
	return nil
}

func (l *Ledger) ensureApprovalSubjectLocked(tenantID, subject, id string) error {
	switch subject {
	case "release":
		item, ok := l.releases[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	case "contract_diff":
		item, ok := l.contractDiffs[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	case "waiver":
		item, ok := l.waivers[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	case "security_review":
		item, ok := l.manualDocs[id]
		if !ok || item.TenantID != tenantID || item.DocumentType != "security_review" {
			return ErrNotFound
		}
	case "customer_package":
		item, ok := l.customerPackages[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	}
	return nil
}

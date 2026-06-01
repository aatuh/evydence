package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"html"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
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
	Name      string
	KeyID     string
	Algorithm string
	PublicKey string
}

type redactionProfilePreset struct {
	Name           string
	Description    string
	AllowedTypes   []string
	ExcludedFields []string
}

var redactionProfilePresets = map[string]redactionProfilePreset{
	"customer_safe": {
		Name:        "customer_safe",
		Description: "Customer-safe package profile for release evidence summaries without raw payloads, secrets, internal notes, or internal-only provenance fields.",
		AllowedTypes: []string{
			"artifact",
			"answer_library",
			"sbom",
			"vulnerability_scan",
			"vex",
			"vulnerability_decision",
			"release_bundle",
			"approval",
			"exception",
			"object_lock_proof",
			"waiver",
		},
		ExcludedFields: []string{
			"action_internal_url",
			"environment_hash",
			"internal_notes",
			"internal_url",
			"object_key",
			"oidc_subject",
			"parameters_hash",
			"payload",
			"payload_bytes",
			"payload_ref",
			"private_key",
			"repository",
			"secret",
			"source_identity",
			"token",
			"workflow_ref",
		},
	},
	"security_review": {
		Name:        "security_review",
		Description: "Security-review package profile for broader technical evidence review while still excluding raw payloads, secrets, token material, and private keys.",
		AllowedTypes: []string{
			"api_security",
			"approval",
			"answer_library",
			"artifact",
			"build",
			"build_attestation",
			"dast",
			"exception",
			"license_scan",
			"manual_security_document",
			"object_lock_proof",
			"openapi_contract",
			"pen_test_report",
			"release_bundle",
			"sast",
			"sbom",
			"secret_scan",
			"security_review",
			"threat_model",
			"vex",
			"vulnerability_decision",
			"vulnerability_scan",
			"waiver",
		},
		ExcludedFields: []string{
			"internal_notes",
			"object_key",
			"payload",
			"payload_bytes",
			"payload_ref",
			"private_key",
			"secret",
			"token",
		},
	},
}

func applyRedactionProfilePreset(in CreateRedactionProfileInput) (CreateRedactionProfileInput, error) {
	presetName := strings.TrimSpace(in.Preset)
	if presetName == "" {
		return in, nil
	}
	preset, ok := redactionProfilePresets[presetName]
	if !ok {
		return CreateRedactionProfileInput{}, ErrValidation
	}
	if len(in.AllowedTypes) > 0 || len(in.ExcludedFields) > 0 {
		return CreateRedactionProfileInput{}, ErrValidation
	}
	in.Name = preset.Name
	in.Description = preset.Description
	in.AllowedTypes = append([]string(nil), preset.AllowedTypes...)
	in.ExcludedFields = append([]string(nil), preset.ExcludedFields...)
	return in, nil
}

func (l *Ledger) CreateWaiver(ctx context.Context, actor domain.Actor, in CreateWaiverInput) (domain.Waiver, error) {
	if err := ctx.Err(); err != nil {
		return domain.Waiver{}, err
	}
	if err := require(actor, ScopePolicyWrite); err != nil {
		return domain.Waiver{}, err
	}
	in.ScopeType, in.ScopeID = strings.TrimSpace(in.ScopeType), strings.TrimSpace(in.ScopeID)
	in.Owner, in.Risk, in.Reason = strings.TrimSpace(in.Owner), strings.TrimSpace(in.Risk), strings.TrimSpace(in.Reason)
	if !validWaiverScope(in.ScopeType) || in.ScopeID == "" || in.Owner == "" || in.Risk == "" || in.Reason == "" || !in.ExpiresAt.After(l.now()) {
		return domain.Waiver{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureWaiverScopeLocked(actor.TenantID, in.ScopeType, in.ScopeID); err != nil {
		return domain.Waiver{}, err
	}
	if in.ControlID != "" {
		control, ok := l.controls[strings.TrimSpace(in.ControlID)]
		if !ok || control.TenantID != actor.TenantID {
			return domain.Waiver{}, ErrNotFound
		}
	}
	if in.PolicyID != "" {
		policy, ok := l.customPolicies[strings.TrimSpace(in.PolicyID)]
		if !ok || policy.TenantID != actor.TenantID {
			return domain.Waiver{}, ErrNotFound
		}
	}
	if in.Supersedes != "" {
		prev, ok := l.waivers[strings.TrimSpace(in.Supersedes)]
		if !ok || prev.TenantID != actor.TenantID || prev.SupersededBy != "" {
			return domain.Waiver{}, ErrNotFound
		}
	}
	waiver := domain.Waiver{
		ID:            newID("wv"),
		TenantID:      actor.TenantID,
		ScopeType:     in.ScopeType,
		ScopeID:       in.ScopeID,
		ControlID:     strings.TrimSpace(in.ControlID),
		PolicyID:      strings.TrimSpace(in.PolicyID),
		Owner:         in.Owner,
		Risk:          in.Risk,
		Reason:        in.Reason,
		ExpiresAt:     in.ExpiresAt.UTC(),
		Supersedes:    strings.TrimSpace(in.Supersedes),
		SchemaVersion: domain.WaiverSchemaVersion,
		CreatedAt:     l.now(),
	}
	if waiver.Supersedes != "" {
		prev := l.waivers[waiver.Supersedes]
		prev.SupersededBy = waiver.ID
		l.waivers[prev.ID] = prev
	}
	l.waivers[waiver.ID] = waiver
	_, _ = l.appendChainLocked(actor.TenantID, "waiver.created", "waiver", waiver.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Waiver{}, err
	}
	return waiver, nil
}

func (l *Ledger) ApproveWaiver(ctx context.Context, actor domain.Actor, id string) (domain.Waiver, error) {
	if err := ctx.Err(); err != nil {
		return domain.Waiver{}, err
	}
	if err := require(actor, ScopePolicyWrite); err != nil {
		return domain.Waiver{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	waiver, ok := l.waivers[strings.TrimSpace(id)]
	if !ok || waiver.TenantID != actor.TenantID {
		return domain.Waiver{}, ErrNotFound
	}
	if waiver.Approved || !waiver.ExpiresAt.After(l.now()) {
		return domain.Waiver{}, ErrConflict
	}
	now := l.now()
	waiver.Approved = true
	waiver.ApprovedBy = actorID(actor)
	waiver.ApprovedAt = &now
	l.waivers[waiver.ID] = waiver
	_, _ = l.appendChainLocked(actor.TenantID, "waiver.approved", "waiver", waiver.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Waiver{}, err
	}
	return waiver, nil
}

func (l *Ledger) CreateApprovalRecord(ctx context.Context, actor domain.Actor, in CreateApprovalInput) (domain.ApprovalRecord, error) {
	if err := ctx.Err(); err != nil {
		return domain.ApprovalRecord{}, err
	}
	if err := require(actor, ScopeReleaseWrite); err != nil {
		return domain.ApprovalRecord{}, err
	}
	in.SubjectType, in.SubjectID = strings.TrimSpace(in.SubjectType), strings.TrimSpace(in.SubjectID)
	in.Decision, in.Reason = strings.TrimSpace(in.Decision), strings.TrimSpace(in.Reason)
	if !validApprovalSubject(in.SubjectType) || in.SubjectID == "" || !validApprovalDecision(in.Decision) || in.Reason == "" {
		return domain.ApprovalRecord{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureApprovalSubjectLocked(actor.TenantID, in.SubjectType, in.SubjectID); err != nil {
		return domain.ApprovalRecord{}, err
	}
	if in.EvidenceID != "" {
		item, ok := l.evidence[strings.TrimSpace(in.EvidenceID)]
		if !ok || item.TenantID != actor.TenantID {
			return domain.ApprovalRecord{}, ErrNotFound
		}
	}
	approval := domain.ApprovalRecord{ID: newID("apr"), TenantID: actor.TenantID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, Decision: in.Decision, Reason: in.Reason, ApproverID: actorID(actor), EvidenceID: strings.TrimSpace(in.EvidenceID), SchemaVersion: domain.ApprovalRecordSchemaVersion, CreatedAt: l.now()}
	l.approvals[approval.ID] = approval
	_, _ = l.appendChainLocked(actor.TenantID, "approval.created", "approval", approval.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ApprovalRecord{}, err
	}
	return approval, nil
}

func (s packageReportService) CreateRedactionProfile(ctx context.Context, actor domain.Actor, in CreateRedactionProfileInput) (domain.RedactionProfile, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.RedactionProfile{}, err
	}
	if err := require(actor, ScopePackageWrite); err != nil {
		return domain.RedactionProfile{}, err
	}
	var err error
	in, err = applyRedactionProfilePreset(in)
	if err != nil {
		return domain.RedactionProfile{}, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return domain.RedactionProfile{}, ErrValidation
	}
	if len(in.AllowedTypes) == 0 {
		return domain.RedactionProfile{}, ErrValidation
	}
	for _, typ := range in.AllowedTypes {
		if strings.TrimSpace(typ) == "" {
			return domain.RedactionProfile{}, ErrValidation
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	profile := domain.RedactionProfile{ID: newID("rp"), TenantID: actor.TenantID, Name: in.Name, Description: strings.TrimSpace(in.Description), AllowedTypes: sortedStrings(in.AllowedTypes), ExcludedFields: sortedStrings(in.ExcludedFields), SchemaVersion: domain.RedactionProfileSchemaVersion, CreatedAt: l.now()}
	l.redactions[profile.ID] = profile
	_, _ = l.appendChainLocked(actor.TenantID, "redaction_profile.created", "redaction_profile", profile.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.RedactionProfile{}, err
	}
	return profile, nil
}

func (s packageReportService) CreateCustomerSecurityPackage(ctx context.Context, actor domain.Actor, in CreateCustomerPackageInput) (domain.CustomerSecurityPackage, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	if err := require(actor, ScopePackageWrite); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	in.ProductID, in.ReleaseID = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID)
	in.RedactionProfileID, in.Title = strings.TrimSpace(in.RedactionProfileID), strings.TrimSpace(in.Title)
	if in.ProductID == "" || in.RedactionProfileID == "" || in.Title == "" || !in.ExpiresAt.After(l.now()) {
		return domain.CustomerSecurityPackage{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopePackageWrite, resourceRefs{ProductID: in.ProductID, ReleaseID: in.ReleaseID}); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	profile, ok := l.redactions[in.RedactionProfileID]
	if !ok || profile.TenantID != actor.TenantID {
		return domain.CustomerSecurityPackage{}, ErrNotFound
	}
	evidenceIDs := l.packageEvidenceIDsLocked(actor.TenantID, in.ProductID, in.ReleaseID, profile)
	packageID := newID("csp")
	generatedAt := l.now()
	manifest := l.customerPackageManifestLocked(packageID, generatedAt, actor.TenantID, in.Title, in.ProductID, in.ReleaseID, profile, evidenceIDs)
	hash, err := canonicalAnyHash(manifest)
	if err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	pkg := domain.CustomerSecurityPackage{ID: packageID, TenantID: actor.TenantID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, RedactionProfileID: profile.ID, Title: in.Title, State: "generated", Manifest: manifest, ManifestHash: hash, ExpiresAt: in.ExpiresAt.UTC(), SchemaVersion: domain.CustomerPackageSchemaVersion, CreatedAt: generatedAt}
	l.customerPackages[pkg.ID] = pkg
	_, _ = l.appendChainLocked(actor.TenantID, "customer_package.generated", "customer_security_package", pkg.ID, "api_key", actor.KeyID, hash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	return pkg, nil
}

func (l *Ledger) customerPackageManifestLocked(packageID string, generatedAt time.Time, tenantID, title, productID, releaseID string, profile domain.RedactionProfile, evidenceIDs []string) map[string]any {
	product := l.products[productID]
	var release domain.Release
	if releaseID != "" {
		release = l.releases[releaseID]
	}
	checks := l.packageReadinessChecksLocked(tenantID, releaseID)
	gaps := []string{}
	readinessResult := "not_applicable"
	if releaseID != "" {
		readinessResult = "passed"
		for _, check := range checks {
			gaps = append(gaps, check.Missing...)
			if check.Result == "failed" {
				readinessResult = "failed"
			}
		}
		sort.Strings(gaps)
	}
	manifest := map[string]any{
		"schema_version":        domain.CustomerPackageSchemaVersion,
		"package_version":       domain.CustomerPackageSchemaVersion,
		"package_id":            packageID,
		"id":                    packageID,
		"title":                 title,
		"generated_at":          generatedAt.UTC().Format(time.RFC3339Nano),
		"tenant":                l.packageTenantMetadataLocked(tenantID),
		"organization":          l.packageOrganizationMetadataLocked(tenantID),
		"product":               packageProductMetadata(product),
		"product_id":            productID,
		"release":               packageReleaseMetadata(release),
		"release_id":            releaseID,
		"redaction_profile_id":  profile.ID,
		"redaction_profile":     packageRedactionProfileMetadata(profile),
		"evidence_ids":          append([]string(nil), evidenceIDs...),
		"artifact_digests":      l.packageArtifactMetadataLocked(tenantID, releaseID),
		"readiness_summary":     packageReadinessSummary(readinessResult, checks, gaps),
		"verification_material": l.packageVerificationMaterialLocked(tenantID, releaseID),
		"limitations": []string{
			"Package contents are scoped by product, release, redaction profile, and package expiry.",
			"Raw tenant evidence payload bytes, object-store payload references, bearer tokens, private keys, API key hashes, SSO/session token hashes, and internal decision notes are not included.",
			"Package data reflects records present in this Evydence instance at generation time.",
		},
		"non_claims": []string{
			"This package supports technical evidence review and compliance readiness only.",
			"It is not legal compliance proof, certification, complete SBOM proof, an authoritative vulnerability result, regulator acceptance, or a secure-release guarantee.",
		},
	}
	if customerSafeGaps := packageCustomerSafeGaps(checks, profile); len(customerSafeGaps) > 0 {
		manifest["customer_safe_gaps"] = customerSafeGaps
	}
	if profileAllowsPackageType(profile, "sbom") {
		manifest["sboms"] = l.packageSBOMMetadataLocked(tenantID, releaseID)
	}
	if profileAllowsPackageType(profile, "vulnerability_scan") {
		manifest["vulnerability_scans"] = l.packageVulnerabilityScanMetadataLocked(tenantID, releaseID)
	}
	if profileAllowsPackageType(profile, "vex") {
		manifest["vex_documents"] = l.packageVEXMetadataLocked(tenantID, releaseID)
	}
	if profileAllowsPackageType(profile, "openapi_contract") {
		manifest["api_contracts"] = l.packageAPIContractMetadataLocked(tenantID, releaseID)
	}
	if decisions := l.packageDecisionSummariesLocked(tenantID, releaseID, profile); len(decisions) > 0 {
		manifest["vulnerability_decisions"] = decisions
	}
	if profileAllowsPackageType(profile, "approval") {
		manifest["approvals"] = l.packageApprovalSummariesLocked(tenantID, productID, releaseID)
	}
	if profileAllowsPackageType(profile, "exception") {
		manifest["exceptions"] = l.packageExceptionSummariesLocked(tenantID, releaseID)
	}
	if profileAllowsPackageType(profile, "waiver") {
		manifest["waivers"] = l.packageWaiverSummariesLocked(tenantID, productID, releaseID)
	}
	if profileAllowsPackageType(profile, "answer_library") {
		manifest["answer_library"] = l.packageAnswerLibraryMetadataLocked(tenantID, productID, releaseID)
	}
	if profileAllowsPackageType(profile, "object_lock_proof") {
		manifest["object_lock_proofs"] = l.packageObjectLockProofsLocked(tenantID)
	}
	if profileAllowsPackageType(profile, "build") || profileAllowsPackageType(profile, "build_attestation") {
		manifest["provenance"] = l.packageProvenanceMetadataLocked(tenantID, releaseID, profile)
	}
	return manifest
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

func packageRedactionProfileMetadata(profile domain.RedactionProfile) map[string]any {
	return map[string]any{
		"id":              profile.ID,
		"name":            profile.Name,
		"description":     profile.Description,
		"allowed_types":   append([]string(nil), profile.AllowedTypes...),
		"excluded_fields": append([]string(nil), profile.ExcludedFields...),
		"schema_version":  profile.SchemaVersion,
	}
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
			"author":          vex.Author,
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
	out := make([]map[string]any, 0, len(operations))
	for _, operation := range operations {
		method := strings.ToUpper(strings.TrimSpace(operation.Method))
		path := strings.TrimSpace(operation.Path)
		if method == "" || path == "" {
			continue
		}
		out = append(out, map[string]any{
			"label":                   method + " " + path,
			"path":                    path,
			"method":                  method,
			"operation_id":            operation.OperationID,
			"deprecated":              operation.Deprecated,
			"request_body_required":   operation.RequestBodyRequired,
			"required_request_fields": append([]string(nil), operation.RequiredRequestFields...),
			"response_statuses":       append([]string(nil), operation.ResponseStatuses...),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		left, _ := out[i]["label"].(string)
		right, _ := out[j]["label"].(string)
		return left < right
	})
	return out
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
	out := []map[string]any{}
	for _, policy := range l.retentionPolicies {
		if policy.TenantID != tenantID {
			continue
		}
		proof := map[string]any{
			"id":                           policy.ID,
			"name":                         policy.Name,
			"object_prefix_configured":     policy.ObjectPrefix != "",
			"sample_object_key_configured": policy.ObjectKey != "",
			"require_legal_hold":           policy.RequireLegalHold,
			"mode":                         policy.Mode,
			"retention_days":               policy.RetentionDays,
			"status":                       policy.Status,
			"verification_hash":            policy.VerificationHash,
			"verification_checks":          packageVerifyChecks(policy.VerificationChecks),
			"verification_limitations":     append([]string(nil), policy.VerificationLimitations...),
			"created_at":                   policy.CreatedAt.UTC().Format(time.RFC3339),
			"limitations": []string{
				"Object-lock proof records show configured Evydence verification results for tenant object-storage settings only.",
				"They do not prove external WORM enforcement, IAM policy, lifecycle policy, backup behavior, or legal compliance.",
			},
		}
		if policy.VerifiedAt != nil {
			proof["verified_at"] = policy.VerifiedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, proof)
	}
	sortManifestMapsByID(out)
	return out
}

func packageVerifyChecks(checks []domain.VerifyCheck) []map[string]any {
	out := make([]map[string]any, 0, len(checks))
	for _, check := range checks {
		out = append(out, map[string]any{"name": check.Name, "result": check.Result, "detail": check.Detail})
	}
	sort.Slice(out, func(i, j int) bool {
		left, _ := out[i]["name"].(string)
		right, _ := out[j]["name"].(string)
		return left < right
	})
	return out
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
	out := make([]map[string]any, 0, len(outputs))
	for _, output := range outputs {
		out = append(out, map[string]any{"artifact_id": output.ArtifactID, "digest": output.Digest})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["artifact_id"].(string)+"\x00"+out[i]["digest"].(string) < out[j]["artifact_id"].(string)+"\x00"+out[j]["digest"].(string)
	})
	return out
}

func packageOptionalTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func (l *Ledger) packageReadinessChecksLocked(tenantID, releaseID string) []domain.PolicyCheck {
	if releaseID == "" {
		return nil
	}
	return []domain.PolicyCheck{
		l.checkReleaseHasEvidenceLocked(tenantID, releaseID, "sbom", "release_requires_sbom", "high"),
		l.checkReleaseHasEvidenceLocked(tenantID, releaseID, "vulnerability_scan", "release_requires_vulnerability_scan", "high"),
		l.checkReleaseHasArtifactDigestLocked(tenantID, releaseID),
		l.checkReleaseHasSignedBundleLocked(tenantID, releaseID),
		l.checkReleaseHasPassedBuildLocked(tenantID, releaseID),
		l.checkReleaseHasBuildAttestationLocked(tenantID, releaseID),
		l.checkNoOpenCriticalLocked(tenantID, releaseID),
	}
}

func packageReadinessSummary(result string, checks []domain.PolicyCheck, gaps []string) map[string]any {
	checkSummaries := make([]map[string]any, 0, len(checks))
	for _, check := range checks {
		checkSummaries = append(checkSummaries, map[string]any{
			"name":        check.Name,
			"result":      check.Result,
			"severity":    check.Severity,
			"missing":     append([]string(nil), check.Missing...),
			"explanation": check.Explanation,
			"remediation": check.Remediation,
		})
	}
	return map[string]any{
		"result": result,
		"checks": checkSummaries,
		"gaps":   append([]string(nil), gaps...),
		"limitations": []string{
			"Readiness is derived from recorded package-scope evidence only.",
			"Readiness output is not a compliance, certification, or secure-release conclusion.",
		},
	}
}

func packageCustomerSafeGaps(checks []domain.PolicyCheck, profile domain.RedactionProfile) []map[string]any {
	out := []map[string]any{}
	for _, check := range checks {
		if check.Result == "passed" {
			continue
		}
		for _, missing := range check.Missing {
			if !packageGapVisibleForProfile(missing, profile) {
				continue
			}
			out = append(out, map[string]any{
				"id":               "gap_" + check.Name + "_" + missing,
				"category":         "missing_evidence",
				"evidence_type":    missing,
				"source_check":     check.Name,
				"severity":         check.Severity,
				"summary":          check.Explanation,
				"remediation":      check.Remediation,
				"customer_visible": true,
				"limitations": []string{
					"Gap is based only on evidence metadata included by this package redaction profile.",
				},
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		left, _ := out[i]["id"].(string)
		right, _ := out[j]["id"].(string)
		return left < right
	})
	return out
}

func packageGapVisibleForProfile(missing string, profile domain.RedactionProfile) bool {
	switch strings.TrimSpace(missing) {
	case "artifact", "artifact_digest":
		return profileAllowsPackageType(profile, "artifact")
	case "sbom":
		return profileAllowsPackageType(profile, "sbom")
	case "vulnerability_scan":
		return profileAllowsPackageType(profile, "vulnerability_scan")
	case "vulnerability_decision":
		return profileAllowsPackageType(profile, "vulnerability_decision")
	case "signed_release_bundle":
		return profileAllowsPackageType(profile, "release_bundle")
	case "passed_build":
		return profileAllowsPackageType(profile, "build")
	case "build_attestation":
		return profileAllowsPackageType(profile, "build_attestation")
	default:
		return false
	}
}

func (l *Ledger) packageVerificationMaterialLocked(tenantID, releaseID string) map[string]any {
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
	return map[string]any{
		"hash_algorithm":      "sha256",
		"canonicalization":    domain.CanonicalizationProfileVersion,
		"manifest_hash_field": "manifest_hash",
		"release_bundles":     bundles,
		"audit_chain":         l.packageAuditChainSummaryLocked(tenantID),
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
		"checks":          checks,
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

func (s packageReportService) AccessCustomerSecurityPackage(ctx context.Context, actor domain.Actor, id string) (domain.CustomerSecurityPackage, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	if err := require(actor, ScopePackageRead); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	pkg, ok := l.customerPackages[strings.TrimSpace(id)]
	if !ok || pkg.TenantID != actor.TenantID {
		return domain.CustomerSecurityPackage{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopePackageRead, resourceRefs{ProductID: pkg.ProductID, ReleaseID: pkg.ReleaseID, CustomerPackageID: pkg.ID}); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	if !pkg.ExpiresAt.After(l.now()) {
		return domain.CustomerSecurityPackage{}, ErrConflict
	}
	pkg.AccessCount++
	l.customerPackages[pkg.ID] = pkg
	_, _ = l.appendChainLocked(actor.TenantID, "customer_package.accessed", "customer_security_package", pkg.ID, actorType(actor), actorID(actor), pkg.ManifestHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	return pkg, nil
}

func (s packageReportService) ExportCustomerSecurityPackageArchive(ctx context.Context, actor domain.Actor, id string) (CustomerPackageArchive, error) {
	l := s.ledger
	pkg, err := l.AccessCustomerSecurityPackage(ctx, actor, id)
	if err != nil {
		return CustomerPackageArchive{}, err
	}
	return customerPackageArchive(pkg)
}

func (s packageReportService) ExportCustomerPortalPackageArchive(ctx context.Context, token string) (CustomerPackageArchive, error) {
	return s.ExportCustomerPortalPackageArchiveWithAcceptance(ctx, token, CustomerPortalAcceptanceInput{})
}

func (s packageReportService) ExportCustomerPortalPackageArchiveWithAcceptance(ctx context.Context, token string, in CustomerPortalAcceptanceInput) (CustomerPackageArchive, error) {
	l := s.ledger
	pkg, err := l.identityService().accessCustomerPortalPackage(ctx, token, in, "customer_portal_package.downloaded")
	if err != nil {
		return CustomerPackageArchive{}, err
	}
	return customerPackageArchive(pkg)
}

func (s packageReportService) SecurityReviewPackageReport(ctx context.Context, actor domain.Actor, packageID string) (domain.SecurityReviewPackageReport, error) {
	l := s.ledger
	pkg, err := l.AccessCustomerSecurityPackage(ctx, actor, packageID)
	if err != nil {
		return domain.SecurityReviewPackageReport{}, err
	}
	ids := []string{}
	switch evidenceIDs := pkg.Manifest["evidence_ids"].(type) {
	case []string:
		ids = append(ids, evidenceIDs...)
	case []any:
		for _, id := range evidenceIDs {
			if value, ok := id.(string); ok {
				ids = append(ids, value)
			}
		}
	}
	return domain.SecurityReviewPackageReport{ReportType: "security_review_package", TemplateVersion: "security-review-package.v1.0.0", PackageID: pkg.ID, ProductID: pkg.ProductID, ReleaseID: pkg.ReleaseID, EvidenceIDs: ids, Assumptions: []string{"Report includes only package-scoped evidence metadata."}, Limitations: []string{"This report supports customer review but is not a compliance, legal, or secure-release conclusion."}, GeneratedAt: l.now()}, nil
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
	readme := "Evydence customer security package\n\n" +
		"This ZIP contains a scoped package manifest, package metadata, and verification guidance.\n" +
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
		body, err := json.MarshalIndent(entry.body, "", "  ")
		if err != nil {
			_ = zw.Close()
			return CustomerPackageArchive{}, err
		}
		body = append(body, '\n')
		if err := addZIPFile(zw, entry.name, body); err != nil {
			_ = zw.Close()
			return CustomerPackageArchive{}, err
		}
	}
	if err := addZIPFile(zw, "README.txt", []byte(readme)); err != nil {
		_ = zw.Close()
		return CustomerPackageArchive{}, err
	}
	if pkg.DistributionWatermark != "" {
		if err := addZIPFile(zw, "WATERMARK.txt", []byte(pkg.DistributionWatermark+"\n")); err != nil {
			_ = zw.Close()
			return CustomerPackageArchive{}, err
		}
	}
	if err := addZIPFile(zw, "report.html", customerPackageHTMLReport(pkg, metadata, verification)); err != nil {
		_ = zw.Close()
		return CustomerPackageArchive{}, err
	}
	if err := zw.Close(); err != nil {
		return CustomerPackageArchive{}, err
	}
	body := buf.Bytes()
	return CustomerPackageArchive{PackageID: pkg.ID, Filename: "evydence-customer-package-" + pkg.ID + ".zip", MediaType: "application/zip", Bytes: body, Hash: hashBytes(body), Size: int64(len(body))}, nil
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
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>")
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
			b.WriteString("<h3>VEX Documents</h3><table><thead><tr><th>ID</th><th>Format</th><th>Author</th><th>Statements</th><th>Status Summary</th></tr></thead><tbody>")
			for _, record := range vexDocuments {
				b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(record["id"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["format"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["author"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["statement_count"])) + "</td><td>" + packageHTMLEscape(packageHTMLJSON(record["status_summary"])) + "</td></tr>")
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

func addZIPFile(zw *zip.Writer, name string, body []byte) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(0o644)
	header.Modified = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	writer, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = writer.Write(body)
	return err
}

func (s packageReportService) CRAReadinessHTMLPackage(ctx context.Context, actor domain.Actor, productID, releaseID string) (domain.HTMLReportPackage, error) {
	l := s.ledger
	report, err := l.CRAReadinessReport(ctx, actor, CRAReadinessReportInput{ProductID: productID, ReleaseID: releaseID})
	if err != nil {
		return domain.HTMLReportPackage{}, err
	}
	htmlBody := "<!doctype html><html><head><meta charset=\"utf-8\"><title>CRA readiness</title></head><body><h1>CRA readiness</h1><p>Result: " + html.EscapeString(report.Result) + "</p><h2>Limitations</h2><ul>"
	for _, limitation := range report.Limitations {
		htmlBody += "<li>" + html.EscapeString(limitation) + "</li>"
	}
	htmlBody += "</ul></body></html>"
	hash := hashBytes([]byte(htmlBody))
	l.mu.Lock()
	defer l.mu.Unlock()
	pkg := domain.HTMLReportPackage{ID: newID("html"), TenantID: actor.TenantID, ReportType: "cra_readiness", ProductID: productID, ReleaseID: releaseID, HTML: htmlBody, Hash: hash, SchemaVersion: "html-report-package.v1.0.0", CreatedAt: l.now()}
	l.htmlReports[pkg.ID] = pkg
	_, _ = l.appendChainLocked(actor.TenantID, "html_report.generated", "html_report", pkg.ID, "api_key", actor.KeyID, hash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.HTMLReportPackage{}, err
	}
	return pkg, nil
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
	if err := ctx.Err(); err != nil {
		return domain.ControlFramework{}, err
	}
	if err := require(actor, ScopeControlsAdmin); err != nil {
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
	l.frameworks[framework.ID] = framework
	for _, templateControl := range selected.Controls {
		control := templateControl
		control.ID = newID("ctrl")
		control.TenantID = actor.TenantID
		control.FrameworkID = framework.ID
		control.SchemaVersion = domain.SecurityControlSchemaVersion
		control.CreatedAt = l.now()
		l.controls[control.ID] = control
	}
	_, _ = l.appendChainLocked(actor.TenantID, "control_framework_template.installed", "control_framework", framework.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ControlFramework{}, err
	}
	return framework, nil
}

func (s packageReportService) CreateCustomReportTemplate(ctx context.Context, actor domain.Actor, in CreateReportTemplateInput) (domain.CustomReportTemplate, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.CustomReportTemplate{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.CustomReportTemplate{}, err
	}
	in.Name, in.Version, in.ReportType = strings.TrimSpace(in.Name), strings.TrimSpace(in.Version), strings.TrimSpace(in.ReportType)
	if in.Name == "" || in.Version == "" || in.ReportType == "" || len(in.AllowedFields) == 0 {
		return domain.CustomReportTemplate{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tpl := domain.CustomReportTemplate{ID: newID("rptpl"), TenantID: actor.TenantID, Name: in.Name, Version: in.Version, ReportType: in.ReportType, AllowedFields: sortedStrings(in.AllowedFields), Template: strings.TrimSpace(in.Template), SchemaVersion: domain.ReportTemplateSchemaVersion, CreatedAt: l.now()}
	l.reportTemplates[tpl.ID] = tpl
	_, _ = l.appendChainLocked(actor.TenantID, "report_template.created", "report_template", tpl.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CustomReportTemplate{}, err
	}
	return tpl, nil
}

func (s packageReportService) RenderCustomReport(ctx context.Context, actor domain.Actor, in RenderReportInput) (domain.RenderedCustomReport, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.RenderedCustomReport{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.RenderedCustomReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tpl, ok := l.reportTemplates[strings.TrimSpace(in.TemplateID)]
	if !ok || tpl.TenantID != actor.TenantID {
		return domain.RenderedCustomReport{}, ErrNotFound
	}
	output := map[string]any{}
	source := map[string]any{"subject_type": in.SubjectType, "subject_id": in.SubjectID, "generated_at": l.now().UTC().Format(time.RFC3339)}
	for _, field := range tpl.AllowedFields {
		if value, ok := source[field]; ok {
			output[field] = value
		}
	}
	hash, err := canonicalAnyHash(output)
	if err != nil {
		return domain.RenderedCustomReport{}, err
	}
	rendered := domain.RenderedCustomReport{ID: newID("rr"), TenantID: actor.TenantID, TemplateID: tpl.ID, SubjectType: strings.TrimSpace(in.SubjectType), SubjectID: strings.TrimSpace(in.SubjectID), Output: output, Hash: hash, SchemaVersion: "rendered-report.v1.0.0", CreatedAt: l.now()}
	l.renderedReports[rendered.ID] = rendered
	_, _ = l.appendChainLocked(actor.TenantID, "report_template.rendered", "rendered_report", rendered.ID, "api_key", actor.KeyID, hash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.RenderedCustomReport{}, err
	}
	return rendered, nil
}

func (s packageReportService) ExportEvidenceBundle(ctx context.Context, actor domain.Actor, releaseID string, evidenceIDs []string) (domain.EvidenceBundle, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.EvidenceBundle{}, err
	}
	if err := require(actor, ScopeBundleRead); err != nil {
		return domain.EvidenceBundle{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ids := []string{}
	if len(evidenceIDs) == 0 {
		if releaseID != "" {
			release, ok := l.releases[strings.TrimSpace(releaseID)]
			if !ok || release.TenantID != actor.TenantID {
				return domain.EvidenceBundle{}, ErrNotFound
			}
			if err := l.authorizeResourceLocked(actor, ScopeBundleRead, resourceRefs{ReleaseID: release.ID}); err != nil {
				return domain.EvidenceBundle{}, err
			}
		} else if err := l.authorizeResourceLocked(actor, ScopeBundleRead, resourceRefs{}); err != nil {
			return domain.EvidenceBundle{}, err
		}
		for _, item := range l.evidence {
			if item.TenantID == actor.TenantID && (releaseID == "" || item.ReleaseID == releaseID) && l.resourceAllowedLocked(actor, ScopeBundleRead, refsForEvidence(item)) {
				ids = append(ids, item.ID)
			}
		}
	} else {
		for _, id := range evidenceIDs {
			item, ok := l.evidence[strings.TrimSpace(id)]
			if !ok || item.TenantID != actor.TenantID {
				return domain.EvidenceBundle{}, ErrNotFound
			}
			if err := l.authorizeResourceLocked(actor, ScopeBundleRead, refsForEvidence(item)); err != nil {
				return domain.EvidenceBundle{}, err
			}
			ids = append(ids, item.ID)
		}
	}
	sort.Strings(ids)
	head := ""
	if entries := l.chain[actor.TenantID]; len(entries) > 0 {
		head = entries[len(entries)-1].EntryHash
	}
	manifest := map[string]any{
		"bundle_version":      domain.EvidenceBundleSchemaVersion,
		"tenant_id":           actor.TenantID,
		"release_id":          releaseID,
		"evidence_ids":        ids,
		"audit_chain_head":    head,
		"object_lock_proofs":  l.packageObjectLockProofsLocked(actor.TenantID),
		"verification":        "Run evydence verify-evidence-bundle <bundle.json> offline.",
		"verification_limits": []string{"Object-lock proof records reflect Evydence verification metadata and do not prove legal compliance, provider IAM correctness, or complete WORM enforcement."},
	}
	hash, err := canonicalAnyHash(manifest)
	if err != nil {
		return domain.EvidenceBundle{}, err
	}
	sig, err := l.signLocked(actor.TenantID, "evidence_bundle", "pending", []byte(hash))
	if err != nil {
		return domain.EvidenceBundle{}, err
	}
	bundle := domain.EvidenceBundle{ID: newID("eb"), TenantID: actor.TenantID, ReleaseID: releaseID, EvidenceIDs: ids, Manifest: manifest, ManifestHash: hash, SignatureRefs: []string{sig.ID}, VerificationText: "Verify manifest_hash over manifest canonical JSON and signature references with tenant public keys.", SchemaVersion: domain.EvidenceBundleSchemaVersion, CreatedAt: l.now()}
	l.evidenceBundles[bundle.ID] = bundle
	_, _ = l.appendChainLocked(actor.TenantID, "evidence_bundle.exported", "evidence_bundle", bundle.ID, "api_key", actor.KeyID, hash, sig.ID)
	if err := l.persistLocked(ctx); err != nil {
		return domain.EvidenceBundle{}, err
	}
	return bundle, nil
}

func (s packageReportService) ImportEvidenceBundle(ctx context.Context, actor domain.Actor, bundle domain.EvidenceBundle) (domain.EvidenceBundleImport, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.EvidenceBundleImport{}, err
	}
	if err := require(actor, ScopeBundleWrite); err != nil {
		return domain.EvidenceBundleImport{}, err
	}
	hash, err := canonicalAnyHash(bundle.Manifest)
	if err != nil || hash != bundle.ManifestHash {
		return domain.EvidenceBundleImport{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record := domain.EvidenceBundleImport{ID: newID("ebi"), TenantID: actor.TenantID, BundleHash: bundle.ManifestHash, Result: "accepted", ImportedCount: len(bundle.EvidenceIDs), SchemaVersion: domain.EvidenceBundleImportVersion, CreatedAt: l.now()}
	l.bundleImports[record.ID] = record
	_, _ = l.appendChainLocked(actor.TenantID, "evidence_bundle.imported", "evidence_bundle_import", record.ID, "api_key", actor.KeyID, bundle.ManifestHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.EvidenceBundleImport{}, err
	}
	return record, nil
}

func (l *Ledger) CreateDSSETrustRoot(ctx context.Context, actor domain.Actor, in CreateDSSETrustRootInput) (domain.DSSETrustRoot, error) {
	if err := ctx.Err(); err != nil {
		return domain.DSSETrustRoot{}, err
	}
	if err := require(actor, ScopeKeysAdmin); err != nil {
		return domain.DSSETrustRoot{}, err
	}
	in.Name, in.KeyID, in.Algorithm, in.PublicKey = strings.TrimSpace(in.Name), strings.TrimSpace(in.KeyID), strings.TrimSpace(in.Algorithm), strings.TrimSpace(in.PublicKey)
	if in.Name == "" || in.KeyID == "" || in.Algorithm != "Ed25519" {
		return domain.DSSETrustRoot{}, ErrValidation
	}
	pub, err := base64.StdEncoding.DecodeString(in.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return domain.DSSETrustRoot{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	root := domain.DSSETrustRoot{ID: newID("dtr"), TenantID: actor.TenantID, Name: in.Name, KeyID: in.KeyID, Algorithm: in.Algorithm, PublicKey: in.PublicKey, Status: "active", SchemaVersion: domain.DSSETrustRootSchemaVersion, CreatedAt: l.now()}
	l.dsseTrustRoots[root.ID] = root
	_, _ = l.appendChainLocked(actor.TenantID, "dsse_trust_root.created", "dsse_trust_root", root.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.DSSETrustRoot{}, err
	}
	return root, nil
}

func (l *Ledger) VerifyDSSEAttestationSignature(ctx context.Context, actor domain.Actor, attestationID string) (domain.VerificationResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.VerificationResult{}, err
	}
	if err := require(actor, ScopeVerifyRead); err != nil {
		return domain.VerificationResult{}, err
	}
	l.mu.Lock()
	att, ok := l.attestations[strings.TrimSpace(attestationID)]
	if !ok || att.TenantID != actor.TenantID {
		l.mu.Unlock()
		return domain.VerificationResult{}, ErrNotFound
	}
	roots := []domain.DSSETrustRoot{}
	for _, root := range l.dsseTrustRoots {
		if root.TenantID == actor.TenantID && root.Status == "active" {
			roots = append(roots, root)
		}
	}
	l.mu.Unlock()
	if l.objects == nil || att.PayloadRef == "" {
		return domain.VerificationResult{}, ErrValidation
	}
	object, err := l.objects.Get(ctx, strings.TrimPrefix(att.PayloadRef, "object://"))
	if err != nil {
		return domain.VerificationResult{}, err
	}
	var envelope dsseEnvelope
	if err := json.Unmarshal(object.Bytes, &envelope); err != nil {
		return domain.VerificationResult{}, ErrValidation
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return domain.VerificationResult{}, ErrValidation
	}
	checks := []domain.VerifyCheck{}
	passed := false
	for _, sig := range envelope.Signatures {
		for _, root := range roots {
			if sig.KeyID != root.KeyID {
				continue
			}
			pub, _ := base64.StdEncoding.DecodeString(root.PublicKey)
			value, err := base64.StdEncoding.DecodeString(sig.Sig)
			if err == nil && ed25519.Verify(ed25519.PublicKey(pub), payload, value) {
				passed = true
				checks = append(checks, domain.VerifyCheck{Name: "dsse_signature", Result: "passed", Detail: root.KeyID})
			}
		}
	}
	result := "passed"
	if !passed {
		result = "failed"
		checks = append(checks, domain.VerifyCheck{Name: "dsse_signature", Result: "failed"})
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	vr := domain.VerificationResult{ID: newID("vr"), TenantID: actor.TenantID, SubjectType: "build_attestation", SubjectID: att.ID, Result: result, Checks: checks, VerifiedAt: l.now()}
	l.verifications[vr.ID] = vr
	if err := l.persistLocked(ctx); err != nil {
		return domain.VerificationResult{}, err
	}
	if result != "passed" {
		return vr, ErrVerificationFailed
	}
	return vr, nil
}

func (l *Ledger) packageEvidenceIDsLocked(tenantID, productID, releaseID string, profile domain.RedactionProfile) []string {
	allowed := map[string]struct{}{}
	for _, typ := range profile.AllowedTypes {
		allowed[typ] = struct{}{}
	}
	ids := []string{}
	for _, item := range l.evidence {
		if item.TenantID != tenantID {
			continue
		}
		if releaseID != "" {
			if item.ReleaseID != releaseID {
				continue
			}
		} else if productID != "" && item.ProductID != productID {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[item.Type]; !ok {
				continue
			}
		}
		ids = append(ids, item.ID)
	}
	sort.Strings(ids)
	return ids
}

func (l *Ledger) packageDecisionSummariesLocked(tenantID, releaseID string, profile domain.RedactionProfile) []map[string]any {
	if !profileAllowsPackageType(profile, "vulnerability_decision") {
		return nil
	}
	excluded := profileExcludedFields(profile)
	summaries := []map[string]any{}
	for _, decision := range l.decisions {
		if decision.TenantID != tenantID || decision.ReleaseID != releaseID || decision.SupersededBy != "" || !decision.CustomerVisible {
			continue
		}
		summary := map[string]any{
			"id":                  decision.ID,
			"finding_id":          decision.FindingID,
			"scan_id":             decision.ScanID,
			"release_id":          decision.ReleaseID,
			"vulnerability":       decision.Vulnerability,
			"component":           decision.Component,
			"sbom_id":             decision.SBOMID,
			"sbom_component_purl": decision.SBOMComponentPURL,
			"sbom_component_name": decision.SBOMComponentName,
			"status":              decision.Status,
			"impact_statement":    decision.ImpactStatement,
			"source":              decision.Source,
			"created_at":          decision.CreatedAt.UTC().Format(time.RFC3339),
		}
		if decision.ReviewedAt != nil && !excluded["reviewed_at"] {
			summary["reviewed_at"] = decision.ReviewedAt.UTC().Format(time.RFC3339)
		}
		if decision.ReviewDueAt != nil && !excluded["review_due_at"] {
			summary["review_due_at"] = decision.ReviewDueAt.UTC().Format(time.RFC3339)
		}
		if decision.ActionStatement != "" && !excluded["action_statement"] {
			summary["action_statement"] = decision.ActionStatement
		}
		if decision.Justification != "" && !excluded["justification"] {
			summary["justification"] = decision.Justification
		}
		if decision.EvidenceID != "" && !excluded["evidence_id"] {
			summary["evidence_id"] = decision.EvidenceID
		}
		if decision.VEXDocumentID != "" && !excluded["vex_document_id"] {
			summary["vex_document_id"] = decision.VEXDocumentID
		}
		if len(decision.EvidenceIDs) > 0 && !excluded["evidence_ids"] {
			summary["evidence_ids"] = append([]string(nil), decision.EvidenceIDs...)
		}
		if len(decision.SupportingRefs) > 0 && !excluded["supporting_refs"] {
			summary["supporting_refs"] = cloneSubjectRefs(decision.SupportingRefs)
		}
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(i, j int) bool {
		left := summaries[i]["vulnerability"].(string) + "\x00" + summaries[i]["id"].(string)
		right := summaries[j]["vulnerability"].(string) + "\x00" + summaries[j]["id"].(string)
		return left < right
	})
	return summaries
}

func profileAllowsPackageType(profile domain.RedactionProfile, typ string) bool {
	for _, allowed := range profile.AllowedTypes {
		if strings.TrimSpace(allowed) == typ {
			return true
		}
	}
	return false
}

func profileExcludedFields(profile domain.RedactionProfile) map[string]bool {
	excluded := map[string]bool{}
	for _, field := range profile.ExcludedFields {
		excluded[strings.TrimSpace(field)] = true
	}
	return excluded
}

func builtinTemplatePacks() []domain.ControlFrameworkTemplatePack {
	return []domain.ControlFrameworkTemplatePack{
		{ID: "tpl_cra_readiness", Name: "Evydence CRA Readiness", Slug: "evydence-cra-readiness", Version: "2026.05", Description: "Starter technical evidence controls for CRA readiness tracking.", SchemaVersion: "control-framework-template-pack.v1.0.0", Controls: []domain.SecurityControl{
			{Code: "CRA-SBOM", Title: "SBOM evidence", Objective: "Release records SBOM evidence.", EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: "sbom", Required: true}}, Limitations: []string{"SBOM presence does not prove completeness."}},
			{Code: "CRA-VULN", Title: "Vulnerability evidence", Objective: "Release records vulnerability scan and decisions.", EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: "vulnerability_scan", Required: true}}},
		}},
		{ID: "tpl_nist_ssdf_lite", Name: "NIST SSDF Lite", Slug: "nist-ssdf-lite", Version: "2026.05", Description: "Small starter control pack for secure development evidence.", SchemaVersion: "control-framework-template-pack.v1.0.0", Controls: []domain.SecurityControl{
			{Code: "SSDF-BUILD", Title: "Build provenance", Objective: "Release has build and attestation evidence.", EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: "build", Required: true}, {Type: "build_attestation", Required: true}}},
		}},
		{ID: "tpl_soc2_technical_lite", Name: "SOC 2 Technical Evidence Lite", Slug: "soc2-technical-lite", Version: "2026.05", Description: "Starter technical evidence controls for SOC 2-style review preparation.", SchemaVersion: "control-framework-template-pack.v1.0.0", Controls: []domain.SecurityControl{
			{Code: "SOC2-CHANGE", Title: "Change evidence", Objective: "Release records source, build, and approval evidence for change review.", EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: "build", Required: true}, {Type: "artifact", Required: true}, {Type: "release_bundle", Required: true}}, Limitations: []string{"This pack organizes technical evidence only and does not state SOC 2 control effectiveness."}},
			{Code: "SOC2-VULN", Title: "Vulnerability review evidence", Objective: "Release records vulnerability scan evidence and decisions or exceptions.", EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: "vulnerability_scan", Required: true}, {Type: "vulnerability_decision", Required: false}, {Type: "exception", Required: false}}},
		}},
		{ID: "tpl_iso27001_technical_lite", Name: "ISO 27001 Technical Evidence Lite", Slug: "iso27001-technical-lite", Version: "2026.05", Description: "Starter technical evidence controls for ISO 27001-style evidence organization.", SchemaVersion: "control-framework-template-pack.v1.0.0", Controls: []domain.SecurityControl{
			{Code: "ISO-ASSET", Title: "Software asset evidence", Objective: "Release records artifacts, SBOM, and dependency evidence.", EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: "artifact", Required: true}, {Type: "sbom", Required: true}}, Limitations: []string{"Artifact and SBOM evidence does not prove inventory completeness."}},
			{Code: "ISO-CHANGE", Title: "Release change evidence", Objective: "Release records build provenance and bundle verification evidence.", EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: "build", Required: true}, {Type: "build_attestation", Required: false}, {Type: "release_bundle", Required: true}}},
		}},
	}
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

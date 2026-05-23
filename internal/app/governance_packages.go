package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"html"
	"sort"
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

func (l *Ledger) CreateRedactionProfile(ctx context.Context, actor domain.Actor, in CreateRedactionProfileInput) (domain.RedactionProfile, error) {
	if err := ctx.Err(); err != nil {
		return domain.RedactionProfile{}, err
	}
	if err := require(actor, ScopePackageWrite); err != nil {
		return domain.RedactionProfile{}, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
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

func (l *Ledger) CreateCustomerSecurityPackage(ctx context.Context, actor domain.Actor, in CreateCustomerPackageInput) (domain.CustomerSecurityPackage, error) {
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
	manifest := map[string]any{
		"package_version":      domain.CustomerPackageSchemaVersion,
		"title":                in.Title,
		"product_id":           in.ProductID,
		"release_id":           in.ReleaseID,
		"redaction_profile_id": profile.ID,
		"evidence_ids":         evidenceIDs,
		"limitations":          []string{"Package contents are scoped and redacted; raw evidence payload bytes are not included in this manifest."},
	}
	hash, err := canonicalAnyHash(manifest)
	if err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	pkg := domain.CustomerSecurityPackage{ID: newID("csp"), TenantID: actor.TenantID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, RedactionProfileID: profile.ID, Title: in.Title, State: "generated", Manifest: manifest, ManifestHash: hash, ExpiresAt: in.ExpiresAt.UTC(), SchemaVersion: domain.CustomerPackageSchemaVersion, CreatedAt: l.now()}
	l.customerPackages[pkg.ID] = pkg
	_, _ = l.appendChainLocked(actor.TenantID, "customer_package.generated", "customer_security_package", pkg.ID, "api_key", actor.KeyID, hash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	return pkg, nil
}

func (l *Ledger) AccessCustomerSecurityPackage(ctx context.Context, actor domain.Actor, id string) (domain.CustomerSecurityPackage, error) {
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

func (l *Ledger) SecurityReviewPackageReport(ctx context.Context, actor domain.Actor, packageID string) (domain.SecurityReviewPackageReport, error) {
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

func (l *Ledger) CRAReadinessHTMLPackage(ctx context.Context, actor domain.Actor, productID, releaseID string) (domain.HTMLReportPackage, error) {
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

func (l *Ledger) CreateCustomReportTemplate(ctx context.Context, actor domain.Actor, in CreateReportTemplateInput) (domain.CustomReportTemplate, error) {
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

func (l *Ledger) RenderCustomReport(ctx context.Context, actor domain.Actor, in RenderReportInput) (domain.RenderedCustomReport, error) {
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

func (l *Ledger) ExportEvidenceBundle(ctx context.Context, actor domain.Actor, releaseID string, evidenceIDs []string) (domain.EvidenceBundle, error) {
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
	manifest := map[string]any{"bundle_version": domain.EvidenceBundleSchemaVersion, "tenant_id": actor.TenantID, "release_id": releaseID, "evidence_ids": ids, "audit_chain_head": head, "verification": "Run evydence verify-evidence-bundle <bundle.json> offline."}
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

func (l *Ledger) ImportEvidenceBundle(ctx context.Context, actor domain.Actor, bundle domain.EvidenceBundle) (domain.EvidenceBundleImport, error) {
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
		if item.TenantID != tenantID || (productID != "" && item.ProductID != productID) || (releaseID != "" && item.ReleaseID != releaseID) {
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

package app

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

const (
	controlStatusSatisfied     = "satisfied"
	controlStatusPartial       = "partial"
	controlStatusMissing       = "missing"
	controlStatusWaived        = "waived"
	controlStatusNotApplicable = "not_applicable"
	controlStatusUnknown       = "unknown"

	confidenceHigh        = "high"
	confidenceMedium      = "medium"
	confidenceLow         = "low"
	confidenceUnsupported = "unsupported"
)

type CreateControlFrameworkInput struct {
	Name        string
	Slug        string
	Version     string
	Description string
}

type CreateSecurityControlInput struct {
	FrameworkID          string
	Code                 string
	Title                string
	Objective            string
	EvidenceRequirements []domain.ControlEvidenceRequirement
	Applicability        []string
	Limitations          []string
}

type LinkControlEvidenceInput struct {
	EvidenceType string
	SubjectType  string
	SubjectID    string
	ProductID    string
	ReleaseID    string
	Confidence   string
	Notes        string
}

type ControlCoverageReportInput struct {
	FrameworkID string
	ProductID   string
	ReleaseID   string
}

type CRAReadinessReportInput struct {
	ProductID string
	ReleaseID string
}

func (l *Ledger) CreateControlFramework(ctx context.Context, actor domain.Actor, in CreateControlFrameworkInput) (domain.ControlFramework, error) {
	if err := ctx.Err(); err != nil {
		return domain.ControlFramework{}, err
	}
	if err := require(actor, ScopeControlsAdmin); err != nil {
		return domain.ControlFramework{}, err
	}
	name := strings.TrimSpace(in.Name)
	slug := strings.TrimSpace(in.Slug)
	version := strings.TrimSpace(in.Version)
	if slug == "" {
		slug = slugify(name)
	}
	if name == "" || slug == "" || version == "" {
		return domain.ControlFramework{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, existing := range l.frameworks {
		if existing.TenantID == actor.TenantID && existing.Slug == slug && existing.Version == version {
			return domain.ControlFramework{}, ErrConflict
		}
	}
	framework := domain.ControlFramework{
		ID:            newID("fw"),
		TenantID:      actor.TenantID,
		Name:          name,
		Slug:          slug,
		Version:       version,
		Description:   strings.TrimSpace(in.Description),
		Status:        "active",
		SchemaVersion: domain.ControlFrameworkSchemaVersion,
		CreatedAt:     l.now(),
	}
	l.frameworks[framework.ID] = framework
	_, _ = l.appendChainLocked(actor.TenantID, "control_framework.created", "control_framework", framework.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ControlFramework{}, err
	}
	return framework, nil
}

func (l *Ledger) ListControlFrameworks(ctx context.Context, actor domain.Actor) ([]domain.ControlFramework, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeControlsRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.ControlFramework{}
	for _, framework := range l.frameworks {
		if framework.TenantID == actor.TenantID {
			out = append(out, framework)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Slug == out[j].Slug {
			return out[i].Version < out[j].Version
		}
		return out[i].Slug < out[j].Slug
	})
	return out, nil
}

func (l *Ledger) CreateSecurityControl(ctx context.Context, actor domain.Actor, in CreateSecurityControlInput) (domain.SecurityControl, error) {
	if err := ctx.Err(); err != nil {
		return domain.SecurityControl{}, err
	}
	if err := require(actor, ScopeControlsAdmin); err != nil {
		return domain.SecurityControl{}, err
	}
	in.FrameworkID = strings.TrimSpace(in.FrameworkID)
	code := strings.TrimSpace(in.Code)
	title := strings.TrimSpace(in.Title)
	objective := strings.TrimSpace(in.Objective)
	if in.FrameworkID == "" || code == "" || title == "" || objective == "" {
		return domain.SecurityControl{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	framework, ok := l.frameworks[in.FrameworkID]
	if !ok || framework.TenantID != actor.TenantID {
		return domain.SecurityControl{}, ErrNotFound
	}
	requirements, err := normalizeControlRequirements(in.EvidenceRequirements)
	if err != nil {
		return domain.SecurityControl{}, err
	}
	for _, existing := range l.controls {
		if existing.TenantID == actor.TenantID && existing.FrameworkID == framework.ID && existing.Code == code {
			return domain.SecurityControl{}, ErrConflict
		}
	}
	control := domain.SecurityControl{
		ID:                   newID("ctrl"),
		TenantID:             actor.TenantID,
		FrameworkID:          framework.ID,
		Code:                 code,
		Title:                title,
		Objective:            objective,
		EvidenceRequirements: requirements,
		Applicability:        sortedStrings(in.Applicability),
		Limitations:          cleanStrings(in.Limitations),
		SchemaVersion:        domain.SecurityControlSchemaVersion,
		CreatedAt:            l.now(),
	}
	l.controls[control.ID] = control
	_, _ = l.appendChainLocked(actor.TenantID, "security_control.created", "security_control", control.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SecurityControl{}, err
	}
	return control, nil
}

func (l *Ledger) GetSecurityControl(ctx context.Context, actor domain.Actor, id string) (domain.SecurityControl, error) {
	if err := ctx.Err(); err != nil {
		return domain.SecurityControl{}, err
	}
	if err := require(actor, ScopeControlsRead); err != nil {
		return domain.SecurityControl{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	control, ok := l.controls[strings.TrimSpace(id)]
	if !ok || control.TenantID != actor.TenantID {
		return domain.SecurityControl{}, ErrNotFound
	}
	return control, nil
}

func (l *Ledger) LinkControlEvidence(ctx context.Context, actor domain.Actor, controlID string, in LinkControlEvidenceInput) (domain.ControlEvidence, error) {
	if err := ctx.Err(); err != nil {
		return domain.ControlEvidence{}, err
	}
	if err := require(actor, ScopeControlsWrite); err != nil {
		return domain.ControlEvidence{}, err
	}
	controlID = strings.TrimSpace(controlID)
	in.EvidenceType = strings.TrimSpace(in.EvidenceType)
	in.SubjectType = strings.TrimSpace(in.SubjectType)
	in.SubjectID = strings.TrimSpace(in.SubjectID)
	in.ProductID = strings.TrimSpace(in.ProductID)
	in.ReleaseID = strings.TrimSpace(in.ReleaseID)
	in.Confidence = strings.TrimSpace(in.Confidence)
	if controlID == "" || !supportedControlEvidenceType(in.EvidenceType) || in.SubjectType == "" || in.SubjectID == "" || !validControlConfidence(in.Confidence) {
		return domain.ControlEvidence{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	control, ok := l.controls[controlID]
	if !ok || control.TenantID != actor.TenantID {
		return domain.ControlEvidence{}, ErrNotFound
	}
	if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
		return domain.ControlEvidence{}, err
	}
	if !l.controlSubjectExistsLocked(actor.TenantID, in.SubjectType, in.SubjectID, in.ProductID, in.ReleaseID) {
		return domain.ControlEvidence{}, ErrNotFound
	}
	for _, existing := range l.controlLinks {
		if existing.TenantID == actor.TenantID && existing.ControlID == control.ID && existing.EvidenceType == in.EvidenceType && existing.SubjectType == in.SubjectType && existing.SubjectID == in.SubjectID && existing.ProductID == in.ProductID && existing.ReleaseID == in.ReleaseID {
			return existing, nil
		}
	}
	link := domain.ControlEvidence{
		ID:            newID("ce"),
		TenantID:      actor.TenantID,
		ControlID:     control.ID,
		EvidenceType:  in.EvidenceType,
		SubjectType:   in.SubjectType,
		SubjectID:     in.SubjectID,
		ProductID:     in.ProductID,
		ReleaseID:     in.ReleaseID,
		Confidence:    in.Confidence,
		Notes:         strings.TrimSpace(in.Notes),
		SchemaVersion: domain.ControlEvidenceSchemaVersion,
		CreatedAt:     l.now(),
	}
	l.controlLinks[link.ID] = link
	_, _ = l.appendChainLocked(actor.TenantID, "control_evidence.linked", "control_evidence", link.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ControlEvidence{}, err
	}
	return link, nil
}

func (l *Ledger) ListControlEvidence(ctx context.Context, actor domain.Actor, controlID, productID, releaseID string) ([]domain.ControlEvidence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeControlsRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.ControlEvidence{}
	for _, link := range l.controlLinks {
		if link.TenantID != actor.TenantID {
			continue
		}
		if controlID != "" && link.ControlID != controlID {
			continue
		}
		if productID != "" && link.ProductID != productID {
			continue
		}
		if releaseID != "" && link.ReleaseID != releaseID {
			continue
		}
		out = append(out, link)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (l *Ledger) ControlCoverageReport(ctx context.Context, actor domain.Actor, in ControlCoverageReportInput) (domain.ControlCoverageReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.ControlCoverageReport{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.ControlCoverageReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	report, err := l.controlCoverageReportLocked(actor.TenantID, in)
	if err != nil {
		return domain.ControlCoverageReport{}, err
	}
	return report, nil
}

func (l *Ledger) CRAReadinessReport(ctx context.Context, actor domain.Actor, in CRAReadinessReportInput) (domain.CRAReadinessReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.CRAReadinessReport{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.CRAReadinessReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if strings.TrimSpace(in.ProductID) == "" {
		return domain.CRAReadinessReport{}, ErrValidation
	}
	if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
		return domain.CRAReadinessReport{}, err
	}
	frameworkID := l.firstFrameworkIDLocked(actor.TenantID)
	coverage, err := l.controlCoverageReportLocked(actor.TenantID, ControlCoverageReportInput{FrameworkID: frameworkID, ProductID: in.ProductID, ReleaseID: in.ReleaseID})
	if err != nil {
		return domain.CRAReadinessReport{}, err
	}
	return domain.CRAReadinessReport{
		ReportType:         "cra_readiness",
		TemplateVersion:    domain.CRAReadinessTemplateVersion,
		ProductID:          in.ProductID,
		ReleaseID:          in.ReleaseID,
		Result:             coverage.Result,
		Controls:           coverage.Controls,
		MissingEvidence:    coverage.MissingEvidence,
		AcceptedExceptions: coverage.AcceptedExceptions,
		Assumptions:        []string{"This report organizes technical evidence for CRA readiness review and is not a legal compliance conclusion."},
		Limitations:        []string{"Readiness is based only on evidence, mappings, exceptions, and release records in this Evydence instance.", "Evidence presence does not prove SBOM completeness, scanner authority, secure release status, or legal sufficiency."},
		GeneratedAt:        l.now(),
	}, nil
}

func (l *Ledger) controlCoverageReportLocked(tenantID string, in ControlCoverageReportInput) (domain.ControlCoverageReport, error) {
	if strings.TrimSpace(in.ProductID) != "" || strings.TrimSpace(in.ReleaseID) != "" {
		if err := l.ensureScopeLocked(tenantID, in.ProductID, "", in.ReleaseID); err != nil {
			return domain.ControlCoverageReport{}, err
		}
	}
	frameworkID := strings.TrimSpace(in.FrameworkID)
	if frameworkID == "" {
		frameworkID = l.firstFrameworkIDLocked(tenantID)
	}
	if frameworkID == "" {
		return domain.ControlCoverageReport{}, ErrNotFound
	}
	framework, ok := l.frameworks[frameworkID]
	if !ok || framework.TenantID != tenantID {
		return domain.ControlCoverageReport{}, ErrNotFound
	}
	controls := l.controlsForFrameworkLocked(tenantID, framework.ID)
	items := make([]domain.ControlCoverageItem, 0, len(controls))
	missing := []string{}
	accepted := l.acceptedControlExceptionsLocked(tenantID, in.ReleaseID)
	result := "passed"
	for _, control := range controls {
		item := l.evaluateControlLocked(tenantID, control, in.ProductID, in.ReleaseID)
		items = append(items, item)
		missing = append(missing, item.Missing...)
		if item.Status == controlStatusMissing || item.Status == controlStatusPartial || item.Status == controlStatusUnknown {
			result = "failed"
		}
	}
	sort.Strings(missing)
	return domain.ControlCoverageReport{
		ReportType:         "control_coverage",
		TemplateVersion:    domain.ControlCoverageTemplateVersion,
		FrameworkID:        framework.ID,
		ProductID:          in.ProductID,
		ReleaseID:          in.ReleaseID,
		Result:             result,
		Controls:           items,
		MissingEvidence:    missing,
		AcceptedExceptions: accepted,
		Assumptions:        []string{"Control coverage organizes technical evidence and is not a legal compliance conclusion."},
		Limitations:        []string{"Coverage is based only on evidence links, exceptions, and controls recorded in this Evydence instance."},
		GeneratedAt:        l.now(),
	}, nil
}

func (l *Ledger) evaluateControlLocked(tenantID string, control domain.SecurityControl, productID, releaseID string) domain.ControlCoverageItem {
	if exception, ok := l.acceptedExceptionForControlLocked(tenantID, control.ID, releaseID); ok {
		return domain.ControlCoverageItem{ControlID: control.ID, Code: control.Code, Title: control.Title, Status: controlStatusWaived, Confidence: confidenceMedium, LinkedEvidence: nil, Explanation: "approved unexpired exception waives this control for the selected scope", Limitations: append([]string(nil), exception.Reason)}
	}
	if len(control.EvidenceRequirements) == 0 {
		return domain.ControlCoverageItem{ControlID: control.ID, Code: control.Code, Title: control.Title, Status: controlStatusUnknown, Confidence: confidenceUnsupported, Missing: []string{"evidence_requirement"}, Explanation: "control has no evidence requirements", Limitations: append([]string(nil), control.Limitations...)}
	}
	linked := []domain.ControlEvidence{}
	missing := []string{}
	stale := false
	for _, requirement := range control.EvidenceRequirements {
		if !requirement.Required {
			continue
		}
		matches := l.controlLinksForRequirementLocked(tenantID, control.ID, requirement, productID, releaseID)
		if len(matches) == 0 {
			missing = append(missing, requirement.Type)
			continue
		}
		for _, match := range matches {
			linked = append(linked, match)
			if requirement.FreshnessDays > 0 && l.controlEvidenceTimeLocked(match).Before(l.now().Add(-time.Duration(requirement.FreshnessDays)*24*time.Hour)) {
				stale = true
				missing = append(missing, "fresh_"+requirement.Type)
			}
		}
	}
	sort.Slice(linked, func(i, j int) bool { return linked[i].ID < linked[j].ID })
	sort.Strings(missing)
	status := controlStatusSatisfied
	explanation := "required control evidence is present"
	if len(linked) == 0 {
		status = controlStatusMissing
		explanation = "required control evidence is missing"
	} else if len(missing) > 0 || stale {
		status = controlStatusPartial
		explanation = "some required control evidence is missing or stale"
	}
	return domain.ControlCoverageItem{ControlID: control.ID, Code: control.Code, Title: control.Title, Status: status, Confidence: aggregateConfidence(linked), LinkedEvidence: linked, Missing: missing, Explanation: explanation, Limitations: append([]string(nil), control.Limitations...)}
}

func (l *Ledger) controlLinksForRequirementLocked(tenantID, controlID string, requirement domain.ControlEvidenceRequirement, productID, releaseID string) []domain.ControlEvidence {
	out := []domain.ControlEvidence{}
	for _, link := range l.controlLinks {
		if link.TenantID != tenantID || link.ControlID != controlID || link.EvidenceType != requirement.Type {
			continue
		}
		if productID != "" && link.ProductID != "" && link.ProductID != productID {
			continue
		}
		if releaseID != "" && link.ReleaseID != "" && link.ReleaseID != releaseID {
			continue
		}
		if !l.controlSubjectExistsLocked(tenantID, link.SubjectType, link.SubjectID, productID, releaseID) {
			continue
		}
		out = append(out, link)
	}
	return out
}

func (l *Ledger) controlSubjectExistsLocked(tenantID, subjectType, subjectID, productID, releaseID string) bool {
	switch subjectType {
	case "evidence", "evidence_item":
		item, ok := l.evidence[subjectID]
		return ok && item.TenantID == tenantID && scopeMatches(item.ProductID, productID) && scopeMatches(item.ReleaseID, releaseID)
	case "product":
		product, ok := l.products[subjectID]
		return ok && product.TenantID == tenantID && scopeMatches(product.ID, productID)
	case "release":
		release, ok := l.releases[subjectID]
		return ok && release.TenantID == tenantID && scopeMatches(release.ProductID, productID) && scopeMatches(release.ID, releaseID)
	case "artifact":
		artifact, ok := l.artifacts[subjectID]
		return ok && artifact.TenantID == tenantID
	case "sbom":
		sbom, ok := l.sboms[subjectID]
		return ok && sbom.TenantID == tenantID && scopeMatches(sbom.ReleaseID, releaseID)
	case "vulnerability_scan":
		scan, ok := l.scans[subjectID]
		return ok && scan.TenantID == tenantID && scopeMatches(scan.ReleaseID, releaseID)
	case "vex":
		vex, ok := l.vexDocuments[subjectID]
		return ok && vex.TenantID == tenantID && scopeMatches(vex.ReleaseID, releaseID)
	case "vulnerability_decision":
		decision, ok := l.decisions[subjectID]
		return ok && decision.TenantID == tenantID && scopeMatches(decision.ReleaseID, releaseID)
	case "finding", "vulnerability_finding":
		scan, _, ok := l.findFindingLocked(tenantID, subjectID)
		return ok && scopeMatches(scan.ReleaseID, releaseID)
	case "exception":
		exception, ok := l.exceptions[subjectID]
		return ok && exception.TenantID == tenantID && scopeMatches(exception.ReleaseID, releaseID)
	case "build":
		build, ok := l.buildRuns[subjectID]
		return ok && build.TenantID == tenantID && scopeMatches(build.ReleaseID, releaseID)
	case "build_attestation":
		attestation, ok := l.attestations[subjectID]
		if !ok || attestation.TenantID != tenantID {
			return false
		}
		build, ok := l.buildRuns[attestation.BuildID]
		return ok && build.TenantID == tenantID && scopeMatches(build.ReleaseID, releaseID)
	case "openapi_contract":
		contract, ok := l.contracts[subjectID]
		return ok && contract.TenantID == tenantID && scopeMatches(contract.ProductID, productID) && scopeMatches(contract.ReleaseID, releaseID)
	case "release_bundle":
		bundle, ok := l.bundles[subjectID]
		return ok && bundle.TenantID == tenantID && scopeMatches(bundle.ReleaseID, releaseID)
	default:
		return false
	}
}

func (l *Ledger) controlEvidenceTimeLocked(link domain.ControlEvidence) time.Time {
	switch link.SubjectType {
	case "evidence", "evidence_item":
		if item, ok := l.evidence[link.SubjectID]; ok {
			return item.ObservedAt
		}
	case "sbom":
		if sbom, ok := l.sboms[link.SubjectID]; ok {
			return sbom.CreatedAt
		}
	case "vulnerability_scan":
		if scan, ok := l.scans[link.SubjectID]; ok {
			return scan.CreatedAt
		}
	case "vex":
		if vex, ok := l.vexDocuments[link.SubjectID]; ok {
			return vex.CreatedAt
		}
	case "vulnerability_decision":
		if decision, ok := l.decisions[link.SubjectID]; ok {
			return decision.CreatedAt
		}
	case "exception":
		if exception, ok := l.exceptions[link.SubjectID]; ok {
			return exception.CreatedAt
		}
	case "build":
		if build, ok := l.buildRuns[link.SubjectID]; ok {
			return build.CreatedAt
		}
	case "build_attestation":
		if attestation, ok := l.attestations[link.SubjectID]; ok {
			return attestation.CreatedAt
		}
	case "openapi_contract":
		if contract, ok := l.contracts[link.SubjectID]; ok {
			return contract.CreatedAt
		}
	case "release_bundle":
		if bundle, ok := l.bundles[link.SubjectID]; ok {
			return bundle.CreatedAt
		}
	}
	return link.CreatedAt
}

func (l *Ledger) controlsForFrameworkLocked(tenantID, frameworkID string) []domain.SecurityControl {
	out := []domain.SecurityControl{}
	for _, control := range l.controls {
		if control.TenantID == tenantID && control.FrameworkID == frameworkID {
			out = append(out, control)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

func (l *Ledger) firstFrameworkIDLocked(tenantID string) string {
	frameworks := []domain.ControlFramework{}
	for _, framework := range l.frameworks {
		if framework.TenantID == tenantID {
			frameworks = append(frameworks, framework)
		}
	}
	sort.Slice(frameworks, func(i, j int) bool {
		if frameworks[i].Slug == frameworks[j].Slug {
			return frameworks[i].Version < frameworks[j].Version
		}
		return frameworks[i].Slug < frameworks[j].Slug
	})
	if len(frameworks) == 0 {
		return ""
	}
	return frameworks[0].ID
}

func (l *Ledger) acceptedExceptionForControlLocked(tenantID, controlID, releaseID string) (domain.Exception, bool) {
	for _, exception := range l.exceptions {
		if exception.TenantID != tenantID || exception.ControlID != controlID || !exception.Approved || !exception.ExpiresAt.After(l.now()) {
			continue
		}
		if releaseID != "" && exception.ReleaseID != releaseID {
			continue
		}
		return exception, true
	}
	return domain.Exception{}, false
}

func (l *Ledger) acceptedControlExceptionsLocked(tenantID, releaseID string) []domain.Exception {
	out := []domain.Exception{}
	for _, exception := range l.exceptions {
		if exception.TenantID != tenantID || exception.ControlID == "" || !exception.Approved || !exception.ExpiresAt.After(l.now()) {
			continue
		}
		if releaseID != "" && exception.ReleaseID != releaseID {
			continue
		}
		out = append(out, exception)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func normalizeControlRequirements(in []domain.ControlEvidenceRequirement) ([]domain.ControlEvidenceRequirement, error) {
	out := make([]domain.ControlEvidenceRequirement, 0, len(in))
	seen := map[string]struct{}{}
	for _, req := range in {
		req.Type = strings.TrimSpace(req.Type)
		if !supportedControlEvidenceType(req.Type) || req.FreshnessDays < 0 || req.FreshnessDays > 3650 {
			return nil, ErrValidation
		}
		if _, ok := seen[req.Type]; ok {
			return nil, ErrValidation
		}
		seen[req.Type] = struct{}{}
		out = append(out, req)
	}
	return out, nil
}

func supportedControlEvidenceType(value string) bool {
	switch strings.TrimSpace(value) {
	case "sbom", "vulnerability_scan", "vex", "vulnerability_decision", "artifact", "build", "build_attestation", "openapi_contract", "release_bundle", "exception":
		return true
	default:
		return false
	}
}

func validControlConfidence(value string) bool {
	switch strings.TrimSpace(value) {
	case confidenceHigh, confidenceMedium, confidenceLow, confidenceUnsupported:
		return true
	default:
		return false
	}
}

func aggregateConfidence(links []domain.ControlEvidence) string {
	if len(links) == 0 {
		return confidenceUnsupported
	}
	rank := map[string]int{confidenceHigh: 3, confidenceMedium: 2, confidenceLow: 1, confidenceUnsupported: 0}
	best := confidenceUnsupported
	for _, link := range links {
		if rank[link.Confidence] > rank[best] {
			best = link.Confidence
		}
	}
	return best
}

func scopeMatches(resourceValue, requestedValue string) bool {
	return requestedValue == "" || resourceValue == "" || resourceValue == requestedValue
}

func slugify(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func cleanStrings(in []string) []string {
	out := []string{}
	for _, value := range in {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

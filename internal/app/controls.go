package app

import (
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
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

type ControlCoverageReportInput struct {
	FrameworkID string
	ProductID   string
	ReleaseID   string
}

type CRAReadinessReportInput struct {
	ProductID string
	ReleaseID string
}

// craReadinessReportLocked produces one report from a single committed
// compatibility read view. The caller owns the read-model lock and performs
// authorization before returning the result to an actor.
func (l *Ledger) craReadinessReportLocked(tenantID, productID, releaseID string) (domain.CRAReadinessReport, error) {
	frameworkID := l.firstFrameworkIDLocked(tenantID)
	coverage, err := l.controlCoverageReportLocked(tenantID, ControlCoverageReportInput{FrameworkID: frameworkID, ProductID: productID, ReleaseID: releaseID})
	if err != nil {
		return domain.CRAReadinessReport{}, err
	}
	return domain.CRAReadinessReport{
		ReportType:         "cra_readiness",
		TemplateVersion:    domain.CRAReadinessTemplateVersion,
		ProductID:          productID,
		ReleaseID:          releaseID,
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

func (l *Ledger) refsForControlEvidenceSubjectLocked(subjectType, subjectID, productID, releaseID string) resourceRefs {
	refs := resourceRefs{ProductID: strings.TrimSpace(productID), ReleaseID: strings.TrimSpace(releaseID)}
	switch strings.TrimSpace(subjectType) {
	case "product":
		refs.ProductID = nonEmpty(refs.ProductID, strings.TrimSpace(subjectID))
	case "evidence", "evidence_item":
		if item, ok := l.evidence[strings.TrimSpace(subjectID)]; ok {
			refs.ProductID = nonEmpty(refs.ProductID, item.ProductID)
			refs.ProjectID = item.ProjectID
			refs.ReleaseID = nonEmpty(refs.ReleaseID, item.ReleaseID)
		}
	case "release":
		refs.ReleaseID = nonEmpty(refs.ReleaseID, strings.TrimSpace(subjectID))
	case "artifact":
		refs.ArtifactID = strings.TrimSpace(subjectID)
	case "build":
		refs.BuildID = strings.TrimSpace(subjectID)
	case "build_attestation":
		if attestation, ok := l.attestations[strings.TrimSpace(subjectID)]; ok {
			refs.BuildID = attestation.BuildID
		}
	case "security_scan":
		refs.SecurityScanID = strings.TrimSpace(subjectID)
	case "vulnerability_scan":
		if scan, ok := l.scans[strings.TrimSpace(subjectID)]; ok {
			refs.ReleaseID = nonEmpty(refs.ReleaseID, scan.ReleaseID)
		}
	case "incident":
		refs.IncidentID = strings.TrimSpace(subjectID)
	case "deployment":
		refs.DeploymentID = strings.TrimSpace(subjectID)
	case "openapi_contract":
		if contract, ok := l.contracts[strings.TrimSpace(subjectID)]; ok {
			refs.ProductID = nonEmpty(refs.ProductID, contract.ProductID)
			refs.ReleaseID = nonEmpty(refs.ReleaseID, contract.ReleaseID)
		}
	case "release_bundle":
		if bundle, ok := l.bundles[strings.TrimSpace(subjectID)]; ok {
			refs.ReleaseID = nonEmpty(refs.ReleaseID, bundle.ReleaseID)
		}
	case "customer_package":
		refs.CustomerPackageID = strings.TrimSpace(subjectID)
	}
	return refs
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
	owned := make([]riskdomain.ControlEvidenceRequirement, 0, len(in))
	for _, req := range in {
		owned = append(owned, riskdomain.ControlEvidenceRequirement{Type: req.Type, FreshnessDays: req.FreshnessDays, Required: req.Required})
	}
	normalized, err := riskdomain.NormalizeControlRequirements(owned)
	if err != nil {
		return nil, ErrValidation
	}
	out := make([]domain.ControlEvidenceRequirement, 0, len(normalized))
	for _, req := range normalized {
		out = append(out, domain.ControlEvidenceRequirement{Type: req.Type, FreshnessDays: req.FreshnessDays, Required: req.Required})
	}
	return out, nil
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
	return riskdomain.ControlFrameworkSlug(value)
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

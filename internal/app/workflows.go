package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) ReleaseEvidenceFlowPlan(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseEvidenceFlow, error) {
	return l.releaseEvidenceService().ReleaseEvidenceFlowPlan(ctx, actor, releaseID)
}

func (l *Ledger) ReleaseSecuritySummary(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseSecuritySummary, error) {
	return l.releaseEvidenceService().ReleaseSecuritySummary(ctx, actor, releaseID)
}

func (s releaseEvidenceService) ReleaseEvidenceFlowPlan(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseEvidenceFlow, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.ReleaseEvidenceFlow{}, err
	}
	if err := require(actor, ScopeReleaseRead); err != nil {
		return domain.ReleaseEvidenceFlow{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return domain.ReleaseEvidenceFlow{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	release, ok := l.releases[releaseID]
	if !ok || release.TenantID != actor.TenantID {
		return domain.ReleaseEvidenceFlow{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeReleaseRead, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
		return domain.ReleaseEvidenceFlow{}, err
	}
	counts := releaseEvidenceFlowCountsLocked(l, actor.TenantID, release.ID)
	steps := []domain.ReleaseEvidenceFlowStep{
		releaseEvidenceFlowStep("artifact_digest", "Register artifact digest", counts["artifact_refs"] > 0, true, "POST", "/v1/artifacts", []string{ScopeEvidenceWrite}, "Register the release artifact digest or upload build output metadata that references the artifact."),
		releaseEvidenceFlowStep("build_provenance", "Record build provenance", counts["passed_builds"] > 0, true, "POST", "/v1/builds", []string{ScopeBuildWrite}, "Record CI build metadata, commit identity, and output digests for the release."),
		releaseEvidenceFlowStep("sbom", "Upload SBOM", counts["sboms"] > 0, true, "POST", "/v1/sboms", []string{ScopeEvidenceWrite}, "Upload CycloneDX or SPDX SBOM evidence linked to the release and artifact where available."),
		releaseEvidenceFlowStep("vulnerability_scan", "Upload vulnerability scan", counts["vulnerability_scans"] > 0, true, "POST", "/v1/vulnerability-scans", []string{ScopeEvidenceWrite}, "Upload generic vulnerability scan evidence for review and decision workflows."),
		releaseEvidenceFlowStep("vex_or_decisions", "Record VEX or decisions", counts["vex_documents"]+counts["vulnerability_decisions"] > 0, false, "POST", "/v1/vex", []string{ScopeEvidenceWrite}, "Upload OpenVEX/CycloneDX VEX or create manual vulnerability decisions for relevant findings."),
		releaseEvidenceFlowStep("release_bundle", "Create release bundle", counts["release_bundles"] > 0, true, "POST", "/v1/release-bundles", []string{ScopeBundleWrite}, "Create an immutable release bundle after the required evidence is present."),
		releaseEvidenceFlowStep("readiness", "Read release readiness", true, true, "GET", "/v1/reports/release-readiness?release_id="+release.ID, []string{ScopeVerifyRead}, "Review deterministic policy checks, gaps, assumptions, exceptions, and limitations."),
		releaseEvidenceFlowStep("customer_package", "Create customer package", counts["customer_packages"] > 0, false, "POST", "/v1/customer-packages", []string{ScopePackageWrite}, "Create a scoped customer-safe package only after redaction profile review."),
	}
	status := "ready_for_review"
	for _, step := range steps {
		if step.Required && step.Status != "present" {
			status = "needs_evidence"
			break
		}
	}
	return domain.ReleaseEvidenceFlow{
		ReleaseID: release.ID,
		ProductID: release.ProductID,
		Status:    status,
		Counts:    counts,
		Steps:     steps,
		Assumptions: []string{
			"Workflow steps describe Evydence API evidence collection and do not replace CI provider, scanner, or operator review.",
			"Scanner and SBOM uploads are recorded as evidence with limitations, not as complete or authoritative coverage.",
		},
		Limitations: []string{
			"This workflow plan does not make legal compliance conclusions, grant certification, or guarantee release security.",
			"Artifact-to-release association is inferred from release-linked SBOMs, build outputs, attestations, and uploaded evidence references.",
		},
		SchemaVersion: domain.ReleaseEvidenceFlowVersion,
		GeneratedAt:   l.now(),
	}, nil
}

func releaseEvidenceFlowCountsLocked(l *Ledger, tenantID, releaseID string) map[string]int {
	counts := map[string]int{
		"artifact_refs":           0,
		"passed_builds":           0,
		"build_attestations":      0,
		"sboms":                   0,
		"vulnerability_scans":     0,
		"vex_documents":           0,
		"vulnerability_decisions": 0,
		"release_bundles":         0,
		"customer_packages":       0,
	}
	artifactRefs := map[string]struct{}{}
	for _, sbom := range l.sboms {
		if sbom.TenantID == tenantID && sbom.ReleaseID == releaseID {
			counts["sboms"]++
			if sbom.ArtifactID != "" {
				artifactRefs[sbom.ArtifactID] = struct{}{}
			}
		}
	}
	for _, scan := range l.scans {
		if scan.TenantID == tenantID && scan.ReleaseID == releaseID {
			counts["vulnerability_scans"]++
		}
	}
	for _, vex := range l.vexDocuments {
		if vex.TenantID == tenantID && vex.ReleaseID == releaseID {
			counts["vex_documents"]++
			if vex.ArtifactID != "" {
				artifactRefs[vex.ArtifactID] = struct{}{}
			}
		}
	}
	for _, decision := range l.decisions {
		if decision.TenantID == tenantID && decision.ReleaseID == releaseID && decision.SupersededBy == "" {
			counts["vulnerability_decisions"]++
		}
	}
	for _, build := range l.buildRuns {
		if build.TenantID == tenantID && build.ReleaseID == releaseID {
			if build.Status == "passed" {
				counts["passed_builds"]++
			}
			for _, output := range build.Outputs {
				if output.ArtifactID != "" {
					artifactRefs[output.ArtifactID] = struct{}{}
				}
			}
		}
	}
	for _, attestation := range l.attestations {
		build, ok := l.buildRuns[attestation.BuildID]
		if ok && attestation.TenantID == tenantID && build.ReleaseID == releaseID {
			counts["build_attestations"]++
		}
	}
	for _, bundle := range l.bundles {
		if bundle.TenantID == tenantID && bundle.ReleaseID == releaseID {
			counts["release_bundles"]++
		}
	}
	for _, pkg := range l.customerPackages {
		if pkg.TenantID == tenantID && pkg.ReleaseID == releaseID {
			counts["customer_packages"]++
		}
	}
	counts["artifact_refs"] = len(artifactRefs)
	return counts
}

func releaseEvidenceFlowStep(id, title string, present, required bool, method, path string, scopes []string, description string) domain.ReleaseEvidenceFlowStep {
	status := "missing"
	if present {
		status = "present"
	} else if !required {
		status = "optional"
	}
	return domain.ReleaseEvidenceFlowStep{
		ID:                  id,
		Title:               title,
		Status:              status,
		Required:            required,
		Method:              method,
		Path:                path,
		RequiredScopes:      scopes,
		IdempotencyRequired: method == "POST",
		Description:         description,
		NextReference:       path,
	}
}

func (s releaseEvidenceService) ReleaseSecuritySummary(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseSecuritySummary, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.ReleaseSecuritySummary{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.ReleaseSecuritySummary{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return domain.ReleaseSecuritySummary{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	release, ok := l.releases[releaseID]
	if !ok || release.TenantID != actor.TenantID {
		return domain.ReleaseSecuritySummary{}, ErrNotFound
	}
	product, ok := l.products[release.ProductID]
	if !ok || product.TenantID != actor.TenantID {
		return domain.ReleaseSecuritySummary{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeReportRead, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
		return domain.ReleaseSecuritySummary{}, err
	}
	counts := releaseEvidenceFlowCountsLocked(l, actor.TenantID, release.ID)
	openBySeverity, decisionsByStatus := releaseSecurityFindingDecisionCountsLocked(l, actor.TenantID, release.ID)
	missing := []domain.ReleaseSecurityMissingDecision{}
	for _, finding := range l.unhandledFindingsBySeverityLocked(actor.TenantID, release.ID, "critical", "high") {
		missing = append(missing, domain.ReleaseSecurityMissingDecision{
			FindingID:     finding.FindingID,
			ScanID:        finding.ScanID,
			Vulnerability: finding.Vulnerability,
			Component:     finding.Component,
			Severity:      finding.Severity,
			State:         nonEmpty(finding.State, "open"),
		})
	}
	checks := l.releasePolicyChecksLocked(actor.TenantID, release.ID)
	readiness := releasePolicyResult(checks)
	packageStatus := "not_generated"
	if counts["customer_packages"] > 0 {
		packageStatus = "generated"
	}
	return domain.ReleaseSecuritySummary{
		Product: domain.ReleaseSecurityProductSummary{
			ID: product.ID, Name: product.Name, Slug: product.Slug,
		},
		Release: domain.ReleaseSecurityReleaseSummary{
			ID: release.ID, Version: release.Version, State: release.State,
		},
		ArtifactCount:            counts["artifact_refs"],
		SBOMStatus:               presentMissingStatus(counts["sboms"] > 0),
		VulnerabilityScanStatus:  presentMissingStatus(counts["vulnerability_scans"] > 0),
		OpenFindingsBySeverity:   openBySeverity,
		DecisionsByStatus:        decisionsByStatus,
		MissingRequiredDecisions: missing,
		ApprovalSummary:          releaseSecurityApprovalSummaryLocked(l, actor.TenantID, release.ID),
		ExceptionSummary:         releaseSecurityExceptionSummaryLocked(l, actor.TenantID, release.ID),
		ReadinessStatus:          readiness,
		PackageStatus:            packageStatus,
		Counts:                   counts,
		Assumptions: []string{
			"Summary values are derived only from evidence, decisions, exceptions, approvals, bundles, packages, and build records in this Evydence tenant.",
			"Open finding counts reflect uploaded scanner evidence and recorded decisions or exceptions; scanner results are not treated as complete or authoritative coverage.",
		},
		Limitations: []string{
			"This summary supports technical review and compliance readiness, not legal compliance conclusions, certification, or release security guarantees.",
			"Raw SBOM, scanner, VEX, build, and package payload bytes are intentionally excluded from the summary.",
		},
		SchemaVersion: domain.ReleaseSecuritySummaryVersion,
		GeneratedAt:   l.now(),
	}, nil
}

func releaseSecurityFindingDecisionCountsLocked(l *Ledger, tenantID, releaseID string) (map[string]int, map[string]int) {
	openBySeverity := map[string]int{}
	for _, scan := range l.scans {
		if scan.TenantID != tenantID || scan.ReleaseID != releaseID {
			continue
		}
		for _, finding := range scan.Findings {
			if strings.ToLower(nonEmpty(finding.State, "open")) != "open" {
				continue
			}
			openBySeverity[strings.ToLower(nonEmpty(finding.Severity, "unknown"))]++
		}
	}
	decisionsByStatus := map[string]int{}
	for _, decision := range l.decisions {
		if decision.TenantID == tenantID && decision.ReleaseID == releaseID && decision.SupersededBy == "" {
			decisionsByStatus[decision.Status]++
		}
	}
	return openBySeverity, decisionsByStatus
}

func releaseSecurityApprovalSummaryLocked(l *Ledger, tenantID, releaseID string) domain.ReleaseSecurityApprovalSummary {
	summary := domain.ReleaseSecurityApprovalSummary{}
	for _, approval := range l.approvals {
		if approval.TenantID != tenantID || approval.SubjectType != "release" || approval.SubjectID != releaseID {
			continue
		}
		summary.Total++
		if approval.Decision == "approved" {
			summary.Approved++
		}
	}
	return summary
}

func releaseSecurityExceptionSummaryLocked(l *Ledger, tenantID, releaseID string) domain.ReleaseSecurityExceptionSummary {
	summary := domain.ReleaseSecurityExceptionSummary{}
	now := l.now()
	for _, exception := range l.exceptions {
		if exception.TenantID != tenantID || exception.ReleaseID != releaseID {
			continue
		}
		summary.Total++
		if !exception.ExpiresAt.After(now) {
			summary.Expired++
			continue
		}
		if exception.Approved {
			summary.ApprovedUnexpired++
		} else {
			summary.Unapproved++
		}
	}
	return summary
}

func presentMissingStatus(present bool) string {
	if present {
		return "present"
	}
	return "missing"
}

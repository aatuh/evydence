package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) ReleaseEvidenceFlowPlan(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseEvidenceFlow, error) {
	return l.releaseEvidenceService().ReleaseEvidenceFlowPlan(ctx, actor, releaseID)
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

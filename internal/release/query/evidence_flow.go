package query

import (
	"context"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// EvidenceFlowSnapshot contains one tenant-owned release and its aggregate
// counts from the same database statement. It never contains evidence rows.
type EvidenceFlowSnapshot struct {
	TenantID  string
	ReleaseID string
	ProductID string
	Counts    map[string]int
}

type EvidenceFlowReader interface {
	ReadEvidenceFlowSnapshot(context.Context, string, string) (EvidenceFlowSnapshot, error)
}

type EvidenceFlows struct {
	reader     EvidenceFlowReader
	authorizer application.Authorizer
	clock      application.Clock
}

func NewEvidenceFlows(reader EvidenceFlowReader, authorizer application.Authorizer, clock application.Clock) (*EvidenceFlows, error) {
	if reader == nil || authorizer == nil || clock == nil {
		return nil, ErrValidation
	}
	return &EvidenceFlows{reader: reader, authorizer: authorizer, clock: clock}, nil
}

func (s *EvidenceFlows) Plan(ctx context.Context, actor identitydomain.Actor, releaseID string) (releasedomain.ReleaseEvidenceFlow, error) {
	if s == nil || ctx == nil {
		return releasedomain.ReleaseEvidenceFlow{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return releasedomain.ReleaseEvidenceFlow{}, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scopeReleaseRead, ScopeOnly: true}); err != nil {
		return releasedomain.ReleaseEvidenceFlow{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return releasedomain.ReleaseEvidenceFlow{}, ErrValidation
	}
	snapshot, err := s.reader.ReadEvidenceFlowSnapshot(ctx, actor.TenantID, releaseID)
	if err != nil {
		return releasedomain.ReleaseEvidenceFlow{}, err
	}
	if snapshot.TenantID != actor.TenantID || snapshot.ReleaseID != releaseID || strings.TrimSpace(snapshot.ProductID) == "" {
		return releasedomain.ReleaseEvidenceFlow{}, ErrNotFound
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{
		Scope: scopeReleaseRead, Resources: application.ResourceReferences{ProductID: snapshot.ProductID, ReleaseID: releaseID},
	}); err != nil {
		return releasedomain.ReleaseEvidenceFlow{}, err
	}
	counts := make(map[string]int, len(flowCountKeys))
	for _, key := range flowCountKeys {
		count := snapshot.Counts[key]
		if count < 0 {
			return releasedomain.ReleaseEvidenceFlow{}, ErrValidation
		}
		counts[key] = count
	}
	return AssembleEvidenceFlow(releaseID, snapshot.ProductID, counts, s.clock.Now()), nil
}

var flowCountKeys = []string{
	"artifact_refs", "passed_builds", "build_attestations", "sboms", "vulnerability_scans",
	"vex_documents", "vulnerability_decisions", "release_bundles", "customer_packages",
}

// AssembleEvidenceFlow keeps the workflow vocabulary identical for durable
// and local-memory profiles. Counts are evidence presence, not assurance.
func AssembleEvidenceFlow(releaseID, productID string, counts map[string]int, at time.Time) releasedomain.ReleaseEvidenceFlow {
	steps := []releasedomain.ReleaseEvidenceFlowStep{
		flowStep("artifact_digest", "Register artifact digest", counts["artifact_refs"] > 0, true, "POST", "/v1/artifacts", []string{"evidence:write"}, "Register the release artifact digest or upload build output metadata that references the artifact."),
		flowStep("build_provenance", "Record build provenance", counts["passed_builds"] > 0, true, "POST", "/v1/builds", []string{"build:write"}, "Record CI build metadata, commit identity, and output digests for the release."),
		flowStep("sbom", "Upload SBOM", counts["sboms"] > 0, true, "POST", "/v1/sboms", []string{"evidence:write"}, "Upload CycloneDX or SPDX SBOM evidence linked to the release and artifact where available."),
		flowStep("vulnerability_scan", "Upload vulnerability scan", counts["vulnerability_scans"] > 0, true, "POST", "/v1/vulnerability-scans", []string{"evidence:write"}, "Upload generic vulnerability scan evidence for review and decision workflows."),
		flowStep("vex_or_decisions", "Record VEX or decisions", counts["vex_documents"]+counts["vulnerability_decisions"] > 0, false, "POST", "/v1/vex", []string{"evidence:write"}, "Upload OpenVEX/CycloneDX VEX or create manual vulnerability decisions for relevant findings."),
		flowStep("release_bundle", "Create release bundle", counts["release_bundles"] > 0, true, "POST", "/v1/release-bundles", []string{"bundle:write"}, "Create an immutable release bundle after the required evidence is present."),
		flowStep("readiness", "Read release readiness", true, true, "GET", "/v1/reports/release-readiness?release_id="+releaseID, []string{"verify:read"}, "Review deterministic policy checks, gaps, assumptions, exceptions, and limitations."),
		flowStep("customer_package", "Create customer package", counts["customer_packages"] > 0, false, "POST", "/v1/customer-packages", []string{"package:write"}, "Create a scoped customer-safe package only after redaction profile review."),
	}
	status := "ready_for_review"
	for _, step := range steps {
		if step.Required && step.Status != "present" {
			status = "needs_evidence"
			break
		}
	}
	return releasedomain.ReleaseEvidenceFlow{
		ReleaseID: releaseID, ProductID: productID, Status: status,
		Counts: counts, Steps: steps,
		Assumptions: []string{
			"Workflow steps describe Evydence API evidence collection and do not replace CI provider, scanner, or operator review.",
			"Scanner and SBOM uploads are recorded as evidence with limitations, not as complete or authoritative coverage.",
		},
		Limitations: []string{
			"This workflow plan does not make legal compliance conclusions, grant certification, or guarantee release security.",
			"Artifact-to-release association is inferred from release-linked SBOMs, build outputs, attestations, and uploaded evidence references.",
		},
		SchemaVersion: releasedomain.ReleaseEvidenceFlowVersion,
		GeneratedAt:   at.UTC(),
	}
}

func flowStep(id, title string, present, required bool, method, path string, scopes []string, description string) releasedomain.ReleaseEvidenceFlowStep {
	status := "missing"
	if present {
		status = "present"
	} else if !required {
		status = "optional"
	}
	return releasedomain.ReleaseEvidenceFlowStep{
		ID: id, Title: title, Status: status, Required: required,
		Method: method, Path: path, RequiredScopes: scopes,
		IdempotencyRequired: method == "POST", Description: description, NextReference: path,
	}
}

package query

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

const MaxSecuritySummaryFindings = 4096

type ReleaseSecuritySummarySnapshot struct {
	TenantID                 string
	Product                  riskdomain.ReleaseSecurityProductSummary
	Release                  riskdomain.ReleaseSecurityReleaseSummary
	Counts                   map[string]int
	OpenFindingsBySeverity   map[string]int
	DecisionsByStatus        map[string]int
	MissingRequiredDecisions []riskdomain.ReleaseSecurityMissingDecision
	ApprovalSummary          riskdomain.ReleaseSecurityApprovalSummary
	ExceptionSummary         riskdomain.ReleaseSecurityExceptionSummary
	Readiness                riskapp.ReadinessSnapshot
}

type ReleaseSecuritySummaryReader interface {
	ReadReleaseSecuritySummarySnapshot(context.Context, string, string) (ReleaseSecuritySummarySnapshot, error)
}

type ReleaseSecuritySummary struct {
	reader ReleaseSecuritySummaryReader
	now    func() time.Time
}

func NewReleaseSecuritySummary(reader ReleaseSecuritySummaryReader, now func() time.Time) (*ReleaseSecuritySummary, error) {
	if reader == nil || now == nil {
		return nil, ErrValidation
	}
	return &ReleaseSecuritySummary{reader: reader, now: now}, nil
}

func (s *ReleaseSecuritySummary) Summary(ctx context.Context, actor identitydomain.Actor, releaseID string) (riskdomain.ReleaseSecuritySummary, error) {
	var empty riskdomain.ReleaseSecuritySummary
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return empty, application.ErrUnauthorized
	}
	if !actor.HasScope("report:read") && !actor.HasScope("admin") {
		return empty, application.ErrForbidden
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return empty, ErrValidation
	}
	tenantWide, products, releases := decisionVisibility(actor, "report:read")
	if !tenantWide && len(products) == 0 && !decisionAllowed(false, nil, releases, "", releaseID) {
		return empty, application.ErrForbidden
	}
	snapshot, err := s.reader.ReadReleaseSecuritySummarySnapshot(ctx, actor.TenantID, releaseID)
	if err != nil {
		return empty, err
	}
	if snapshot.TenantID != actor.TenantID || snapshot.Product.ID == "" || snapshot.Release.ID != releaseID ||
		snapshot.Readiness.SnapshotVersion != riskapp.ReadinessSnapshotVersion || snapshot.Readiness.TenantID != actor.TenantID || snapshot.Readiness.ProductID != snapshot.Product.ID || snapshot.Readiness.ReleaseID != releaseID ||
		len(snapshot.MissingRequiredDecisions) > MaxSecuritySummaryFindings {
		return empty, ErrInvalidProjection
	}
	if !decisionAllowed(tenantWide, products, releases, snapshot.Product.ID, releaseID) {
		return empty, application.ErrForbidden
	}
	for _, item := range snapshot.MissingRequiredDecisions {
		if item.FindingID == "" || item.ScanID == "" || item.Severity == "" || item.State == "" {
			return empty, ErrInvalidProjection
		}
	}
	counts := make(map[string]int, len(securitySummaryCountKeys))
	for _, key := range securitySummaryCountKeys {
		if snapshot.Counts[key] < 0 {
			return empty, ErrInvalidProjection
		}
		counts[key] = snapshot.Counts[key]
	}
	open, err := safeSummaryCounts(snapshot.OpenFindingsBySeverity)
	if err != nil {
		return empty, err
	}
	decisions, err := safeSummaryCounts(snapshot.DecisionsByStatus)
	if err != nil {
		return empty, err
	}
	if snapshot.ApprovalSummary.Total < 0 || snapshot.ApprovalSummary.Approved < 0 || snapshot.ApprovalSummary.Approved > snapshot.ApprovalSummary.Total ||
		snapshot.ExceptionSummary.Total < 0 || snapshot.ExceptionSummary.ApprovedUnexpired < 0 || snapshot.ExceptionSummary.Unapproved < 0 || snapshot.ExceptionSummary.Expired < 0 ||
		snapshot.ExceptionSummary.ApprovedUnexpired+snapshot.ExceptionSummary.Unapproved+snapshot.ExceptionSummary.Expired != snapshot.ExceptionSummary.Total {
		return empty, ErrInvalidProjection
	}
	now := s.now().UTC()
	evaluation, err := riskapp.EvaluateReadinessSnapshot(snapshot.Readiness, now)
	if err != nil {
		return empty, ErrInvalidProjection
	}
	packageStatus := "not_generated"
	if counts["customer_packages"] > 0 {
		packageStatus = "generated"
	}
	return riskdomain.ReleaseSecuritySummary{
		Product: snapshot.Product, Release: snapshot.Release,
		ArtifactCount: counts["artifact_refs"], SBOMStatus: securityPresence(counts["sboms"]), VulnerabilityScanStatus: securityPresence(counts["vulnerability_scans"]),
		OpenFindingsBySeverity: open, DecisionsByStatus: decisions,
		MissingRequiredDecisions: append([]riskdomain.ReleaseSecurityMissingDecision(nil), snapshot.MissingRequiredDecisions...),
		ApprovalSummary:          snapshot.ApprovalSummary, ExceptionSummary: snapshot.ExceptionSummary,
		ReadinessStatus: evaluation.Result, PackageStatus: packageStatus, Counts: counts,
		Assumptions: []string{
			"Summary values are derived only from evidence, decisions, exceptions, approvals, bundles, packages, and build records in this Evydence tenant.",
			"Open finding counts reflect uploaded scanner evidence and recorded decisions or exceptions; scanner results are not treated as complete or authoritative coverage.",
		},
		Limitations: []string{
			"This summary supports technical review and compliance readiness, not legal compliance conclusions, certification, or release security guarantees.",
			"Raw SBOM, scanner, VEX, build, and package payload bytes are intentionally excluded from the summary.",
		},
		SchemaVersion: riskdomain.ReleaseSecuritySummaryVersion, GeneratedAt: now,
	}, nil
}

var securitySummaryCountKeys = []string{
	"artifact_refs", "passed_builds", "build_attestations", "sboms", "vulnerability_scans",
	"vex_documents", "vulnerability_decisions", "release_bundles", "customer_packages",
}

func securityPresence(count int) string {
	if count > 0 {
		return "present"
	}
	return "missing"
}

func safeSummaryCounts(source map[string]int) (map[string]int, error) {
	if len(source) > 32 {
		return nil, ErrInvalidProjection
	}
	result := make(map[string]int, len(source))
	for key, value := range source {
		if key == "" || len(key) > 64 || value < 0 {
			return nil, ErrInvalidProjection
		}
		result[key] = value
	}
	return result, nil
}

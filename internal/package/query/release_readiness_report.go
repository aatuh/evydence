package query

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

var (
	ErrReleaseReadinessValidation = errors.New("invalid release readiness report query")
	ErrReleaseReadinessNotFound   = errors.New("release readiness report scope not found")
	ErrReleaseReadinessProjection = errors.New("invalid or oversized release readiness report projection")
)

const MaxReleaseReadinessEntries = 4096

// ReleaseReadinessReportSnapshot contains bounded report-safe facts gathered
// from one committed view. Policy interpretation stays in the Risk domain.
type ReleaseReadinessReportSnapshot struct {
	Readiness                riskdomain.ReadinessSnapshot
	BlockingFindings         []packagedomain.BlockingFinding
	AcceptedExceptions       []packagedomain.AcceptedExceptionSnapshot
	ActiveDecisionCount      int
	HasActiveCustomerPackage bool
}

type ReleaseReadinessReportReader interface {
	ReadReleaseReadinessReportSnapshot(context.Context, string, string, time.Time) (ReleaseReadinessReportSnapshot, error)
}

type ReleaseReadinessReport struct {
	reader ReleaseReadinessReportReader
	now    func() time.Time
}

func NewReleaseReadinessReport(reader ReleaseReadinessReportReader, now func() time.Time) (*ReleaseReadinessReport, error) {
	if reader == nil || now == nil {
		return nil, ErrReleaseReadinessValidation
	}
	return &ReleaseReadinessReport{reader: reader, now: now}, nil
}

func (s *ReleaseReadinessReport) Report(ctx context.Context, actor identitydomain.Actor, releaseID string) (packagedomain.ReleaseReadinessReport, error) {
	var empty packagedomain.ReleaseReadinessReport
	if s == nil || ctx == nil {
		return empty, ErrReleaseReadinessValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if actor.TenantID == "" || actor.UserID == "" && actor.KeyID == "" && actor.CollectorID == "" {
		return empty, application.ErrUnauthorized
	}
	if !actor.HasScope("verify:read") && !actor.HasScope("admin") {
		return empty, application.ErrForbidden
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return empty, ErrReleaseReadinessValidation
	}
	mayRead := releaseScopeAllowed(actor, "verify:read", "", releaseID)
	// A product grant needs one scoped lookup to resolve the current parent.
	for _, grant := range actor.ResourceGrants {
		if grant.ResourceType == "product" && grant.ResourceID != "" && releaseScopeAllowed(actor, "verify:read", grant.ResourceID, releaseID) {
			mayRead = true
			break
		}
	}
	if !mayRead {
		return empty, application.ErrForbidden
	}
	now := s.now().UTC()
	if now.IsZero() {
		return empty, ErrReleaseReadinessValidation
	}
	snapshot, err := s.reader.ReadReleaseReadinessReportSnapshot(ctx, actor.TenantID, releaseID, now)
	if err != nil {
		return empty, err
	}
	facts := snapshot.Readiness
	if facts.TenantID != actor.TenantID || facts.ReleaseID != releaseID || strings.TrimSpace(facts.ProductID) == "" {
		return empty, ErrReleaseReadinessProjection
	}
	if !releaseScopeAllowed(actor, "verify:read", facts.ProductID, releaseID) {
		return empty, application.ErrForbidden
	}
	entries := len(snapshot.BlockingFindings) + len(snapshot.AcceptedExceptions) + len(facts.MissingCustomerStatementIDs) + len(facts.MissingNotAffectedReasonIDs) + len(facts.IncompleteExceptionIDs) + len(facts.InvalidPackageOrProfileIDs)
	if entries > MaxReleaseReadinessEntries || snapshot.ActiveDecisionCount < 0 {
		return empty, ErrReleaseReadinessProjection
	}
	for _, finding := range snapshot.BlockingFindings {
		if finding.ScanID == "" || finding.Severity != "critical" || finding.State != "open" {
			return empty, ErrReleaseReadinessProjection
		}
	}
	for _, exception := range snapshot.AcceptedExceptions {
		if !exception.ExpiresAt.After(now) {
			return empty, ErrReleaseReadinessProjection
		}
	}
	evaluation, err := riskdomain.EvaluateReadinessSnapshot(facts, now)
	if err != nil {
		return empty, ErrReleaseReadinessProjection
	}
	checks := make([]packagedomain.PolicyCheckSnapshot, 0, len(evaluation.Checks))
	for _, check := range evaluation.Checks {
		checks = append(checks, packagedomain.PolicyCheckSnapshot{Name: check.Name, Result: check.Result, Severity: check.Severity, Missing: check.Missing, Explanation: check.Explanation, Remediation: check.Remediation})
	}
	report, err := packageapp.RenderReleaseReadinessReport(packageapp.ReadinessReportSnapshot{
		SnapshotVersion: packageapp.ReadinessReportSnapshotVersion, TenantID: facts.TenantID, ProductID: facts.ProductID, ReleaseID: releaseID,
		Result: evaluation.Result, PolicySet: evaluation.PolicySet, Checks: checks,
		BlockingFindings: snapshot.BlockingFindings, AcceptedExceptions: snapshot.AcceptedExceptions,
		ActiveDecisionCount: snapshot.ActiveDecisionCount, HasActiveCustomerPackage: snapshot.HasActiveCustomerPackage,
	}, now)
	if err != nil {
		return empty, ErrReleaseReadinessProjection
	}
	return report, nil
}

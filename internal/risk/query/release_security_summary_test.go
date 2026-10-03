package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type securitySummaryReaderFake struct {
	snapshot ReleaseSecuritySummarySnapshot
	calls    int
}

func (f *securitySummaryReaderFake) ReadReleaseSecuritySummarySnapshot(context.Context, string, string) (ReleaseSecuritySummarySnapshot, error) {
	f.calls++
	return f.snapshot, nil
}

func TestReleaseSecuritySummaryScopesAndAssemblesCommittedFacts(t *testing.T) {
	reader := &securitySummaryReaderFake{snapshot: ReleaseSecuritySummarySnapshot{
		TenantID: "ten_a", Product: riskdomain.ReleaseSecurityProductSummary{ID: "prod_a", Name: "Product", Slug: "product"},
		Release:                riskdomain.ReleaseSecurityReleaseSummary{ID: "rel_a", Version: "1", State: "draft"},
		Counts:                 map[string]int{"artifact_refs": 2, "sboms": 1, "vulnerability_scans": 1, "customer_packages": 1},
		OpenFindingsBySeverity: map[string]int{"critical": 1}, DecisionsByStatus: map[string]int{"not_affected": 1},
		MissingRequiredDecisions: []riskdomain.ReleaseSecurityMissingDecision{{FindingID: "finding_a", ScanID: "scan_a", Severity: "critical", State: "open"}},
		ApprovalSummary:          riskdomain.ReleaseSecurityApprovalSummary{Total: 2, Approved: 1},
		ExceptionSummary:         riskdomain.ReleaseSecurityExceptionSummary{Total: 1, Unapproved: 1},
		Readiness:                riskapp.ReadinessSnapshot{SnapshotVersion: riskapp.ReadinessSnapshotVersion, TenantID: "ten_a", ProductID: "prod_a", ReleaseID: "rel_a"},
	}}
	query, err := NewReleaseSecuritySummary(reader, func() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_a", UserID: "user_a", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_a", Scopes: []string{"report:read"}}}}
	summary, err := query.Summary(context.Background(), actor, "rel_a")
	if err != nil || summary.Product.ID != "prod_a" || summary.Release.ID != "rel_a" || summary.ArtifactCount != 2 || summary.SBOMStatus != "present" || summary.VulnerabilityScanStatus != "present" || summary.PackageStatus != "generated" || summary.ReadinessStatus != "failed" || summary.ApprovalSummary.Approved != 1 || len(summary.MissingRequiredDecisions) != 1 {
		t.Fatalf("summary=%#v err=%v", summary, err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_other"
	before := reader.calls
	if _, err := query.Summary(context.Background(), actor, "rel_a"); !errors.Is(err, application.ErrForbidden) || reader.calls != before {
		t.Fatalf("foreign grant err=%v calls=%d", err, reader.calls)
	}
	actor.ResourceGrants[0].ResourceID = "rel_a"
	reader.snapshot.Readiness.TenantID = "ten_other"
	if _, err := query.Summary(context.Background(), actor, "rel_a"); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign readiness snapshot err=%v", err)
	}
}

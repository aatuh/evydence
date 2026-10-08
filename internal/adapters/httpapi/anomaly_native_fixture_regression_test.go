package httpapi

import (
	"context"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
)

func TestAnomalyFixtureReadsRepositoryFactsWithoutAggregatePublication(t *testing.T) {
	ledger, factory, _, _ := reportSigningRegressionLedger(t)
	owner := seedReportSigningFixtureScope(t, ledger, "Native")
	source, err := ledger.CreateEvidence(t.Context(), owner.actor, app.CreateEvidenceInput{ProductID: owner.product.ID, ReleaseID: owner.release.ID, Type: "vulnerability_scan", Title: "Scan metadata", PayloadHash: "sha256:" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	scan := domain.VulnerabilityScan{ID: "repository-only-scan", TenantID: owner.actor.TenantID, ReleaseID: owner.release.ID, EvidenceID: source.ID, Scanner: "fixture", TargetRef: "release", CreatedAt: source.CreatedAt, Findings: []domain.VulnerabilityFinding{{ID: "recorded-critical", Vulnerability: "CVE-fixture", Component: "component", Severity: "critical", State: "open"}}}
	if err := app.ExecuteUnitOfWork(t.Context(), factory, func(ctx context.Context, repos app.Repositories) error {
		return repos.Evidence.InsertVulnerabilityScan(ctx, scan)
	}); err != nil {
		t.Fatal(err)
	}
	f := reportSigningFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	v, err := f.GenerateAnomalyReport(t.Context(), owner.actor, experimentalapp.AnomalyReportInput{SubjectType: "release", SubjectID: owner.release.ID})
	if err != nil || len(v.Signals) != 3 || v.Signals[2].Name != "unhandled_critical_finding" {
		t.Fatal("anomaly consulted stale aggregate facts", v.Signals, err)
	}
	saved, err := factory.Snapshot()
	if err != nil || saved.AnomalyReports[v.ID].SubjectID != owner.release.ID {
		t.Fatal("native anomaly was not persisted", err)
	}
}

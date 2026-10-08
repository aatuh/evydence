package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

type riskQueryFixtureScope struct {
	evidenceFixtureScope
	release domain.Release
	head    domain.VulnerabilityDecision
}

func seedRiskQueryFixtureScope(t *testing.T, ledger *app.Ledger, name string) riskQueryFixtureScope {
	t.Helper()
	scope := riskQueryFixtureScope{evidenceFixtureScope: seedEvidenceFixtureScope(t, ledger, name)}
	var err error
	scope.release, err = ledger.CreateRelease(t.Context(), scope.actor, scope.product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := ledger.UploadVulnerabilityScan(t.Context(), scope.actor, []byte(fmt.Sprintf(`{"scanner":"grype","target_ref":"pkg:oci/api","release_id":%q,"findings":[{"vulnerability":"CVE-2026-0001","component":"component-one","severity":"high","state":"open"},{"vulnerability":"CVE-2026-0002","component":"component-two","severity":"high","state":"open"}]}`, scope.release.ID)))
	if err != nil || len(scan.Findings) != 2 {
		t.Fatal("fixture scan lacks owned findings", err)
	}
	for _, tc := range []struct {
		index  int
		status string
		public bool
	}{{0, "under_investigation", true}, {0, "affected", true}, {1, "under_investigation", false}} {
		value, err := ledger.CreateVulnerabilityDecision(t.Context(), scope.actor, scan.Findings[tc.index].ID, app.CreateVulnerabilityDecisionInput{Status: tc.status, Justification: "reviewed", ImpactStatement: "impact under review", ActionStatement: "patch planned", CustomerVisible: tc.public, InternalNotes: "private triage " + name})
		if err != nil {
			t.Fatalf("seed %s decision %s: %v", name, tc.status, err)
		}
		if tc.status == "affected" {
			scope.head = value
		}
	}
	governance := governanceFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: application.ClockFunc(func() time.Time { return scope.release.CreatedAt })}
	for i := range 2 {
		exception, err := governance.CreateException(t.Context(), scope.actor, riskapp.CreateExceptionInput{ReleaseID: scope.release.ID, Reason: fmt.Sprintf("exception-%d", i), Owner: "security", ExpiresAt: scope.release.CreatedAt.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if _, err := governance.ApproveException(t.Context(), scope.actor, exception.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	return scope
}

func TestRiskQueryFixturesPreserveTenantFiltersPrivacyPagingAndReadOnlyState(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Now: func() time.Time { return time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC) }})
	owners := []riskQueryFixtureScope{seedRiskQueryFixtureScope(t, ledger, "Alpha"), seedRiskQueryFixtureScope(t, ledger, "Bravo")}
	decisions := decisionQueryFixture{catalogFixtureCommands{ledger: ledger}}
	exceptions := exceptionQueryFixture{catalogFixtureCommands{ledger: ledger}}
	summaries := decisionSummaryQueryFixture{catalogFixtureCommands{ledger: ledger}}
	request := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range owners {
		active := true
		filter := riskquery.DecisionFilter{ProductID: owner.product.ID, ReleaseID: owner.release.ID, Vulnerability: "CVE-2026-0001", Component: "component-one", Status: "affected", Active: &active}
		page, err := decisions.ListPage(t.Context(), owner.actor, filter, request, nil)
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != owner.head.ID || page.Items[0].TenantID != owner.actor.TenantID || page.Items[0].InternalNotes != "" || page.Next != nil {
			t.Fatal("decision fixture lost filtering, scope, active head or note omission", err)
		}
		seen := map[string]bool{}
		var after *appquery.SortKey
		for range 4 {
			page, err := decisions.ListPage(t.Context(), owner.actor, riskquery.DecisionFilter{}, request, after)
			if err != nil || len(page.Items) != 1 || page.Items[0].TenantID != owner.actor.TenantID || page.Items[0].InternalNotes != "" || seen[page.Items[0].ID] {
				t.Fatal("decision fixture pagination leaked, repeated or omitted history", err)
			}
			seen[page.Items[0].ID] = true
			after = page.Next
			if after == nil {
				break
			}
		}
		if len(seen) != 3 || after != nil {
			t.Fatal("decision fixture did not return exactly its complete tenant history")
		}
		first, err := exceptions.ListPage(t.Context(), owner.actor, owner.release.ID, request, nil)
		if err != nil || len(first.Items) != 1 || first.Next == nil || first.Items[0].TenantID != owner.actor.TenantID {
			t.Fatal("exception fixture lost tenant scope or continuation", err)
		}
		second, err := exceptions.ListPage(t.Context(), owner.actor, owner.release.ID, request, first.Next)
		if err != nil || len(second.Items) != 1 || second.Next != nil || second.Items[0].ID == first.Items[0].ID || second.Items[0].TenantID != owner.actor.TenantID {
			t.Fatal("exception fixture continuation repeated, leaked or lost data", err)
		}
		for _, value := range append(first.Items, second.Items...) {
			if value.Approved && (value.ApprovedAt == nil || value.ApprovedBy == "") {
				t.Fatal("exception fixture lost approval metadata")
			}
		}
		summary, err := summaries.SummaryReport(t.Context(), owner.actor, owner.release.ID)
		if err != nil || summary.ProductID != owner.product.ID || summary.ReleaseID != owner.release.ID || len(summary.Decisions) != 1 || summary.Decisions[0].ID != owner.head.ID {
			t.Fatal("summary fixture did not restrict to visible active release decisions", err)
		}
		foreign := owners[0]
		if foreign.actor.TenantID == owner.actor.TenantID {
			foreign = owners[1]
		}
		if _, err := decisions.ListPage(t.Context(), foreign.actor, filter, request, nil); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("decision fixture accepted foreign parent filters", err)
		}
		if _, err := exceptions.ListPage(t.Context(), foreign.actor, owner.release.ID, request, nil); !errors.Is(err, riskquery.ErrNotFound) {
			t.Fatal("exception fixture accepted a foreign release", err)
		}
		if _, err := summaries.SummaryReport(t.Context(), foreign.actor, owner.release.ID); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("summary fixture exposed another tenant's release", err)
		}
		denied := owner.actor
		denied.Scopes = []string{"product:read"}
		if _, err := decisions.ListPage(t.Context(), denied, filter, request, nil); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("decision fixture skipped evidence read authority", err)
		}
		if _, err := exceptions.ListPage(t.Context(), denied, owner.release.ID, request, nil); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("exception fixture skipped verification read authority", err)
		}
		if _, err := summaries.SummaryReport(t.Context(), denied, owner.release.ID); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("summary fixture skipped report read authority", err)
		}
		human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"*"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"*"}}}}
		if page, err := decisions.ListPage(t.Context(), human, filter, request, nil); err != nil || len(page.Items) != 1 || page.Items[0].ID != owner.head.ID {
			t.Fatal("decision fixture rejected a matching current human grant", err)
		}
		if page, err := exceptions.ListPage(t.Context(), human, owner.release.ID, request, nil); err != nil || len(page.Items) != 1 || page.Items[0].ReleaseID != owner.release.ID {
			t.Fatal("exception fixture rejected a matching current human grant", err)
		}
		if report, err := summaries.SummaryReport(t.Context(), human, owner.release.ID); err != nil || report.ReleaseID != owner.release.ID {
			t.Fatal("summary fixture rejected a matching current human grant", err)
		}
		for _, grants := range [][]domain.ResourceGrant{
			{{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"*"}}},
			nil,
		} {
			human.ResourceGrants = grants
			if _, err := decisions.ListPage(t.Context(), human, filter, request, nil); !errors.Is(err, app.ErrForbidden) {
				t.Fatal("decision fixture retained wrong or removed resource authority", err)
			}
			if _, err := exceptions.ListPage(t.Context(), human, owner.release.ID, request, nil); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("exception fixture retained wrong or removed resource authority", err)
			}
			if _, err := summaries.SummaryReport(t.Context(), human, owner.release.ID); !errors.Is(err, app.ErrForbidden) {
				t.Fatal("summary fixture retained wrong or removed resource authority", err)
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := decisions.ListPage(ctx, owner.actor, filter, request, nil); !errors.Is(err, context.Canceled) {
			t.Fatal("decision fixture ignored cancellation", err)
		}
		if _, err := exceptions.ListPage(ctx, owner.actor, owner.release.ID, request, nil); !errors.Is(err, context.Canceled) {
			t.Fatal("exception fixture ignored cancellation", err)
		}
		if _, err := summaries.SummaryReport(ctx, owner.actor, owner.release.ID); !errors.Is(err, context.Canceled) {
			t.Fatal("summary fixture ignored cancellation", err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("risk fixture reads changed repository state", err)
	}
}

func TestRiskQueryFixtureMappingPreservesPublicMetadataAndOmitsPrivateNotes(t *testing.T) {
	now := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	value := domain.VulnerabilityDecision{ID: "decision", TenantID: "tenant", FindingID: "finding", ScanID: "scan", ReleaseID: "release", Vulnerability: "CVE", Component: "component", SBOMID: "sbom", SBOMComponentPURL: "purl", SBOMComponentName: "library", Status: "affected", Justification: "reviewed", ImpactStatement: "impact", ActionStatement: "action", CustomerVisible: true, InternalNotes: "private triage", Source: "manual", EvidenceID: "evidence", EvidenceIDs: []string{"evidence"}, SupportingRefs: []domain.SubjectRef{{Type: "artifact", ID: "artifact", Digest: "digest"}}, VEXDocumentID: "vex", Supersedes: "old", SupersededBy: "new", ApprovedBy: "approver", ReviewedAt: &now, ReviewDueAt: &now, SchemaVersion: "decision.v1", CreatedAt: now}
	model, err := decisionQueryFixtureModel(value)
	value.InternalNotes = ""
	if err != nil || model.InternalNotes != "" || !reflect.DeepEqual(domain.VulnerabilityDecisionFromContextModel(model), value) {
		t.Fatal("decision query mapping exposed notes or lost public history", err)
	}
	model.EvidenceIDs[0], model.SupportingRefs[0].Digest = "changed", "changed"
	*model.ReviewedAt = now.Add(time.Hour)
	if value.EvidenceIDs[0] != "evidence" || value.SupportingRefs[0].Digest != "digest" || !value.ReviewedAt.Equal(now) {
		t.Fatal("decision mapping shared mutable metadata")
	}
	value.Status = "invalid"
	if _, err := decisionQueryFixtureModel(value); !errors.Is(err, riskquery.ErrInvalidProjection) {
		t.Fatal("invalid stored decision status did not fail closed", err)
	}
	decision := domain.VulnerabilityDecisionCustomerSummary{ID: "decision", FindingID: "finding", ScanID: "scan", ReleaseID: "release", Vulnerability: "CVE", Component: "component", SBOMID: "sbom", SBOMComponentPURL: "purl", SBOMComponentName: "library", Status: "affected", Justification: "reviewed", ImpactStatement: "impact", ActionStatement: "action", Source: "manual", EvidenceID: "evidence", EvidenceIDs: []string{"evidence"}, SupportingRefs: []domain.SubjectRef{{Type: "artifact", ID: "artifact", Digest: "digest"}}, VEXDocumentID: "vex", ReviewedAt: &now, ReviewDueAt: &now, CreatedAt: now}
	report := domain.VulnerabilityDecisionSummaryReport{ReportType: "summary", TemplateVersion: "1", ProductID: "product", ReleaseID: "release", Decisions: []domain.VulnerabilityDecisionCustomerSummary{decision}, Assumptions: []string{"assumption"}, Limitations: []string{"limitation"}, GeneratedAt: now}
	summary := decisionSummaryFixtureModel(report)
	if !reflect.DeepEqual(decisionSummaryFromQuery(summary), report) {
		t.Fatal("summary query mapping changed recorded metadata or limitations")
	}
	summary.Decisions[0].EvidenceIDs[0], summary.Decisions[0].SupportingRefs[0].Digest, summary.Assumptions[0], summary.Limitations[0] = "changed", "changed", "changed", "changed"
	*summary.Decisions[0].ReviewDueAt = now.Add(time.Hour)
	if report.Decisions[0].EvidenceIDs[0] != "evidence" || report.Decisions[0].SupportingRefs[0].Digest != "digest" || report.Assumptions[0] != "assumption" || report.Limitations[0] != "limitation" || !report.Decisions[0].ReviewDueAt.Equal(now) {
		t.Fatal("summary mapping shared mutable metadata")
	}
	if strings.Contains(fmt.Sprint(summary), "private triage") {
		t.Fatal("private notes entered the customer summary")
	}
}

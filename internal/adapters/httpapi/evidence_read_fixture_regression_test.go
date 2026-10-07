package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

type evidenceReadFixtureScope struct {
	evidenceFixtureScope
	release  domain.Release
	sbom     domain.SBOM
	scan     domain.VulnerabilityScan
	contract domain.OpenAPIContract
	vex      domain.VEXDocument
	report   domain.VEXImportReport
	payload  []byte
}

func seedEvidenceReadFixtureScope(t *testing.T, ledger *app.Ledger, name string) evidenceReadFixtureScope {
	t.Helper()
	scope := evidenceReadFixtureScope{evidenceFixtureScope: seedEvidenceFixtureScope(t, ledger, name)}
	var err error
	scope.release, err = ledger.CreateRelease(t.Context(), scope.actor, scope.product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	scope.sbom, err = ledger.UploadSBOM(t.Context(), scope.actor, scope.release.ID, "", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"one","purl":"pkg:generic/one@1"},{"type":"library","name":"two","purl":"pkg:generic/two@1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	scope.scan, err = ledger.UploadVulnerabilityScan(t.Context(), scope.actor, []byte(fmt.Sprintf(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":%q,"findings":[{"vulnerability":"CVE-2026-1","component":"pkg:generic/one@1","severity":"high","state":"open"}]}`, scope.release.ID)))
	if err != nil {
		t.Fatal(err)
	}
	scope.contract, err = ledger.UploadOpenAPIContract(t.Context(), scope.actor, scope.product.ID, scope.release.ID, "1", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"1"},"paths":{"/items":{"get":{"operationId":"listItems","responses":{"200":{"description":"ok"}}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	scope.payload = []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/fixture","author":"security@example.test","timestamp":"2026-10-07T15:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-1"},"products":[{"@id":"pkg:generic/one@1"}],"status":"affected","justification":"reviewed","impact_statement":"impact","action_statement":"patch planned"}]}`)
	scope.vex, err = ledger.UploadVEX(t.Context(), scope.actor, scope.release.ID, "", scope.payload)
	if err != nil {
		t.Fatal(err)
	}
	scope.report, err = ledger.GetVEXImportReport(t.Context(), scope.actor, scope.vex.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		_, err := ledger.RecordEvidenceLifecycleEvent(t.Context(), scope.actor, scope.original.ID, app.RecordEvidenceLifecycleInput{Action: "amendment", Reason: fmt.Sprintf("review-%d", i), Details: map[string]any{"note": "visible", "nested": map[string]any{"value": "original"}, "secret": "private-value"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	return scope
}

func assertEvidenceFixtureJSON(t *testing.T, got, want any) {
	t.Helper()
	actual, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(want)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("fixture lost public fields: got=%s want=%s err=%v", actual, expected, err)
	}
}

func TestEvidenceReadFixturesPreserveOwnershipPagesPrivacyAndReadOnlyState(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Now: func() time.Time { return time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC) }})
	owners := []evidenceReadFixtureScope{seedEvidenceReadFixtureScope(t, ledger, "Alpha"), seedEvidenceReadFixtureScope(t, ledger, "Bravo")}
	base := catalogFixtureCommands{ledger: ledger}
	read, pages, lifecycle, components := evidenceReadFixture{base}, evidencePageFixture{base}, lifecyclePageFixture{base}, sbomComponentsFixture{base}
	request := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for i, owner := range owners {
		foreign := owners[1-i]
		human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeEvidenceRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopeEvidenceRead}}}}
		for _, tc := range []struct {
			name string
			want any
			run  func(context.Context, domain.Actor) (any, error)
		}{
			{"evidence", owner.original, func(ctx context.Context, a domain.Actor) (any, error) {
				v, err := read.GetEvidence(ctx, a, owner.original.ID)
				return domain.EvidenceFromContextModel(v), err
			}},
			{"sbom", owner.sbom, func(ctx context.Context, a domain.Actor) (any, error) {
				v, err := read.GetSBOM(ctx, a, owner.sbom.ID)
				return sbomFromQuery(v), err
			}},
			{"scan", owner.scan, func(ctx context.Context, a domain.Actor) (any, error) {
				v, err := read.GetVulnerabilityScan(ctx, a, owner.scan.ID)
				return vulnerabilityScanFromQuery(v), err
			}},
			{"contract", owner.contract, func(ctx context.Context, a domain.Actor) (any, error) {
				v, err := read.GetOpenAPIContract(ctx, a, owner.contract.ID)
				return openAPIContractFromQuery(v), err
			}},
			{"vex", owner.vex, func(ctx context.Context, a domain.Actor) (any, error) {
				v, err := read.GetVEXDocument(ctx, a, owner.vex.ID)
				return vexDocumentFromQuery(v), err
			}},
			{"vex-report", owner.report, func(ctx context.Context, a domain.Actor) (any, error) {
				v, err := read.GetVEXImportReport(ctx, a, owner.vex.ID)
				return vexImportReportFromQuery(v), err
			}},
		} {
			value, err := tc.run(t.Context(), human)
			if err != nil {
				t.Fatal("owned fixture point rejected", tc.name, err)
			}
			assertEvidenceFixtureJSON(t, value, tc.want)
			if _, err := tc.run(t.Context(), foreign.actor); !errors.Is(err, app.ErrNotFound) {
				t.Fatal("fixture point exposed foreign ownership", tc.name, err)
			}
			denied := human
			denied.ResourceGrants = nil
			if _, err := tc.run(t.Context(), denied); !errors.Is(err, app.ErrForbidden) {
				t.Fatal("fixture point retained removed authority", tc.name, err)
			}
			denied.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"*"}}}
			if _, err := tc.run(t.Context(), denied); !errors.Is(err, app.ErrForbidden) {
				t.Fatal("fixture point accepted wrong resource grant", tc.name, err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := tc.run(ctx, human); !errors.Is(err, context.Canceled) {
				t.Fatal("fixture point ignored cancellation", tc.name, err)
			}
		}
		filter := evidencequery.EvidencePageFilter{ProductID: owner.product.ID, Type: "manual"}
		first, err := pages.ListPage(t.Context(), human, filter, request, nil)
		if err != nil || len(first.Items) != 1 || first.Next == nil || first.Items[0].TenantID != owner.actor.TenantID {
			t.Fatal("fixture evidence page lost scope or continuation", err)
		}
		second, err := pages.ListPage(t.Context(), human, filter, request, first.Next)
		if err != nil || len(second.Items) != 1 || second.Next != nil || second.Items[0].ID == first.Items[0].ID || second.Items[0].TenantID != owner.actor.TenantID {
			t.Fatal("fixture evidence page repeated, leaked or omitted records", err)
		}
		expectedIDs := map[string]bool{owner.original.ID: true, owner.replacement.ID: true}
		if !expectedIDs[first.Items[0].ID] || !expectedIDs[second.Items[0].ID] {
			t.Fatal("fixture evidence page lost complete filtered inventory")
		}
		denied := human
		denied.ResourceGrants = nil
		if page, err := pages.ListPage(t.Context(), denied, filter, request, nil); err != nil || len(page.Items) != 0 {
			t.Fatal("fixture evidence page leaked after grant removal", err)
		}
		componentFilter := evidencequery.SBOMComponentFilter{SBOMID: owner.sbom.ID, ReleaseID: owner.release.ID, Query: "one", PURL: "pkg:generic/one@1"}
		part, err := components.ListPage(t.Context(), human, componentFilter, request, nil)
		if err != nil || len(part.Items) != 1 || part.Next != nil || part.Items[0].SBOMID != owner.sbom.ID || part.Items[0].Component.Name != "one" {
			t.Fatal("fixture component filters lost ownership or metadata", err)
		}
		if _, err := components.ListPage(t.Context(), foreign.actor, componentFilter, request, nil); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("fixture component page exposed foreign SBOM", err)
		}
		if _, err := components.ListPage(t.Context(), denied, componentFilter, request, nil); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("fixture component page retained removed grants", err)
		}
		inventory := evidencequery.SBOMComponentFilter{SBOMID: owner.sbom.ID}
		part, err = components.ListPage(t.Context(), human, inventory, request, nil)
		if err != nil || len(part.Items) != 1 || part.Next == nil {
			t.Fatal("fixture component page lost inventory continuation", err)
		}
		continued, err := components.ListPage(t.Context(), human, inventory, request, part.Next)
		if err != nil || len(continued.Items) != 1 || continued.Next != nil || continued.Items[0].ID == part.Items[0].ID || continued.Items[0].SBOMID != owner.sbom.ID {
			t.Fatal("fixture component continuation repeated, omitted or leaked records", err)
		}
		events, err := lifecycle.ListPage(t.Context(), human, owner.original.ID, request, nil)
		if err != nil || len(events.Items) != 1 || events.Next == nil {
			t.Fatal("fixture lifecycle page lost continuation", err)
		}
		next, err := lifecycle.ListPage(t.Context(), human, owner.original.ID, request, events.Next)
		if err != nil || len(next.Items) != 1 || next.Next != nil || next.Items[0].ID == events.Items[0].ID {
			t.Fatal("fixture lifecycle page did not cover complete event history", err)
		}
		if _, err := lifecycle.ListPage(t.Context(), foreign.actor, owner.original.ID, request, nil); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("fixture lifecycle page exposed foreign evidence", err)
		}
		if _, err := lifecycle.ListPage(t.Context(), denied, owner.original.ID, request, nil); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("fixture lifecycle page retained removed grants", err)
		}
		encoded, err := json.Marshal(lifecycleEventFromQuery(events.Items[0]))
		if err != nil || strings.Contains(string(encoded), "private-value") || !strings.Contains(string(encoded), "visible") {
			t.Fatal("fixture lifecycle page leaked details or lost public note", err)
		}
		events.Items[0].Details["nested"].(map[string]any)["value"] = "changed"
		refreshed, err := lifecycle.ListPage(t.Context(), human, owner.original.ID, request, nil)
		if err != nil || len(refreshed.Items) != 1 || refreshed.Items[0].Details["nested"].(map[string]any)["value"] != "original" {
			t.Fatal("lifecycle fixture shared the cached record's nested details", err)
		}
		preview, err := read.PreviewVEXImport(t.Context(), human, evidencequery.VEXPreviewInput{ReleaseID: owner.release.ID, Format: "openvex", Payload: owner.payload})
		if err != nil || !preview.Advisory || preview.StatementCount != 1 || preview.DecisionsWouldCreate != 1 {
			t.Fatal("fixture VEX preview lost advisory mapping", err)
		}
		if _, err := read.PreviewVEXImport(t.Context(), foreign.actor, evidencequery.VEXPreviewInput{ReleaseID: owner.release.ID, Format: "openvex", Payload: owner.payload}); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("fixture preview exposed a foreign release", err)
		}
		if _, err := read.PreviewVEXImport(t.Context(), denied, evidencequery.VEXPreviewInput{ReleaseID: owner.release.ID, Format: "openvex", Payload: owner.payload}); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("fixture preview retained removed grants", err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("fixture read, preview or detached metadata mutation changed repository state", err)
	}
}

func TestEvidenceReadFixtureMappingsRetainDetachedDocumentMetadata(t *testing.T) {
	now := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	contract := domain.OpenAPIContract{ID: "contract", TenantID: "tenant", ProductID: "product", ReleaseID: "release", Version: "1", Hash: "hash", PathCount: 1, EvidenceID: "evidence", Operations: []domain.OpenAPIOperation{{Path: "/items", Method: "post", OperationID: "createItem", Deprecated: true, RequestBodyRequired: true, RequiredRequestFields: []string{"name"}, ResponseStatuses: []string{"201"}}}, CreatedAt: now}
	parsed := fixtureOpenAPIContract(contract)
	assertEvidenceFixtureJSON(t, openAPIContractFromQuery(parsed), contract)
	parsed.Operations[0].RequiredRequestFields[0], parsed.Operations[0].ResponseStatuses[0] = "changed", "changed"
	if contract.Operations[0].RequiredRequestFields[0] != "name" || contract.Operations[0].ResponseStatuses[0] != "201" {
		t.Fatal("contract fixture shared operation metadata")
	}
	scan := domain.VulnerabilityScan{ID: "scan", TenantID: "tenant", EvidenceID: "evidence", ReleaseID: "release", Scanner: "scanner", Adapter: "adapter", AdapterVersion: "version", SourceSchema: "schema", TargetRef: "target", Summary: map[string]int{"high": 1}, Findings: []domain.VulnerabilityFinding{{ID: "finding", Vulnerability: "CVE", Component: "library", Severity: "high", State: "open", SeveritySource: "scanner", FixVersion: "2", Identity: domain.VulnerabilityIdentity{CVE: "CVE", GHSA: "GHSA", OSV: "OSV", VendorAdvisory: "vendor", PURL: "purl", CPE: "cpe"}}}, CreatedAt: now}
	projected := fixtureVulnerabilityScan(scan)
	assertEvidenceFixtureJSON(t, vulnerabilityScanFromQuery(projected), scan)
	projected.Summary["high"], projected.Findings[0].Identity.PURL = 99, "changed"
	if scan.Summary["high"] != 1 || scan.Findings[0].Identity.PURL != "purl" {
		t.Fatal("scan fixture shared normalized data")
	}
	report := domain.VEXImportReport{ID: "report", TenantID: "tenant", VEXDocumentID: "vex", EvidenceID: "evidence", ReleaseID: "release", ArtifactID: "artifact", ParserVersion: "parser", Status: "parsed", StatementCount: 3, DecisionsCreated: 2, DecisionsSuperseded: 1, UnsupportedFields: []string{"field"}, Warnings: []string{"warning"}, InvalidStatements: []domain.VEXImportIssue{{StatementIndex: 1, Code: "invalid", Detail: "detail"}}, MappingFailures: []domain.VEXImportIssue{{StatementIndex: 2, Code: "missing", Detail: "missing"}}, FailureCode: "failure", FailureDetail: "safe detail", SchemaVersion: "report.v1", CreatedAt: now, UpdatedAt: now.Add(time.Minute)}
	converted := fixtureVEXReport(report)
	assertEvidenceFixtureJSON(t, vexImportReportFromQuery(converted), report)
	converted.UnsupportedFields[0], converted.Warnings[0], converted.InvalidStatements[0].Detail, converted.MappingFailures[0].Detail = "changed", "changed", "changed", "changed"
	if report.UnsupportedFields[0] != "field" || report.Warnings[0] != "warning" || report.InvalidStatements[0].Detail != "detail" || report.MappingFailures[0].Detail != "missing" {
		t.Fatal("VEX report fixture shared issue history")
	}
	preview := domain.VEXImportPreview{TenantID: "tenant", ReleaseID: "release", ArtifactID: "artifact", Format: "openvex", ParserVersion: "parser", Advisory: true, StatementCount: 3, StatusSummary: map[string]int{"affected": 3}, DecisionsWouldCreate: 2, DecisionsWouldSupersede: 1, Warnings: []string{"warning"}, InvalidStatements: report.InvalidStatements, MappingFailures: report.MappingFailures, Assumptions: []string{"assumption"}, Limitations: []string{"limitation"}, SchemaVersion: "preview.v1", GeneratedAt: now}
	advisory := fixtureVEXPreview(preview)
	assertEvidenceFixtureJSON(t, domain.VEXImportPreviewFromContext(advisory), preview)
	advisory.StatusSummary["affected"], advisory.Warnings[0], advisory.Assumptions[0], advisory.Limitations[0], advisory.InvalidStatements[0].Detail = 99, "changed", "changed", "changed", "changed"
	if preview.StatusSummary["affected"] != 3 || preview.Warnings[0] != "warning" || preview.Assumptions[0] != "assumption" || preview.Limitations[0] != "limitation" || preview.InvalidStatements[0].Detail != "detail" {
		t.Fatal("VEX preview fixture shared advisory metadata")
	}
}

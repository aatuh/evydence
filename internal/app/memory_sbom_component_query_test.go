package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func memorySBOMComponentFixture(t *testing.T) (*memoryUnitOfWork, evidencequery.SBOMComponentReader, *evidencequery.SBOMComponents, domain.Actor) {
	t.Helper()
	tx, _ := memoryParsedPointFixture(t)
	reader, ok := tx.Repositories().Evidence.(evidencequery.SBOMComponentReader)
	if !ok {
		t.Fatal("memory Evidence repository lacks native SBOM component paging")
	}
	query, err := evidencequery.NewSBOMComponents(reader)
	if err != nil {
		t.Fatal(err)
	}
	tx.state.SBOMs = map[string]domain.SBOM{"sbom": tx.state.SBOMs["sbom"]}
	actor := domain.Actor{TenantID: "tenant", UserID: "reader", Scopes: []string{ScopeEvidenceRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "tenant-product", Scopes: []string{ScopeEvidenceRead}}}}
	return tx, reader, query, actor
}

func TestMemorySBOMComponentsPageAllRecordsWithFiltersAndStableCursors(t *testing.T) {
	tx, _, query, actor := memorySBOMComponentFixture(t)
	b := tx.state.SBOMs["sbom"]
	b.Components = make([]domain.SBOMComponent, 501)
	wantIDs := make([]string, len(b.Components))
	for i := range b.Components {
		b.Components[i] = domain.SBOMComponent{Identity: fmt.Sprintf("component-%03d", i), Name: fmt.Sprintf("lib-%03d", i), Version: "1", PURL: fmt.Sprintf("pkg:generic/lib-%03d@1", i)}
		wantIDs[i] = fmt.Sprintf("sbom:%d", i)
	}
	b.ComponentCount = len(b.Components)
	tx.state.SBOMs[b.ID] = b
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(wantIDs)
	for _, direction := range []appquery.Direction{appquery.Ascending, appquery.Descending} {
		page := appquery.PageRequest{PageSize: 500, Sort: appquery.SortID, Direction: direction}
		first, err := query.ListPage(t.Context(), actor, evidencequery.SBOMComponentFilter{SBOMID: " sbom "}, page, nil)
		if err != nil || len(first.Items) != 500 || first.Next == nil || first.Next.ID != first.Items[499].ID || first.Next.Value != first.Next.ID {
			t.Fatal("first page lost bounded records or continuation", len(first.Items), first.Next, err)
		}
		second, err := query.ListPage(t.Context(), actor, evidencequery.SBOMComponentFilter{SBOMID: b.ID}, page, first.Next)
		if err != nil || len(second.Items) != 1 || second.Next != nil {
			t.Fatal("continuation retained the former inventory cap", second, err)
		}
		ids := []string{}
		for _, record := range append(first.Items, second.Items...) {
			ids = append(ids, record.ID)
			if record.SBOMID != b.ID || record.ReleaseID != b.ReleaseID || record.ArtifactID != b.ArtifactID || record.Format != b.Format || record.SpecVersion != b.SpecVersion {
				t.Fatal("component paging lost public document metadata", record)
			}
		}
		want := slices.Clone(wantIDs)
		if direction == appquery.Descending {
			slices.Reverse(want)
		}
		if !reflect.DeepEqual(ids, want) {
			t.Fatal("component pages omitted, repeated or misordered records", ids)
		}
		first.Items[0].Component.Name = "caller-mutated"
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	filtered, err := query.ListPage(t.Context(), actor, evidencequery.SBOMComponentFilter{SBOMID: b.ID, ReleaseID: " tenant-release ", ArtifactID: " artifact ", Query: " LIB-500 ", PURL: " pkg:generic/lib-500@1 "}, page, nil)
	want := evidencedomain.SBOMComponentRecord{ID: "sbom:500", SBOMID: b.ID, ReleaseID: b.ReleaseID, ArtifactID: b.ArtifactID, Format: b.Format, SpecVersion: b.SpecVersion, Component: evidencedomain.SBOMComponent{Identity: "component-500", Name: "lib-500", Version: "1", PURL: "pkg:generic/lib-500@1"}}
	if err != nil || !reflect.DeepEqual(filtered.Items, []evidencedomain.SBOMComponentRecord{want}) || filtered.Next != nil {
		t.Fatal("filtered page lost exact public metadata", filtered, err)
	}
	// Native keysets remain usable if the cursor row is no longer visible.
	after := &appquery.SortKey{Value: "sbom:499a", ID: "sbom:499a"}
	result, err := query.ListPage(t.Context(), actor, evidencequery.SBOMComponentFilter{SBOMID: b.ID}, page, after)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "sbom:5" {
		t.Fatal("keyset required a currently visible cursor row", result, err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("component queries or caller mutations changed recorded rows")
	}
}

func TestMemorySBOMComponentsApplyCurrentOwnershipAndVisibilityBeforeLimits(t *testing.T) {
	for _, change := range []string{"foreign-root", "foreign-source", "wrong-type", "wrong-release", "missing-product", "missing-build", "foreign-artifact", "ambiguous-artifact", "ungranted"} {
		t.Run(change, func(t *testing.T) {
			tx, _, query, actor := memorySBOMComponentFixture(t)
			b, e := tx.state.SBOMs["sbom"], tx.state.Evidence["sbom-source"]
			switch change {
			case "foreign-root":
				b.TenantID = "foreign"
			case "foreign-source":
				e.TenantID = "foreign"
			case "wrong-type":
				e.Type = "manual"
			case "wrong-release":
				e.ReleaseID = "foreign-release"
			case "missing-product":
				delete(tx.state.Products, "tenant-product")
			case "missing-build":
				e.BuildID = "missing"
			case "foreign-artifact":
				a := tx.state.Artifacts["artifact"]
				a.TenantID = "foreign"
				tx.state.Artifacts[a.ID] = a
			case "ambiguous-artifact":
				e.SubjectRefs = append(e.SubjectRefs, domain.SubjectRef{Type: "artifact", ID: "another"})
			case "ungranted":
				actor.ResourceGrants[0].ResourceID = "foreign-product"
			}
			tx.state.SBOMs[b.ID], tx.state.Evidence[e.ID] = b, e
			page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
			point, err := query.ListPage(t.Context(), actor, evidencequery.SBOMComponentFilter{SBOMID: b.ID}, page, nil)
			if !errors.Is(err, evidencequery.ErrNotFound) || len(point.Items) != 0 || point.Next != nil {
				t.Fatal("hidden or incoherent SBOM revealed a page", point, err)
			}
			collection, err := query.ListPage(t.Context(), actor, evidencequery.SBOMComponentFilter{}, page, nil)
			if err != nil || len(collection.Items) != 0 || collection.Next != nil {
				t.Fatal("hidden SBOM consumed a page or failed the collection", collection, err)
			}
		})
	}
	tx, _, query, actor := memorySBOMComponentFixture(t)
	b := tx.state.SBOMs["sbom"]
	b.ID = "aaa-hidden"
	b.TenantID = "foreign"
	tx.state.SBOMs[b.ID] = b
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	result, err := query.ListPage(t.Context(), actor, evidencequery.SBOMComponentFilter{}, page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "sbom:0" || result.Next != nil {
		t.Fatal("foreign row displaced the visible page", result, err)
	}
	result, err = query.ListPage(t.Context(), actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom", ReleaseID: "foreign-release"}, page, nil)
	if err != nil || len(result.Items) != 0 {
		t.Fatal("nonmatching filter was confused with a hidden root", result, err)
	}
}

func TestMemorySBOMComponentsRejectInvalidRequestsAndDiscardCancellation(t *testing.T) {
	tx, reader, _, _ := memorySBOMComponentFixture(t)
	request := evidencequery.SBOMComponentPageRequest{TenantID: "tenant", TenantWide: true, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	for _, change := range []string{"no-tenant", "no-visibility", "ambiguous-visibility", "bad-limit", "bad-sort", "bad-key"} {
		invalid := request
		switch change {
		case "no-tenant":
			invalid.TenantID = " "
		case "no-visibility":
			invalid.TenantWide = false
		case "ambiguous-visibility":
			invalid.AllowedProductIDs = []string{"tenant-product"}
		case "bad-limit":
			invalid.Page.PageSize = 501
		case "bad-sort":
			invalid.Page.Sort = appquery.SortCreatedAt
		case "bad-key":
			invalid.After = &appquery.SortKey{Value: "different", ID: "sbom:0"}
		}
		result, err := reader.PageSBOMComponents(t.Context(), invalid)
		if !errors.Is(err, evidencequery.ErrValidation) || !reflect.DeepEqual(result, appquery.Result[evidencequery.SBOMComponentPoint]{}) {
			t.Fatal("invalid component request returned data", change, result, err)
		}
	}
	var absent context.Context
	if _, err := reader.PageSBOMComponents(absent, request); !errors.Is(err, evidencequery.ErrValidation) {
		t.Fatal("nil paging context accepted", err)
	}
	base, cancel := context.WithCancel(t.Context())
	during := &memorySBOMCancelDuringPage{Context: base, cancel: cancel}
	b := tx.state.SBOMs["sbom"]
	b.Components = append(b.Components, b.Components[0])
	tx.state.SBOMs[b.ID] = b
	result, err := reader.PageSBOMComponents(during, request)
	cancel()
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, appquery.Result[evidencequery.SBOMComponentPoint]{}) {
		t.Fatal("canceled selection exposed partial components", result, err)
	}
	if _, err := reader.PageSBOMComponents(t.Context(), request); err != nil {
		t.Fatal("canceled page retained its transaction lock", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	result, err = reader.PageSBOMComponents(t.Context(), request)
	if !errors.Is(err, ErrConflict) || !reflect.DeepEqual(result, appquery.Result[evidencequery.SBOMComponentPoint]{}) {
		t.Fatal("closed transaction returned a component page", result, err)
	}
}

func TestMemorySBOMComponentsRequireCurrentExplicitArtifactAssociations(t *testing.T) {
	for _, tc := range []struct {
		name, grant string
		visible     bool
	}{
		{"source-product", "product", true},
		{"derived-product-is-not-explicit", "product", false},
		{"source-project", "project", true},
		{"missing-project-association", "project", false},
		{"build-project", "project", true},
		{"wrong-output-digest", "project", false},
		{"foreign-build", "project", false},
		{"other-association-release", "project", false},
		{"other-build-release", "project", false},
		{"direct-release", "release", true},
		{"no-artifact-product", "product", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, reader, query, actor := memorySBOMComponentFixture(t)
			e, b := tx.state.Evidence["sbom-source"], tx.state.SBOMs["sbom"]
			e.ProductID = ""
			tx.state.Evidence = map[string]domain.EvidenceItem{}
			tx.state.BuildRuns = map[string]domain.BuildRun{}
			actor.ResourceGrants[0].ResourceType = tc.grant
			actor.ResourceGrants[0].ResourceID = "tenant-" + tc.grant
			switch tc.name {
			case "source-product":
				e.ProductID = "tenant-product"
			case "source-project":
				e.ProjectID = "tenant-project"
			case "no-artifact-product":
				b.ArtifactID, e.SubjectRefs = "", nil
			case "other-association-release":
				r := tx.state.Releases["tenant-release"]
				r.ID = "other-release"
				tx.state.Releases[r.ID] = r
				tx.state.Evidence["association"] = domain.EvidenceItem{ID: "association", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: r.ID, SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: "artifact"}}}
			case "build-project", "wrong-output-digest", "foreign-build", "other-build-release":
				build := domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: "tenant-release", Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: tx.state.Artifacts["artifact"].Digest}}}
				if tc.name == "wrong-output-digest" {
					build.Outputs[0].Digest = "wrong"
				}
				if tc.name == "foreign-build" {
					build.TenantID = "foreign"
				}
				if tc.name == "other-build-release" {
					r := tx.state.Releases["tenant-release"]
					r.ID = "other-release"
					tx.state.Releases[r.ID] = r
					build.ReleaseID = r.ID
				}
				tx.state.BuildRuns[build.ID] = build
			}
			tx.state.Evidence[e.ID], tx.state.SBOMs[b.ID] = e, b
			page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
			result, err := query.ListPage(t.Context(), actor, evidencequery.SBOMComponentFilter{SBOMID: b.ID}, page, nil)
			if tc.name == "source-project" {
				raw, err := reader.PageSBOMComponents(t.Context(), evidencequery.SBOMComponentPageRequest{TenantID: actor.TenantID, AllowedProjectIDs: []string{"tenant-project"}, Page: page})
				if err != nil || len(raw.Items) != 1 || raw.Items[0].ProductID != "" || raw.Items[0].ProjectID != "tenant-project" || raw.Items[0].ReleaseID != "tenant-release" {
					t.Fatal("evidence association expanded an unsupplied product", raw, err)
				}
			}
			if tc.visible {
				if err != nil || len(result.Items) != 1 || result.Items[0].ID != "sbom:0" {
					t.Fatal("valid current association did not grant the page", result, err)
				}
			} else if !errors.Is(err, evidencequery.ErrNotFound) || len(result.Items) != 0 || result.Next != nil {
				t.Fatal("invalid association reached the selected page", result, err)
			}
			actor.ResourceGrants = nil
			if _, err := query.ListPage(t.Context(), actor, evidencequery.SBOMComponentFilter{}, page, nil); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("removed grant retained collection access")
			}
		})
	}
}

type memorySBOMCancelDuringPage struct {
	context.Context
	cancel context.CancelFunc
	calls  int
}

func TestMemorySBOMComponentsValidateOnlySelectedComponents(t *testing.T) {
	tx, _, query, actor := memorySBOMComponentFixture(t)
	b := tx.state.SBOMs["sbom"]
	b.Components = append(b.Components, domain.SBOMComponent{Version: "invalid"})
	tx.state.SBOMs[b.ID] = b
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortID, Direction: appquery.Ascending}
	result, err := query.ListPage(t.Context(), actor, evidencequery.SBOMComponentFilter{SBOMID: b.ID}, page, nil)
	if !errors.Is(err, evidencequery.ErrConflict) || !reflect.DeepEqual(result, appquery.Result[evidencedomain.SBOMComponentRecord]{}) {
		t.Fatal("invalid selected component returned partial data", result, err)
	}
	result, err = query.ListPage(t.Context(), actor, evidencequery.SBOMComponentFilter{SBOMID: b.ID, Query: "api"}, page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].Component.Name != "api" {
		t.Fatal("unselected component invalidated a valid page", result, err)
	}
	b.Components, b.ComponentCount = nil, 10
	tx.state.SBOMs[b.ID] = b
	result, err = query.ListPage(t.Context(), actor, evidencequery.SBOMComponentFilter{SBOMID: b.ID}, page, nil)
	if err != nil || len(result.Items) != 0 || result.Next != nil {
		t.Fatal("empty component view incorrectly required point completion", result, err)
	}
}

func (c *memorySBOMCancelDuringPage) Err() error {
	c.calls++
	if c.calls == 5 {
		c.cancel()
	}
	return c.Context.Err()
}

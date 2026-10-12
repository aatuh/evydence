package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func memoryEvidencePageFixture(t *testing.T) (*memoryUnitOfWork, evidencequery.EvidencePageReader, *evidencequery.EvidencePages, domain.Actor) {
	t.Helper()
	tx, _, _, actor := memoryLifecycleFixture(t)
	reader, ok := tx.Repositories().Evidence.(evidencequery.EvidencePageReader)
	if !ok {
		t.Fatal("memory Evidence repository lacks native evidence pages")
	}
	query, err := evidencequery.NewEvidencePages(reader)
	if err != nil {
		t.Fatal(err)
	}
	base := tx.state.Evidence["tenant-evidence"]
	tx.state.Evidence = map[string]domain.EvidenceItem{}
	for i := range 8 {
		e := base
		e.ID, e.Type, e.Subtype, e.SourceSystem, e.CollectorID, e.VerificationStatus = fmt.Sprintf("visible-%02d", 7-i), "document", "review", "ci", "collector", "pending"
		e.CreatedAt = fixedNow().Add(time.Duration(i/2) * time.Microsecond)
		e.Metadata = map[string]any{"nested": map[string]any{"value": "original", "number": json.Number("9007199254740993")}}
		e.Tags = []string{"reviewed"}
		e.SubjectRefs = []domain.SubjectRef{{Type: "artifact", ID: "artifact", Digest: "opaque-digest"}}
		tx.state.Evidence[e.ID] = e
	}
	tx.state.Products["hidden-product"] = domain.Product{ID: "hidden-product", TenantID: "tenant"}
	tx.state.Releases["hidden-release"] = domain.Release{ID: "hidden-release", TenantID: "tenant", ProductID: "hidden-product"}
	for _, id := range []string{"aaa-hidden", "zzz-hidden"} {
		e := base
		e.ID, e.Type, e.ProductID, e.ReleaseID = id, "document", "hidden-product", "hidden-release"
		e.Metadata = map[string]any{"private-invalid": func() {}}
		tx.state.Evidence[e.ID] = e
	}
	return tx, reader, query, actor
}

func TestMemoryEvidencePagesFilterBeforeLimitAndPreserveBothOrders(t *testing.T) {
	tx, _, query, actor := memoryEvidencePageFixture(t)
	// Do not marshal hidden invalid metadata merely to build a test baseline.
	before := tx.state.Evidence["visible-00"]
	wantBody, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []appquery.Sort{appquery.SortID, appquery.SortCreatedAt} {
		for _, direction := range []appquery.Direction{appquery.Ascending, appquery.Descending} {
			want := []domain.EvidenceItem{}
			for _, e := range tx.state.Evidence {
				if strings.HasPrefix(e.ID, "visible-") {
					want = append(want, e)
				}
			}
			sort.Slice(want, func(i, j int) bool {
				if field == appquery.SortCreatedAt && !want[i].CreatedAt.Equal(want[j].CreatedAt) {
					return want[i].CreatedAt.Before(want[j].CreatedAt)
				}
				return want[i].ID < want[j].ID
			})
			if direction == appquery.Descending {
				slices.Reverse(want)
			}
			page := appquery.PageRequest{PageSize: 3, Sort: field, Direction: direction}
			var after *appquery.SortKey
			ids := []string{}
			for n := 0; n < 4; n++ {
				result, err := query.ListPage(t.Context(), actor, evidencequery.EvidencePageFilter{}, page, after)
				if err != nil || len(result.Items) > 3 {
					t.Fatal("hidden private data displaced visible page", result, err)
				}
				for _, item := range result.Items {
					got, err := json.Marshal(domain.EvidenceFromContextModel(item))
					want, marshalErr := json.Marshal(tx.state.Evidence[item.ID])
					if err != nil || marshalErr != nil || !bytes.Equal(got, want) {
						t.Fatal("evidence page lost complete metadata or exact numbers", err, marshalErr)
					}
					ids = append(ids, item.ID)
					item.Metadata["nested"].(map[string]any)["value"] = "caller-mutated"
				}
				after = result.Next
				if after == nil {
					break
				}
			}
			wantIDs := []string{}
			for _, e := range want {
				wantIDs = append(wantIDs, e.ID)
			}
			if !reflect.DeepEqual(ids, wantIDs) || after != nil {
				t.Fatal("evidence pages repeated, omitted or misordered rows", ids, wantIDs)
			}
		}
	}
	filter := evidencequery.EvidencePageFilter{ProductID: "tenant-product", ReleaseID: "tenant-release", Type: "document", Subtype: "review", SourceSystem: "ci", CollectorID: "collector", VerificationStatus: "pending", SubjectType: "artifact", SubjectID: "opaque-digest", Tag: "reviewed", CreatedAfter: before.CreatedAt, CreatedBefore: before.CreatedAt}
	page := appquery.PageRequest{PageSize: 10, Sort: appquery.SortID, Direction: appquery.Ascending}
	result, err := query.ListPage(t.Context(), actor, filter, page, nil)
	if err != nil || len(result.Items) != 2 || result.Items[0].ID != "visible-00" || result.Items[1].ID != "visible-01" {
		t.Fatal("complete search predicate or inclusive time bounds changed", result, err)
	}
	current, err := json.Marshal(tx.state.Evidence["visible-00"])
	if err != nil || !bytes.Equal(current, wantBody) {
		t.Fatal("page reads or caller mutation changed current rows", err)
	}
	actor.ResourceGrants = nil
	if result, err := query.ListPage(t.Context(), actor, evidencequery.EvidencePageFilter{}, page, nil); err != nil || len(result.Items) != 0 || result.Next != nil {
		t.Fatal("revoked grants retained page visibility", result, err)
	}
}

func TestMemoryEvidencePagesRecheckGrantedCandidatesAndSuppressOnlyDenials(t *testing.T) {
	tx, reader, query, actor := memoryEvidencePageFixture(t)
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	e := tx.state.Evidence["visible-00"]
	e.ID, e.ProductID = "aaa-corrupt", "missing-product"
	tx.state.Evidence[e.ID] = e
	if result, err := query.ListPage(t.Context(), actor, evidencequery.EvidencePageFilter{}, page, nil); !errors.Is(err, evidencequery.ErrConflict) || len(result.Items) != 0 || result.Next != nil {
		t.Fatal("granted incoherent candidate was silently dropped", result, err)
	}
	delete(tx.state.Evidence, e.ID)
	e = tx.state.Evidence["visible-00"]
	e.Metadata = map[string]any{"invalid-private": func() {}}
	tx.state.Evidence[e.ID] = e
	request := evidencequery.EvidencePageRequest{TenantID: actor.TenantID, AllowedReleaseIDs: []string{"tenant-release"}, Page: page}
	result, err := reader.PageEvidence(t.Context(), request, func(application.ResourceReferences) error { return application.ErrForbidden })
	if err != nil || len(result.Items) != 0 || result.Next != nil {
		t.Fatal("actual denial selected private data or consumed a page", result, err)
	}
	base, cancel := context.WithCancel(t.Context())
	result, err = reader.PageEvidence(base, request, func(application.ResourceReferences) error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, appquery.Result[evidencequery.EvidencePoint]{}) {
		t.Fatal("canceled page returned partial data", result, err)
	}
	delete(e.Metadata, "invalid-private")
	tx.state.Evidence[e.ID] = e
	if _, err := query.ListPage(t.Context(), actor, evidencequery.EvidencePageFilter{}, page, nil); err != nil {
		t.Fatal("cancellation retained transaction lock", err)
	}
}

func TestMemoryEvidencePagesValidateLookaheadAndReturnedPageBudget(t *testing.T) {
	tx, _, query, actor := memoryEvidencePageFixture(t)
	tx.state.Evidence = map[string]domain.EvidenceItem{}
	for i := range 3 {
		e := domain.EvidenceItem{ID: fmt.Sprintf("large-%d", i), TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", Type: "document", CreatedAt: fixedNow(), Metadata: map[string]any{"large": strings.Repeat("x", (11 << 19))}}
		tx.state.Evidence[e.ID] = e
	}
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortID, Direction: appquery.Ascending}
	result, err := query.ListPage(t.Context(), actor, evidencequery.EvidencePageFilter{}, page, nil)
	if err != nil || len(result.Items) != 2 || result.Next == nil {
		t.Fatal("valid lookahead counted as returned page bytes", err)
	}
	page.PageSize = 3
	result, err = query.ListPage(t.Context(), actor, evidencequery.EvidencePageFilter{}, page, nil)
	if !errors.Is(err, evidencequery.ErrConflict) || len(result.Items) != 0 || result.Next != nil {
		t.Fatal("aggregate page byte overflow returned partial success", err)
	}
	page.PageSize = 1
	lookahead := tx.state.Evidence["large-1"]
	lookahead.Metadata["large"] = strings.Repeat("x", 9<<20)
	tx.state.Evidence[lookahead.ID] = lookahead
	result, err = query.ListPage(t.Context(), actor, evidencequery.EvidencePageFilter{}, page, nil)
	if !errors.Is(err, evidencequery.ErrConflict) || len(result.Items) != 0 || result.Next != nil {
		t.Fatal("oversized lookahead provenance was not validated", err)
	}
}

func TestMemoryEvidencePagesSeparateInferredGrantsFromStoredFilters(t *testing.T) {
	tx, _, query, actor := memoryEvidencePageFixture(t)
	tx.state.Evidence = map[string]domain.EvidenceItem{"build-only": {ID: "build-only", TenantID: "tenant", BuildID: "build", Type: "document", CreatedAt: fixedNow()}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	for _, kind := range []string{"product", "project", "release"} {
		actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: kind, ResourceID: "tenant-" + kind, Scopes: []string{ScopeEvidenceRead}}}
		result, err := query.ListPage(t.Context(), actor, evidencequery.EvidencePageFilter{BuildID: "build"}, page, nil)
		if err != nil || len(result.Items) != 1 || result.Items[0].ID != "build-only" || result.Items[0].ProductID != "" || result.Items[0].ReleaseID != "" || result.Items[0].ProjectID != "" {
			t.Fatal("inferred grant lost visibility or rewrote stored references", kind, result, err)
		}
		result, err = query.ListPage(t.Context(), actor, evidencequery.EvidencePageFilter{ProductID: "tenant-product"}, page, nil)
		if err != nil || len(result.Items) != 0 || result.Next != nil {
			t.Fatal("inferred coordinates changed exact stored-field filtering", result, err)
		}
	}
	build := tx.state.BuildRuns["build"]
	build.ProjectID = "foreign-project"
	tx.state.BuildRuns[build.ID] = build
	result, err := query.ListPage(t.Context(), actor, evidencequery.EvidencePageFilter{}, page, nil)
	if !errors.Is(err, evidencequery.ErrConflict) || len(result.Items) != 0 || result.Next != nil {
		t.Fatal("granted build with foreign current parent was silently filtered", result, err)
	}
}

func TestMemoryEvidencePagesValidateRequestsAndClosedTransactions(t *testing.T) {
	tx, reader, query, actor := memoryEvidencePageFixture(t)
	request := evidencequery.EvidencePageRequest{TenantID: actor.TenantID, AllowedReleaseIDs: []string{"tenant-release"}, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	guard := func(application.ResourceReferences) error { return nil }
	for _, change := range []string{"bad-limit", "bad-sort", "bad-filter", "bad-key", "bad-time-key", "bad-year", "ambiguous-grants"} {
		bad := request
		switch change {
		case "bad-limit":
			bad.Page.PageSize = 501
		case "bad-sort":
			bad.Page.Sort = "unsupported"
		case "bad-filter":
			bad.Filter.Tag = "bad\x00tag"
		case "bad-key":
			bad.After = &appquery.SortKey{ID: "row", Value: "different"}
		case "bad-time-key":
			bad.Page.Sort = appquery.SortCreatedAt
			bad.After = &appquery.SortKey{ID: "row", Value: "2026-01-01T01:00:00+01:00"}
		case "bad-year":
			bad.Filter.CreatedAfter = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)
		case "ambiguous-grants":
			bad.TenantWide = true
		}
		result, err := reader.PageEvidence(t.Context(), bad, guard)
		if !errors.Is(err, evidencequery.ErrValidation) || !reflect.DeepEqual(result, appquery.Result[evidencequery.EvidencePoint]{}) {
			t.Fatal("invalid evidence page returned data", change, result, err)
		}
	}
	var absent context.Context
	if _, err := reader.PageEvidence(absent, request, guard); !errors.Is(err, evidencequery.ErrValidation) {
		t.Fatal("nil page context accepted", err)
	}
	if _, err := reader.PageEvidence(t.Context(), request, nil); !errors.Is(err, evidencequery.ErrValidation) {
		t.Fatal("nil page guard accepted", err)
	}
	missing := &appquery.SortKey{ID: "visible-03a", Value: "visible-03a"}
	result, err := query.ListPage(t.Context(), actor, evidencequery.EvidencePageFilter{}, request.Page, missing)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "visible-04" {
		t.Fatal("native keyset required an existing cursor row", result, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	closed, err := reader.PageEvidence(t.Context(), request, guard)
	if !errors.Is(err, ErrConflict) || !reflect.DeepEqual(closed, appquery.Result[evidencequery.EvidencePoint]{}) {
		t.Fatal("closed transaction returned evidence rows", closed, err)
	}
}

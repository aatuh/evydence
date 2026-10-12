package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func memoryDecisionPageFixture(t *testing.T) (*memoryUnitOfWork, riskquery.VulnerabilityDecisionReader, riskquery.DecisionPageRequest) {
	t.Helper()
	tx, _, _ := memoryDecisionSummaryFixture(t)
	r, ok := tx.Repositories().Decisions.(riskquery.VulnerabilityDecisionReader)
	if !ok {
		t.Fatal("memory Decision repository lacks native history paging")
	}
	d := tx.state.Decisions["decision"]
	tx.state.Decisions = map[string]domain.VulnerabilityDecision{}
	for i := 1; i <= 3; i++ {
		v := d
		v.ID = fmt.Sprintf("decision-%d", i)
		if i == 3 {
			v.CreatedAt = v.CreatedAt.AddDate(0, 0, 1)
		}
		tx.state.Decisions[v.ID] = v
	}
	return tx, r, riskquery.DecisionPageRequest{TenantID: "tenant", AllowedProductIDs: []string{"tenant-product"}, Filter: riskquery.DecisionFilter{ReleaseID: "tenant-release"}, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
}

func TestMemoryDecisionPageTraversesBothOrdersAndReturnsDetachedPublicMetadata(t *testing.T) {
	tx, reader, request := memoryDecisionPageFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, sort := range []appquery.Sort{appquery.SortID, appquery.SortCreatedAt} {
		for _, direction := range []appquery.Direction{appquery.Ascending, appquery.Descending} {
			request.Page.Sort, request.Page.Direction, request.After = sort, direction, nil
			seen := []string{}
			for i := 0; i < 3; i++ {
				page, err := reader.PageVulnerabilityDecisions(t.Context(), request)
				if err != nil || page.FilterRelease != (riskquery.ReleaseScope{ID: "tenant-release", ProductID: "tenant-product"}) || len(page.Page.Items) != 1 || page.Page.Items[0].Decision.InternalNotes != "" {
					t.Fatal("history page lost current ownership or public metadata", err)
				}
				point := page.Page.Items[0]
				want := tx.state.Decisions[point.Decision.ID]
				want.InternalNotes = ""
				model, err := domain.VulnerabilityDecisionToContextModel(want)
				if err != nil || !reflect.DeepEqual(point, riskquery.DecisionPoint{Decision: model, ProductID: "tenant-product"}) {
					t.Fatal("history lost selected public decision fields", err)
				}
				seen = append(seen, point.Decision.ID)
				point.Decision.EvidenceIDs[0], point.Decision.SupportingRefs[0].Digest = "changed", "changed"
				*point.Decision.ReviewedAt = fixedNow().AddDate(1, 0, 0)
				request.After = page.Page.Next
				if (i == 2) != (request.After == nil) {
					t.Fatal("history continuation ended early or repeated rows")
				}
			}
			want := []string{"decision-1", "decision-2", "decision-3"}
			if direction == appquery.Descending {
				want = []string{"decision-3", "decision-2", "decision-1"}
			}
			if !reflect.DeepEqual(seen, want) {
				t.Fatal("history lost deterministic tie ordering", seen)
			}
		}
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("history read or caller mutation changed repository data")
	}
}

func TestMemoryDecisionPageLimitsSelectedWindowAndAppliesFiltersBeforeMetadata(t *testing.T) {
	tx, reader, request := memoryDecisionPageFixture(t)
	v := tx.state.Decisions["decision-3"]
	v.Status, v.ActionStatement = "invalid", strings.Repeat("x", 8<<20)
	tx.state.Decisions[v.ID] = v
	if page, err := reader.PageVulnerabilityDecisions(t.Context(), request); err != nil || len(page.Page.Items) != 1 || page.Page.Next == nil {
		t.Fatal("page inspected unselected metadata beyond lookahead", err)
	}
	v = tx.state.Decisions["decision-2"]
	v.ActionStatement = strings.Repeat("x", 8<<20)
	tx.state.Decisions[v.ID] = v
	if page, err := reader.PageVulnerabilityDecisions(t.Context(), request); !errors.Is(err, riskquery.ErrInvalidProjection) || !reflect.DeepEqual(page, riskquery.DecisionPage{}) {
		t.Fatal("lookahead overflow returned partial history", err)
	}
	request.Filter.Component = "missing"
	if page, err := reader.PageVulnerabilityDecisions(t.Context(), request); err != nil || len(page.Page.Items) != 0 || page.Page.Next != nil {
		t.Fatal("unmatched decisions entered page budget", err)
	}
	request.Filter.Component, request.Filter.ProductID = "", "tenant-product"
	request.AllowedProductIDs, request.AllowedReleaseIDs = nil, []string{"tenant-release"}
	if _, err := reader.PageVulnerabilityDecisions(t.Context(), request); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("product-filter metadata selected with release-only authority", err)
	}
	request.Filter.ProductID, request.AllowedReleaseIDs = "", nil
	if _, err := reader.PageVulnerabilityDecisions(t.Context(), request); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("release-filter authority survived grant removal", err)
	}
	request.TenantID = "foreign"
	if _, err := reader.PageVulnerabilityDecisions(t.Context(), request); !errors.Is(err, riskquery.ErrNotFound) {
		t.Fatal("history exposed another tenant's release", err)
	}
}

func TestMemoryDecisionPageFiltersActiveHistoryAndInvisibleParentsBeforeLimit(t *testing.T) {
	tx, reader, request := memoryDecisionPageFixture(t)
	d := tx.state.Decisions["decision-1"]
	d.SupersededBy, d.CustomerVisible = "decision-2", false
	tx.state.Decisions[d.ID] = d
	tx.state.Products["foreign-product"] = domain.Product{ID: "foreign-product", TenantID: "foreign"}
	tx.state.Releases["foreign-parent"] = domain.Release{ID: "foreign-parent", TenantID: "tenant", ProductID: "foreign-product"}
	for _, kind := range []string{"foreign", "dangling", "foreign-parent"} {
		v := d
		v.ID, v.Status = "a-"+kind, "invalid"
		switch kind {
		case "foreign":
			v.TenantID = "foreign"
		case "dangling":
			v.ReleaseID = "missing"
		case "foreign-parent":
			v.ReleaseID = "foreign-parent"
		}
		tx.state.Decisions[v.ID] = v
	}
	request.Filter = riskquery.DecisionFilter{}
	active := true
	request.Filter.Active = &active
	page, err := reader.PageVulnerabilityDecisions(t.Context(), request)
	if err != nil || len(page.Page.Items) != 1 || page.Page.Items[0].Decision.ID != "decision-2" || page.Page.Next == nil {
		t.Fatal("active history filtered parents after the page limit", err)
	}
	active = false
	page, err = reader.PageVulnerabilityDecisions(t.Context(), request)
	if err != nil || len(page.Page.Items) != 1 || page.Page.Items[0].Decision.ID != d.ID || page.Page.Items[0].Decision.CustomerVisible || page.Page.Next != nil {
		t.Fatal("history omitted non-customer-visible superseded decision", err)
	}
	request.AllowedProductIDs = nil
	if page, err := reader.PageVulnerabilityDecisions(t.Context(), request); err != nil || len(page.Page.Items) != 0 || page.Page.Next != nil {
		t.Fatal("unfiltered history exposed decisions after grant removal", err)
	}
}

func TestMemoryDecisionPageTraversesBeyondFiveHundredAndRejectsInvalidContexts(t *testing.T) {
	tx, reader, request := memoryDecisionPageFixture(t)
	d := tx.state.Decisions["decision-1"]
	tx.state.Decisions = map[string]domain.VulnerabilityDecision{}
	for i := range 501 {
		v := d
		v.ID = fmt.Sprintf("decision-%03d", i)
		tx.state.Decisions[v.ID] = v
	}
	request.Page.PageSize = 500
	first, err := reader.PageVulnerabilityDecisions(t.Context(), request)
	if err != nil || len(first.Page.Items) != 500 || first.Page.Next == nil {
		t.Fatal("history imposed a tenant-inventory cap", err)
	}
	request.After = first.Page.Next
	last, err := reader.PageVulnerabilityDecisions(t.Context(), request)
	if err != nil || len(last.Page.Items) != 1 || last.Page.Items[0].Decision.ID != "decision-500" || last.Page.Next != nil {
		t.Fatal("history lost continuation beyond 500 decisions", err)
	}
	var absent context.Context
	if _, err := reader.PageVulnerabilityDecisions(absent, request); !errors.Is(err, riskquery.ErrValidation) {
		t.Fatal("history accepted nil context", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if page, err := reader.PageVulnerabilityDecisions(ctx, request); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(page, riskquery.DecisionPage{}) {
		t.Fatal("canceled history returned data", err)
	}
	request.After = &appquery.SortKey{ID: "decision-001", Value: "different"}
	if _, err := reader.PageVulnerabilityDecisions(t.Context(), request); !errors.Is(err, riskquery.ErrValidation) {
		t.Fatal("history accepted inconsistent ID cursor", err)
	}
	request.After = nil
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.PageVulnerabilityDecisions(t.Context(), request); !errors.Is(err, ErrConflict) {
		t.Fatal("history read a closed transaction", err)
	}
}

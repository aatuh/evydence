package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func memoryCollectorPorts(t *testing.T) (*memoryUnitOfWork, integrationapp.CollectorWriteReader, integrationquery.CollectorReader) {
	t.Helper()
	_, tx := memoryGovernanceReadFixture(t)
	writes, ok := tx.Repositories().Builds.(integrationapp.CollectorWriteReader)
	if !ok {
		t.Fatal("memory builds lack focused collector write reader")
	}
	pages, ok := tx.Repositories().Builds.(integrationquery.CollectorReader)
	if !ok {
		t.Fatal("memory builds lack focused collector pages")
	}
	return tx, writes, pages
}

func memoryCollectorRecord(id string) domain.Collector {
	at := fixedNow()
	return domain.Collector{ID: id, TenantID: "tenant", Name: "Builder", Type: "generic_ci", Version: "1", APIKeyID: "key", Status: "active", AllowedScopes: []string{"evidence:write"}, LastSeenAt: &at, SchemaVersion: domain.CollectorSchemaVersion, CreatedAt: at}
}

func TestMemoryCollectorNamesUseCurrentTenantWithoutCredentialsOrMetadata(t *testing.T) {
	tx, writes, _ := memoryCollectorPorts(t)
	v := memoryCollectorRecord("owned")
	v.AllowedScopes = []string{strings.Repeat("ignored", 1000000)}
	tx.state.Collectors[v.ID] = v
	foreign := v
	foreign.ID, foreign.TenantID, foreign.Name = "foreign", "foreign", "Foreign"
	tx.state.Collectors[foreign.ID] = foreign
	tx.state.CommercialCollectors["commercial"] = domain.CommercialCollectorDefinition{ID: "commercial", TenantID: "tenant", Provider: "provider", Name: "Commercial", Version: "1"}
	for _, tc := range []struct {
		name string
		want bool
	}{{"Builder", true}, {"Foreign", false}, {"missing", false}} {
		v, err := writes.CollectorNameExists(t.Context(), "tenant", tc.name)
		if err != nil || v != tc.want {
			t.Fatal("collector name read lost current tenant scope", tc.name, err)
		}
	}
	if v, err := writes.CommercialCollectorIdentityExists(t.Context(), "tenant", "provider", "Commercial", "1"); err != nil || !v {
		t.Fatal("commercial identity read lost exact key", err)
	}
	for _, name := range []string{"", " Builder", "Builder\x00", "\xff", strings.Repeat("x", integrationapp.MaxCollectorKeyBytes)} {
		if v, err := writes.CollectorNameExists(t.Context(), "tenant", name); err == nil || v {
			t.Fatal("invalid collector identity accepted", err)
		}
	}
	if err := writes.LockCollectorWrites(t.Context(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown collector tenant accepted", err)
	}
}

func TestMemoryCollectorPagesTraverseAllOrdersBeyondFiveHundredRecords(t *testing.T) {
	tx, _, pages := memoryCollectorPorts(t)
	for i := range 501 {
		v := memoryCollectorRecord(fmt.Sprintf("collector-%03d", i))
		v.CreatedAt = v.CreatedAt.Add(time.Duration((501-i)/3) * time.Minute)
		tx.state.Collectors[v.ID] = v
	}
	foreign := memoryCollectorRecord("foreign")
	foreign.TenantID, foreign.Status = "foreign", "invalid"
	tx.state.Collectors[foreign.ID] = foreign
	for _, sortBy := range []appquery.Sort{appquery.SortID, appquery.SortCreatedAt} {
		for _, direction := range []appquery.Direction{appquery.Ascending, appquery.Descending} {
			req := integrationquery.CollectorPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 7, Sort: sortBy, Direction: direction}}
			var got []string
			for count := 0; count < 80; count++ {
				page, err := pages.PageCollectors(t.Context(), req)
				if err != nil || len(page.Items) > 7 {
					t.Fatal("collector page failed", err)
				}
				for _, v := range page.Items {
					if v.TenantID != "tenant" {
						t.Fatal("foreign collector returned")
					}
					got = append(got, v.ID)
				}
				if page.Next == nil {
					break
				}
				last := page.Items[len(page.Items)-1]
				if *page.Next != appquery.RecordSortKey(last.ID, last.CreatedAt, sortBy) {
					t.Fatal("collector cursor lost final returned record")
				}
				req.After = page.Next
			}
			want := make([]string, 501)
			for i := range want {
				want[i] = fmt.Sprintf("collector-%03d", i)
			}
			if sortBy == appquery.SortCreatedAt {
				slices.SortFunc(want, func(a, b string) int {
					comparison := tx.state.Collectors[a].CreatedAt.Compare(tx.state.Collectors[b].CreatedAt)
					if comparison == 0 {
						comparison = strings.Compare(a, b)
					}
					return comparison
				})
			}
			if direction == appquery.Descending {
				slices.Reverse(want)
			}
			if !slices.Equal(got, want) {
				t.Fatal("collector pages omitted, duplicated or misordered records", sortBy, direction, len(got))
			}
		}
	}
}

func TestMemoryCollectorPageScopesBoundLookaheadAndDetachPublicMetadata(t *testing.T) {
	tx, _, pages := memoryCollectorPorts(t)
	for _, id := range []string{"a", "b", "c"} {
		tx.state.Collectors[id] = memoryCollectorRecord(id)
	}
	req := integrationquery.CollectorPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	v := tx.state.Collectors["a"]
	v.AllowedScopes = []string{strings.Repeat("s", (1<<20)-4)} // Exact encoded array limit.
	tx.state.Collectors["a"] = v
	unselected := tx.state.Collectors["c"]
	unselected.AllowedScopes = []string{strings.Repeat("s", 2<<20)}
	tx.state.Collectors["c"] = unselected
	page, err := pages.PageCollectors(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0].Name != v.Name || page.Items[0].APIKeyID != v.APIKeyID || page.Items[0].Status.String() != v.Status || page.Next == nil {
		t.Fatal("public collector projection lost fields or counted unselected metadata", err)
	}
	page.Items[0].AllowedScopes[0] = "modified"
	*page.Items[0].LastSeenAt = fixedNow().AddDate(1, 0, 0)
	if tx.state.Collectors["a"].AllowedScopes[0] != v.AllowedScopes[0] || !tx.state.Collectors["a"].LastSeenAt.Equal(fixedNow()) {
		t.Fatal("collector page aliases current scopes or heartbeat")
	}
	bad := tx.state.Collectors["b"]
	bad.AllowedScopes = []string{strings.Repeat("s", (1<<20)-3)}
	tx.state.Collectors["b"] = bad
	if v, err := pages.PageCollectors(t.Context(), req); err == nil || !reflect.DeepEqual(v, appquery.Result[integrationdomain.Collector]{}) {
		t.Fatal("oversized lookahead exposed a partial collector page", err)
	}
	var missing context.Context
	if _, err := pages.PageCollectors(missing, req); err == nil {
		t.Fatal("nil context accepted")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := pages.PageCollectors(cancelled, req); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled collector page accepted", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := pages.PageCollectors(t.Context(), req); err == nil {
		t.Fatal("closed collector transaction accepted")
	}
}

func TestMemoryCollectorPagesUseNativeCursorValidationWithoutRequiringCursorRow(t *testing.T) {
	tx, _, pages := memoryCollectorPorts(t)
	tx.state.Collectors["b"] = memoryCollectorRecord("b")
	req := integrationquery.CollectorPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}, After: &appquery.SortKey{ID: "a", Value: "a"}}
	page, err := pages.PageCollectors(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "b" {
		t.Fatal("native keyset required a deleted cursor row", err)
	}
	for _, tc := range []struct {
		sort  appquery.Sort
		after appquery.SortKey
	}{
		{appquery.SortID, appquery.SortKey{ID: "a", Value: "different"}},
		{appquery.SortCreatedAt, appquery.SortKey{ID: "a", Value: "bad-time"}},
		{appquery.SortCreatedAt, appquery.SortKey{ID: "a", Value: "2026-10-09T12:00:00+00:00"}},
	} {
		req.Page.Sort, req.After = tc.sort, &tc.after
		if v, err := pages.PageCollectors(t.Context(), req); !errors.Is(err, appquery.ErrInvalidCursor) || !reflect.DeepEqual(v, appquery.Result[integrationdomain.Collector]{}) {
			t.Fatal("invalid collector cursor returned a page", err)
		}
	}
}

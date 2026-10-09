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
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func memoryCommercialCollectorPageFixture(t *testing.T) (*memoryUnitOfWork, integrationquery.CommercialCollectorReader) {
	t.Helper()
	_, tx := memoryGovernanceReadFixture(t)
	reader, ok := tx.Repositories().Enterprise.(integrationquery.CommercialCollectorReader)
	if !ok {
		t.Fatal("memory enterprise lacks focused commercial collector pages")
	}
	return tx, reader
}
func memoryCommercialCollectorRecord(id string) domain.CommercialCollectorDefinition {
	return domain.CommercialCollectorDefinition{ID: id, TenantID: "tenant", Name: "Scanner", Provider: "provider", Version: "1", ManifestHash: sampleDigest("manifest"), AllowedScopes: []string{"evidence:write"}, Status: "available", SchemaVersion: domain.CommercialCollectorVersion, CreatedAt: fixedNow()}
}

func TestMemoryCommercialCollectorPagesRetainPublicFieldsAndDetachSelectedScopes(t *testing.T) {
	tx, reader := memoryCommercialCollectorPageFixture(t)
	for _, id := range []string{"a", "b", "c"} {
		tx.state.CommercialCollectors[id] = memoryCommercialCollectorRecord(id)
	}
	foreign := memoryCommercialCollectorRecord("foreign")
	foreign.TenantID = "foreign"
	foreign.AllowedScopes = []string{strings.Repeat("ignored", 100000)}
	tx.state.CommercialCollectors[foreign.ID] = foreign
	req := integrationquery.CommercialCollectorPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	page, err := reader.PageCommercialCollectors(t.Context(), req)
	want := memoryCommercialCollectorRecord("a")
	if err != nil || !reflect.DeepEqual(page.Items, []integrationdomain.CommercialCollectorDefinition{integrationdomain.CommercialCollectorDefinition(want)}) || page.Next == nil || page.Next.ID != "a" {
		t.Fatal("commercial page lost public fields, current tenant or cursor", err)
	}
	page.Items[0].AllowedScopes[0] = "modified"
	if tx.state.CommercialCollectors["a"].AllowedScopes[0] != "evidence:write" {
		t.Fatal("commercial scopes alias current state")
	}
	bad := tx.state.CommercialCollectors["c"]
	bad.ID = "bad-coordinate"
	tx.state.CommercialCollectors["c"] = bad
	if _, err := reader.PageCommercialCollectors(t.Context(), req); err != nil {
		t.Fatal("unselected corrupt commercial record affected page", err)
	}
	req.After = page.Next
	if v, err := reader.PageCommercialCollectors(t.Context(), req); err == nil || !reflect.DeepEqual(v, appquery.Result[integrationdomain.CommercialCollectorDefinition]{}) {
		t.Fatal("corrupt lookahead returned a partial commercial page", err)
	}
}

func TestMemoryCommercialCollectorPagesTraverseFiveHundredRecordsInEveryOrder(t *testing.T) {
	tx, reader := memoryCommercialCollectorPageFixture(t)
	for i := range 501 {
		v := memoryCommercialCollectorRecord(fmt.Sprintf("definition-%03d", i))
		v.CreatedAt = v.CreatedAt.Add(time.Duration((501-i)/3) * time.Minute)
		tx.state.CommercialCollectors[v.ID] = v
	}
	for _, sortBy := range []appquery.Sort{appquery.SortID, appquery.SortCreatedAt} {
		for _, direction := range []appquery.Direction{appquery.Ascending, appquery.Descending} {
			req := integrationquery.CommercialCollectorPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 7, Sort: sortBy, Direction: direction}}
			var got []string
			for count := 0; count < 80; count++ {
				page, err := reader.PageCommercialCollectors(t.Context(), req)
				if err != nil || len(page.Items) > 7 {
					t.Fatal("commercial collector page failed", err)
				}
				for _, v := range page.Items {
					got = append(got, v.ID)
				}
				if page.Next == nil {
					break
				}
				last := page.Items[len(page.Items)-1]
				if *page.Next != appquery.RecordSortKey(last.ID, last.CreatedAt, sortBy) {
					t.Fatal("commercial cursor lost final returned record")
				}
				req.After = page.Next
			}
			want := make([]string, 501)
			for i := range want {
				want[i] = fmt.Sprintf("definition-%03d", i)
			}
			if sortBy == appquery.SortCreatedAt {
				slices.SortFunc(want, func(a, b string) int {
					comparison := tx.state.CommercialCollectors[a].CreatedAt.Compare(tx.state.CommercialCollectors[b].CreatedAt)
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
				t.Fatal("commercial traversal omitted, duplicated or misordered records", len(got))
			}
		}
	}
}

func TestMemoryCommercialCollectorPageRejectsInvalidCursorsAndClosedTransactions(t *testing.T) {
	tx, reader := memoryCommercialCollectorPageFixture(t)
	req := integrationquery.CommercialCollectorPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	var missing context.Context
	if _, err := reader.PageCommercialCollectors(missing, req); err == nil {
		t.Fatal("nil commercial page context accepted")
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
		if v, err := reader.PageCommercialCollectors(t.Context(), req); !errors.Is(err, appquery.ErrInvalidCursor) || !reflect.DeepEqual(v, appquery.Result[integrationdomain.CommercialCollectorDefinition]{}) {
			t.Fatal("invalid commercial cursor returned metadata", err)
		}
	}
	req.Page.Sort, req.After = appquery.SortID, nil
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.PageCommercialCollectors(cancelled, req); !errors.Is(err, context.Canceled) {
		t.Fatal("commercial page ignored cancellation", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.PageCommercialCollectors(t.Context(), req); err == nil {
		t.Fatal("closed commercial transaction returned metadata")
	}
}

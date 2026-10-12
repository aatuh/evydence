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
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func memorySourceRepositoryReadFixture(t *testing.T) (*memoryUnitOfWork, integrationapp.SourceRepositoryCreationReader, integrationquery.SourceRepositoryReader) {
	t.Helper()
	_, tx := memoryGovernanceReadFixture(t)
	for _, tenant := range []string{"tenant", "foreign"} {
		id := tenant + "-project"
		tx.state.Projects[id] = domain.Project{ID: id, TenantID: tenant, ProductID: tenant + "-product"}
	}
	creation, ok := tx.Repositories().Source.(integrationapp.SourceRepositoryCreationReader)
	if !ok {
		t.Fatal("memory source lacks current repository creation identities")
	}
	pages, ok := tx.Repositories().Source.(integrationquery.SourceRepositoryReader)
	if !ok {
		t.Fatal("memory source lacks focused repository pages")
	}
	return tx, creation, pages
}

func memorySourceRepositoryRecord(id string) domain.SourceRepository {
	return domain.SourceRepository{ID: id, TenantID: "tenant", ProjectID: "tenant-project", Provider: "git", FullName: "org/" + id, CloneURL: "https://example.invalid/" + id, DefaultBranch: "main", SchemaVersion: domain.SourceRepositorySchemaVersion, CreatedAt: fixedNow()}
}

func TestMemorySourceRepositoryCreationReadsOnlyCurrentOwnedCoordinates(t *testing.T) {
	tx, reader, _ := memorySourceRepositoryReadFixture(t)
	v := memorySourceRepositoryRecord("repository")
	v.CloneURL = strings.Repeat("omitted", 100000)
	tx.state.SourceRepositories[v.ID] = v
	if err := reader.LockRepositoryCreation(t.Context(), "tenant"); err != nil {
		t.Fatal(err)
	}
	p, err := reader.LockRepositoryProject(t.Context(), "tenant", "tenant-project")
	if err != nil || p != (integrationapp.SourceProjectIdentity{ID: "tenant-project", TenantID: "tenant", ProductID: "tenant-product"}) {
		t.Fatal("project identity lost current owned product", err)
	}
	r, found, err := reader.RepositoryIdentityByName(t.Context(), "tenant", v.Provider, v.FullName)
	if err != nil || !found || r != (integrationapp.SourceRepositoryIdentity{ID: v.ID, TenantID: "tenant", ProjectID: v.ProjectID, ProductID: "tenant-product"}) {
		t.Fatal("natural identity read descriptive metadata or lost parents", err)
	}
	if _, err := reader.ReadSourceRepository(t.Context(), "tenant", v.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("selected oversized repository metadata accepted", err)
	}
	if _, err := reader.LockRepositoryProject(t.Context(), "tenant", "foreign-project"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign project identity accepted", err)
	}
	product := tx.state.Products["tenant-product"]
	product.TenantID = "foreign"
	tx.state.Products[product.ID] = product
	if _, err := reader.LockRepositoryProject(t.Context(), "tenant", "tenant-project"); !errors.Is(err, ErrNotFound) {
		t.Fatal("stale product owner accepted", err)
	}
	if _, _, err := reader.RepositoryIdentityByName(t.Context(), "tenant", v.Provider, v.FullName); !errors.Is(err, ErrNotFound) {
		t.Fatal("natural identity accepted broken current parent", err)
	}
}

func TestMemorySourceRepositoryPagesFilterOwnershipAndGrantsBeforeLimit(t *testing.T) {
	tx, _, pages := memorySourceRepositoryReadFixture(t)
	for _, id := range []string{"a", "b", "c"} {
		tx.state.SourceRepositories[id] = memorySourceRepositoryRecord(id)
	}
	detached := memorySourceRepositoryRecord("0-detached")
	detached.ProjectID = ""
	tx.state.SourceRepositories[detached.ID] = detached
	foreign := memorySourceRepositoryRecord("0-foreign")
	foreign.TenantID, foreign.ProjectID = "foreign", "foreign-project"
	tx.state.SourceRepositories[foreign.ID] = foreign
	broken := memorySourceRepositoryRecord("0-broken")
	broken.ProjectID = "foreign-project"
	tx.state.SourceRepositories[broken.ID] = broken
	req := integrationquery.SourceRepositoryPageRequest{TenantID: "tenant", AllowedProductIDs: []string{"tenant-product"}, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	page, err := pages.PageSourceRepositories(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0].Repository.ID != "a" || page.Items[0].ProductID != "tenant-product" || page.Next == nil {
		t.Fatal("scope/parents were checked after limiting or public point lost fields", err)
	}
	req.AllowedProductIDs = []string{""}
	if page, err := pages.PageSourceRepositories(t.Context(), req); err != nil || len(page.Items) != 0 {
		t.Fatal("empty scoped grant exposed detached repository", err)
	}
	req.AllowedProductIDs = []string{"tenant-product"}
	req.ProjectID = "foreign-project"
	if page, err := pages.PageSourceRepositories(t.Context(), req); err != nil || len(page.Items) != 0 {
		t.Fatal("foreign/broken project filter exposed repository", err)
	}
	req.ProjectID, req.TenantWide, req.AllowedProductIDs = "", true, nil
	page, err = pages.PageSourceRepositories(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0].Repository.ID != detached.ID || page.Items[0].ProductID != "" {
		t.Fatal("tenant-wide actor lost detached legacy repository", err)
	}
	bad := tx.state.SourceRepositories["c"]
	bad.ID = "bad-coordinate"
	tx.state.SourceRepositories["c"] = bad
	req.TenantWide, req.AllowedProjectIDs = false, []string{"tenant-project"}
	req.After = &appquery.SortKey{ID: "a", Value: "a"}
	if v, err := pages.PageSourceRepositories(t.Context(), req); err == nil || !reflect.DeepEqual(v, appquery.Result[integrationquery.SourceRepositoryPoint]{}) {
		t.Fatal("corrupt source lookahead returned a partial page", err)
	}
}

func TestMemorySourceRepositoryPagesTraverseEveryOrderAndCreationReadsCancel(t *testing.T) {
	tx, reader, pages := memorySourceRepositoryReadFixture(t)
	for i := range 501 {
		v := memorySourceRepositoryRecord(fmt.Sprintf("repository-%03d", i))
		v.CreatedAt = v.CreatedAt.Add(time.Duration((501-i)/3) * time.Minute)
		tx.state.SourceRepositories[v.ID] = v
	}
	for _, sortBy := range []appquery.Sort{appquery.SortID, appquery.SortCreatedAt} {
		for _, direction := range []appquery.Direction{appquery.Ascending, appquery.Descending} {
			req := integrationquery.SourceRepositoryPageRequest{TenantID: "tenant", TenantWide: true, Page: appquery.PageRequest{PageSize: 7, Sort: sortBy, Direction: direction}}
			var got []string
			for count := 0; count < 80; count++ {
				page, err := pages.PageSourceRepositories(t.Context(), req)
				if err != nil || len(page.Items) > 7 {
					t.Fatal("source keyset page failed", err)
				}
				for _, v := range page.Items {
					got = append(got, v.Repository.ID)
				}
				if page.Next == nil {
					break
				}
				last := page.Items[len(page.Items)-1].Repository
				if *page.Next != appquery.RecordSortKey(last.ID, last.CreatedAt, sortBy) {
					t.Fatal("source cursor lost final returned record")
				}
				req.After = page.Next
			}
			want := make([]string, 501)
			for i := range want {
				want[i] = fmt.Sprintf("repository-%03d", i)
			}
			if sortBy == appquery.SortCreatedAt {
				slices.SortFunc(want, func(a, b string) int {
					comparison := tx.state.SourceRepositories[a].CreatedAt.Compare(tx.state.SourceRepositories[b].CreatedAt)
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
				t.Fatal("source pages omitted, duplicated or misordered records", len(got))
			}
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := reader.LockRepositoryCreation(cancelled, "tenant"); !errors.Is(err, context.Canceled) {
		t.Fatal("source identity ignored cancellation", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.RepositoryIdentityByName(t.Context(), "tenant", "git", "org/repository-000"); err == nil {
		t.Fatal("closed source transaction returned identity")
	}
}

func TestMemorySourceRepositoryReadBoundsAndPageValidation(t *testing.T) {
	tx, reader, pages := memorySourceRepositoryReadFixture(t)
	v := memorySourceRepositoryRecord("repository")
	v.CloneURL = strings.Repeat("x", integrationapp.MaxSourceTextBytes)
	tx.state.SourceRepositories[v.ID] = v
	if got, err := reader.ReadSourceRepository(t.Context(), "tenant", v.ID); err != nil || got.CloneURL != v.CloneURL || got.ID != v.ID {
		t.Fatal("exact source metadata byte boundary rejected", err)
	}
	v.CloneURL += "x"
	tx.state.SourceRepositories[v.ID] = v
	if _, err := reader.ReadSourceRepository(t.Context(), "tenant", v.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("oversized source metadata was not rejected", err)
	}
	var missing context.Context
	if err := reader.LockRepositoryCreation(missing, "tenant"); err == nil {
		t.Fatal("nil source preflight context accepted")
	}
	req := integrationquery.SourceRepositoryPageRequest{TenantID: "tenant", TenantWide: true, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	for _, tc := range []struct {
		sort  appquery.Sort
		after appquery.SortKey
	}{
		{appquery.SortID, appquery.SortKey{ID: "a", Value: "different"}},
		{appquery.SortCreatedAt, appquery.SortKey{ID: "a", Value: "bad-time"}},
		{appquery.SortCreatedAt, appquery.SortKey{ID: "a", Value: "2026-10-09T12:00:00+00:00"}},
	} {
		req.Page.Sort, req.After = tc.sort, &tc.after
		if page, err := pages.PageSourceRepositories(t.Context(), req); !errors.Is(err, appquery.ErrInvalidCursor) || !reflect.DeepEqual(page, appquery.Result[integrationquery.SourceRepositoryPoint]{}) {
			t.Fatal("invalid source cursor returned metadata", err)
		}
	}
}

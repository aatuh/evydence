package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type memoryCatalogQueryReader interface {
	ReadCatalogProduct(context.Context, string, string) (releasedomain.Product, error)
	ReadCatalogProject(context.Context, string, string) (releasedomain.Project, error)
	ReadCatalogRelease(context.Context, string, string) (releasedomain.Release, error)
	PageProducts(context.Context, releasequery.ProductPageRequest) (appquery.Result[releasedomain.Product], error)
}

func TestMemoryCatalogQueriesUseCurrentOwnedPointsAndDetachReleaseTimes(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().ReleaseCatalog.(memoryCatalogQueryReader)
	if !ok {
		t.Fatal("memory release catalog lacks focused point/page readers")
	}
	at := fixedNow()
	tx.state.Products["tenant-product"] = domain.Product{ID: "tenant-product", TenantID: "tenant", Name: "Complete product", Slug: "complete", CreatedAt: at}
	tx.state.Projects["tenant-project"] = domain.Project{ID: "tenant-project", TenantID: "tenant", ProductID: "tenant-product", Name: "Complete project", CreatedAt: at}
	tx.state.Releases["tenant-release"] = domain.Release{ID: "tenant-release", TenantID: "tenant", ProductID: "tenant-product", Version: "1", State: "approved", Revision: 3, CreatedAt: at, FrozenAt: &at, ApprovedAt: &at}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.ReadCatalogProduct(t.Context(), "tenant", "tenant-product")
	if err != nil || p != releasedomain.Product(tx.state.Products["tenant-product"]) {
		t.Fatal("product point lost complete owned metadata", p, err)
	}
	j, err := r.ReadCatalogProject(t.Context(), "tenant", "tenant-project")
	if err != nil || j != releasedomain.Project(tx.state.Projects["tenant-project"]) {
		t.Fatal("project point lost complete owned metadata", j, err)
	}
	v, err := r.ReadCatalogRelease(t.Context(), "tenant", "tenant-release")
	approved, parseErr := releasedomain.ParseReleaseState("approved")
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	want := releasedomain.Release{ID: "tenant-release", TenantID: "tenant", ProductID: "tenant-product", Version: "1", State: approved, Revision: 3, CreatedAt: at, FrozenAt: &at, ApprovedAt: &at}
	if err != nil || !reflect.DeepEqual(v, want) {
		t.Fatal("release point lost complete typed lifecycle metadata", v, err)
	}
	*v.FrozenAt, *v.ApprovedAt = at.Add(time.Hour), at.Add(time.Hour)
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("point result mutation changed repository timestamps")
	}
	corruptParent := tx.state.Products["tenant-product"]
	corruptParent.Name = strings.Repeat("x", 65537)
	tx.state.Products[corruptParent.ID] = corruptParent
	if v, err := r.ReadCatalogProduct(t.Context(), "tenant", corruptParent.ID); !errors.Is(err, releasequery.ErrInvalidProjection) || v != (releasedomain.Product{}) {
		t.Fatal("corrupt product point returned partial data", v, err)
	}
	if _, err := r.ReadCatalogProject(t.Context(), "tenant", "tenant-project"); err != nil {
		t.Fatal("project ownership join selected unrelated parent metadata", err)
	}
	if _, err := r.ReadCatalogRelease(t.Context(), "tenant", "tenant-release"); err != nil {
		t.Fatal("release ownership join selected unrelated parent metadata", err)
	}
	tx.state.Products[corruptParent.ID] = before.Products[corruptParent.ID]
	for _, corrupt := range []domain.Release{
		{ID: "tenant-release", TenantID: "tenant", ProductID: "tenant-product", State: "unknown", Revision: 3, CreatedAt: at},
		{ID: "tenant-release", TenantID: "tenant", ProductID: "tenant-product", State: "draft", Revision: 0, CreatedAt: at},
		{ID: "tenant-release", TenantID: "tenant", ProductID: "tenant-product", State: "draft", Revision: 1, Version: strings.Repeat("x", 65537), CreatedAt: at},
	} {
		tx.state.Releases[corrupt.ID] = corrupt
		if v, err := r.ReadCatalogRelease(t.Context(), "tenant", corrupt.ID); !errors.Is(err, releasequery.ErrInvalidProjection) || !reflect.DeepEqual(v, releasedomain.Release{}) {
			t.Fatal("corrupt release projection returned partial data", v, err)
		}
	}
	tx.state.Releases["tenant-release"] = before.Releases["tenant-release"]
	for _, tenant := range []string{"foreign", "missing"} {
		if v, err := r.ReadCatalogProduct(t.Context(), tenant, "tenant-product"); !errors.Is(err, releasequery.ErrNotFound) || v != (releasedomain.Product{}) {
			t.Fatal("wrong-tenant product returned data", v, err)
		}
		if v, err := r.ReadCatalogProject(t.Context(), tenant, "tenant-project"); !errors.Is(err, releasequery.ErrNotFound) || v != (releasedomain.Project{}) {
			t.Fatal("wrong-tenant project returned data", v, err)
		}
		if v, err := r.ReadCatalogRelease(t.Context(), tenant, "tenant-release"); !errors.Is(err, releasequery.ErrNotFound) || !reflect.DeepEqual(v, releasedomain.Release{}) {
			t.Fatal("wrong-tenant release returned data", v, err)
		}
	}
	for _, root := range []string{"foreign-product", "missing-product"} {
		j := tx.state.Projects["tenant-project"]
		j.ProductID = root
		tx.state.Projects[j.ID] = j
		v := tx.state.Releases["tenant-release"]
		v.ProductID = root
		tx.state.Releases[v.ID] = v
		if _, err := r.ReadCatalogProject(t.Context(), "tenant", j.ID); !errors.Is(err, releasequery.ErrNotFound) {
			t.Fatal("project parent escaped tenant join", err)
		}
		if _, err := r.ReadCatalogRelease(t.Context(), "tenant", v.ID); !errors.Is(err, releasequery.ErrNotFound) {
			t.Fatal("release parent escaped tenant join", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.ReadCatalogProduct(ctx, "tenant", "tenant-product"); !errors.Is(err, context.Canceled) {
		t.Fatal("point read ignored cancellation", err)
	}
	var missingContext context.Context
	if _, err := r.ReadCatalogProduct(missingContext, "tenant", "tenant-product"); !errors.Is(err, releasequery.ErrValidation) {
		t.Fatal("catalog point accepted missing context", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadCatalogProduct(t.Context(), "tenant", "tenant-product"); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction returned catalog metadata", err)
	}
}

func TestMemoryCatalogProductPageFiltersGrantsAndKeysetBeforeMetadata(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().ReleaseCatalog.(memoryCatalogQueryReader)
	if !ok {
		t.Fatal("missing focused catalog reader")
	}
	at := fixedNow()
	tx.state.Products = map[string]domain.Product{}
	for _, id := range []string{"a", "b", "c"} {
		tx.state.Products[id] = domain.Product{ID: id, TenantID: "tenant", Name: id, Slug: id, CreatedAt: at}
	}
	tx.state.Products["foreign"] = domain.Product{ID: "foreign", TenantID: "foreign", Name: strings.Repeat("private", 100000)}
	req := releasequery.ProductPageRequest{TenantID: "tenant", TenantWide: true, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	page, err := r.PageProducts(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0] != releasedomain.Product(tx.state.Products["a"]) || page.Next == nil || page.Next.ID != "a" {
		t.Fatal("complete first product page or cursor changed", page, err)
	}
	req.After = page.Next
	page, err = r.PageProducts(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "b" || page.Next == nil || page.Next.ID != "b" {
		t.Fatal("product keyset did not advance", page, err)
	}
	req.After, req.Page.Direction, req.Page.Sort = nil, appquery.Descending, appquery.SortCreatedAt
	page, err = r.PageProducts(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "c" || page.Next == nil || page.Next.Value != at.Format(time.RFC3339Nano) {
		t.Fatal("created-at product page lost direction or tie-break", page, err)
	}
	bad := tx.state.Products["a"]
	bad.Name = strings.Repeat("x", 65537)
	tx.state.Products["a"] = bad
	req.TenantWide, req.AllowedProductIDs = false, []string{"b"}
	page, err = r.PageProducts(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "b" || page.Next != nil {
		t.Fatal("grant filtering selected excluded metadata or produced wrong cursor", page, err)
	}
	req.TenantWide, req.AllowedProductIDs = true, nil
	if _, err := r.PageProducts(t.Context(), req); err != nil {
		t.Fatal("page projected unselected oversized metadata", err)
	}
	req.Page.Direction = appquery.Ascending
	if v, err := r.PageProducts(t.Context(), req); !errors.Is(err, releasequery.ErrInvalidProjection) || !reflect.DeepEqual(v, appquery.Result[releasedomain.Product]{}) {
		t.Fatal("selected corrupt metadata returned a partial page", v, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := r.PageProducts(ctx, req); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, appquery.Result[releasedomain.Product]{}) {
		t.Fatal("cancelled product page returned data", v, err)
	}
	for _, allowed := range [][]string{nil, {"b"}} {
		req.AllowedProductIDs, req.TenantWide = allowed, len(allowed) != 0
		if _, err := r.PageProducts(t.Context(), req); !errors.Is(err, releasequery.ErrValidation) {
			t.Fatal("contradictory grant request was accepted", err)
		}
	}
}

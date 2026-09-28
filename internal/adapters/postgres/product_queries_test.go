package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func TestPageProductsUsesTenantBoundKeysetAndGrantFilter(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_product_page_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.pool.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+quotedSchema+" CASCADE") }()
	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	for _, tenantID := range []string{"ten_page", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenantID, base); err != nil {
			t.Fatal(err)
		}
	}
	for _, product := range []struct {
		id, tenantID string
		createdAt    time.Time
	}{
		{id: "prod_a", tenantID: "ten_page", createdAt: base},
		{id: "prod_b", tenantID: "ten_page", createdAt: base},
		{id: "prod_c", tenantID: "ten_page", createdAt: base.Add(time.Second)},
		{id: "prod_other", tenantID: "ten_other", createdAt: base.Add(2 * time.Second)},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, product.id, product.tenantID, product.createdAt); err != nil {
			t.Fatal(err)
		}
	}
	product, err := store.GetProduct(ctx, "ten_page", "prod_a")
	if err != nil || product.ID != "prod_a" || product.TenantID != "ten_page" {
		t.Fatalf("tenant-bound product=%#v error=%v", product, err)
	}
	if product, err := store.GetProduct(ctx, "ten_page", "prod_other"); !errors.Is(err, releasequery.ErrNotFound) || product.ID != "" {
		t.Fatalf("cross-tenant product=%#v error=%v", product, err)
	}
	request := releasequery.ProductPageRequest{TenantID: "ten_page", TenantWide: true, Page: appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}}
	first, err := store.PageProducts(ctx, request)
	if err != nil || len(first.Items) != 2 || first.Items[0].ID != "prod_a" || first.Items[1].ID != "prod_b" || first.Next == nil {
		t.Fatalf("first page=%#v error=%v", first, err)
	}
	request.After = first.Next
	second, err := store.PageProducts(ctx, request)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "prod_c" || second.Next != nil {
		t.Fatalf("second page=%#v error=%v", second, err)
	}
	request.After = nil
	request.TenantWide = false
	request.AllowedProductIDs = []string{"prod_a", "prod_c", "prod_other"}
	filtered, err := store.PageProducts(ctx, request)
	if err != nil || len(filtered.Items) != 2 || filtered.Items[0].ID != "prod_a" || filtered.Items[1].ID != "prod_c" || filtered.Next != nil {
		t.Fatalf("grant-filtered page=%#v error=%v", filtered, err)
	}
	request.AllowedProductIDs = nil
	if _, err := store.PageProducts(ctx, request); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("empty scoped grant filter error=%v, want validation", err)
	}
	request.TenantWide = true
	request.After = &appquery.SortKey{Value: "not-a-time", ID: "prod_a"}
	if _, err := store.PageProducts(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("malformed cursor error=%v, want invalid cursor", err)
	}
}

func TestGetCatalogPointsRequiresTenantBoundParentProduct(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_catalog_points_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.pool.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+quotedSchema+" CASCADE") }()
	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	for _, tenantID := range []string{"ten_one", "ten_two"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenantID, createdAt); err != nil {
			t.Fatal(err)
		}
	}
	for _, product := range []struct{ id, tenant string }{{"prod_one", "ten_one"}, {"prod_two", "ten_two"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, product.id, product.tenant, createdAt); err != nil {
			t.Fatal(err)
		}
	}
	for _, project := range []struct{ id, tenant, product string }{
		{"proj_one", "ten_one", "prod_one"},
		{"proj_foreign", "ten_two", "prod_two"},
		{"proj_bad_parent", "ten_one", "prod_two"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ($1, $2, $3, $1, $4)`, project.id, project.tenant, project.product, createdAt); err != nil {
			t.Fatal(err)
		}
	}
	for _, release := range []struct{ id, tenant, product, state string }{
		{"rel_one", "ten_one", "prod_one", "frozen"},
		{"rel_foreign", "ten_two", "prod_two", "draft"},
		{"rel_bad_parent", "ten_one", "prod_two", "draft"},
		{"rel_bad_state", "ten_one", "prod_one", "future"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, revision, frozen_at, created_at) VALUES ($1, $2, $3, $1, $4, 2, $5, $6)`, release.id, release.tenant, release.product, release.state, createdAt, createdAt); err != nil {
			t.Fatal(err)
		}
	}
	project, err := store.GetProject(ctx, "ten_one", "proj_one")
	if err != nil || project.ID != "proj_one" || project.ProductID != "prod_one" {
		t.Fatalf("own project=%#v error=%v", project, err)
	}
	release, err := store.GetRelease(ctx, "ten_one", "rel_one")
	if err != nil || release.ID != "rel_one" || release.Revision != 2 || release.State.String() != "frozen" || release.FrozenAt == nil {
		t.Fatalf("own release=%#v error=%v", release, err)
	}
	for _, id := range []string{"proj_foreign", "proj_bad_parent"} {
		project, err := store.GetProject(ctx, "ten_one", id)
		if !errors.Is(err, releasequery.ErrNotFound) || project.ID != "" {
			t.Fatalf("unsafe project %q=%#v error=%v", id, project, err)
		}
	}
	for _, id := range []string{"rel_foreign", "rel_bad_parent"} {
		release, err := store.GetRelease(ctx, "ten_one", id)
		if !errors.Is(err, releasequery.ErrNotFound) || release.ID != "" {
			t.Fatalf("unsafe release %q=%#v error=%v", id, release, err)
		}
	}
	if release, err := store.GetRelease(ctx, "ten_one", "rel_bad_state"); err == nil || release.ID != "" {
		t.Fatalf("invalid release state=%#v error=%v", release, err)
	}
}

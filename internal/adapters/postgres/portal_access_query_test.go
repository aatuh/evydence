package postgres

import (
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestPostgresPortalAccessPagesAuthorizedPackagesWithoutHashes(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_portal", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, parent := range []struct{ product, tenant string }{{"prod_a", "ten_portal"}, {"prod_b", "ten_portal"}, {"prod_other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, parent.product, parent.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+parent.product, parent.tenant, parent.product, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct{ id, tenant, product, release string }{
		{"pkg_a", "ten_portal", "prod_a", "rel_prod_a"},
		{"pkg_b", "ten_portal", "prod_b", "rel_prod_b"},
		{"pkg_cross", "ten_portal", "prod_a", "rel_prod_b"},
		{"pkg_foreign", "ten_portal", "prod_other", "rel_prod_other"},
		{"pkg_missing", "ten_portal", "prod_missing", ""},
		{"pkg_other", "ten_other", "prod_other", "rel_prod_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO customer_security_packages (id, tenant_id, product_id, release_id, redaction_profile_id, title, state, manifest, manifest_hash, expires_at, schema_version, created_at) VALUES ($1, $2, $3, NULLIF($4, ''), 'rp_1', $1, 'published', '{}'::jsonb, 'sha256:manifest', $5, 'customer-security-package.v1.0.0', $6)`, row.id, row.tenant, row.product, row.release, now.Add(time.Hour), now); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct{ id, tenant, pkg string }{
		{"cpa_a", "ten_portal", "pkg_a"}, {"cpa_b", "ten_portal", "pkg_b"},
		{"cpa_cross", "ten_portal", "pkg_cross"}, {"cpa_foreign", "ten_portal", "pkg_foreign"},
		{"cpa_missing", "ten_portal", "pkg_missing"}, {"cpa_dangling", "ten_portal", "pkg_absent"},
		{"cpa_other", "ten_other", "pkg_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO customer_portal_access (id, tenant_id, package_id, customer_name, prefix, hash, expires_at, schema_version, created_at) VALUES ($1, $2, $3, 'Customer', 'pref', 'private-token-hash', $4, 'customer-portal-access.v1.0.0', $5)`, row.id, row.tenant, row.pkg, now.Add(time.Hour), now); err != nil {
			t.Fatal(err)
		}
	}
	service, err := packagequery.NewPortalAccess(store)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_portal", UserID: "usr_1", Scopes: []string{"package:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_b", Scopes: []string{"package:read"}}}}
	result, err := service.ListPage(ctx, actor, "", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "cpa_b" || result.Items[0].Hash != "" || result.Next != nil {
		t.Fatalf("product-granted page=%#v error=%v", result, err)
	}
	if _, err := service.ListPage(ctx, actor, "pkg_a", page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong-product package filter error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "customer_security_package", ResourceID: "pkg_a", Scopes: []string{"package:read"}}
	result, err = service.ListPage(ctx, actor, "pkg_a", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "cpa_a" || result.Next != nil {
		t.Fatalf("package-granted page=%#v error=%v", result, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "rel_prod_b", Scopes: []string{"package:read"}}
	result, err = service.ListPage(ctx, actor, "", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "cpa_b" {
		t.Fatalf("release-granted page=%#v error=%v", result, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: actor.TenantID, Scopes: []string{"package:read"}}
	result, err = service.ListPage(ctx, actor, "", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "cpa_a" || result.Next == nil {
		t.Fatalf("first tenant page=%#v error=%v", result, err)
	}
	result, err = service.ListPage(ctx, actor, "", page, result.Next)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "cpa_b" || result.Next != nil {
		t.Fatalf("second tenant page=%#v error=%v", result, err)
	}
	for _, id := range []string{"pkg_cross", "pkg_foreign", "pkg_missing", "pkg_other", "pkg_absent"} {
		if _, err := service.ListPage(ctx, actor, id, page, nil); !errors.Is(err, packagequery.ErrPortalAccessNotFound) {
			t.Fatalf("unsafe package filter %s error=%v", id, err)
		}
	}
}

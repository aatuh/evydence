package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestPostgresReleaseBundlePointRequiresCurrentTenantParent(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_bundle", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, parent := range []struct{ product, tenant string }{{"prod_a", "ten_bundle"}, {"prod_b", "ten_bundle"}, {"prod_other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, parent.product, parent.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+parent.product, parent.tenant, parent.product, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct{ id, tenant, release string }{
		{"bun_a", "ten_bundle", "rel_prod_a"},
		{"bun_b", "ten_bundle", "rel_prod_b"},
		{"bun_foreign_parent", "ten_bundle", "rel_prod_other"},
		{"bun_missing_parent", "ten_bundle", "rel_missing"},
		{"bun_other", "ten_other", "rel_prod_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO release_bundles (id, tenant_id, release_id, state, manifest, manifest_hash, signature_refs, created_at) VALUES ($1, $2, $3, 'generated', '{"private":"manifest"}'::jsonb, 'sha256:hash', '["sig_1"]'::jsonb, $4)`, row.id, row.tenant, row.release, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO release_bundles (id, tenant_id, release_id, state, manifest, manifest_hash, signature_refs, created_at) VALUES ('bun_invalid_manifest', 'ten_bundle', 'rel_prod_a', 'generated', '["not-an-object"]'::jsonb, 'sha256:hash', '[]'::jsonb, $1)`, now); err != nil {
		t.Fatal(err)
	}
	service, err := packagequery.NewReleaseBundles(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_bundle", UserID: "usr_1", Scopes: []string{"bundle:read"},
		ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"bundle:read"}}}}
	bundle, err := service.GetReleaseBundle(ctx, actor, "bun_a")
	if err != nil || bundle.Manifest["private"] != "manifest" || len(bundle.SignatureRefs) != 1 {
		t.Fatalf("allowed bundle=%#v error=%v", bundle, err)
	}
	if _, err := service.GetReleaseBundle(ctx, actor, "bun_b"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("other product error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "rel_prod_b", Scopes: []string{"bundle:read"}}
	if _, err := service.GetReleaseBundle(ctx, actor, "bun_b"); err != nil {
		t.Fatalf("release grant error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_bundle", Scopes: []string{"bundle:read"}}
	for _, id := range []string{"bun_foreign_parent", "bun_missing_parent", "bun_other", "bun_unknown"} {
		if _, err := service.GetReleaseBundle(ctx, actor, id); !errors.Is(err, packagequery.ErrReleaseBundleNotFound) {
			t.Fatalf("unsafe bundle %s error=%v", id, err)
		}
	}
	if _, err := service.GetReleaseBundle(ctx, actor, "bun_invalid_manifest"); !errors.Is(err, packagequery.ErrReleaseBundleProjection) {
		t.Fatalf("invalid manifest projection error=%v", err)
	}
}

package postgres

import (
	"errors"
	"fmt"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresLifecycleEventsPageScopesParentAndBeyondLegacyCap(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	hash := "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
	for _, tenant := range []string{"ten_life", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ('prod_life', 'ten_life', 'Product', 'product', $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ('rel_life', 'ten_life', 'prod_life', '1.0.0', 'draft', $1)`, now); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ id, kind string }{{"ev_life", "document"}, {"ev_worker", "sbom"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, release_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, trust_level, verification_status, created_at) VALUES ($1, 'ten_life', 'prod_life', 'rel_life', $2, 'Evidence', 'test', $3, 1, 'evidence-item.v1.0.0', $4, $4, 'canonical-json.v1', 'L2', 'pending', $3)`, item.id, item.kind, now, hash); err != nil {
			t.Fatal(err)
		}
	}
	for index := range 501 {
		id := fmt.Sprintf("life_%03d", index)
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_lifecycle_events (id, tenant_id, evidence_id, action, reason, details, actor_id, schema_version, created_at) VALUES ($1, 'ten_life', 'ev_life', 'amendment', 'safe', '{"secret":"hidden","note":"visible"}'::jsonb, 'usr_1', 'evidence-lifecycle.v1', $2)`, id, now.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_lifecycle_events (id, tenant_id, evidence_id, action, reason, actor_id, schema_version, created_at) VALUES ('life_other', 'ten_other', 'ev_life', 'amendment', 'foreign', 'usr_2', 'evidence-lifecycle.v1', $1)`, now); err != nil {
		t.Fatal(err)
	}
	service, err := evidencequery.NewLifecycleEvents(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_life", UserID: "usr_1", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_life", Scopes: []string{"evidence:read"}}}}
	request := appquery.PageRequest{PageSize: 500, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	first, err := service.ListPage(ctx, actor, "ev_life", request, nil)
	if err != nil || len(first.Items) != 500 || first.Next == nil || first.Items[0].ID != "life_000" {
		t.Fatalf("first page count=%d next=%#v error=%v", len(first.Items), first.Next, err)
	}
	second, err := service.ListPage(ctx, actor, "ev_life", request, first.Next)
	if err != nil || len(second.Items) != 1 || second.Next != nil || second.Items[0].ID != "life_500" {
		t.Fatalf("second page=%#v error=%v", second, err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_other"
	if _, err := service.ListPage(ctx, actor, "ev_life", request, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong release grant error=%v", err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_life"
	actor.TenantID = "ten_other"
	if _, err := service.ListPage(ctx, actor, "ev_life", request, nil); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatalf("foreign evidence error=%v", err)
	}
	actor.TenantID = "ten_life"
	if _, err := service.ListPage(ctx, actor, "ev_worker", request, nil); !errors.Is(err, evidencequery.ErrRequiresProjection) {
		t.Fatalf("worker-owned evidence error=%v", err)
	}
}

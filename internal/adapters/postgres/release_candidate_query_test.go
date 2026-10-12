package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func TestPostgresReleaseCandidatesJoinCurrentParentAndFilterGrantsBeforeLimit(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_candidate", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, parent := range []struct{ product, tenant string }{{"prod_a", "ten_candidate"}, {"prod_b", "ten_candidate"}, {"prod_other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, parent.product, parent.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+parent.product, parent.tenant, parent.product, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct{ id, tenant, release string }{
		{"cand_a", "ten_candidate", "rel_prod_a"}, {"cand_b", "ten_candidate", "rel_prod_b"},
		{"cand_foreign_parent", "ten_candidate", "rel_prod_other"}, {"cand_missing_parent", "ten_candidate", "rel_missing"},
		{"cand_other", "ten_other", "rel_prod_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO release_candidates (id, tenant_id, release_id, name, state, snapshot_hash, document, schema_version, created_at) VALUES ($1, $2, $3, $1, 'open', 'sha256:test', '{"build_ids":["bld_1"]}'::jsonb, 'release-candidate.v1.0.0', $4)`, row.id, row.tenant, row.release, now); err != nil {
			t.Fatal(err)
		}
	}
	service, err := releasequery.NewReleaseCandidates(store, releasequery.NewCatalogAuthorizer())
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_candidate", UserID: "usr_1", Scopes: []string{"release:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_prod_b", Scopes: []string{"release:read"}}}}
	result, err := service.ListPage(ctx, actor, "", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "cand_b" || result.Next != nil || len(result.Items[0].BuildIDs) != 1 {
		t.Fatalf("release-granted SQL page=%#v error=%v", result, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"release:read"}}
	result, err = service.ListPage(ctx, actor, "", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "cand_a" || result.Next != nil {
		t.Fatalf("product-granted SQL page=%#v error=%v", result, err)
	}
	if _, err := service.GetReleaseCandidate(ctx, actor, "cand_b"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong-product point error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_candidate", Scopes: []string{"release:read"}}
	result, err = service.ListPage(ctx, actor, "", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "cand_a" || result.Next == nil {
		t.Fatalf("first tenant page=%#v error=%v", result, err)
	}
	result, err = service.ListPage(ctx, actor, "", page, result.Next)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "cand_b" || result.Next != nil {
		t.Fatalf("second tenant page=%#v error=%v", result, err)
	}
	page.Sort = appquery.SortID
	page.Direction = appquery.Descending
	result, err = service.ListPage(ctx, actor, "rel_prod_b", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "cand_b" || result.Next != nil {
		t.Fatalf("filtered descending page=%#v error=%v", result, err)
	}
	point, err := service.GetReleaseCandidate(ctx, actor, "cand_b")
	if err != nil || point.ID != "cand_b" || point.Revision != 1 || len(point.BuildIDs) != 1 {
		t.Fatalf("candidate point=%#v error=%v", point, err)
	}
	for _, id := range []string{"cand_foreign_parent", "cand_missing_parent", "cand_other"} {
		if _, err := service.GetReleaseCandidate(ctx, actor, id); !errors.Is(err, releasequery.ErrNotFound) {
			t.Fatalf("unsafe candidate %s error=%v", id, err)
		}
	}
	request := releasequery.ReleaseCandidatePageRequest{TenantID: "ten_candidate", Page: page}
	if _, err := store.PageReleaseCandidates(ctx, request); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("empty grant SQL request error=%v", err)
	}
	request.TenantWide = true
	request.After = &appquery.SortKey{ID: "cand_a", Value: "not-the-id"}
	if _, err := store.PageReleaseCandidates(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("noncanonical ID cursor error=%v", err)
	}
	request.Page.Sort = appquery.SortCreatedAt
	request.After = &appquery.SortKey{ID: "cand_a", Value: "not-a-time"}
	if _, err := store.PageReleaseCandidates(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("malformed time cursor error=%v", err)
	}
}

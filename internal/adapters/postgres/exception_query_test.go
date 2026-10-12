package postgres

import (
	"errors"
	"fmt"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func TestPostgresExceptionPagesScopeGrantsBeforeLimit(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_ex", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, parent := range []struct{ suffix, tenant string }{{"a", "ten_ex"}, {"b", "ten_ex"}, {"other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, "prod_"+parent.suffix, parent.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+parent.suffix, parent.tenant, "prod_"+parent.suffix, now); err != nil {
			t.Fatal(err)
		}
	}
	for index := range 501 {
		if _, err := store.pool.Exec(ctx, `INSERT INTO exceptions (id, tenant_id, release_id, reason, owner, expires_at, approved, created_at) VALUES ($1, 'ten_ex', 'rel_a', 'reviewed', 'security', $2, false, $3)`, fmt.Sprintf("ex_%03d", index), now.Add(24*time.Hour), now.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	for _, extra := range []struct{ id, tenant, release string }{{"ex_b", "ten_ex", "rel_b"}, {"ex_other", "ten_other", "rel_other"}, {"ex_dangling", "ten_ex", "rel_missing"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO exceptions (id, tenant_id, release_id, reason, owner, expires_at, approved, created_at) VALUES ($1, $2, $3, 'reviewed', 'security', $4, false, $5)`, extra.id, extra.tenant, extra.release, now.Add(24*time.Hour), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `UPDATE exceptions SET finding_id = 'finding_b', control_id = 'control_b', approved = true, approved_by = 'reviewer_b', approved_at = $1 WHERE id = 'ex_b'`, now); err != nil {
		t.Fatal(err)
	}
	service, err := riskquery.NewExceptions(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_ex", UserID: "usr_1", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"verify:read"}}}}
	page := appquery.PageRequest{PageSize: 500, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	first, err := service.ListPage(ctx, actor, "rel_a", page, nil)
	if err != nil || len(first.Items) != 500 || first.Next == nil || first.Items[0].ID != "ex_000" {
		t.Fatalf("first page count=%d next=%#v error=%v", len(first.Items), first.Next, err)
	}
	second, err := service.ListPage(ctx, actor, "rel_a", page, first.Next)
	if err != nil || len(second.Items) != 1 || second.Next != nil || second.Items[0].ID != "ex_500" {
		t.Fatalf("second page=%#v error=%v", second, err)
	}
	actor.ResourceGrants[0].ResourceID = "prod_b"
	if _, err := service.ListPage(ctx, actor, "rel_a", page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("hidden filtered release error=%v", err)
	}
	unfiltered, err := service.ListPage(ctx, actor, "", page, nil)
	if err != nil || len(unfiltered.Items) != 1 || unfiltered.Items[0].ID != "ex_b" || !unfiltered.Items[0].Approved || unfiltered.Items[0].ApprovedAt == nil || unfiltered.Items[0].ApprovedBy != "reviewer_b" || unfiltered.Items[0].FindingID != "finding_b" || unfiltered.Items[0].ControlID != "control_b" {
		t.Fatalf("filtered grant page=%#v error=%v", unfiltered, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "rel_a", Scopes: []string{"verify:read"}}
	if releasePage, err := service.ListPage(ctx, actor, "rel_a", appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Descending}, nil); err != nil || len(releasePage.Items) != 1 || releasePage.Items[0].ReleaseID != "rel_a" {
		t.Fatalf("release grant page=%#v error=%v", releasePage, err)
	}
	actor.ResourceGrants[0].ResourceID = "prod_a"
	actor.ResourceGrants[0].ResourceType = "product"
	if _, err := service.ListPage(ctx, actor, "rel_missing", page, nil); !errors.Is(err, riskquery.ErrNotFound) {
		t.Fatalf("missing release error=%v", err)
	}
	actor.TenantID = "ten_other"
	if _, err := service.ListPage(ctx, actor, "rel_a", page, nil); !errors.Is(err, riskquery.ErrNotFound) {
		t.Fatalf("foreign release error=%v", err)
	}
}

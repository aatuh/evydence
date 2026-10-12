package postgres

import (
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func TestPostgresCollectorPageScopesTenantAndKeyset(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_collectors", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct{ id, tenant string }{{"col_a", "ten_collectors"}, {"col_b", "ten_collectors"}, {"col_other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO collectors (id, tenant_id, name, type, version, api_key_id, status, allowed_scopes, schema_version, created_at) VALUES ($1, $2, $1, 'ci', '1', $1, 'active', '["evidence:write"]'::jsonb, 'collector.v1.0.0', $3)`, item.id, item.tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	service, err := integrationquery.NewCollectors(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_collectors", KeyID: "key_1", Scopes: []string{"collector:read"}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	first, err := service.ListPage(ctx, actor, page, nil)
	if err != nil || len(first.Items) != 1 || first.Items[0].ID != "col_a" || first.Next == nil || len(first.Items[0].AllowedScopes) != 1 {
		t.Fatalf("first collector page=%#v error=%v", first, err)
	}
	second, err := service.ListPage(ctx, actor, page, first.Next)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "col_b" || second.Next != nil {
		t.Fatalf("second collector page=%#v error=%v", second, err)
	}
	page.Sort = appquery.SortID
	page.Direction = appquery.Descending
	last, err := service.ListPage(ctx, actor, page, nil)
	if err != nil || len(last.Items) != 1 || last.Items[0].ID != "col_b" || last.Next == nil {
		t.Fatalf("descending collector page=%#v error=%v", last, err)
	}
	request := integrationquery.CollectorPageRequest{TenantID: "ten_collectors", Page: page, After: &appquery.SortKey{ID: "col_a", Value: "not-the-id"}}
	if _, err := store.PageCollectors(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("malformed cursor error=%v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE collectors SET status = 'invalid' WHERE id = 'col_a'`); err != nil {
		t.Fatal(err)
	}
	page.PageSize = 2
	if _, err := service.ListPage(ctx, actor, page, nil); !errors.Is(err, integrationquery.ErrInvalidProjection) {
		t.Fatalf("invalid status projection error=%v", err)
	}
}

package postgres

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	identityquery "github.com/aatuh/evydence/internal/identity/query"
)

func TestPostgresAPIKeyQueryTenantKeysetsAndNoHashes(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	base := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	for _, tenantID := range []string{"ten_keys", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenantID, base); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		id, tenantID, prefix string
		createdAt            time.Time
		revoked              bool
	}{
		{id: "key_a", tenantID: "ten_keys", prefix: "prefix_a", createdAt: base},
		{id: "key_b", tenantID: "ten_keys", prefix: "prefix_b", createdAt: base},
		{id: "key_c", tenantID: "ten_keys", prefix: "prefix_c", createdAt: base.Add(time.Second), revoked: true},
		{id: "key_other", tenantID: "ten_other", prefix: "prefix_x", createdAt: base.Add(2 * time.Second)},
	} {
		var revokedAt *time.Time
		if item.revoked {
			revokedAt = &base
		}
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO api_keys (id, tenant_id, name, prefix, hash, scopes, revoked_at, created_at)
			VALUES ($1, $2, $1, $3, 'stored-secret-hash', '["admin"]', $4, $5)`,
			item.id, item.tenantID, item.prefix, revokedAt, item.createdAt); err != nil {
			t.Fatal(err)
		}
	}
	request := identityquery.APIKeyPageRequest{TenantID: "ten_keys", Page: appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}}
	first, err := store.PageAPIKeys(ctx, request)
	if err != nil || len(first.Items) != 2 || first.Items[0].ID != "key_a" || first.Items[1].ID != "key_b" || first.Next == nil || first.Items[0].Hash != "" {
		t.Fatalf("first key page=%#v error=%v", first, err)
	}
	request.After = first.Next
	second, err := store.PageAPIKeys(ctx, request)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "key_c" || second.Items[0].RevokedAt == nil || second.Next != nil || second.Items[0].Hash != "" {
		t.Fatalf("second key page=%#v error=%v", second, err)
	}
	request.After = nil
	request.Page.Sort = appquery.SortID
	request.Page.Direction = appquery.Descending
	byID, err := store.PageAPIKeys(ctx, request)
	if err != nil || len(byID.Items) != 2 || byID.Items[0].ID != "key_c" || byID.Items[1].ID != "key_b" || byID.Next == nil {
		t.Fatalf("ID key page=%#v error=%v", byID, err)
	}
	request.After = &appquery.SortKey{Value: "key_b", ID: "key_a"}
	if _, err := store.PageAPIKeys(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("noncanonical ID cursor error=%v", err)
	}
	request.TenantID = "ten_missing"
	request.After = nil
	missing, err := store.PageAPIKeys(ctx, request)
	if err != nil || len(missing.Items) != 0 {
		t.Fatalf("other-tenant key page=%#v error=%v", missing, err)
	}
}

func TestPostgresAPIKeyQueryIndexMigrationRoundTrip(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	check := func(want bool) {
		t.Helper()
		rows, err := store.pool.Query(t.Context(), `
			SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema()
			AND indexname IN ('api_keys_tenant_created_id_idx', 'api_keys_tenant_id_idx')`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		indexes := map[string]string{}
		for rows.Next() {
			var name, definition string
			if err := rows.Scan(&name, &definition); err != nil {
				t.Fatal(err)
			}
			indexes[name] = definition
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		for name, columns := range map[string]string{
			"api_keys_tenant_created_id_idx": "(tenant_id, created_at, id)",
			"api_keys_tenant_id_idx":         "(tenant_id, id)",
		} {
			if want && !strings.Contains(indexes[name], columns) {
				t.Fatalf("missing key index %q: %q", name, indexes[name])
			}
			if !want && indexes[name] != "" {
				t.Fatalf("down migration retained key index %q", name)
			}
		}
	}
	check(true)
	for _, migration := range []struct {
		file string
		want bool
	}{
		{file: "../../../migrations/20260928000400_api_key_list_indexes.down.sql"},
		{file: "../../../migrations/20260928000400_api_key_list_indexes.up.sql", want: true},
	} {
		statement, err := os.ReadFile(migration.file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(t.Context(), string(statement)); err != nil {
			t.Fatalf("run key index migration %q: %v", migration.file, err)
		}
		check(migration.want)
	}
}

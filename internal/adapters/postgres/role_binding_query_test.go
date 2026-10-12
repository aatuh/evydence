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

func TestPostgresRoleBindingQueryTenantKeysets(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	base := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	for _, tenantID := range []string{"ten_bindings", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenantID, base); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		id, tenantID string
		createdAt    time.Time
	}{
		{id: "rbac_a", tenantID: "ten_bindings", createdAt: base},
		{id: "rbac_b", tenantID: "ten_bindings", createdAt: base},
		{id: "rbac_c", tenantID: "ten_bindings", createdAt: base.Add(time.Second)},
		{id: "rbac_other", tenantID: "ten_other", createdAt: base.Add(2 * time.Second)},
	} {
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO role_bindings (id, tenant_id, subject_type, subject_id, role, resource_type, resource_id, schema_version, created_at)
			VALUES ($1, $2, 'user', 'usr_1', 'tenant_admin', 'tenant', $2, 'v1', $3)`,
			item.id, item.tenantID, item.createdAt); err != nil {
			t.Fatal(err)
		}
	}
	request := identityquery.RoleBindingPageRequest{TenantID: "ten_bindings", Page: appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}}
	first, err := store.PageRoleBindings(ctx, request)
	if err != nil || len(first.Items) != 2 || first.Items[0].ID != "rbac_a" || first.Items[1].ID != "rbac_b" || first.Next == nil || first.Items[0].ResourceID != "ten_bindings" {
		t.Fatalf("first binding page=%#v error=%v", first, err)
	}
	request.After = first.Next
	second, err := store.PageRoleBindings(ctx, request)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "rbac_c" || second.Next != nil {
		t.Fatalf("second binding page=%#v error=%v", second, err)
	}
	request.After = nil
	request.Page.Sort = appquery.SortID
	request.Page.Direction = appquery.Descending
	byID, err := store.PageRoleBindings(ctx, request)
	if err != nil || len(byID.Items) != 2 || byID.Items[0].ID != "rbac_c" || byID.Items[1].ID != "rbac_b" || byID.Next == nil {
		t.Fatalf("ID binding page=%#v error=%v", byID, err)
	}
	request.After = &appquery.SortKey{Value: "rbac_b", ID: "rbac_a"}
	if _, err := store.PageRoleBindings(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("noncanonical ID cursor error=%v", err)
	}
	request.TenantID = "ten_missing"
	request.After = nil
	missing, err := store.PageRoleBindings(ctx, request)
	if err != nil || len(missing.Items) != 0 {
		t.Fatalf("other-tenant binding page=%#v error=%v", missing, err)
	}
}

func TestPostgresRoleBindingQueryIndexMigrationRoundTrip(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	check := func(want bool) {
		t.Helper()
		rows, err := store.pool.Query(t.Context(), `
			SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema()
			AND indexname IN ('role_bindings_tenant_created_id_idx', 'role_bindings_tenant_id_idx')`)
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
			"role_bindings_tenant_created_id_idx": "(tenant_id, created_at, id)",
			"role_bindings_tenant_id_idx":         "(tenant_id, id)",
		} {
			if want && !strings.Contains(indexes[name], columns) {
				t.Fatalf("missing binding index %q: %q", name, indexes[name])
			}
			if !want && indexes[name] != "" {
				t.Fatalf("down migration retained binding index %q", name)
			}
		}
	}
	check(true)
	for _, migration := range []struct {
		file string
		want bool
	}{
		{file: "../../../migrations/20260928000500_role_binding_list_indexes.down.sql"},
		{file: "../../../migrations/20260928000500_role_binding_list_indexes.up.sql", want: true},
	} {
		statement, err := os.ReadFile(migration.file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(t.Context(), string(statement)); err != nil {
			t.Fatalf("run binding index migration %q: %v", migration.file, err)
		}
		check(migration.want)
	}
}

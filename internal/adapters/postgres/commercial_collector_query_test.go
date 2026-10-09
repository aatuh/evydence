package postgres

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func TestPostgresCommercialCollectorQueryPagesTenantDefinitions(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"tenant_commercial", "tenant_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		id, tenant string
		createdAt  time.Time
	}{
		{"commercial_a", "tenant_commercial", now},
		{"commercial_b", "tenant_commercial", now},
		{"commercial_c", "tenant_commercial", now.Add(time.Second)},
		{"commercial_other", "tenant_other", now},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO commercial_collectors (id, tenant_id, name, provider, version, manifest_hash, allowed_scopes, status, schema_version, created_at) VALUES ($1, $2, $1, 'scanner', $1, 'sha256:manifest', ARRAY['evidence:write'], 'available', 'commercial-collector.v1.0.0', $3)`, row.id, row.tenant, row.createdAt); err != nil {
			t.Fatal(err)
		}
	}
	request := integrationquery.CommercialCollectorPageRequest{TenantID: "tenant_commercial", Page: appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}}
	first, err := store.PageCommercialCollectors(ctx, request)
	if err != nil || len(first.Items) != 2 || first.Items[0].ID != "commercial_a" || first.Items[1].ID != "commercial_b" || first.Next == nil || len(first.Items[0].AllowedScopes) != 1 {
		t.Fatalf("first commercial page=%#v error=%v", first, err)
	}
	request.After = first.Next
	second, err := store.PageCommercialCollectors(ctx, request)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "commercial_c" || second.Next != nil {
		t.Fatalf("second commercial page=%#v error=%v", second, err)
	}
	request.After = nil
	request.Page.Sort, request.Page.Direction = appquery.SortID, appquery.Descending
	byID, err := store.PageCommercialCollectors(ctx, request)
	if err != nil || len(byID.Items) != 2 || byID.Items[0].ID != "commercial_c" || byID.Items[1].ID != "commercial_b" {
		t.Fatalf("descending ID page=%#v error=%v", byID, err)
	}
	request.After = &appquery.SortKey{Value: "commercial_b", ID: "commercial_a"}
	if _, err := store.PageCommercialCollectors(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("malformed cursor error=%v", err)
	}
	request.After = nil
	request.TenantID = "tenant_other"
	other, err := store.PageCommercialCollectors(ctx, request)
	if err != nil || len(other.Items) != 1 || other.Items[0].ID != "commercial_other" {
		t.Fatalf("foreign tenant page=%#v error=%v", other, err)
	}
}

func TestPostgresCommercialCollectorQueryIndexMigrationRoundTrip(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	check := func(want bool) {
		t.Helper()
		rows, err := store.pool.Query(t.Context(), `SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() AND indexname IN ('commercial_collectors_tenant_created_id_idx', 'commercial_collectors_tenant_id_idx')`)
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
			"commercial_collectors_tenant_created_id_idx": "(tenant_id, created_at, id)",
			"commercial_collectors_tenant_id_idx":         "(tenant_id, id)",
		} {
			if want && !strings.Contains(indexes[name], columns) {
				t.Fatalf("missing commercial collector index %q: %q", name, indexes[name])
			}
			if !want && indexes[name] != "" {
				t.Fatalf("down migration retained commercial collector index %q", name)
			}
		}
	}
	check(true)
	for _, migration := range []struct {
		file string
		want bool
	}{
		{file: "../../../migrations/20260929000200_commercial_collector_list_indexes.down.sql"},
		{file: "../../../migrations/20260929000200_commercial_collector_list_indexes.up.sql", want: true},
	} {
		statement, err := os.ReadFile(migration.file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(t.Context(), string(statement)); err != nil {
			t.Fatalf("run commercial collector index migration %q: %v", migration.file, err)
		}
		check(migration.want)
	}
}

package postgres

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func TestPostgresCollectorHealthPointScopesTenantAndSelectsCurrentReleases(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_health", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id,name,created_at) VALUES ($1,$1,$2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct{ id, tenant string }{{"col_health", "ten_health"}, {"col_other", "ten_other"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO collectors (id,tenant_id,name,type,version,api_key_id,status,allowed_scopes,schema_version,created_at) VALUES ($1,$2,$1,'generic_ci','2',$1,'active','["evidence:write"]'::jsonb,'collector.v1.0.0',$3)`, row.id, row.tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		id, tenant, collector, version string
		pinned                         bool
		created                        time.Time
	}{
		{"rel_first", "ten_health", "col_health", "1", false, now.Add(-time.Hour)},
		{"rel_pinned", "ten_health", "col_health", "1.5", true, now.Add(-time.Minute)},
		{"rel_latest", "ten_health", "col_health", "2", false, now},
		{"rel_other", "ten_other", "col_other", "9", true, now.Add(time.Hour)},
		{"rel_foreign_ref", "ten_other", "col_health", "10", true, now.Add(2 * time.Hour)},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO collector_releases (id,tenant_id,collector_id,version,artifact_digest,pinned,verification_status,health_status,limitations,schema_version,created_at) VALUES ($1,$2,$3,$4,'sha256:fixture',$5,'recorded','needs_evidence',ARRAY['recorded only'],'collector-release.v1.0.0',$6)`, row.id, row.tenant, row.collector, row.version, row.pinned, row.created); err != nil {
			t.Fatal(err)
		}
	}
	point, err := store.GetCollectorHealthPoint(ctx, "ten_health", "col_health")
	if err != nil || point.Collector.ID != "col_health" || point.LatestRelease == nil || point.LatestRelease.ID != "rel_latest" || point.PinnedRelease == nil || point.PinnedRelease.ID != "rel_pinned" || len(point.LatestRelease.Limitations) != 1 {
		t.Fatalf("health point=%#v error=%v", point, err)
	}
	if _, err := store.GetCollectorHealthPoint(ctx, "ten_health", "col_other"); !errors.Is(err, integrationquery.ErrNotFound) {
		t.Fatalf("foreign collector error=%v", err)
	}
	if _, err := store.GetCollectorHealthPoint(ctx, "ten_other", "col_health"); !errors.Is(err, integrationquery.ErrNotFound) {
		t.Fatalf("reverse foreign collector error=%v", err)
	}
}

func TestPostgresCollectorHealthIndexesRoundTrip(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	check := func(want bool) {
		t.Helper()
		rows, err := store.pool.Query(t.Context(), `SELECT indexname,indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname IN ('collector_releases_health_latest_idx','collector_releases_health_pinned_idx')`)
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
		for name, fragment := range map[string]string{
			"collector_releases_health_latest_idx": "(tenant_id, collector_id, created_at DESC, id DESC)",
			"collector_releases_health_pinned_idx": "WHERE (pinned = true)",
		} {
			if want && !strings.Contains(indexes[name], fragment) {
				t.Fatalf("missing index %q: %q", name, indexes[name])
			}
			if !want && indexes[name] != "" {
				t.Fatalf("down migration retained index %q", name)
			}
		}
	}
	check(true)
	for _, migration := range []struct {
		file string
		want bool
	}{
		{file: "../../../migrations/20260929000500_collector_health_indexes.down.sql"},
		{file: "../../../migrations/20260929000500_collector_health_indexes.up.sql", want: true},
	} {
		statement, err := os.ReadFile(migration.file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(t.Context(), string(statement)); err != nil {
			t.Fatalf("migration %q: %v", migration.file, err)
		}
		check(migration.want)
	}
}

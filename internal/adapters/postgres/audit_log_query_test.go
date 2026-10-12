package postgres

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func TestPostgresAuditLogQueryScopesFiltersAndKeysets(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	base := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	for _, tenantID := range []string{"ten_audit", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenantID, base); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		id, tenantID, subjectType, subjectID string
		sequence                             int
		occurredAt                           time.Time
	}{
		{id: "ace_a", tenantID: "ten_audit", subjectType: "release", subjectID: "rel_1", sequence: 1, occurredAt: base},
		{id: "ace_b", tenantID: "ten_audit", subjectType: "release", subjectID: "rel_1", sequence: 2, occurredAt: base},
		{id: "ace_c", tenantID: "ten_audit", subjectType: "release", subjectID: "rel_2", sequence: 3, occurredAt: base.Add(time.Second)},
		{id: "ace_foreign", tenantID: "ten_other", subjectType: "release", subjectID: "rel_1", sequence: 1, occurredAt: base.Add(2 * time.Second)},
	} {
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO audit_chain_entries (id, tenant_id, sequence, entry_type, subject_type,
				subject_id, actor_type, actor_id, occurred_at, canonical_entry_hash,
				previous_entry_hash, entry_hash, schema_version)
			VALUES ($1, $2, $3, 'release.created', $4, $5, 'api_key', 'key_1', $6,
				'sha256:canonical', 'sha256:previous', 'sha256:entry', 'audit-chain-entry.v1')`,
			item.id, item.tenantID, item.sequence, item.subjectType, item.subjectID, item.occurredAt); err != nil {
			t.Fatal(err)
		}
	}
	request := verificationquery.AuditPageRequest{
		TenantID: "ten_audit",
		Page:     appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending},
	}
	first, err := store.PageAuditLog(ctx, request)
	if err != nil || len(first.Items) != 2 || first.Items[0].ID != "ace_a" || first.Items[1].ID != "ace_b" || first.Next == nil {
		t.Fatalf("first audit page=%#v error=%v", first, err)
	}
	request.After = first.Next
	second, err := store.PageAuditLog(ctx, request)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "ace_c" || second.Next != nil {
		t.Fatalf("second audit page=%#v error=%v", second, err)
	}
	request.After = nil
	request.Filter = verificationquery.AuditFilter{SubjectType: "release", SubjectID: "rel_1", Since: &base}
	filtered, err := store.PageAuditLog(ctx, request)
	if err != nil || len(filtered.Items) != 2 || filtered.Items[0].ID != "ace_a" || filtered.Items[1].ID != "ace_b" || filtered.Next != nil {
		t.Fatalf("filtered audit page=%#v error=%v", filtered, err)
	}
	request.Page.Sort = appquery.SortID
	request.Page.Direction = appquery.Descending
	request.Filter = verificationquery.AuditFilter{}
	byID, err := store.PageAuditLog(ctx, request)
	if err != nil || len(byID.Items) != 2 || byID.Items[0].ID != "ace_c" || byID.Items[1].ID != "ace_b" || byID.Next == nil {
		t.Fatalf("id audit page=%#v error=%v", byID, err)
	}
	request.After = &appquery.SortKey{Value: "ace_b", ID: "ace_a"}
	if _, err := store.PageAuditLog(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("noncanonical ID cursor error=%v", err)
	}
}

func TestPostgresAuditLogQueryIndexMigrationRoundTrip(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	check := func(want bool) {
		t.Helper()
		rows, err := store.pool.Query(t.Context(), `
			SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema()
			AND indexname IN ('audit_chain_tenant_time_id_idx',
			'audit_chain_tenant_subject_time_id_idx', 'audit_chain_tenant_id_idx')`)
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
			"audit_chain_tenant_time_id_idx":         "(tenant_id, occurred_at, id)",
			"audit_chain_tenant_subject_time_id_idx": "(tenant_id, subject_type, subject_id, occurred_at, id)",
			"audit_chain_tenant_id_idx":              "(tenant_id, id)",
		} {
			if want && !strings.Contains(indexes[name], columns) {
				t.Fatalf("missing audit index %q: %q", name, indexes[name])
			}
			if !want && indexes[name] != "" {
				t.Fatalf("down migration retained audit index %q", name)
			}
		}
	}
	check(true)
	for _, migration := range []struct {
		file string
		want bool
	}{
		{file: "../../../migrations/20260928000300_audit_log_query_indexes.down.sql"},
		{file: "../../../migrations/20260928000300_audit_log_query_indexes.up.sql", want: true},
	} {
		statement, err := os.ReadFile(migration.file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(t.Context(), string(statement)); err != nil {
			t.Fatalf("run audit index migration %q: %v", migration.file, err)
		}
		check(migration.want)
	}
}

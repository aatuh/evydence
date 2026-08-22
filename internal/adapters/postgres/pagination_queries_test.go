package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
)

func TestStoreListEvidencePageUsesTenantBoundKeyset(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_evidence_page_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = admin.pool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"ten_page", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $2, $3)`, tenant, tenant, time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)); err != nil {
			t.Fatalf("insert tenant %s: %v", tenant, err)
		}
	}
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	for _, item := range []struct {
		id        string
		tenantID  string
		createdAt time.Time
	}{
		{id: "ev_a", tenantID: "ten_page", createdAt: base},
		{id: "ev_b", tenantID: "ten_page", createdAt: base},
		{id: "ev_c", tenantID: "ten_page", createdAt: base.Add(time.Second)},
		{id: "ev_other", tenantID: "ten_other", createdAt: base.Add(2 * time.Second)},
	} {
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO evidence_items (
				id, tenant_id, type, title, source_system, observed_at,
				evidence_version, schema_version, payload_hash, canonical_hash,
				canonicalization, trust_level, verification_status, created_at
			) VALUES ($1, $2, 'build', 'page test', 'test', $3, 1, 'evidence-item.v1.0.0',
				'sha256:payload', 'sha256:canonical', 'canonical-json.v1', 'uploaded', 'pending', $3)`, item.id, item.tenantID, item.createdAt); err != nil {
			t.Fatalf("insert evidence %s: %v", item.id, err)
		}
	}
	request := app.EvidencePageRequest{
		TenantID: "ten_page",
		Type:     "build",
		Page:     appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending},
	}
	first, err := store.ListEvidencePage(ctx, request)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if got, want := evidenceIDs(first.Items), "ev_a,ev_b"; got != want || first.Next == nil {
		t.Fatalf("first page ids=%q next=%#v, want %q and a cursor", got, first.Next, want)
	}
	request.After = first.Next
	second, err := store.ListEvidencePage(ctx, request)
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if got, want := evidenceIDs(second.Items), "ev_c"; got != want || second.Next != nil {
		t.Fatalf("second page ids=%q next=%#v, want %q and no cursor", got, second.Next, want)
	}
	request.Page = appquery.PageRequest{PageSize: 2, Sort: appquery.SortID, Direction: appquery.Descending}
	request.After = nil
	descending, err := store.ListEvidencePage(ctx, request)
	if err != nil {
		t.Fatalf("descending page: %v", err)
	}
	if got, want := evidenceIDs(descending.Items), "ev_c,ev_b"; got != want {
		t.Fatalf("descending ids=%q, want %q", got, want)
	}
	searchRequest := app.EvidenceSearchPageRequest{
		TenantID: "ten_page",
		Filter:   app.EvidenceSearchInput{Type: "build"},
		Page:     appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Descending},
	}
	searchFirst, err := store.SearchEvidencePage(ctx, searchRequest)
	if err != nil {
		t.Fatalf("first search page: %v", err)
	}
	if got, want := evidenceIDs(searchFirst.Items), "ev_c,ev_b"; got != want || searchFirst.Next == nil {
		t.Fatalf("first search ids=%q next=%#v, want %q and a cursor", got, searchFirst.Next, want)
	}
	searchRequest.After = searchFirst.Next
	searchSecond, err := store.SearchEvidencePage(ctx, searchRequest)
	if err != nil {
		t.Fatalf("second search page: %v", err)
	}
	if got, want := evidenceIDs(searchSecond.Items), "ev_a"; got != want || searchSecond.Next != nil {
		t.Fatalf("second search ids=%q next=%#v, want %q and no cursor", got, searchSecond.Next, want)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET tags = '["ci"]'::jsonb, subject_refs = '[{"type":"release","id":"rel_page"}]'::jsonb WHERE id = 'ev_c'`); err != nil {
		t.Fatalf("seed JSON search fields: %v", err)
	}
	filtered, err := store.SearchEvidencePage(ctx, app.EvidenceSearchPageRequest{
		TenantID: "ten_page",
		Filter:   app.EvidenceSearchInput{Type: "build", Tag: "ci", SubjectType: "release", SubjectID: "rel_page"},
		Page:     appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Descending},
	})
	if err != nil || evidenceIDs(filtered.Items) != "ev_c" {
		t.Fatalf("filtered search items=%q err=%v, want ev_c", evidenceIDs(filtered.Items), err)
	}
}

func evidenceIDs(items []domain.EvidenceItem) string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	return strings.Join(ids, ",")
}

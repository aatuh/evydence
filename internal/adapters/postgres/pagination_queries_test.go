package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
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
	visible := func(item domain.EvidenceItem) (bool, error) {
		if item.TenantID != "ten_page" {
			t.Fatalf("foreign tenant row reached visibility policy: %#v", item)
		}
		return item.ID == "ev_b" || item.ID == "ev_c", nil
	}
	visibleRequest := app.EvidencePageRequest{TenantID: "ten_page", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}}
	visibleFirst, err := store.ListEvidencePageVisible(ctx, visibleRequest, visible)
	if err != nil || evidenceIDs(visibleFirst.Items) != "ev_b" || visibleFirst.Next == nil {
		t.Fatalf("first grant-filtered page=%#v error=%v", visibleFirst, err)
	}
	visibleRequest.After = visibleFirst.Next
	visibleSecond, err := store.ListEvidencePageVisible(ctx, visibleRequest, visible)
	if err != nil || evidenceIDs(visibleSecond.Items) != "ev_c" || visibleSecond.Next != nil {
		t.Fatalf("second grant-filtered page=%#v error=%v", visibleSecond, err)
	}
	visibleSearch, err := store.SearchEvidencePageVisible(ctx, app.EvidenceSearchPageRequest{
		TenantID: "ten_page", Filter: app.EvidenceSearchInput{Type: "build", Tag: "ci"},
		Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending},
	}, visible)
	if err != nil || evidenceIDs(visibleSearch.Items) != "ev_c" || visibleSearch.Next != nil {
		t.Fatalf("grant-filtered search=%#v error=%v", visibleSearch, err)
	}
	if _, err := store.ListEvidencePageVisible(ctx, visibleRequest, nil); err == nil {
		t.Fatal("visibility query accepted a missing authorization policy")
	}
	deniedErr := errors.New("authorization lookup failed")
	failed, err := store.ListEvidencePageVisible(ctx, app.EvidencePageRequest{
		TenantID: "ten_page", Page: visibleRequest.Page,
	}, func(domain.EvidenceItem) (bool, error) { return false, deniedErr })
	if !errors.Is(err, deniedErr) || len(failed.Items) != 0 {
		t.Fatalf("failed policy returned data: page=%#v error=%v", failed, err)
	}
	for i := range 70 {
		id := fmt.Sprintf("ev_hidden_%03d", i)
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO evidence_items (
				id, tenant_id, type, title, source_system, observed_at,
				evidence_version, schema_version, payload_hash, canonical_hash,
				canonicalization, trust_level, verification_status, created_at
			) VALUES ($1, 'ten_page', 'build', 'hidden', 'test', $2, 1,
				'evidence-item.v1.0.0', 'sha256:payload', 'sha256:canonical',
				'canonical-json.v1', 'uploaded', 'pending', $2)`, id, base); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO evidence_items (
			id, tenant_id, type, title, source_system, observed_at,
			evidence_version, schema_version, payload_hash, canonical_hash,
			canonicalization, trust_level, verification_status, created_at
		) VALUES ('ev_visible_z', 'ten_page', 'build', 'visible', 'test', $1, 1,
			'evidence-item.v1.0.0', 'sha256:payload', 'sha256:canonical',
			'canonical-json.v1', 'uploaded', 'pending', $1)`, base); err != nil {
		t.Fatal(err)
	}
	inserted := false
	seenInserted := false
	snapshotVisible := func(item domain.EvidenceItem) (bool, error) {
		if !inserted {
			inserted = true
			if _, err := store.pool.Exec(ctx, `
				INSERT INTO evidence_items (
					id, tenant_id, type, title, source_system, observed_at,
					evidence_version, schema_version, payload_hash, canonical_hash,
					canonicalization, trust_level, verification_status, created_at
				) VALUES ('ev_visible_mid', 'ten_page', 'build', 'late', 'test', $1, 1,
					'evidence-item.v1.0.0', 'sha256:payload', 'sha256:canonical',
					'canonical-json.v1', 'uploaded', 'pending', $1)`, base); err != nil {
				return false, err
			}
		}
		if item.ID == "ev_visible_mid" {
			seenInserted = true
		}
		return item.ID == "ev_visible_mid" || item.ID == "ev_visible_z", nil
	}
	snapshot, err := store.ListEvidencePageVisible(ctx, app.EvidencePageRequest{
		TenantID: "ten_page", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending},
	}, snapshotVisible)
	if err != nil || evidenceIDs(snapshot.Items) != "ev_visible_z" || snapshot.Next != nil || seenInserted {
		t.Fatalf("snapshot page=%#v late row seen=%v error=%v", snapshot, seenInserted, err)
	}
	for _, product := range []string{"prod_allowed", "prod_hidden"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, 'ten_page', $1, $1, $2)`, product, base); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET product_id = 'prod_allowed' WHERE id IN ('ev_b', 'ev_c')`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET product_id = 'prod_hidden' WHERE id = 'ev_a'`); err != nil {
		t.Fatal(err)
	}
	pages, err := evidencequery.NewEvidencePages(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{
		TenantID: "ten_page", UserID: "usr_restricted", Scopes: []string{app.ScopeEvidenceRead},
		ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_allowed", Scopes: []string{app.ScopeEvidenceRead}}},
	}
	boundPage := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	firstBound, err := pages.ListPage(ctx, actor, evidencequery.EvidencePageFilter{}, boundPage, nil)
	if err != nil || len(firstBound.Items) != 1 || firstBound.Items[0].ID != "ev_b" || firstBound.Next == nil {
		t.Fatalf("restricted focused first page=%#v error=%v", firstBound, err)
	}
	secondBound, err := pages.ListPage(ctx, actor, evidencequery.EvidencePageFilter{}, boundPage, firstBound.Next)
	if err != nil || len(secondBound.Items) != 1 || secondBound.Items[0].ID != "ev_c" || secondBound.Next != nil {
		t.Fatalf("restricted focused second page=%#v error=%v", secondBound, err)
	}
	actor.ResourceGrants = nil
	revoked, err := pages.ListPage(ctx, actor, evidencequery.EvidencePageFilter{Type: "build"}, boundPage, nil)
	if err != nil || len(revoked.Items) != 0 || revoked.Next != nil {
		t.Fatalf("revoked ledger search=%#v error=%v", revoked, err)
	}
}

func evidenceIDs(items []domain.EvidenceItem) string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	return strings.Join(ids, ",")
}

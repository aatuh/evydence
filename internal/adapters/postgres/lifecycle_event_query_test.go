package postgres

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresLifecycleEventsPageScopesParentAndBeyondLegacyCap(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	hash := "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
	for _, tenant := range []string{"ten_life", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ('prod_life', 'ten_life', 'Product', 'product', $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ('rel_life', 'ten_life', 'prod_life', '1.0.0', 'draft', $1)`, now); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ id, kind string }{{"ev_life", "document"}, {"ev_worker", "sbom"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, release_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, trust_level, verification_status, created_at) VALUES ($1, 'ten_life', 'prod_life', 'rel_life', $2, 'Evidence', 'test', $3, 1, 'evidence-item.v1.0.0', $4, $4, 'canonical-json.v1', 'L2', 'pending', $3)`, item.id, item.kind, now, hash); err != nil {
			t.Fatal(err)
		}
	}
	for index := range 501 {
		id := fmt.Sprintf("life_%03d", index)
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_lifecycle_events (id, tenant_id, evidence_id, action, reason, details, actor_id, schema_version, created_at) VALUES ($1, 'ten_life', 'ev_life', 'amendment', 'safe', '{"secret":"hidden","note":"visible"}'::jsonb, 'usr_1', 'evidence-lifecycle.v1', $2)`, id, now.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_lifecycle_events (id, tenant_id, evidence_id, action, reason, actor_id, schema_version, created_at) VALUES ('life_other', 'ten_other', 'ev_life', 'amendment', 'foreign', 'usr_2', 'evidence-lifecycle.v1', $1)`, now); err != nil {
		t.Fatal(err)
	}
	service, err := evidencequery.NewLifecycleEvents(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_life", UserID: "usr_1", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_life", Scopes: []string{"evidence:read"}}}}
	request := appquery.PageRequest{PageSize: 500, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	first, err := service.ListPage(ctx, actor, "ev_life", request, nil)
	if err != nil || len(first.Items) != 500 || first.Next == nil || first.Items[0].ID != "life_000" {
		t.Fatalf("first page count=%d next=%#v error=%v", len(first.Items), first.Next, err)
	}
	second, err := service.ListPage(ctx, actor, "ev_life", request, first.Next)
	if err != nil || len(second.Items) != 1 || second.Next != nil || second.Items[0].ID != "life_500" {
		t.Fatalf("second page=%#v error=%v", second, err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_other"
	if _, err := service.ListPage(ctx, actor, "ev_life", request, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong release grant error=%v", err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_life"
	actor.TenantID = "ten_other"
	if _, err := service.ListPage(ctx, actor, "ev_life", request, nil); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatalf("foreign evidence error=%v", err)
	}
	actor.TenantID = "ten_life"
	if _, err := service.ListPage(ctx, actor, "ev_worker", request, nil); err != nil {
		t.Fatalf("queued worker-owned evidence rejected: %v", err)
	}
}

func TestPostgresEvidenceReadsAuthorizeBeforeOversizedPayloadsAndBoundLifecyclePage(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := store.pool.Exec(ctx, statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name) VALUES('tenant','Tenant');
		INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','Product','product');
		INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('release','tenant','product','1','draft');
		INSERT INTO evidence_items(id,tenant_id,product_id,release_id,type,title,source_system,observed_at,evidence_version,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)
		VALUES('evidence','tenant','product','release','note','Note','ci',now(),1,'evidence-item.v1.0.0','hash','hash','legacy','L2','pending')`)
	points, err := evidencequery.NewEvidencePoints(store)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := evidencequery.NewLifecycleEvents(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "other", Scopes: []string{"evidence:read"}}}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	check := func(wantPoint, wantPage error) {
		t.Helper()
		item, err := points.GetEvidence(ctx, actor, "evidence")
		if !errors.Is(err, wantPoint) || (wantPoint != nil && item.ID != "") {
			t.Fatalf("point wanted %v got %v", wantPoint, err)
		}
		result, err := lifecycle.ListPage(ctx, actor, "evidence", page, nil)
		if !errors.Is(err, wantPage) || (wantPage != nil && (len(result.Items) != 0 || result.Next != nil)) {
			t.Fatalf("page wanted %v got %v", wantPage, err)
		}
	}
	exec(`UPDATE evidence_items SET metadata=jsonb_build_object('large',repeat('x',9*1024*1024)) WHERE id='evidence'`)
	check(application.ErrForbidden, application.ErrForbidden)
	actor.ResourceGrants[0].ResourceID = "release"
	check(evidencequery.ErrConflict, evidencequery.ErrConflict)
	exec(`UPDATE evidence_items SET metadata='{}' WHERE id='evidence'`)
	exec(`INSERT INTO evidence_lifecycle_events(id,tenant_id,evidence_id,action,reason,details,actor_id,schema_version,created_at)
		VALUES('first','tenant','evidence','amendment','safe',jsonb_build_object('large',repeat('x',9*1024*1024)),'user','evidence-lifecycle.v1',now())`)
	actor.ResourceGrants[0].ResourceID = "other"
	check(application.ErrForbidden, application.ErrForbidden)
	actor.ResourceGrants[0].ResourceID = "release"
	check(nil, evidencequery.ErrConflict)
	// Each row fits individually. The lookahead row must still count toward
	// the aggregate budget; returning a truncated successful page is unsafe.
	exec(`UPDATE evidence_lifecycle_events SET details=jsonb_build_object('large',repeat('x',5*1024*1024)) WHERE id='first'`)
	exec(`INSERT INTO evidence_lifecycle_events(id,tenant_id,evidence_id,action,reason,details,actor_id,schema_version,created_at)
		SELECT 'second',tenant_id,evidence_id,action,reason,details,actor_id,schema_version,created_at+interval '1 second' FROM evidence_lifecycle_events WHERE id='first'`)
	check(nil, evidencequery.ErrConflict)
	// All text fields, not just JSON details, must count toward the limit.
	exec(`UPDATE evidence_lifecycle_events SET details='{}',reason=CASE WHEN id='first' THEN repeat('x',9*1024*1024) ELSE 'safe' END`)
	check(nil, evidencequery.ErrConflict)
	exec(`UPDATE evidence_lifecycle_events SET reason='safe'`)
	result, err := lifecycle.ListPage(ctx, actor, "evidence", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "first" || result.Next == nil {
		t.Fatalf("recovered page=%#v err=%v", result, err)
	}
	for _, table := range []string{"audit_chain_entries", "outbox_jobs", "verification_results"} {
		var count int
		if err := store.pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("read effects %s=%d err=%v", table, count, err)
		}
	}
	for _, id := range []string{"bad\x00id", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		guard := func(application.ResourceReferences) error { t.Fatal("invalid ID reached authorization"); return nil }
		if _, err := store.PageLifecycleEvents(ctx, "tenant", id, page, nil, guard); !errors.Is(err, evidencequery.ErrValidation) {
			t.Fatalf("malformed lifecycle ID error=%v", err)
		}
	}
}

package wiring

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
)

func retentionMarkerHTTP(t *testing.T, store *postgres.Store, path, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.RetentionMarkerCommands == nil {
		t.Fatal("marker native wiring absent", err)
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private-") || (want != 201 && strings.Contains(w.Body.String(), `"data"`)) {
		t.Fatalf("marker status=%d want=%d canary=%t body=%s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	return w.Body.String()
}
func retentionMarkerCounts(t *testing.T, p *pgxpool.Pool) [4]int {
	t.Helper()
	var v [4]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM legal_holds)+(SELECT count(*)FROM retention_overrides),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&v[0], &v[1], &v[2], &v[3]); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPostgresRetentionMarkerHTTPNativeReplayAndRevocation(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	for _, path := range []string{"/v1/legal-holds", "/v1/retention-overrides"} {
		body := `{"scope_type":"tenant","scope_id":"tenant","reason":"review","owner":"legal"}`
		if strings.HasSuffix(path, "overrides") {
			body = strings.TrimSuffix(body, "}") + fmt.Sprintf(`,"retention_until":%q}`, time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339Nano))
		}
		one := retentionMarkerHTTP(t, store, path, path, body, 201)
		assertRetentionHTTPReplay(t, one, retentionMarkerHTTP(t, store, path, path, body, 201))
		retentionMarkerHTTP(t, store, path, path, " "+body, 409)
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='p' WHERE id='grant'`); err != nil {
			t.Fatal(err)
		}
		retentionMarkerHTTP(t, store, path, path, body, 403)
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='grant'`); err != nil {
			t.Fatal(err)
		}
	}
	if retentionMarkerCounts(t, p) != [4]int{2, 2, 2, 0} {
		t.Fatal("replay duplicated markers or audit")
	}
	var actor, subject string
	if err := p.QueryRow(t.Context(), `SELECT actor_id,subject_id FROM audit_chain_entries LIMIT 1`).Scan(&actor, &subject); err != nil || actor != "user" || subject != "tenant" {
		t.Fatal("subject audit identity changed", err)
	}
}

func TestPostgresRetentionMarkerHTTPAllOwnedScopesAndForeignReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO products(id,tenant_id,name,slug) VALUES('p','tenant',repeat('private-product',700000),'p'),('foreign','other','Foreign','foreign'); INSERT INTO projects(id,tenant_id,product_id,name) VALUES('pr','tenant','p','Project'); INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('r','tenant','p','1','draft'); INSERT INTO evidence_items(id,tenant_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES('e','tenant','sbom',repeat('private-evidence',700000),'test',now(),'evidence.v1',repeat('a',64),repeat('b',64),'canonical-json','unverified','pending')`); err != nil {
		t.Fatal(err)
	}
	for _, subject := range []struct{ kind, id, table string }{{"tenant", "tenant", "tenants"}, {"product", "p", "products"}, {"project", "pr", "projects"}, {"release", "r", "releases"}, {"evidence", "e", "evidence_items"}} {
		for _, override := range []bool{false, true} {
			path := "/v1/legal-holds"
			extra := ""
			if override {
				path = "/v1/retention-overrides"
				extra = fmt.Sprintf(`,"retention_until":%q`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
			}
			body := fmt.Sprintf(`{"scope_type":%q,"scope_id":%q,"reason":"review","owner":"legal"%s}`, subject.kind, subject.id, extra)
			key := subject.kind + path
			one := retentionMarkerHTTP(t, store, path, key, body, 201)
			assertRetentionHTTPReplay(t, one, retentionMarkerHTTP(t, store, path, key, body, 201))
			bad := strings.Replace(body, fmt.Sprintf(`"scope_id":%q`, subject.id), `"scope_id":"foreign"`, 1)
			retentionMarkerHTTP(t, store, path, "foreign-"+key, bad, 404)
			if subject.kind != "tenant" {
				if _, err := p.Exec(t.Context(), "UPDATE "+subject.table+" SET tenant_id='other' WHERE id=$1", subject.id); err != nil {
					t.Fatal(err)
				}
				retentionMarkerHTTP(t, store, path, key, body, 404)
				if _, err := p.Exec(t.Context(), "UPDATE "+subject.table+" SET tenant_id='tenant' WHERE id=$1", subject.id); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if retentionMarkerCounts(t, p) != [4]int{10, 10, 10, 0} {
		t.Fatal("ownership checks or replay generated effects")
	}
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now() WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	retentionMarkerHTTP(t, store, "/v1/legal-holds", "tenant/v1/legal-holds", `{"scope_type":"tenant","scope_id":"tenant","reason":"review","owner":"legal"}`, 401)
}

func TestPostgresRetentionMarkerHTTPAtomicFailuresDoNotPublishMarkerOrReplay(t *testing.T) {
	for _, override := range []bool{false, true} {
		for _, stage := range []string{"write", "audit", "replay", "commit"} {
			t.Run(fmt.Sprintf("override-%t/%s", override, stage), func(t *testing.T) {
				store, p := openHTMLReportWiringStore(t)
				seedProviderReceiptHTTP(t, p)
				path, table, body := "/v1/legal-holds", "legal_holds", `{"scope_type":"tenant","scope_id":"tenant","reason":"review","owner":"legal"}`
				if override {
					path, table = "/v1/retention-overrides", "retention_overrides"
					body = strings.TrimSuffix(body, "}") + fmt.Sprintf(`,"retention_until":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
				}
				event := "INSERT"
				if stage == "audit" {
					table = "audit_chain_entries"
				}
				if stage == "replay" {
					table, event = "idempotency_records", "UPDATE"
				}
				trigger := fmt.Sprintf("CREATE TRIGGER reject_marker BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION reject_marker()", event, table)
				if stage == "replay" {
					trigger = `CREATE TRIGGER reject_marker BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed') EXECUTE FUNCTION reject_marker()`
				}
				if stage == "commit" {
					trigger = fmt.Sprintf("CREATE CONSTRAINT TRIGGER reject_marker AFTER INSERT ON %s DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_marker()", table)
				}
				if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_marker() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-marker SQL password=secret';END$$;`+trigger); err != nil {
					t.Fatal(err)
				}
				retentionMarkerHTTP(t, store, path, "failed", body, 500)
				want := [4]int{}
				if stage == "write" || stage == "audit" {
					want[3] = 1
				}
				if retentionMarkerCounts(t, p) != want {
					t.Fatal("partial marker/audit/replay committed")
				}
				var leaked int
				if err := p.QueryRow(t.Context(), `SELECT count(*) FROM idempotency_records WHERE response IS NOT NULL AND response<>'null'::jsonb`).Scan(&leaked); err != nil || leaked != 0 {
					t.Fatal("failed marker published response", err)
				}
				if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_marker ON "+table); err != nil {
					t.Fatal(err)
				}
				key := "failed"
				if want[3] > 0 {
					key = "fresh-retry"
				}
				retentionMarkerHTTP(t, store, path, key, body, 201)
				want[0], want[1], want[2] = 1, 1, 1
				if retentionMarkerCounts(t, p) != want {
					t.Fatal("retry duplicated effects")
				}
			})
		}
	}
}

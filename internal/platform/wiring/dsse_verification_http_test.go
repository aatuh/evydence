package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func dsseHTTP(t *testing.T, store *postgres.Store, objects *countedDSSEReader, id, key, body string, want int) string {
	t.Helper()
	var objectStore app.ObjectStore
	if objects != nil {
		objectStore = objects
	}
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Objects: objectStore}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.DSSEVerification == nil || opts.DurableCommandExecutor == nil {
		t.Fatal("native DSSE composition missing", err)
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/build-attestations/"+id+"/verify-signature", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private-") || want != 200 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("unsafe/legacy DSSE route status=%d want=%d canary=%t body=%s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	if want == 200 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("missing replay key")
	}
	return w.Body.String()
}

// Receipt, audit, successful replay, failed reservation, verification job.
func dsseHTTPCounts(t *testing.T, p *pgxpool.Pool) [5]int {
	t.Helper()
	var v [5]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM verification_results WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed'),(SELECT count(*)FROM outbox_jobs)`).Scan(&v[0], &v[1], &v[2], &v[3], &v[4]); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPostgresDSSEHTTPRestartReplayAndCurrentScopedAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects := seedDSSEVerification(t, p, true)
	one := dsseHTTP(t, store, objects, "attestation", "verify", `{}`, 200)
	var envelope struct {
		Data domain.VerificationResult `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &envelope); err != nil {
		t.Fatal(err)
	}
	v := envelope.Data
	if v.Result != "passed" || v.SubjectType != "build_attestation" || v.SubjectID != "attestation" || len(v.Checks) != 7 || len(v.Profile.RequiredChecks) != 7 || objects.reads != 1 || dsseHTTPCounts(t, p) != [5]int{1, 1, 1, 0, 1} {
		t.Fatal("DSSE profile or effects changed", one, objects.reads)
	}
	var actor, kind, saved, job string
	if err := p.QueryRow(t.Context(), `SELECT a.actor_id,a.entry_type,i.response::text,o.subject_id FROM audit_chain_entries a JOIN idempotency_records i ON i.tenant_id=a.tenant_id AND i.idempotency_key='verify' JOIN outbox_jobs o ON o.payload->>'result_id'=a.subject_id WHERE a.subject_id=$1`, v.ID).Scan(&actor, &kind, &saved, &job); err != nil || actor != "user" || kind != "subject.verified" || job != "attestation" || strings.Contains(saved, "private-") {
		t.Fatal("DSSE receipt/audit/job/replay mismatch", err)
	}
	assertRetentionHTTPReplay(t, one, dsseHTTP(t, store, objects, "attestation", "verify", `{}`, 200))
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := p.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Historical delivery must not inspect current mutable facts, even after
	// restart without an object reader and with metadata beyond view budgets.
	exec(`UPDATE build_attestations SET payload_ref=repeat('private-location',600000)WHERE id='attestation';UPDATE evidence_items SET title=repeat('private-title',900000)WHERE id='evidence';UPDATE build_runs SET outputs=jsonb_build_array(jsonb_build_object('artifact_id',repeat('private-artifact',600000)))WHERE id='build';UPDATE dsse_trust_roots SET name=repeat('private-root',800000),status='legacy_untrusted'WHERE id='root';UPDATE object_payloads SET status='failed'WHERE tenant_id='tenant'`)
	assertRetentionHTTPReplay(t, one, dsseHTTP(t, store, nil, "attestation", "verify", `{}`, 200))
	dsseHTTP(t, store, nil, "attestation", "verify", `{} `, 409)
	dsseHTTP(t, store, objects, "attestation", "oversized", `{}`, 409)
	dsseHTTP(t, store, nil, "missing", "missing", `{}`, 404)
	for _, tc := range []struct {
		table, id string
		status    int
	}{{"build_attestations", "attestation", 404}, {"evidence_items", "evidence", 404}, {"build_runs", "build", 409}, {"projects", "project", 409}, {"releases", "release", 409}, {"products", "product", 409}} {
		exec("UPDATE "+tc.table+" SET tenant_id='other'WHERE id=$1", tc.id)
		dsseHTTP(t, store, nil, "attestation", "verify", `{}`, tc.status)
		dsseHTTP(t, store, nil, "attestation", "foreign-fresh", `{}`, tc.status)
		exec("UPDATE "+tc.table+" SET tenant_id='tenant'WHERE id=$1", tc.id)
	}
	for _, grant := range []struct{ kind, id string }{{"product", "product"}, {"project", "project"}, {"release", "release"}, {"tenant", "tenant"}} {
		exec(`UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, grant.kind, grant.id)
		assertRetentionHTTPReplay(t, one, dsseHTTP(t, store, nil, "attestation", "verify", `{}`, 200))
		exec(`UPDATE role_bindings SET resource_id='unrelated'WHERE id='grant'`)
		dsseHTTP(t, store, nil, "attestation", "verify", `{}`, 403)
		dsseHTTP(t, store, nil, "attestation", "denied-fresh", `{}`, 403)
	}
	exec(`UPDATE role_bindings SET role='viewer',resource_type='tenant',resource_id='tenant'WHERE id='grant'`)
	dsseHTTP(t, store, nil, "attestation", "verify", `{}`, 403)
	exec(`UPDATE role_bindings SET role='tenant_admin'WHERE id='grant';UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`)
	dsseHTTP(t, store, nil, "attestation", "verify", `{}`, 401)
	if objects.reads != 1 || dsseHTTPCounts(t, p) != [5]int{1, 1, 1, 1, 1} {
		t.Fatal("replay/denial inspected payload or changed business effects", dsseHTTPCounts(t, p))
	}
}

func TestPostgresDSSEHTTPFailuresRollbackReceiptAuditJobAndReplay(t *testing.T) {
	for _, stage := range []string{"result", "audit", "outbox", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			objects := seedDSSEVerification(t, p, true)
			table := map[string]string{"result": "verification_results", "audit": "audit_chain_entries", "outbox": "outbox_jobs", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_dsse_http BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_dsse_http()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_dsse_http BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_dsse_http()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_dsse_http AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_dsse_http()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_dsse_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-dsse-write-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			dsseHTTP(t, store, objects, "attestation", "failed", `{}`, 500)
			want := [5]int{}
			if stage != "replay" && stage != "commit" {
				want[3] = 1
			}
			if dsseHTTPCounts(t, p) != want {
				t.Fatal("partial DSSE verification success", dsseHTTPCounts(t, p), want)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_dsse_http ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed"
			if want[3] == 1 {
				before := objects.reads
				dsseHTTP(t, store, objects, "attestation", key, `{}`, 409)
				if objects.reads != before || dsseHTTPCounts(t, p) != want {
					t.Fatal("failed delivery key reran DSSE verification")
				}
				key = "recovered"
			}
			dsseHTTP(t, store, objects, "attestation", key, `{}`, 200)
			want[0], want[1], want[2], want[4] = 1, 1, 1, 1
			if dsseHTTPCounts(t, p) != want || objects.reads != 2 {
				t.Fatal("recovery did not commit one atomic receipt", dsseHTTPCounts(t, p), objects.reads)
			}
		})
	}
}

func TestPostgresDSSEHTTPFailedInspectionAndUnavailableTrustRemainConservative(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects := seedDSSEVerification(t, p, true)
	if _, err := p.Exec(t.Context(), `UPDATE evidence_items SET subject_refs='[]'WHERE id='evidence'`); err != nil {
		t.Fatal(err)
	}
	dsseHTTP(t, store, objects, "attestation", "failed", `{}`, 422)
	if dsseHTTPCounts(t, p) != [5]int{0, 0, 0, 1, 0} {
		t.Fatal("failed HTTP inspection published a successful receipt")
	}
	before := objects.reads
	dsseHTTP(t, store, objects, "attestation", "failed", `{}`, 409)
	if objects.reads != before {
		t.Fatal("failed replay re-inspected bytes")
	}
	if _, err := p.Exec(t.Context(), `UPDATE dsse_trust_roots SET status='legacy_untrusted'WHERE id='root'`); err != nil {
		t.Fatal(err)
	}
	one := dsseHTTP(t, store, objects, "attestation", "unavailable", `{}`, 200)
	var e struct {
		Data domain.VerificationResult `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &e); err != nil || e.Data.Result != "not_verified" || len(e.Data.Checks) != 7 {
		t.Fatal("unavailable trust assigned a passing result", err, one)
	}
	assertRetentionHTTPReplay(t, one, dsseHTTP(t, store, nil, "attestation", "unavailable", `{}`, 200))
	if dsseHTTPCounts(t, p) != [5]int{1, 1, 1, 1, 1} {
		t.Fatal("conservative receipt/replay was not atomic")
	}
}

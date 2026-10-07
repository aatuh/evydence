package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/domain"
)

func bundleImportNativeBody(t *testing.T) string {
	t.Helper()
	b := importTestBundle(t)
	// All supplied identities, signatures, and times are untrusted source labels.
	b.ID, b.ReleaseID = "missing-source-bundle", "missing-source-release"
	b.CreatedAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.FixedZone("source", 3600))
	raw, err := json.Marshal(domain.EvidenceBundle{ID: b.ID, TenantID: b.TenantID, ReleaseID: b.ReleaseID, EvidenceIDs: b.EvidenceIDs, Manifest: b.Manifest, ManifestHash: b.ManifestHash, SignatureRefs: b.SignatureRefs, VerificationText: b.VerificationText, SchemaVersion: b.SchemaVersion, CreatedAt: b.CreatedAt})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func bundleImportNativeHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	o := subjectVerificationOptions(t, store, nil)
	if o.BundleImportCommand == nil {
		t.Fatal("native import composition is missing")
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/evidence-bundles/import", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native import status=%d want=%d canary=%t: %s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("import lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("import lost Problem Details")
	}
	return w.Body.String()
}

func bundleImportNativeCounts(t *testing.T, p *pgxpool.Pool) [5]int {
	t.Helper()
	var n [5]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM evidence_bundle_imports),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed'),(SELECT count(*)FROM evidence_items)+(SELECT count(*)FROM evidence_bundles)+(SELECT count(*)FROM signatures)+(SELECT count(*)FROM outbox_jobs)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresBundleImportNativeReplayAndCurrentAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	body := bundleImportNativeBody(t)
	one := bundleImportNativeHTTP(t, store, "original", body, 201)
	var e struct {
		Data domain.EvidenceBundleImport `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &e); err != nil || e.Data.ID == "" || e.Data.TenantID != "tenant" || e.Data.BundleHash != importTestBundle(t).ManifestHash || e.Data.Result != "accepted" || e.Data.ImportedCount != 1 || e.Data.SchemaVersion != domain.EvidenceBundleImportVersion || e.Data.CreatedAt.IsZero() || e.Data.CreatedAt.Location() != time.UTC || e.Data.CreatedAt.Nanosecond()%1000 != 0 {
		t.Fatal("receipt contract changed", one, err)
	}
	var actor, kind string
	if err := p.QueryRow(t.Context(), `SELECT actor_id,actor_type FROM audit_chain_entries WHERE subject_id=$1`, e.Data.ID).Scan(&actor, &kind); err != nil || actor != "user" || kind != "human_user" {
		t.Fatal("import lost caller attribution", actor, kind, err)
	}
	assertDeploymentCreationReplay(t, one, bundleImportNativeHTTP(t, store, "original", body, 201))
	bundleImportNativeHTTP(t, store, "original", body+" ", 409)
	for _, grant := range []struct{ kind, id string }{{"product", "product"}, {"project", "project"}, {"release", "missing-source-release"}, {"tenant", "other"}} {
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, grant.kind, grant.id); err != nil {
			t.Fatal(err)
		}
		bundleImportNativeHTTP(t, store, "original", body, 403)
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='customer_verifier'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	bundleImportNativeHTTP(t, store, "original", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET role='tenant_admin'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	assertDeploymentCreationReplay(t, one, bundleImportNativeHTTP(t, store, "original", body, 201))
	if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	bundleImportNativeHTTP(t, store, "original", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	bundleImportNativeHTTP(t, store, "original", body, 401)
	if got := bundleImportNativeCounts(t, p); got != [5]int{1, 1, 1, 0, 0} {
		t.Fatal("import replay or denial persisted extra effects", got)
	}
	var response string
	if err := p.QueryRow(t.Context(), `SELECT response::text FROM idempotency_records`).Scan(&response); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(response, "must-not-be-persisted") || strings.Contains(response, "source_evidence") || strings.Contains(response, "untrusted_reference") {
		t.Fatal("private source manifest retained in replay", response)
	}
}

func TestPostgresBundleImportNativeRollbackAndRecovery(t *testing.T) {
	for _, stage := range []string{"receipt", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedSourceRepositoryNative(t, p)
			body := bundleImportNativeBody(t)
			table := map[string]string{"receipt": "evidence_bundle_imports", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_native_import BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_native_import()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_native_import BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_native_import()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_native_import AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_native_import()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_native_import()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-import-write-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			bundleImportNativeHTTP(t, store, "failed", body, 500)
			want := [5]int{}
			if stage == "receipt" || stage == "audit" {
				want[3] = 1
			}
			if got := bundleImportNativeCounts(t, p); got != want {
				t.Fatal("import partially committed", stage, got, want)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_native_import ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed"
			if want[3] == 1 {
				bundleImportNativeHTTP(t, store, key, body, 409)
				key = "recovered"
			}
			one := bundleImportNativeHTTP(t, store, key, body, 201)
			assertDeploymentCreationReplay(t, one, bundleImportNativeHTTP(t, store, key, body, 201))
			want[0], want[1], want[2] = 1, 1, 1
			if got := bundleImportNativeCounts(t, p); got != want {
				t.Fatal("recovery duplicated import effects", stage, got, want)
			}
		})
	}
}

func TestPostgresBundleImportNativeGuardLocksOnlyTargetThroughReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"bundle:write"}}
	b := importTestBundle(t)
	calls, guards := 0, 0
	for range 2 {
		_, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/evidence-bundles/import", "locks", []byte("original"), func(ctx context.Context) error {
			if err := o.BundleImportCommand.AuthorizeBundleImport(ctx, a, b); err != nil {
				return err
			}
			guards++
			for _, tc := range []struct {
				table, id string
				blocked   bool
			}{{"tenants", "tenant", true}, {"tenants", "other", false}, {"products", "product", false}, {"projects", "project", false}, {"sso_sessions", "operator-session", false}} {
				probe, err := p.Begin(ctx)
				if err != nil {
					return err
				}
				_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", tc.id)
				_ = probe.Rollback(context.WithoutCancel(ctx))
				var pe *pgconn.PgError
				if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
					t.Fatal("import locks escaped target identity", tc, err)
				}
			}
			return nil
		}, func(context.Context) (int, any, error) { calls++; return 201, map[string]any{"id": "guard-only"}, nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || guards != 2 || bundleImportNativeCounts(t, p) != [5]int{0, 0, 1, 0, 0} {
		t.Fatal("guard wrote domain effects or bypassed replay", calls, guards)
	}
}

func TestPostgresBundleImportNativeConcurrentReplayWritesOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"bundle:write"}}
	b := importTestBundle(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var calls atomic.Int32
	type result struct {
		status int
		value  any
		err    error
	}
	done, start := make(chan result, 2), make(chan struct{})
	for range 2 {
		go func() {
			<-start
			status, v, err := o.DurableCommandExecutor.WithBody(ctx, a, "POST", "/v1/evidence-bundles/import", "concurrent", []byte("original"), func(ctx context.Context) error { return o.BundleImportCommand.AuthorizeBundleImport(ctx, a, b) }, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := o.BundleImportCommand.ImportEvidenceBundle(ctx, a, b)
				return 201, domain.EvidenceBundleImport{ID: v.ID, TenantID: v.TenantID, BundleHash: v.BundleHash, Result: v.Result, ImportedCount: v.ImportedCount, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}, err
			})
			done <- result{status, v, err}
		}()
	}
	close(start)
	var replies [2]result
	for n := range replies {
		select {
		case replies[n] = <-done:
		case <-ctx.Done():
			t.Fatal("concurrent import leaked transaction", ctx.Err())
		}
	}
	one, two := replies[0], replies[1]
	if one.err != nil || two.err != nil || one.status != 201 || two.status != 201 || calls.Load() != 1 {
		t.Fatal("concurrent import did not execute once", one, two, calls.Load())
	}
	x, err := json.Marshal(one.value)
	if err != nil {
		t.Fatal(err)
	}
	y, err := json.Marshal(two.value)
	if err != nil {
		t.Fatal(err)
	}
	assertDeploymentCreationReplay(t, string(x), string(y))
	if got := bundleImportNativeCounts(t, p); got != [5]int{1, 1, 1, 0, 0} {
		t.Fatal("concurrent import duplicated durable effects", got)
	}
}

func TestPostgresBundleImportCancelledGuardReleasesFenceBeforeTenantLock(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"bundle:write"}}
	leader, err := p.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = leader.Rollback(context.WithoutCancel(t.Context())) }()
	if err := coordination.LockWorkerProjection(t.Context(), leader, "tenant"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	b := importTestBundle(t)
	go func() { done <- o.BundleImportCommand.AuthorizeBundleImport(ctx, a, b) }()
	pid := leader.Conn().PgConn().PID()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var waiting bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting)
		return waiting, err
	}, done)
	if _, err := leader.Exec(t.Context(), `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
		t.Fatal("tenant lock preceded fence", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("lost cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled import leaked transaction")
	}
	if err := leader.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := o.BundleImportCommand.AuthorizeBundleImport(t.Context(), a, importTestBundle(t)); err != nil {
		t.Fatal("cancelled guard leaked fence", err)
	}
	if got := bundleImportNativeCounts(t, p); got != [5]int{} {
		t.Fatal("cancelled guard wrote effects", got)
	}
}

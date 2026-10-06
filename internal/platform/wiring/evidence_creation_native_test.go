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

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

func seedEvidenceCreationNative(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedDeploymentCreationNative(t, p)
	if _, err := p.Exec(t.Context(), `UPDATE artifacts SET digest='sha256:'||repeat('a',64)WHERE id='artifact';
INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,schema_version)VALUES('build','tenant','project','release','generic_ci','0123456789abcdef','passed',now(),'[{"artifact_id":"artifact","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]','v1')`); err != nil {
		t.Fatal(err)
	}
}

func evidenceCreationNativeCounts(t *testing.T, p *pgxpool.Pool) [6]int {
	t.Helper()
	var n [6]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM object_payloads),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresEvidenceCreationNativeRollbackAndRecovery(t *testing.T) {
	for _, stage := range []string{"record", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedEvidenceCreationNative(t, p)
			table := map[string]string{"record": "evidence_items", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_native_evidence BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_native_evidence()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_native_evidence BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_native_evidence()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_native_evidence AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_native_evidence()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_native_evidence()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-evidence-write-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			body := strings.Replace(evidenceCreationNativeBody(), `"payload_ref":"opaque-private-reference",`, "", 1)
			evidenceCreationNativeHTTP(t, store, "failed", body, 500)
			want := [6]int{}
			if stage == "record" || stage == "audit" {
				want[5] = 1
			}
			if got := evidenceCreationNativeCounts(t, p); got != want {
				t.Fatal("evidence partially committed", stage, got, want)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_native_evidence ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed"
			if want[5] == 1 {
				evidenceCreationNativeHTTP(t, store, key, body, 409)
				key = "recovered"
			}
			one := evidenceCreationNativeHTTP(t, store, key, body, 201)
			assertDeploymentCreationReplay(t, one, evidenceCreationNativeHTTP(t, store, key, body, 201))
			want[0], want[1], want[4] = 1, 1, 1
			if got := evidenceCreationNativeCounts(t, p); got != want {
				t.Fatal("evidence recovery duplicated effects", stage, got, want)
			}
		})
	}
}

func evidenceCreationNativeInput(t *testing.T) evidenceapp.CreateEvidenceInput {
	t.Helper()
	d := json.NewDecoder(strings.NewReader(evidenceCreationNativeBody()))
	d.UseNumber()
	var v domain.EvidenceItem
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	x := domain.EvidenceToContextModel(v)
	return evidenceapp.CreateEvidenceInput{BuildID: x.BuildID, DeploymentID: x.DeploymentID, Type: x.Type, Title: x.Title, PayloadHash: x.PayloadHash, PayloadSize: x.PayloadSize, SourceIdentity: x.SourceIdentity, Metadata: x.Metadata, SubjectRefs: x.SubjectRefs, Tags: x.Tags, Limitations: x.Limitations, ObservedAt: x.ObservedAt}
}

func TestPostgresEvidenceCreationNativeConcurrentReplayWritesOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceCreationNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"evidence:write"}}
	in := evidenceCreationNativeInput(t)
	body := strings.Replace(evidenceCreationNativeBody(), `"payload_ref":"opaque-private-reference",`, "", 1)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var calls atomic.Int32
	type reply struct {
		status int
		value  any
		err    error
	}
	done, start := make(chan reply, 2), make(chan struct{})
	for range 2 {
		go func() {
			<-start
			s, v, err := o.DurableCommandExecutor.WithBody(ctx, a, "POST", "/v1/evidence", "concurrent", []byte(body), func(ctx context.Context) error {
				return o.EvidenceCreationCommands.AuthorizeEvidenceCreation(ctx, a, in)
			}, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := o.EvidenceCreationCommands.CreateEvidence(ctx, a, in)
				return 201, domain.EvidenceFromContextModel(v), err
			})
			done <- reply{s, v, err}
		}()
	}
	close(start)
	var replies [2]string
	for n := range replies {
		select {
		case r := <-done:
			if r.err != nil || r.status != 201 {
				t.Fatal(r.status, r.err)
			}
			b, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			replies[n] = string(b)
		case <-ctx.Done():
			t.Fatal("evidence leaked transaction", ctx.Err())
		}
	}
	assertDeploymentCreationReplay(t, replies[0], replies[1])
	if got := evidenceCreationNativeCounts(t, p); calls.Load() != 1 || got != [6]int{1, 1, 0, 0, 1, 0} {
		t.Fatal("concurrent evidence duplicated effects", calls.Load(), got)
	}
}

func TestPostgresEvidenceCreationGuardKeepsOwnershipLocksThroughReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceCreationNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"evidence:write"}}
	in := evidenceCreationNativeInput(t)
	guards, calls := 0, 0
	for range 2 {
		_, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/evidence", "locks", []byte(evidenceCreationNativeBody()), func(ctx context.Context) error {
			if err := o.EvidenceCreationCommands.AuthorizeEvidenceCreation(ctx, a, in); err != nil {
				return err
			}
			guards++
			for _, tc := range []struct {
				table, id string
				blocked   bool
			}{{"tenants", "tenant", true}, {"products", "product", true}, {"projects", "project", true}, {"releases", "release", true}, {"build_runs", "build", true}, {"deployment_events", "rollback", true}, {"deployment_environments", "env", true}, {"artifacts", "artifact", true}, {"products", "other-product", false}, {"projects", "other-project", false}, {"artifacts", "artifact-b", false}, {"deployment_events", "other-rollback", false}, {"sso_sessions", "operator-session", false}} {
				probe, err := p.Begin(ctx)
				if err != nil {
					return err
				}
				_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", tc.id)
				_ = probe.Rollback(context.WithoutCancel(ctx))
				var pe *pgconn.PgError
				if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
					t.Fatal("evidence guard lost lock or reached unrelated row", tc, err)
				}
			}
			return nil
		}, func(context.Context) (int, any, error) { calls++; return 201, map[string]any{"id": "guard-only"}, nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	if guards != 2 || calls != 1 || evidenceCreationNativeCounts(t, p) != [6]int{0, 0, 0, 0, 1, 0} {
		t.Fatal("evidence guard wrote domain effects or skipped replay", guards, calls, evidenceCreationNativeCounts(t, p))
	}
}

func TestPostgresEvidenceCreationCancelledGuardReleasesFenceBeforeOwnershipLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceCreationNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"evidence:write"}}
	in := evidenceCreationNativeInput(t)
	leader, err := p.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = leader.Rollback(context.WithoutCancel(t.Context())) }()
	if err := coordination.LockWorkerProjection(t.Context(), leader, "tenant"); err != nil {
		t.Fatal(err)
	}
	pid := leader.Conn().PgConn().PID()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- o.EvidenceCreationCommands.AuthorizeEvidenceCreation(ctx, a, in) }()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var blocked bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked)
		return blocked, err
	}, done)
	if _, err := leader.Exec(t.Context(), `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
		t.Fatal("evidence ownership lock preceded writer fence", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("guard lost cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("evidence cancellation leaked transaction")
	}
	if err := leader.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := o.EvidenceCreationCommands.AuthorizeEvidenceCreation(t.Context(), a, in); err != nil {
		t.Fatal("cancelled guard leaked fence", err)
	}
	if evidenceCreationNativeCounts(t, p) != [6]int{} {
		t.Fatal("cancelled guard wrote effects", evidenceCreationNativeCounts(t, p))
	}
}
func evidenceCreationNativeHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	o := subjectVerificationOptions(t, store, nil)
	noReload := &decisionHTTPNoReloadStore{}
	l, err := newLegacyLedgerFixtureWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, o)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/evidence", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || want != 201 && (strings.Contains(w.Body.String(), "private-") || strings.Contains(w.Body.String(), `"data"`)) {
		t.Fatalf("native evidence status=%d want=%d loads=%d: %s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("evidence lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("evidence lost Problem Details")
	}
	return w.Body.String()
}
func evidenceCreationNativeBody() string {
	return `{"build_id":"build","deployment_id":"rollback","type":"manual","title":"Evidence","payload_hash":"sha256:` + strings.Repeat("c", 64) + `","payload_ref":"opaque-private-reference","payload_size":7,"source_identity":{"job":"run"},"metadata":{"exact_number":9007199254740993},"subject_refs":[{"type":"artifact","id":"artifact","digest":"sha256:` + strings.Repeat("a", 64) + `"},{"type":"release","id":"release"},{"type":"opaque","id":"unresolved-label"}],"tags":["b","a","b"],"limitations":["record only"],"observed_at":"2026-10-01T12:00:00.123456789+03:00"}`
}

func TestPostgresEvidenceCreationNativeReplayChecksCurrentAuthorityNotMetadata(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceCreationNative(t, p)
	body := evidenceCreationNativeBody()
	one := evidenceCreationNativeHTTP(t, store, "original", body, 201)
	var envelope struct {
		Data domain.EvidenceItem `json:"data"`
	}
	d := json.NewDecoder(strings.NewReader(one))
	d.UseNumber()
	if err := d.Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	v := envelope.Data
	if v.ID == "" || v.PayloadRef != "opaque-private-reference" || v.BuildID != "build" || v.ProductID != "" || v.ObservedAt.Nanosecond() != 123456000 || v.Metadata["exact_number"] != json.Number("9007199254740993") || v.VerificationStatus != "pending" || v.ChainEntryID == "" {
		t.Fatal("evidence public contract or precision changed", one)
	}
	point, err := store.GetEvidencePoint(t.Context(), "tenant", v.ID, func(application.ResourceReferences) error { return nil })
	if err != nil {
		t.Fatal("created evidence not immediately readable", err)
	}
	if got, err := (evidenceCanonicalHasher{}).HashEvidence(t.Context(), point.Item); err != nil || got != v.CanonicalHash {
		t.Fatal("numeric metadata changed durable canonical commitment", got, v.CanonicalHash, err)
	}
	var principal, kind string
	if err := p.QueryRow(t.Context(), `SELECT actor_id,actor_type FROM audit_chain_entries WHERE subject_id=$1`, v.ID).Scan(&principal, &kind); err != nil || principal != "user" || kind != "human_user" {
		t.Fatal("evidence audit attribution changed", principal, kind, err)
	}
	// The existing privacy projection deliberately omits opaque payload refs.
	var fresh map[string]any
	d = json.NewDecoder(strings.NewReader(one))
	d.UseNumber()
	if err := d.Decode(&fresh); err != nil {
		t.Fatal(err)
	}
	delete(fresh["data"].(map[string]any), "payload_ref")
	expected, err := json.Marshal(fresh)
	if err != nil {
		t.Fatal(err)
	}
	replay := evidenceCreationNativeHTTP(t, store, "original", body, 201)
	assertDeploymentCreationReplay(t, string(expected), replay)
	if strings.Contains(replay, "opaque-private-reference") {
		t.Fatal("opaque reference persisted in replay", replay)
	}
	evidenceCreationNativeHTTP(t, store, "original", body+" ", 409)
	if _, err := p.Exec(t.Context(), `UPDATE evidence_items SET title=repeat('private-',1200000),metadata=jsonb_build_object('private',repeat('private-',1200000));UPDATE products SET name=repeat('private-',1200000);UPDATE projects SET name=repeat('private-',1200000);UPDATE releases SET state=repeat('private-',1200000);UPDATE deployment_environments SET kind=repeat('private-',1200000);UPDATE artifacts SET name=repeat('private-',1200000)`); err != nil {
		t.Fatal(err)
	}
	assertDeploymentCreationReplay(t, replay, evidenceCreationNativeHTTP(t, store, "original", body, 201))
	for _, g := range []struct {
		kind, id string
		allowed  bool
	}{{"product", "product", true}, {"project", "project", false}, {"release", "release", true}, {"project", "other-project", false}, {"tenant", "other", false}} {
		// Explicit release subjects require matching parent authority. A
		// build-only project grant must not authorize that release-only subject;
		// the matching release grant retains its existing allowed behavior.
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, g.kind, g.id); err != nil {
			t.Fatal(err)
		}
		want := 403
		if g.allowed {
			want = 201
		}
		evidenceCreationNativeHTTP(t, store, "original", body, want)
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='tenant_admin'WHERE id='grant';UPDATE products SET tenant_id='other'WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	evidenceCreationNativeHTTP(t, store, "original", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE products SET tenant_id='tenant'WHERE id='product';UPDATE artifacts SET tenant_id='other'WHERE id='artifact'`); err != nil {
		t.Fatal(err)
	}
	evidenceCreationNativeHTTP(t, store, "original", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE artifacts SET tenant_id='tenant',digest='sha256:'||repeat('b',64)WHERE id='artifact'`); err != nil {
		t.Fatal(err)
	}
	// Tenant-wide authority checks identity, not the old supplied digest.
	assertDeploymentCreationReplay(t, replay, evidenceCreationNativeHTTP(t, store, "original", body, 201))
	evidenceCreationNativeHTTP(t, store, "digest-drift-fresh", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	evidenceCreationNativeHTTP(t, store, "original", body, 403)
	if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	evidenceCreationNativeHTTP(t, store, "original", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	evidenceCreationNativeHTTP(t, store, "original", body, 401)
	var n [6]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM object_payloads),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]); err != nil || n != [6]int{1, 1, 0, 0, 1, 1} {
		t.Fatal("evidence replay/denial wrote effects", n, err)
	}
}

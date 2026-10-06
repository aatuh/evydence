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
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

var nativeRelationshipRequests = []struct{ name, path, body string }{
	{"supersede", "/v1/evidence/original/supersede", `{"replacement_evidence_id":"replacement","reason":"reviewed"}`},
	{"link", "/v1/evidence/original/link", `{"target_type":"release","target_id":"release"}`},
	{"lifecycle", "/v1/evidence/original/lifecycle-events", `{"action":"amendment","reason":"reviewed","replacement_id":"replacement","details":{"token":"secret","sequence":9007199254740993}}`},
}

func TestEvidenceRelationshipCompositionRequiresTransactions(t *testing.T) {
	if c, err := BuildEvidenceRelationshipCommands(nil); err == nil || c != nil {
		t.Fatal("missing transactions accepted")
	}
}
func relationshipNativeGuard(ctx context.Context, o httpapi.ServerOptions, a domain.Actor, name string) error {
	switch name {
	case "supersede":
		return o.EvidenceRelationshipCommands.AuthorizeSupersedeEvidence(ctx, a, "original", "replacement", "reviewed")
	case "link":
		return o.EvidenceRelationshipCommands.AuthorizeLinkEvidence(ctx, a, "original", "release", "release")
	default:
		return o.EvidenceRelationshipCommands.AuthorizeLifecycleEvent(ctx, a, "original", evidenceapp.RecordLifecycleInput{Action: "amendment", Reason: "reviewed", ReplacementID: "replacement"})
	}
}
func relationshipNativeRun(ctx context.Context, o httpapi.ServerOptions, a domain.Actor, name string) (int, any, error) {
	switch name {
	case "supersede":
		v, err := o.EvidenceRelationshipCommands.SupersedeEvidence(ctx, a, "original", "replacement", "reviewed")
		return 201, domain.EvidenceFromContextModel(v), err
	case "link":
		v, err := o.EvidenceRelationshipCommands.LinkEvidence(ctx, a, "original", "release", "release")
		return 201, domain.EvidenceFromContextModel(v), err
	default:
		v, err := o.EvidenceRelationshipCommands.RecordLifecycleEvent(ctx, a, "original", evidenceapp.RecordLifecycleInput{Action: "amendment", Reason: "reviewed", ReplacementID: "replacement"})
		return 201, domain.EvidenceLifecycleEvent{ID: v.ID, EvidenceID: v.EvidenceID, Action: v.Action.String(), Reason: v.Reason, CreatedAt: v.CreatedAt}, err
	}
}
func TestPostgresEvidenceRelationshipsConcurrentReplayWritesOnce(t *testing.T) {
	for _, tc := range nativeRelationshipRequests {
		t.Run(tc.name, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedEvidenceRelationshipNative(t, p)
			o := subjectVerificationOptions(t, store, nil)
			a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"evidence:write"}}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			var runs atomic.Int32
			type result struct {
				status int
				value  any
				err    error
			}
			done, start := make(chan result, 2), make(chan struct{})
			for range 2 {
				go func() {
					<-start
					status, value, err := o.DurableCommandExecutor.WithBody(ctx, a, "POST", tc.path, "concurrent", []byte(tc.body), func(ctx context.Context) error { return relationshipNativeGuard(ctx, o, a, tc.name) }, func(ctx context.Context) (int, any, error) {
						runs.Add(1)
						return relationshipNativeRun(ctx, o, a, tc.name)
					})
					done <- result{status, value, err}
				}()
			}
			close(start)
			var replies [2]string
			for i := range replies {
				select {
				case r := <-done:
					if r.err != nil || r.status != 201 {
						t.Fatal("concurrent relationship failed", r.status, r.err)
					}
					raw, err := json.Marshal(r.value)
					if err != nil {
						t.Fatal(err)
					}
					replies[i] = string(raw)
				case <-ctx.Done():
					t.Fatal("concurrent relationship leaked transaction", ctx.Err())
				}
			}
			assertDeploymentCreationReplay(t, replies[0], replies[1])
			if runs.Load() != 1 || relationshipNativeCounts(t, p) != [5]int{1, 1, 1, 0, 0} {
				t.Fatal("concurrent delivery duplicated effects", runs.Load(), relationshipNativeCounts(t, p))
			}
		})
	}
}
func TestPostgresEvidenceRelationshipGuardsRetainOnlySelectedLocksThroughReplay(t *testing.T) {
	for _, tc := range nativeRelationshipRequests {
		t.Run(tc.name, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedEvidenceRelationshipNative(t, p)
			o := subjectVerificationOptions(t, store, nil)
			a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"evidence:write"}}
			guards, runs := 0, 0
			for range 2 {
				_, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", tc.path, "locks", []byte(tc.body), func(ctx context.Context) error {
					if err := relationshipNativeGuard(ctx, o, a, tc.name); err != nil {
						return err
					}
					guards++
					for _, probe := range []struct {
						table, id string
						blocked   bool
					}{
						{"tenants", "tenant", true}, {"products", "product", true}, {"projects", "project", true}, {"releases", "release", true}, {"build_runs", "build", true}, {"deployment_events", "rollback", true}, {"deployment_environments", "env", true}, {"evidence_items", "original", true},
						{"evidence_items", "replacement", tc.name != "link"}, {"products", "other-product", tc.name != "link"}, {"projects", "other-project", tc.name != "link"}, {"releases", "other-release", tc.name != "link"},
						{"evidence_items", "foreign-evidence", false}, {"deployment_events", "other-rollback", false}, {"artifacts", "artifact", false}, {"sso_sessions", "operator-session", false},
					} {
						tx, err := p.Begin(ctx)
						if err != nil {
							return err
						}
						_, err = tx.Exec(ctx, "SELECT 1 FROM "+probe.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", probe.id)
						_ = tx.Rollback(context.WithoutCancel(ctx))
						var pe *pgconn.PgError
						if probe.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !probe.blocked && err != nil {
							t.Fatal("lost selected lock or locked unrelated row", probe, err)
						}
					}
					return nil
				}, func(context.Context) (int, any, error) { runs++; return 201, map[string]any{"id": "guard-only"}, nil })
				if err != nil {
					t.Fatal(err)
				}
			}
			if guards != 2 || runs != 1 || relationshipNativeCounts(t, p) != [5]int{0, 0, 1, 0, 0} {
				t.Fatal("guard wrote domain data or skipped replay", guards, runs, relationshipNativeCounts(t, p))
			}
		})
	}
}

func TestPostgresEvidenceRelationshipCancelledGuardReleasesWriterFence(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceRelationshipNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"evidence:write"}}
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
	go func() { done <- relationshipNativeGuard(ctx, o, a, "lifecycle") }()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var blocked bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked)
		return blocked, err
	}, done)
	if _, err := leader.Exec(t.Context(), `SELECT 1 FROM evidence_items WHERE id='original' FOR UPDATE NOWAIT`); err != nil {
		t.Fatal("guard locked evidence before the writer fence", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("guard lost cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled relationship guard leaked a transaction")
	}
	if err := leader.Rollback(context.WithoutCancel(t.Context())); err != nil {
		t.Fatal(err)
	}
	if err := relationshipNativeGuard(t.Context(), o, a, "lifecycle"); err != nil {
		t.Fatal("cancelled guard retained ownership/fence locks", err)
	}
	if got := relationshipNativeCounts(t, p); got != [5]int{} {
		t.Fatal("cancelled/read-only guard wrote effects", got)
	}
}

func seedEvidenceRelationshipNative(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedEvidenceCreationNative(t, p)
	_, err := p.Exec(t.Context(), `INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,build_id,deployment_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,metadata)
VALUES('original','tenant','product','project','release','build','rollback','manual','Evidence','test','2026-10-01T12:00:00Z','evidence.v1',$1,$1,$2,'L1','pending','{"sequence":9007199254740993}'),
('replacement','tenant','other-product','other-project','other-release',NULL,NULL,'manual','Replacement','test','2026-10-01T12:00:00Z','evidence.v1',$1,$1,$2,'L1','pending','{}'),
('foreign-evidence','other','foreign-product','foreign-project','foreign-release',NULL,'foreign-rollback','manual','Foreign','test','2026-10-01T12:00:00Z','evidence.v1',$1,$1,$2,'L1','pending','{}')`, "sha256:"+strings.Repeat("a", 64), evidencedomain.EvidenceCanonicalizationProfileVersion)
	if err != nil {
		t.Fatal(err)
	}
}
func relationshipNativeHTTP(t *testing.T, store *postgres.Store, path, key, body string, want int) string {
	t.Helper()
	opts := subjectVerificationOptions(t, store, nil)
	if opts.EvidenceRelationshipCommands == nil {
		t.Fatal("missing native relationship composition")
	}
	noReload := &decisionHTTPNoReloadStore{}
	l, err := app.NewLedgerWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native relationship status=%d want=%d loads=%d: %s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("missing replay header")
	}
	return w.Body.String()
}
func relationshipNativeCounts(t *testing.T, p *pgxpool.Pool) [5]int {
	t.Helper()
	var n [5]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM evidence_lifecycle_events),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed'),(SELECT count(*)FROM outbox_jobs)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresEvidenceRelationshipsNativeWritesAndCurrentReplayAuthority(t *testing.T) {
	for _, tc := range nativeRelationshipRequests {
		t.Run(tc.name, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedEvidenceRelationshipNative(t, p)
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := p.Exec(t.Context(), sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			var core []byte
			if err := p.QueryRow(t.Context(), `SELECT to_jsonb(e)-ARRAY['product_id','release_id','related_evidence_refs','supersedes','superseded_by'] FROM evidence_items e WHERE id='original'`).Scan(&core); err != nil {
				t.Fatal(err)
			}
			one := relationshipNativeHTTP(t, store, tc.path, "original", tc.body, 201)
			var same bool
			if err := p.QueryRow(t.Context(), `SELECT (to_jsonb(e)-ARRAY['product_id','release_id','related_evidence_refs','supersedes','superseded_by'])=$1::jsonb FROM evidence_items e WHERE id='original'`, core).Scan(&same); err != nil || !same {
				t.Fatal("immutable evidence core changed", err)
			}
			if got := relationshipNativeCounts(t, p); got != [5]int{1, 1, 1, 0, 0} {
				t.Fatal("incorrect native effects", got)
			}
			if tc.name == "lifecycle" && (strings.Contains(one, `"token"`) || !strings.Contains(one, "9007199254740993")) {
				t.Fatal("lifecycle failed redaction or rounded details", one)
			}
			// A completed retry must not reread bounded metadata, rehash an origin,
			// or reject an already-recorded supersession as a new business command.
			exec(`UPDATE evidence_items SET metadata=jsonb_build_object('oversized',repeat('x',9000000))WHERE id IN('original','replacement')`)
			assertDeploymentCreationReplay(t, one, relationshipNativeHTTP(t, store, tc.path, "original", tc.body, 201))
			exec(`UPDATE role_bindings SET resource_type='product',resource_id='other-product'WHERE id='grant'`)
			relationshipNativeHTTP(t, store, tc.path, "original", tc.body, 403)
			exec(`UPDATE role_bindings SET resource_type='tenant',resource_id='tenant'WHERE id='grant';UPDATE evidence_items SET tenant_id='other'WHERE id='original'`)
			relationshipNativeHTTP(t, store, tc.path, "original", tc.body, 404)
			exec(`UPDATE evidence_items SET tenant_id='tenant'WHERE id='original';UPDATE products SET tenant_id='other'WHERE id='product'`)
			// A stored evidence row with broken parent ownership is an integrity
			// conflict, not an invitation to use the foreign parent's grant.
			relationshipNativeHTTP(t, store, tc.path, "original", tc.body, 409)
			exec(`UPDATE products SET tenant_id='tenant'WHERE id='product'`)
			assertDeploymentCreationReplay(t, one, relationshipNativeHTTP(t, store, tc.path, "original", tc.body, 201))
			relationshipNativeHTTP(t, store, strings.Replace(tc.path, "original", "foreign-evidence", 1), "foreign", tc.body, 404)
			exec(`UPDATE role_bindings SET role='viewer'WHERE id='grant'`)
			relationshipNativeHTTP(t, store, tc.path, "original", tc.body, 403)
			exec(`UPDATE role_bindings SET role='tenant_admin'WHERE id='grant';DELETE FROM role_bindings WHERE id='grant'`)
			relationshipNativeHTTP(t, store, tc.path, "original", tc.body, 403)
			exec(`UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`)
			relationshipNativeHTTP(t, store, tc.path, "original", tc.body, 401)
			if got := relationshipNativeCounts(t, p); got != [5]int{1, 1, 1, 0, 0} {
				t.Fatal("denied/replayed relationship wrote effects", got)
			}
		})
	}
}

func TestPostgresEvidenceRelationshipsNativeRollbackAndRecovery(t *testing.T) {
	for _, tc := range nativeRelationshipRequests {
		for _, stage := range []string{"event", "audit", "replay", "commit", "record"} {
			if stage == "record" && tc.name == "lifecycle" {
				continue
			}
			t.Run(tc.name+"/"+stage, func(t *testing.T) {
				store, p := openHTMLReportWiringStore(t)
				seedEvidenceRelationshipNative(t, p)
				table := map[string]string{"event": "evidence_lifecycle_events", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries", "record": "evidence_items"}[stage]
				trigger := "CREATE TRIGGER reject_relationship BEFORE INSERT ON " + table + " FOR EACH ROW EXECUTE FUNCTION reject_relationship()"
				if stage == "record" {
					trigger = "CREATE TRIGGER reject_relationship BEFORE UPDATE ON evidence_items FOR EACH ROW EXECUTE FUNCTION reject_relationship()"
				}
				if stage == "replay" {
					trigger = `CREATE TRIGGER reject_relationship BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_relationship()`
				}
				if stage == "commit" {
					trigger = `CREATE CONSTRAINT TRIGGER reject_relationship AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_relationship()`
				}
				if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_relationship()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-relationship-write-failure';END$$;`+trigger); err != nil {
					t.Fatal(err)
				}
				relationshipNativeHTTP(t, store, tc.path, "failed", tc.body, 500)
				want := [5]int{}
				if stage != "replay" && stage != "commit" {
					want[3] = 1
				}
				if got := relationshipNativeCounts(t, p); got != want {
					t.Fatal("partial relationship commit", stage, got, want)
				}
				var unchanged bool
				if err := p.QueryRow(t.Context(), `SELECT bool_and(supersedes IS NULL AND superseded_by IS NULL AND (related_evidence_refs IS NULL OR related_evidence_refs='[]'::jsonb))FROM evidence_items`).Scan(&unchanged); err != nil || !unchanged {
					t.Fatal("failed command changed evidence relationships", err)
				}
				if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_relationship ON "+table); err != nil {
					t.Fatal(err)
				}
				key := "failed"
				if want[3] != 0 {
					relationshipNativeHTTP(t, store, tc.path, key, tc.body, 409)
					key = "recovered"
				}
				one := relationshipNativeHTTP(t, store, tc.path, key, tc.body, 201)
				assertDeploymentCreationReplay(t, one, relationshipNativeHTTP(t, store, tc.path, key, tc.body, 201))
				want[0], want[1], want[2] = 1, 1, 1
				if got := relationshipNativeCounts(t, p); got != want {
					t.Fatal("recovery duplicated effects", got, want)
				}
			})
		}
	}
}

func TestPostgresEvidenceRelationshipsLegacyOriginsRemainReproducible(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceRelationshipNative(t, p)
	if _, err := p.Exec(t.Context(), `UPDATE evidence_items SET canonicalization=$1 WHERE id IN('original','replacement')`, evidencedomain.LegacyEvidenceCanonicalizationProfileVersion); err != nil {
		t.Fatal(err)
	}
	reads := evidenceRelationshipReads{evidenceCreationReads{store}}
	for _, id := range []string{"original", "replacement"} {
		v, err := reads.GetEvidence(t.Context(), "tenant", id)
		if err != nil {
			t.Fatal(err)
		}
		hash, err := (evidenceCanonicalHasher{}).HashEvidence(t.Context(), v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Exec(t.Context(), `UPDATE evidence_items SET canonical_hash=$2 WHERE id=$1`, id, hash); err != nil {
			t.Fatal(err)
		}
	}
	link := nativeRelationshipRequests[1]
	one := relationshipNativeHTTP(t, store, link.path, "link", link.body, 201)
	assertDeploymentCreationReplay(t, one, relationshipNativeHTTP(t, store, link.path, "link", link.body, 201))
	// Same operation with a different key intentionally appends another link.
	relationshipNativeHTTP(t, store, link.path, "link-again", link.body, 201)
	supersede := nativeRelationshipRequests[0]
	relationshipNativeHTTP(t, store, supersede.path, "supersede", supersede.body, 201)
	if got := relationshipNativeCounts(t, p); got != [5]int{4, 3, 3, 0, 0} {
		t.Fatal("legacy origins not recorded for both subjects", got)
	}
	if err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, repos app.Repositories) error {
		tx := repos.Evidence.(evidenceRelationshipFacts)
		for _, id := range []string{"original", "replacement"} {
			origins, err := tx.ReadRelationshipOrigins(ctx, "tenant", id)
			if err != nil {
				return err
			}
			if len(origins) == 0 || origins[0].Details[evidencedomain.LegacyCanonicalOriginDetailKey] == nil {
				return fmt.Errorf("missing immutable origin for %s", id)
			}
			encoded, err := json.Marshal(origins)
			if err != nil {
				return err
			}
			if strings.Contains(string(encoded), `"token"`) {
				return fmt.Errorf("origin leaked sensitive details")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

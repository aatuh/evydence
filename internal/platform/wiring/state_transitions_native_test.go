package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/domain"
)

type nativeTransitionCase struct {
	kind, path, table, body string
	revision                int64
}

func nativeTransitionCases() []nativeTransitionCase {
	return []nativeTransitionCase{
		{"freeze", "/v1/releases/release/freeze", "releases", `{}`, 1}, {"approve", "/v1/releases/release/approve", "releases", `{}`, 2},
		{"promote", "/v1/release-candidates/candidate/promote", "release_candidates", `{"reason":" Reviewed "}`, 1}, {"reject", "/v1/release-candidates/candidate/reject", "release_candidates", `{"reason":" Reviewed "}`, 1},
	}
}
func (c nativeTransitionCase) candidate() bool { return c.table == "release_candidates" }
func (c nativeTransitionCase) guard(ctx context.Context, o httpapi.ServerOptions, a domain.Actor) error {
	if c.candidate() {
		return o.CandidateStateCommands.AuthorizeCandidateTransition(ctx, a, "candidate")
	}
	return o.ReleaseStateCommands.AuthorizeReleaseTransition(ctx, a, "release")
}

func (c nativeTransitionCase) create(ctx context.Context, o httpapi.ServerOptions, a domain.Actor) (int, any, error) {
	switch c.kind {
	case "freeze":
		v, err := o.ReleaseStateCommands.FreezeRelease(ctx, a, "release", c.revision)
		return 200, domain.ReleaseFromContextModel(v), err
	case "approve":
		v, err := o.ReleaseStateCommands.ApproveRelease(ctx, a, "release", c.revision)
		return 200, domain.ReleaseFromContextModel(v), err
	default:
		target := "promoted"
		if c.kind == "reject" {
			target = "rejected"
		}
		v, err := o.CandidateStateCommands.UpdateReleaseCandidateState(ctx, a, "candidate", target, "Reviewed", c.revision)
		return 200, candidateRecord(v), err
	}
}
func (c nativeTransitionCase) fingerprint(body string, rev int64) []byte {
	v, err := json.Marshal(struct {
		Version  string `json:"version"`
		Revision int64  `json:"revision"`
		Body     []byte `json:"body"`
	}{"conditional-action-v1", rev, []byte(body)})
	if err != nil {
		panic(err)
	}
	return v
}
func seedStateTransitionNative(t *testing.T, p *pgxpool.Pool, c nativeTransitionCase) {
	t.Helper()
	seedSourceRepositoryNative(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO releases(id,tenant_id,product_id,version,state,revision,created_at)VALUES('release','tenant','product','1','draft',1,'2026-10-02T12:00:00Z'),('other-release','tenant','other-product','2','draft',1,'2026-10-02T12:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if c.kind == "approve" {
		if _, err := p.Exec(t.Context(), `UPDATE releases SET state='frozen',revision=2,frozen_at='2026-10-02T13:00:00Z'WHERE id='release'`); err != nil {
			t.Fatal(err)
		}
	}
	if c.candidate() {
		if _, err := p.Exec(t.Context(), `INSERT INTO release_candidates(id,tenant_id,release_id,name,state,snapshot_hash,document,schema_version,revision,created_at)VALUES('candidate','tenant','release','Snapshot','open','sha256:'||repeat('c',64),'{"build_ids":["build","build"],"artifact_ids":["artifact"],"sbom_ids":["sbom"],"scan_ids":["scan"],"vex_ids":["vex"],"contract_ids":["contract"],"bundle_ids":["bundle"]}','release-candidate.v1.0.0',1,'2026-10-02T12:00:00Z')`); err != nil {
			t.Fatal(err)
		}
	}
}
func stateTransitionNativeHTTP(t *testing.T, store *postgres.Store, c nativeTransitionCase, key, body string, rev int64, want int) string {
	t.Helper()
	o := subjectVerificationOptions(t, store, nil)
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", c.path, strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("If-Match", `"`+strconv.FormatInt(rev, 10)+`"`)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private-") || want != 200 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native %s status=%d want=%d canary=%t: %s", c.kind, w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	if want == 200 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("transition lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("transition lost Problem Details")
	}
	return w.Body.String()
}
func stateTransitionNativeCounts(t *testing.T, p *pgxpool.Pool) [6]int {
	t.Helper()
	var n [6]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT revision FROM releases WHERE id='release'),COALESCE((SELECT revision FROM release_candidates WHERE id='candidate'),0),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]); err != nil {
		t.Fatal(err)
	}
	return n
}
func TestPostgresStateTransitionsNativeReplayAndCurrentAuthority(t *testing.T) {
	for _, c := range nativeTransitionCases() {
		t.Run(c.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedStateTransitionNative(t, p, c)
			one := stateTransitionNativeHTTP(t, store, c, "original", c.body, c.revision, 200)
			var e struct {
				Data map[string]json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal([]byte(one), &e); err != nil {
				t.Fatal(err)
			}
			state := map[string]string{"freeze": "frozen", "approve": "approved", "promote": "promoted", "reject": "rejected"}[c.kind]
			if string(e.Data["tenant_id"]) != `"tenant"` || string(e.Data["state"]) != `"`+state+`"` || string(e.Data["revision"]) != strconv.FormatInt(c.revision+1, 10) {
				t.Fatal("transition lifecycle changed", one)
			}
			if c.candidate() && (string(e.Data["name"]) != `"Snapshot"` || string(e.Data["build_ids"]) != `["build","build"]` || string(e.Data["snapshot_hash"]) != `"sha256:`+strings.Repeat("c", 64)+`"`) {
				t.Fatal("transition altered snapshot", one)
			}
			assertRetentionHTTPReplay(t, one, stateTransitionNativeHTTP(t, store, c, "original", c.body, c.revision, 200))
			stateTransitionNativeHTTP(t, store, c, "original", c.body, c.revision+1, 409)
			stateTransitionNativeHTTP(t, store, c, "original", c.body+" ", c.revision, 409)
			o := subjectVerificationOptions(t, store, nil)
			a, err := o.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", c.path, "historical", c.fingerprint(c.body, c.revision), func(ctx context.Context) error { return c.guard(ctx, o, a) }, func(context.Context) (int, any, error) {
				return 200, map[string]any{"id": "historical", "exact_number": json.Number("9007199254740993")}, nil
			}); err != nil {
				t.Fatal(err)
			}
			if !c.candidate() {
				// Keep indexed version text above the fresh-read limit while staying
				// within PostgreSQL's encoded index capacity. Private unindexed fields
				// below remain much larger and must not be loaded during replay.
				if _, err := p.Exec(t.Context(), `UPDATE releases SET state='approved',revision=9007199254740993,version=repeat('v',65537)WHERE id='release'`); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := p.Exec(t.Context(), `UPDATE release_candidates SET state='rejected',revision=9007199254740993,name=repeat('private-',1200000),document=jsonb_build_object('private',repeat('private-',1200000))WHERE id='candidate'`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := p.Exec(t.Context(), `UPDATE products SET name=repeat('private-',1200000),slug=repeat('s',65537)WHERE id='product'`); err != nil {
				t.Fatal(err)
			}
			assertRetentionHTTPReplay(t, one, stateTransitionNativeHTTP(t, store, c, "original", c.body, c.revision, 200))
			if out := stateTransitionNativeHTTP(t, store, c, "historical", c.body, c.revision, 200); !strings.Contains(out, "9007199254740993") {
				t.Fatal("historical revision rounded", out)
			}
			stateTransitionNativeHTTP(t, store, c, "oversized-fresh", c.body, c.revision, 409)
			for _, g := range []struct {
				kind, id string
				allowed  bool
			}{{"product", "product", true}, {"release", "release", true}, {"project", "project", false}, {"product", "other-product", false}, {"release", "other-release", false}, {"tenant", "other", false}} {
				if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, g.kind, g.id); err != nil {
					t.Fatal(err)
				}
				want := 403
				if g.allowed {
					want = 200
				}
				stateTransitionNativeHTTP(t, store, c, "original", c.body, c.revision, want)
			}
			if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='tenant_admin'WHERE id='grant';UPDATE products SET tenant_id='other'WHERE id='product'`); err != nil {
				t.Fatal(err)
			}
			stateTransitionNativeHTTP(t, store, c, "original", c.body, c.revision, 404)
			if _, err := p.Exec(t.Context(), `UPDATE products SET tenant_id='tenant'WHERE id='product';UPDATE releases SET tenant_id='other'WHERE id='release'`); err != nil {
				t.Fatal(err)
			}
			stateTransitionNativeHTTP(t, store, c, "original", c.body, c.revision, 404)
			if _, err := p.Exec(t.Context(), `UPDATE releases SET tenant_id='tenant'WHERE id='release';UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
				t.Fatal(err)
			}
			stateTransitionNativeHTTP(t, store, c, "original", c.body, c.revision, 403)
			if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
				t.Fatal(err)
			}
			stateTransitionNativeHTTP(t, store, c, "original", c.body, c.revision, 403)
			if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
				t.Fatal(err)
			}
			stateTransitionNativeHTTP(t, store, c, "original", c.body, c.revision, 401)
			var n [4]int
			if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil || n != [4]int{1, 0, 2, 1} {
				t.Fatal("replay or denial wrote effects", n, err)
			}
		})
	}
}

func TestPostgresStateTransitionsNativeRollbackAndRecovery(t *testing.T) {
	for _, c := range nativeTransitionCases() {
		t.Run(c.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedStateTransitionNative(t, p, c)
			for _, stage := range []string{"record", "audit", "replay", "commit"} {
				t.Run(stage, func(t *testing.T) {
					baseline := stateTransitionNativeCounts(t, p)
					table := c.table
					if stage != "record" {
						table = map[string]string{"audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
					}
					trigger := fmt.Sprintf("CREATE TRIGGER reject_native_transition BEFORE UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION reject_native_transition()", table)
					if stage == "audit" {
						trigger = `CREATE TRIGGER reject_native_transition BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_native_transition()`
					}
					if stage == "replay" {
						trigger = `CREATE TRIGGER reject_native_transition BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_native_transition()`
					}
					if stage == "commit" {
						trigger = `CREATE CONSTRAINT TRIGGER reject_native_transition AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_native_transition()`
					}
					if _, err := p.Exec(t.Context(), `CREATE OR REPLACE FUNCTION reject_native_transition()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-transition-write-failure';END$$;`+trigger); err != nil {
						t.Fatal(err)
					}
					key := "failed-" + stage
					stateTransitionNativeHTTP(t, store, c, key, c.body, c.revision, 500)
					want := baseline
					if stage == "record" || stage == "audit" {
						want[5]++
					}
					if got := stateTransitionNativeCounts(t, p); got != want {
						t.Fatal("partial transition committed", stage, got, want)
					}
					if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_native_transition ON "+table); err != nil {
						t.Fatal(err)
					}
					if want[5] > baseline[5] {
						stateTransitionNativeHTTP(t, store, c, key, c.body, c.revision, 409)
						key = "recovered-" + stage
					}
					one := stateTransitionNativeHTTP(t, store, c, key, c.body, c.revision, 200)
					assertRetentionHTTPReplay(t, one, stateTransitionNativeHTTP(t, store, c, key, c.body, c.revision, 200))
					if c.candidate() {
						want[1]++
					} else {
						want[0]++
					}
					want[2]++
					want[4]++
					if got := stateTransitionNativeCounts(t, p); got != want {
						t.Fatal("transition recovery duplicated effects", got, want)
					}
					if c.candidate() {
						if _, err := p.Exec(t.Context(), `UPDATE release_candidates SET state='open',revision=1,promoted_at=NULL,rejected_at=NULL WHERE id='candidate'`); err != nil {
							t.Fatal(err)
						}
					} else {
						target := "draft"
						if c.kind == "approve" {
							target = "frozen"
						}
						if _, err := p.Exec(t.Context(), `UPDATE releases SET state=$1,revision=$2,approved_at=NULL WHERE id='release'`, target, c.revision); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		})
	}
}

package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func seedCandidateCreationNative(t *testing.T, p *pgxpool.Pool, store *postgres.Store) {
	t.Helper()
	seedSourceRepositoryNative(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO releases(id,tenant_id,product_id,version,state,revision)VALUES('release','tenant','product','1','draft',1),('other-release','tenant','other-product','2','draft',1)`); err != nil {
		t.Fatal(err)
	}
	if err := app.ExecuteUnitOfWork(t.Context(), store, candidateReferenceFixture); err != nil {
		t.Fatal(err)
	}
}
func candidateCreationNativeInput() releaseapp.CreateReleaseCandidateInput {
	return releaseapp.CreateReleaseCandidateInput{ReleaseID: "release", Name: "Snapshot", BuildIDs: []string{"build", "build"}, ArtifactIDs: []string{"artifact"}, SBOMIDs: []string{"sbom"}, ScanIDs: []string{"scan"}, VEXIDs: []string{"vex"}, ContractIDs: []string{"contract"}, BundleIDs: []string{"bundle"}}
}
func candidateCreationNativeBody() string {
	return `{"release_id":" release ","name":" Snapshot ","build_ids":[" build ","build"],"artifact_ids":[" artifact "],"sbom_ids":["sbom"],"scan_ids":["scan"],"vex_ids":["vex"],"contract_ids":["contract"],"bundle_ids":["bundle"]}`
}
func candidateCreationNativeHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	o := subjectVerificationOptions(t, store, nil)
	noReload := &decisionHTTPNoReloadStore{}
	l, err := app.NewLedgerWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, o)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/release-candidates", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native candidate status=%d want=%d loads=%d: %s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("candidate lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("candidate lost Problem Details")
	}
	return w.Body.String()
}
func candidateCreationNativeCounts(t *testing.T, p *pgxpool.Pool) [5]int {
	t.Helper()
	var n [5]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM release_candidates),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
		t.Fatal(err)
	}
	return n
}
func TestPostgresCandidateCreationNativeGuardLocksSelectedOwnershipThroughReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedCandidateCreationNative(t, p, store)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"release:write"}}
	calls, guards := 0, 0
	for range 2 {
		_, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/release-candidates", "locks", []byte(candidateCreationNativeBody()), func(ctx context.Context) error {
			if err := o.CandidateCommands.AuthorizeCandidateCreation(ctx, a, candidateCreationNativeInput()); err != nil {
				return err
			}
			guards++
			for _, tc := range []struct {
				table, id string
				blocked   bool
			}{{"tenants", "tenant", true}, {"products", "product", true}, {"projects", "project", true}, {"releases", "release", true}, {"build_runs", "build", true}, {"artifacts", "artifact", true}, {"sboms", "sbom", true}, {"vulnerability_scans", "scan", true}, {"vex_documents", "vex", true}, {"openapi_contracts", "contract", true}, {"release_bundles", "bundle", true}, {"evidence_items", "ev-sbom", true}, {"evidence_items", "ev-scan", true}, {"evidence_items", "ev-vex", true}, {"evidence_items", "ev-contract", true}, {"products", "other-product", false}, {"releases", "other-release", false}, {"sso_sessions", "operator-session", false}} {
				probe, err := p.Begin(ctx)
				if err != nil {
					return err
				}
				_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", tc.id)
				_ = probe.Rollback(context.WithoutCancel(ctx))
				var pe *pgconn.PgError
				if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
					t.Errorf("candidate guard lost ownership lock or loaded unrelated row: %+v: %v", tc, err)
				}
			}
			return nil
		}, func(context.Context) (int, any, error) {
			calls++
			return 201, map[string]any{"id": "guard-only", "exact_number": json.Number("9007199254740993")}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || guards != 2 || candidateCreationNativeCounts(t, p) != [5]int{0, 0, 0, 1, 0} {
		t.Fatal("guard/replay wrote snapshot effects", calls, guards, candidateCreationNativeCounts(t, p))
	}
}

func TestPostgresCandidateCreationNativeHTTPReplayAndCurrentAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedCandidateCreationNative(t, p, store)
	body := candidateCreationNativeBody()
	one := candidateCreationNativeHTTP(t, store, "original", body, 201)
	var e struct {
		Data domain.ReleaseCandidate `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &e); err != nil || e.Data.ID == "" || e.Data.TenantID != "tenant" || e.Data.ReleaseID != "release" || e.Data.Name != "Snapshot" || e.Data.State != "open" || e.Data.Revision != 1 || len(e.Data.BuildIDs) != 2 || e.Data.BuildIDs[0] != "build" || e.Data.BuildIDs[1] != "build" {
		t.Fatal("candidate snapshot contract changed", one, err)
	}
	copy := e.Data
	copy.SnapshotHash = ""
	hash, err := application.NormalizedJSONHash(copy)
	if err != nil || hash != e.Data.SnapshotHash {
		t.Fatal("candidate canonical profile changed", hash, e.Data.SnapshotHash, err)
	}
	assertRetentionHTTPReplay(t, one, candidateCreationNativeHTTP(t, store, "original", body, 201))
	candidateCreationNativeHTTP(t, store, "original", body+" ", 409)
	second := candidateCreationNativeHTTP(t, store, "different-key", body, 201)
	var two struct {
		Data domain.ReleaseCandidate `json:"data"`
	}
	if err := json.Unmarshal([]byte(second), &two); err != nil || two.Data.ID == e.Data.ID {
		t.Fatal("candidate name became a natural-key reuse identity", second, err)
	}
	var badAudits int
	if err := p.QueryRow(t.Context(), `SELECT count(*)FROM audit_chain_entries WHERE actor_id!='user'OR actor_type!='human_user'`).Scan(&badAudits); err != nil || badAudits != 0 {
		t.Fatal("candidate lost caller audit", badAudits, err)
	}
	o := subjectVerificationOptions(t, store, nil)
	a, err := o.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/release-candidates", "historical", []byte(body), func(ctx context.Context) error {
		return o.CandidateCommands.AuthorizeCandidateCreation(ctx, a, candidateCreationNativeInput())
	}, func(context.Context) (int, any, error) {
		return 201, map[string]any{"id": "historical", "exact_number": json.Number("9007199254740993")}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE products SET name=repeat('private-',1200000);UPDATE projects SET name=repeat('private-',1200000);UPDATE evidence_items SET title=repeat('private-',1200000);UPDATE artifacts SET name=repeat('private-',1200000);UPDATE release_candidates SET name=repeat('private-',1200000),document=jsonb_set(document,'{name}',to_jsonb(repeat('private-',1200000)))`); err != nil {
		t.Fatal(err)
	}
	assertRetentionHTTPReplay(t, one, candidateCreationNativeHTTP(t, store, "original", body, 201))
	if out := candidateCreationNativeHTTP(t, store, "historical", body, 201); !strings.Contains(out, "9007199254740993") {
		t.Fatal("historical candidate number rounded", out)
	}
	for _, g := range []struct {
		kind, id string
		allowed  bool
	}{{"product", "product", true}, {"release", "release", true}, {"project", "project", false}, {"product", "other-product", false}, {"release", "other-release", false}, {"tenant", "other", false}} {
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, g.kind, g.id); err != nil {
			t.Fatal(err)
		}
		want := 403
		if g.allowed {
			want = 201
		}
		candidateCreationNativeHTTP(t, store, "original", body, want)
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='tenant_admin'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []struct{ table, id string }{{"build_runs", "build"}, {"artifacts", "artifact"}, {"sboms", "sbom"}, {"vulnerability_scans", "scan"}, {"vex_documents", "vex"}, {"openapi_contracts", "contract"}, {"release_bundles", "bundle"}, {"products", "product"}, {"projects", "project"}, {"releases", "release"}, {"evidence_items", "ev-sbom"}, {"evidence_items", "ev-scan"}, {"evidence_items", "ev-vex"}, {"evidence_items", "ev-contract"}} {
		if _, err := p.Exec(t.Context(), "UPDATE "+ref.table+" SET tenant_id='other' WHERE id=$1", ref.id); err != nil {
			t.Fatal(err)
		}
		candidateCreationNativeHTTP(t, store, "original", body, 404)
		if _, err := p.Exec(t.Context(), "UPDATE "+ref.table+" SET tenant_id='tenant' WHERE id=$1", ref.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE evidence_items SET type='invalid'WHERE id='ev-sbom'`); err != nil {
		t.Fatal(err)
	}
	candidateCreationNativeHTTP(t, store, "original", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE evidence_items SET type='sbom'WHERE id='ev-sbom';UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	candidateCreationNativeHTTP(t, store, "original", body, 403)
	if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	candidateCreationNativeHTTP(t, store, "original", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	candidateCreationNativeHTTP(t, store, "original", body, 401)
	if got := candidateCreationNativeCounts(t, p); got != [5]int{2, 2, 0, 3, 0} {
		t.Fatal("replay or denial changed durable effects", got)
	}
}

func TestPostgresCandidateCreationNativeHTTPRollbackAndRecovery(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedCandidateCreationNative(t, p, store)
	for _, stage := range []string{"record", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			baseline := candidateCreationNativeCounts(t, p)
			table := map[string]string{"record": "release_candidates", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_native_candidate BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_native_candidate()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_native_candidate BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_native_candidate()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_native_candidate AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_native_candidate()`
			}
			if _, err := p.Exec(t.Context(), `CREATE OR REPLACE FUNCTION reject_native_candidate()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-candidate-write-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			key := "failed-" + stage
			body := candidateCreationNativeBody()
			candidateCreationNativeHTTP(t, store, key, body, 500)
			want := baseline
			if stage == "record" || stage == "audit" {
				want[4]++
			}
			if got := candidateCreationNativeCounts(t, p); got != want {
				t.Fatal("candidate partially committed", got, want)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_native_candidate ON "+table); err != nil {
				t.Fatal(err)
			}
			if want[4] > baseline[4] {
				candidateCreationNativeHTTP(t, store, key, body, 409)
				key = "recovered-" + stage
			}
			one := candidateCreationNativeHTTP(t, store, key, body, 201)
			assertRetentionHTTPReplay(t, one, candidateCreationNativeHTTP(t, store, key, body, 201))
			want[0]++
			want[1]++
			want[3]++
			if got := candidateCreationNativeCounts(t, p); got != want {
				t.Fatal("candidate recovery duplicated effects", got, want)
			}
		})
	}
}

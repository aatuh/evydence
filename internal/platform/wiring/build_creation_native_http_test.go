package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func seedBuildCreationNative(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedSourceRepositoryNative(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft'),('other-release','tenant','other-product','2','draft'),('foreign-release','other','foreign-product','3','draft');INSERT INTO artifacts(id,tenant_id,name,media_type,size,digest)VALUES('artifact','tenant','Artifact','application/octet-stream',1,'sha256:'||repeat('a',64)),('foreign-artifact','other','Foreign','application/octet-stream',1,'sha256:'||repeat('b',64));INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,source_identity,outputs,schema_version,created_at)VALUES('linked-build','tenant','project','release','generic_ci',repeat('b',40),'passed',now(),'{}',jsonb_build_array(jsonb_build_object('artifact_id','artifact','digest','sha256:'||repeat('a',64))),'build-run.v1.0.0',now())`); err != nil {
		t.Fatal(err)
	}
}

func buildCreationNativeInput() releaseapp.CreateBuildRunInput {
	return releaseapp.CreateBuildRunInput{ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: parseNativeBuildTime(), ProviderMetadata: map[string]any{"oidc_verified": true, "source": "spoofed"}, Outputs: []releasedomain.BuildOutput{{ArtifactID: "artifact", Digest: "sha256:" + strings.Repeat("a", 64)}}}
}
func parseNativeBuildTime() time.Time { return time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC) }
func buildCreationNativeBody() string {
	return `{"project_id":" project ","release_id":" release ","provider":"generic_ci","commit_sha":"` + strings.Repeat("a", 40) + `","status":"passed","started_at":"2026-10-02T12:00:00Z","provider_metadata":{"oidc_verified":true,"source":"spoofed"},"outputs":[{"artifact_id":"artifact","digest":"sha256:` + strings.Repeat("a", 64) + `"}]}`
}

func buildCreationNativeHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	o := subjectVerificationOptions(t, store, nil)
	if o.BuildCommands == nil {
		t.Fatal("missing native build composition")
	}
	noReload := &decisionHTTPNoReloadStore{}
	l, err := newLegacyLedgerFixtureWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, o)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/builds", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native build status=%d want=%d loads=%d: %s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("build lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("build lost problem contract")
	}
	return w.Body.String()
}

func buildCreationNativeCounts(t *testing.T, p *pgxpool.Pool) [5]int {
	t.Helper()
	var n [5]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM build_runs),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresBuildCreationNativeHTTPReplayAndCurrentGrants(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBuildCreationNative(t, p)
	body := buildCreationNativeBody()
	one := buildCreationNativeHTTP(t, store, "original", body, 201)
	var e struct {
		Data domain.BuildRun `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &e); err != nil || e.Data.ID == "" || e.Data.TenantID != "tenant" || e.Data.ProjectID != "project" || e.Data.ReleaseID != "release" || e.Data.Provider != "generic_ci" || e.Data.CommitSHA != strings.Repeat("a", 40) || e.Data.Status != "passed" || e.Data.SchemaVersion != domain.BuildRunSchemaVersion || e.Data.SourceIdentity["oidc_verified"] != false || e.Data.SourceIdentity["source"] != "api" || len(e.Data.Outputs) != 1 || e.Data.Outputs[0].ArtifactID != "artifact" || e.Data.Outputs[0].Digest != "sha256:"+strings.Repeat("a", 64) || e.Data.CreatedAt.IsZero() {
		t.Fatal("build creation contract changed", one, err)
	}
	var actor, kind string
	if err := p.QueryRow(t.Context(), `SELECT actor_id,actor_type FROM audit_chain_entries WHERE subject_id=$1`, e.Data.ID).Scan(&actor, &kind); err != nil || actor != "user" || kind != "human_user" {
		t.Fatal("build lost audit caller", actor, kind, err)
	}
	assertRetentionHTTPReplay(t, one, buildCreationNativeHTTP(t, store, "original", body, 201))
	buildCreationNativeHTTP(t, store, "original", body+" ", 409)
	o := subjectVerificationOptions(t, store, nil)
	a, err := o.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/builds", "historical", []byte(body), func(ctx context.Context) error {
		return o.BuildCommands.AuthorizeBuildCreation(ctx, a, buildCreationNativeInput())
	}, func(context.Context) (int, any, error) {
		return 201, map[string]any{"id": "historical", "exact_number": json.Number("9007199254740993")}, nil
	}); err != nil {
		t.Fatal(err)
	}
	// Keep the indexed version above the fresh-read bound without exceeding
	// PostgreSQL's index tuple limit. Unindexed metadata remains much larger.
	if _, err := p.Exec(t.Context(), `UPDATE releases SET version=repeat('v',65537);UPDATE products SET name=repeat('private-',1200000);UPDATE projects SET name=repeat('private-',1200000);UPDATE artifacts SET name=repeat('private-',1200000),media_type=repeat('private-',1200000);UPDATE build_runs SET repository=repeat('private-',1200000)`); err != nil {
		t.Fatal(err)
	}
	assertRetentionHTTPReplay(t, one, buildCreationNativeHTTP(t, store, "original", body, 201))
	if out := buildCreationNativeHTTP(t, store, "historical", body, 201); !strings.Contains(out, "9007199254740993") {
		t.Fatal("historical build number rounded", out)
	}
	buildCreationNativeHTTP(t, store, "oversized-fresh", body, 409)
	for _, grant := range []struct {
		kind, id string
		allowed  bool
	}{{"product", "product", true}, {"project", "project", true}, {"release", "release", true}, {"product", "other-product", false}, {"project", "other-project", false}, {"release", "other-release", false}, {"tenant", "other", false}} {
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, grant.kind, grant.id); err != nil {
			t.Fatal(err)
		}
		want := 403
		if grant.allowed {
			want = 201
		}
		buildCreationNativeHTTP(t, store, "original", body, want)
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='tenant_admin'WHERE id='grant';UPDATE products SET tenant_id='other'WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	buildCreationNativeHTTP(t, store, "original", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE products SET tenant_id='tenant'WHERE id='product';UPDATE artifacts SET tenant_id='other'WHERE id='artifact'`); err != nil {
		t.Fatal(err)
	}
	buildCreationNativeHTTP(t, store, "original", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE artifacts SET tenant_id='tenant'WHERE id='artifact';UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	buildCreationNativeHTTP(t, store, "original", body, 403)
	if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	buildCreationNativeHTTP(t, store, "original", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	buildCreationNativeHTTP(t, store, "original", body, 401)
	if got := buildCreationNativeCounts(t, p); got != [5]int{2, 1, 0, 2, 1} {
		t.Fatal("build replay or denial changed effects", got)
	}
}

func TestPostgresBuildCreationNativeHTTPRollbackAndRecovery(t *testing.T) {
	for _, stage := range []string{"build", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedBuildCreationNative(t, p)
			baseline := buildCreationNativeCounts(t, p)
			table := map[string]string{"build": "build_runs", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_native_build BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_native_build()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_native_build BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_native_build()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_native_build AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_native_build()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_native_build()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-build-write-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			body := buildCreationNativeBody()
			buildCreationNativeHTTP(t, store, "failed", body, 500)
			want := baseline
			if stage == "build" || stage == "audit" {
				want[4]++
			}
			if got := buildCreationNativeCounts(t, p); got != want {
				t.Fatal("build partially committed", stage, got, want)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_native_build ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed"
			if want[4] > baseline[4] {
				buildCreationNativeHTTP(t, store, key, body, 409)
				key = "recovered"
			}
			one := buildCreationNativeHTTP(t, store, key, body, 201)
			assertRetentionHTTPReplay(t, one, buildCreationNativeHTTP(t, store, key, body, 201))
			want[0]++
			want[1]++
			want[3]++
			if got := buildCreationNativeCounts(t, p); got != want {
				t.Fatal("build recovery duplicated effects", stage, got, want)
			}
		})
	}
}

func TestPostgresBuildCreationNativeFreshChecksDigestsReplayChecksCurrentOwnership(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBuildCreationNative(t, p)
	body := buildCreationNativeBody()
	one := buildCreationNativeHTTP(t, store, "original", body, 201)
	if _, err := p.Exec(t.Context(), `UPDATE artifacts SET digest='sha256:'||repeat('c',64)WHERE id='artifact'`); err != nil {
		t.Fatal(err)
	}
	assertRetentionHTTPReplay(t, one, buildCreationNativeHTTP(t, store, "original", body, 201))
	buildCreationNativeHTTP(t, store, "mismatched-fresh", body, 400)
	if got := buildCreationNativeCounts(t, p); got != [5]int{2, 1, 0, 1, 1} {
		t.Fatal("digest mismatch or replay wrote build/audit effects", got)
	}
	if _, err := p.Exec(t.Context(), `UPDATE artifacts SET digest='sha256:'||repeat('a',64)WHERE id='artifact';DELETE FROM build_runs WHERE id='linked-build';UPDATE role_bindings SET resource_type='project',resource_id='project'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	// The remaining build still provides a current authorized artifact association.
	assertRetentionHTTPReplay(t, one, buildCreationNativeHTTP(t, store, "original", body, 201))
	if _, err := p.Exec(t.Context(), `UPDATE build_runs SET outputs='[]'`); err != nil {
		t.Fatal(err)
	}
	buildCreationNativeHTTP(t, store, "original", body, 403)
	if got := buildCreationNativeCounts(t, p); got != [5]int{1, 1, 0, 1, 1} {
		t.Fatal("removed output association retained replay authority or wrote effects", got)
	}
}

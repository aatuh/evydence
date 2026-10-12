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
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func seedSourceRepositoryNative(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedProviderReceiptHTTP(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Source','source'),('other-product','tenant','Other','other'),('foreign-product','other','Foreign','foreign');INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product','Source'),('other-project','tenant','other-product','Other'),('foreign-project','other','foreign-product','Foreign')`); err != nil {
		t.Fatal(err)
	}
}

func sourceRepositoryNativeHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	opts := subjectVerificationOptions(t, store, nil)
	if opts.SourceRepositoryCommands == nil {
		t.Fatal("missing native source composition")
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/source/repositories", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native source status=%d want=%d canary=%t: %s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("source lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("source lost problem contract")
	}
	return w.Body.String()
}

func sourceRepositoryNativeCounts(t *testing.T, p *pgxpool.Pool) [5]int {
	t.Helper()
	var n [5]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM source_repositories),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresSourceRepositoryNativeHTTPRestartReplayAndCurrentAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	body := `{"project_id":" project ","provider":" github ","full_name":" org/api ","clone_url":" https://example.test/org/api.git ","default_branch":" main "}`
	one := sourceRepositoryNativeHTTP(t, store, "attached", body, 201)
	var e struct {
		Data domain.SourceRepository `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &e); err != nil || e.Data.ID == "" || e.Data.TenantID != "tenant" || e.Data.ProjectID != "project" || e.Data.Provider != "github" || e.Data.FullName != "org/api" || e.Data.CloneURL != "https://example.test/org/api.git" || e.Data.DefaultBranch != "main" || e.Data.SchemaVersion != domain.SourceRepositorySchemaVersion || e.Data.CreatedAt.IsZero() || e.Data.CreatedAt.Nanosecond()%1000 != 0 {
		t.Fatal("source creation changed contract", one, err)
	}
	var principal, kind string
	if err := p.QueryRow(t.Context(), `SELECT actor_id,actor_type FROM audit_chain_entries WHERE subject_id=$1`, e.Data.ID).Scan(&principal, &kind); err != nil || principal != "user" || kind != "human_user" {
		t.Fatal("source lost audit caller", principal, kind, err)
	}
	assertRetentionHTTPReplay(t, one, sourceRepositoryNativeHTTP(t, store, "attached", body, 201))
	sourceRepositoryNativeHTTP(t, store, "attached", body+" ", 409)
	changed := `{"project_id":"other-project","provider":"github","full_name":"org/api","clone_url":"changed","default_branch":"changed"}`
	assertRetentionHTTPReplay(t, one, sourceRepositoryNativeHTTP(t, store, "natural-duplicate", changed, 201))
	detachedBody := `{"provider":"gitlab","full_name":"org/detached"}`
	detached := sourceRepositoryNativeHTTP(t, store, "detached", detachedBody, 201)
	opts := subjectVerificationOptions(t, store, nil)
	a, err := opts.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
	if err != nil {
		t.Fatal(err)
	}
	in := integrationapp.CreateSourceRepositoryInput{ProjectID: "project", Provider: "github", FullName: "org/api"}
	historicalBody := `{"project_id":"project","provider":"github","full_name":"org/api"}`
	if _, _, err := opts.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/source/repositories", "historical", []byte(historicalBody), func(ctx context.Context) error {
		return opts.SourceRepositoryCommands.AuthorizeSourceRepositoryCreation(ctx, a, in)
	}, func(context.Context) (int, any, error) {
		return 201, map[string]any{"id": "historical", "exact_number": json.Number("9007199254740993")}, nil
	}); err != nil {
		t.Fatal(err)
	}
	historical := sourceRepositoryNativeHTTP(t, store, "historical", historicalBody, 201)
	if !strings.Contains(historical, "9007199254740993") {
		t.Fatal("source replay rounded historical number", historical)
	}
	if _, err := p.Exec(t.Context(), `UPDATE source_repositories SET clone_url=repeat('private-',1200000),default_branch=repeat('private-',1200000);UPDATE products SET name=repeat('private-',1200000);UPDATE projects SET name=repeat('private-',1200000)`); err != nil {
		t.Fatal(err)
	}
	assertRetentionHTTPReplay(t, one, sourceRepositoryNativeHTTP(t, store, "attached", body, 201))
	assertRetentionHTTPReplay(t, detached, sourceRepositoryNativeHTTP(t, store, "detached", detachedBody, 201))
	assertRetentionHTTPReplay(t, historical, sourceRepositoryNativeHTTP(t, store, "historical", historicalBody, 201))
	sourceRepositoryNativeHTTP(t, store, "oversized-fresh", body, 409)
	for _, grant := range []struct {
		kind, id string
		allowed  bool
	}{{"product", "product", true}, {"project", "project", true}, {"product", "other-product", false}, {"project", "other-project", false}, {"release", "release", false}, {"tenant", "other", false}} {
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, grant.kind, grant.id); err != nil {
			t.Fatal(err)
		}
		want := 403
		if grant.allowed {
			want = 201
		}
		sourceRepositoryNativeHTTP(t, store, "attached", body, want)
		sourceRepositoryNativeHTTP(t, store, "detached", detachedBody, 403)
		// An allowed submitted project cannot authorize the current existing owner.
		sourceRepositoryNativeHTTP(t, store, "natural-duplicate", changed, 403)
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='tenant_admin'WHERE id='grant';UPDATE products SET tenant_id='other'WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	sourceRepositoryNativeHTTP(t, store, "attached", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE products SET tenant_id='tenant'WHERE id='product';UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	sourceRepositoryNativeHTTP(t, store, "attached", body, 403)
	if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	sourceRepositoryNativeHTTP(t, store, "attached", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	sourceRepositoryNativeHTTP(t, store, "attached", body, 401)
	if got := sourceRepositoryNativeCounts(t, p); got != [5]int{2, 2, 0, 4, 1} {
		t.Fatal("source replay or denial wrote effects", got)
	}
}

func TestPostgresSourceRepositoryNativeHTTPRollbackAndRecovery(t *testing.T) {
	for _, stage := range []string{"repository", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedSourceRepositoryNative(t, p)
			table := map[string]string{"repository": "source_repositories", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_source_native BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_source_native()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_source_native BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_source_native()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_source_native AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_source_native()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_source_native()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-source-write-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			body := `{"project_id":"project","provider":"github","full_name":"org/api"}`
			sourceRepositoryNativeHTTP(t, store, "failed", body, 500)
			want := [5]int{}
			if stage == "repository" || stage == "audit" {
				want[4] = 1
			}
			if got := sourceRepositoryNativeCounts(t, p); got != want {
				t.Fatal("source partially committed", stage, got, want)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_source_native ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed"
			if want[4] == 1 {
				sourceRepositoryNativeHTTP(t, store, key, body, 409)
				key = "recovered"
			}
			one := sourceRepositoryNativeHTTP(t, store, key, body, 201)
			assertRetentionHTTPReplay(t, one, sourceRepositoryNativeHTTP(t, store, key, body, 201))
			want[0], want[1], want[3] = 1, 1, 1
			if got := sourceRepositoryNativeCounts(t, p); got != want {
				t.Fatal("source recovery duplicated effects", stage, got, want)
			}
		})
	}
}

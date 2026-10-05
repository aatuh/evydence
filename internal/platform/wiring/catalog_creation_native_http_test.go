package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

type nativeCatalogCase struct{ kind, path, body, table string }

func nativeCatalogCases() []nativeCatalogCase {
	return []nativeCatalogCase{
		{"product", "/v1/products", `{"name":" New Product ","slug":" new-product "}`, "products"},
		{"project", "/v1/projects", `{"product_id":" product ","name":" New Project "}`, "projects"},
		{"release", "/v1/releases", `{"product_id":" product ","version":" 2 "}`, "releases"},
	}
}
func (c nativeCatalogCase) guard(ctx context.Context, o httpapi.ServerOptions, a domain.Actor) error {
	switch c.kind {
	case "product":
		return o.ProductCommands.AuthorizeProductCreation(ctx, a, releaseapp.CreateProductInput{Name: "New Product", Slug: "new-product"})
	case "project":
		return o.ProjectCommands.AuthorizeProjectCreation(ctx, a, releaseapp.CreateProjectInput{ProductID: "product", Name: "New Project"})
	default:
		return o.ReleaseCreationCommands.AuthorizeReleaseCreation(ctx, a, releaseapp.CreateReleaseInput{ProductID: "product", Version: "2"})
	}
}
func (c nativeCatalogCase) create(ctx context.Context, o httpapi.ServerOptions, a domain.Actor) (int, any, error) {
	switch c.kind {
	case "product":
		v, err := o.ProductCommands.CreateProduct(ctx, a, releaseapp.CreateProductInput{Name: "New Product", Slug: "new-product"})
		return 201, domain.Product(v), err
	case "project":
		v, err := o.ProjectCommands.CreateProject(ctx, a, releaseapp.CreateProjectInput{ProductID: "product", Name: "New Project"})
		return 201, domain.Project(v), err
	default:
		v, err := o.ReleaseCreationCommands.CreateRelease(ctx, a, releaseapp.CreateReleaseInput{ProductID: "product", Version: "2"})
		return 201, domain.ReleaseFromContextModel(v), err
	}
}

func catalogNativeHTTP(t *testing.T, store *postgres.Store, c nativeCatalogCase, key, body string, want int) string {
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
	r := httptest.NewRequest("POST", c.path, strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native %s status=%d want=%d loads=%d: %s", c.kind, w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("catalog lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("catalog lost Problem Details")
	}
	return w.Body.String()
}
func catalogNativeCounts(t *testing.T, p *pgxpool.Pool) [7]int {
	t.Helper()
	var n [7]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM products),(SELECT count(*)FROM projects),(SELECT count(*)FROM releases),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6]); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresCatalogCreationNativeHTTPReplayAndCurrentAuthority(t *testing.T) {
	for _, c := range nativeCatalogCases() {
		t.Run(c.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedSourceRepositoryNative(t, p)
			one := catalogNativeHTTP(t, store, c, "original", c.body, 201)
			var e struct {
				Data map[string]any `json:"data"`
			}
			if err := json.Unmarshal([]byte(one), &e); err != nil || e.Data["id"] == "" || e.Data["tenant_id"] != "tenant" {
				t.Fatal("catalog lost identity", one, err)
			}
			if c.kind == "product" && (e.Data["name"] != "New Product" || e.Data["slug"] != "new-product") || c.kind == "project" && (e.Data["product_id"] != "product" || e.Data["name"] != "New Project") || c.kind == "release" && (e.Data["product_id"] != "product" || e.Data["version"] != "2" || e.Data["state"] != "draft" || e.Data["revision"] != float64(1)) {
				t.Fatal("catalog normalization or lifecycle changed", one)
			}
			var badAudits int
			if err := p.QueryRow(t.Context(), `SELECT count(*)FROM audit_chain_entries WHERE actor_id!='user'OR actor_type!='human_user'`).Scan(&badAudits); err != nil || badAudits != 0 {
				t.Fatal("catalog lost caller", badAudits, err)
			}
			assertRetentionHTTPReplay(t, one, catalogNativeHTTP(t, store, c, "original", c.body, 201))
			catalogNativeHTTP(t, store, c, "original", c.body+" ", 409)
			o := subjectVerificationOptions(t, store, nil)
			a, err := o.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", c.path, "historical", []byte(c.body), func(ctx context.Context) error { return c.guard(ctx, o, a) }, func(context.Context) (int, any, error) {
				return 201, map[string]any{"id": "historical", "exact_number": json.Number("9007199254740993")}, nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Exec(t.Context(), `UPDATE products SET name=repeat('private-',1200000);UPDATE projects SET name=repeat('private-',1200000)`); err != nil {
				t.Fatal(err)
			}
			if c.kind != "product" {
				if _, err := p.Exec(t.Context(), `UPDATE products SET slug=repeat('s',65537)WHERE id='product'`); err != nil {
					t.Fatal(err)
				}
			}
			assertRetentionHTTPReplay(t, one, catalogNativeHTTP(t, store, c, "original", c.body, 201))
			if out := catalogNativeHTTP(t, store, c, "historical", c.body, 201); !strings.Contains(out, "9007199254740993") {
				t.Fatal("catalog historical number rounded", out)
			}
			wantFresh := 409
			catalogNativeHTTP(t, store, c, "fresh", c.body, wantFresh)
			for _, g := range []struct {
				kind, id string
				allowed  bool
			}{{"tenant", "tenant", true}, {"product", "product", c.kind != "product"}, {"product", "other-product", false}, {"project", "project", false}, {"release", "release", false}, {"tenant", "other", false}} {
				if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, g.kind, g.id); err != nil {
					t.Fatal(err)
				}
				want := 403
				if g.allowed {
					want = 201
				}
				catalogNativeHTTP(t, store, c, "original", c.body, want)
			}
			if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant'WHERE id='grant'`); err != nil {
				t.Fatal(err)
			}
			if c.kind != "product" {
				if _, err := p.Exec(t.Context(), `UPDATE products SET tenant_id='other'WHERE id='product'`); err != nil {
					t.Fatal(err)
				}
				catalogNativeHTTP(t, store, c, "original", c.body, 404)
				if _, err := p.Exec(t.Context(), `UPDATE products SET tenant_id='tenant'WHERE id='product'`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
				t.Fatal(err)
			}
			catalogNativeHTTP(t, store, c, "original", c.body, 403)
			if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
				t.Fatal(err)
			}
			catalogNativeHTTP(t, store, c, "original", c.body, 403)
			if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
				t.Fatal(err)
			}
			catalogNativeHTTP(t, store, c, "original", c.body, 401)
			want := [7]int{3, 3, 0, 1, 0, 2, 1}
			switch c.kind {
			case "product":
				want[0]++
			case "project":
				want[1]++
			case "release":
				want[2]++
			}
			if got := catalogNativeCounts(t, p); got != want {
				t.Fatal("catalog replay or denial wrote effects", got, want)
			}
		})
	}
}

func TestPostgresCatalogCreationNativeHTTPRollbackAndRecovery(t *testing.T) {
	for _, c := range nativeCatalogCases() {
		t.Run(c.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedSourceRepositoryNative(t, p)
			for _, stage := range []string{"record", "audit", "replay", "commit"} {
				t.Run(stage, func(t *testing.T) {
					baseline := catalogNativeCounts(t, p)
					table := c.table
					if stage != "record" {
						table = map[string]string{"audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
					}
					trigger := fmt.Sprintf("CREATE TRIGGER reject_native_catalog BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_native_catalog()", table)
					if stage == "replay" {
						trigger = `CREATE TRIGGER reject_native_catalog BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_native_catalog()`
					}
					if stage == "commit" {
						trigger = `CREATE CONSTRAINT TRIGGER reject_native_catalog AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_native_catalog()`
					}
					if _, err := p.Exec(t.Context(), `CREATE OR REPLACE FUNCTION reject_native_catalog()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-catalog-write-failure';END$$;`+trigger); err != nil {
						t.Fatal(err)
					}
					body := strings.ReplaceAll(c.body, "new-product", "new-"+stage)
					if c.kind == "release" {
						body = strings.Replace(c.body, `" 2 "`, `" `+stage+` "`, 1)
					}
					key := "failed-" + stage
					catalogNativeHTTP(t, store, c, key, body, 500)
					want := baseline
					if stage == "record" || stage == "audit" {
						want[6]++
					}
					if got := catalogNativeCounts(t, p); got != want {
						t.Fatal("catalog partially committed", stage, got, want)
					}
					if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_native_catalog ON "+table); err != nil {
						t.Fatal(err)
					}
					if want[6] > baseline[6] {
						catalogNativeHTTP(t, store, c, key, body, 409)
						key = "recovered-" + stage
					}
					one := catalogNativeHTTP(t, store, c, key, body, 201)
					assertRetentionHTTPReplay(t, one, catalogNativeHTTP(t, store, c, key, body, 201))
					switch c.kind {
					case "product":
						want[0]++
					case "project":
						want[1]++
					case "release":
						want[2]++
					}
					want[3]++
					want[5]++
					if got := catalogNativeCounts(t, p); got != want {
						t.Fatal("catalog recovery repeated effects", got, want)
					}
				})
			}
		})
	}
}

package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresReleaseCreationHTTPAndConsumersDoNotRequireLedgerReleases(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Release HTTP'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product');INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000));INSERT INTO deployment_environments(id,tenant_id,product_id,name,kind,schema_version,created_at)VALUES('env','tenant','product','Prod','production','v1',now())`)
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"release:write", "release:read", "build:write", "evidence:write", "deployment:write"}}
	auth := &attestationHTTPActor{actor: actor}
	newServer := func() http.Handler {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.ReleaseCreationCommands == nil || opts.BuildCommands == nil || opts.EvidenceCreationCommands == nil || opts.DeploymentCommands == nil {
			t.Fatal("focused release chain missing", err)
		}
		opts.Authenticator = auth
		ledger, err := app.NewLedgerWithContext(ctx, app.Config{UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.GetProduct(ctx, domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"product:read"}}, "product"); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("HTTP harness has cached parents", err)
		}
		server, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		return server.Handler()
	}
	request := func(h http.Handler, method, path, key string, body []byte, want int) []byte {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want || bytes.Contains(rec.Body.Bytes(), []byte("private release SQL")) {
			t.Fatalf("HTTP %s %s got %d want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		return append([]byte(nil), rec.Body.Bytes()...)
	}
	counts := func() [5]int {
		t.Helper()
		var n [5]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM releases),(SELECT count(*)FROM build_runs),(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM deployment_events),(SELECT count(*)FROM audit_chain_entries)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	body := []byte(`{"product_id":"product","version":" 1.0.0 "}`)
	response := request(newServer(), "POST", "/v1/releases", "create-release", body, 201)
	var envelope struct {
		Data domain.Release `json:"data"`
	}
	if err := json.Unmarshal(response, &envelope); err != nil || envelope.Data.ID == "" || envelope.Data.TenantID != "tenant" || envelope.Data.ProductID != "product" || envelope.Data.Version != "1.0.0" || envelope.Data.State != "draft" || envelope.Data.Revision != 1 || envelope.Data.CreatedAt.IsZero() || envelope.Data.FrozenAt != nil || envelope.Data.ApprovedAt != nil || counts() != [5]int{1, 0, 0, 0, 1} {
		t.Fatal("release response/effects changed", string(response), err, counts())
	}
	release := envelope.Data
	replay := request(newServer(), "POST", "/v1/releases", "create-release", body, 201)
	var originalJSON, replayJSON any
	if err := json.Unmarshal(response, &originalJSON); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(replay, &replayJSON); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(originalJSON, replayJSON) || counts() != [5]int{1, 0, 0, 0, 1} {
		t.Fatal("fresh-instance replay changed result/effects", string(replay), counts())
	}
	read := request(newServer(), "GET", "/v1/releases/"+release.ID, "", nil, 200)
	if err := json.Unmarshal(read, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Data.CreatedAt = envelope.Data.CreatedAt.UTC()
	if !reflect.DeepEqual(envelope.Data, release) {
		t.Fatal("release point read changed metadata", string(read))
	}
	handler := newServer()
	request(handler, "POST", "/v1/releases", "duplicate-version", body, 409)
	request(handler, "POST", "/v1/releases", "create-release", append(body, ' '), 409)
	for i, bad := range []string{
		`{`, `[]`, `null`, `{}`, string(body) + `{}`,
		`{"product_id":"product","version":"a","version":"b"}`,
		`{"product_id":null,"version":"2"}`, `{"product_id":"product","version":null}`,
		`{"product_id":"product","version":123}`, `{"product_id":"product","version":" "}`,
		`{"product_id":"product","version":"2","state":"approved"}`,
		`{"product_id":"product","version":"bad\u0000version"}`,
		`{"product_id":"bad\u0000parent","version":"2"}`,
		`{"product_id":"product","version":"` + strings.Repeat("界", 22000) + `"}`,
		`{"product_id":"` + strings.Repeat("x", 1025) + `","version":"2"}`,
	} {
		request(handler, "POST", "/v1/releases", fmt.Sprintf("invalid-release-%d", i), []byte(bad), 400)
	}
	auth.actor.TenantID = "other"
	request(handler, "POST", "/v1/releases", "foreign-product", body, 404)
	request(handler, "GET", "/v1/releases/"+release.ID, "", nil, 404)
	auth.actor = domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: release.ID, Scopes: []string{"release:write"}}}}
	request(handler, "POST", "/v1/releases", "wrong-level-grant", []byte(`{"product_id":"product","version":"2"}`), 403)
	if counts() != [5]int{1, 0, 0, 0, 1} {
		t.Fatal("invalid/denied release requests wrote effects", counts())
	}
	auth.actor = actor
	build := request(newServer(), "POST", "/v1/builds", "release-build", []byte(`{"project_id":"project","release_id":"`+release.ID+`","provider":"generic_ci","commit_sha":"`+strings.Repeat("b", 40)+`","status":"passed","started_at":"2026-10-02T12:00:00Z"}`), 201)
	evidence := request(newServer(), "POST", "/v1/evidence", "release-evidence", []byte(`{"release_id":"`+release.ID+`","type":"manual","title":"Review","payload_hash":"sha256:`+strings.Repeat("a", 64)+`","payload_size":1}`), 201)
	deployment := request(newServer(), "POST", "/v1/deployments", "release-deployment", []byte(`{"environment_id":"env","release_id":"`+release.ID+`","status":"succeeded","started_at":"2026-10-02T12:00:00Z"}`), 201)
	for _, consumer := range [][]byte{build, evidence, deployment} {
		if !bytes.Contains(consumer, []byte(`"release_id":"`+release.ID+`"`)) {
			t.Fatal("focused consumer lost release", string(consumer))
		}
	}
	if counts() != [5]int{1, 1, 2, 1, 5} {
		t.Fatal("focused consumers wrote incorrect effects", counts())
	}
	auth.actor = domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"release:write"}}}}
	request(newServer(), "POST", "/v1/releases", "granted-release", []byte(`{"product_id":"product","version":"2"}`), 201)
	auth.actor = actor
	fresh := []byte(`{"product_id":"product","version":"3"}`)
	exec(`UPDATE products SET slug=repeat('界',22000)WHERE id='product'`)
	request(handler, "POST", "/v1/releases", "oversized-parent", fresh, 409)
	exec(`UPDATE products SET slug='product'WHERE id='product'`)
	for _, table := range []string{"releases", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_http_release()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private release SQL';END$$`)
		exec(`CREATE TRIGGER reject_http_release BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_http_release()`)
		request(handler, "POST", "/v1/releases", "failed-release-"+table, fresh, 500)
		if counts() != [5]int{2, 1, 2, 1, 6} {
			t.Fatal("failed release/audit insert committed effects", table, counts())
		}
		exec(`DROP TRIGGER reject_http_release ON ` + table)
		request(handler, "POST", "/v1/releases", "failed-release-"+table, fresh, 409)
	}
}

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

func TestPostgresProjectHTTPAndConsumersDoNotRequireLedgerParents(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Project HTTP'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product');INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft')`)
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"project:write", "project:read", "build:write", "evidence:write", "source:write"}}
	auth := &attestationHTTPActor{actor: actor}
	newServer := func() http.Handler {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.ProjectCommands == nil || opts.BuildCommands == nil || opts.EvidenceCreationCommands == nil || opts.SourceRepositoryCommands == nil {
			t.Fatal("focused project chain missing", err)
		}
		opts.Authenticator = auth
		ledger, err := app.NewLedgerWithContext(ctx, app.Config{UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.GetProduct(ctx, domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"product:read"}}, "product"); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("HTTP harness has cached parent", err)
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
		if rec.Code != want || bytes.Contains(rec.Body.Bytes(), []byte("private project SQL")) {
			t.Fatalf("HTTP %s %s got %d want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		return append([]byte(nil), rec.Body.Bytes()...)
	}
	counts := func() [5]int {
		t.Helper()
		var n [5]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM projects),(SELECT count(*)FROM build_runs),(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM source_repositories),(SELECT count(*)FROM audit_chain_entries)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	body := []byte(`{"product_id":"product","name":" Child "}`)
	response := request(newServer(), "POST", "/v1/projects", "create-project", body, 201)
	var envelope struct {
		Data domain.Project `json:"data"`
	}
	if err := json.Unmarshal(response, &envelope); err != nil || envelope.Data.ID == "" || envelope.Data.TenantID != "tenant" || envelope.Data.ProductID != "product" || envelope.Data.Name != "Child" || envelope.Data.CreatedAt.IsZero() || counts() != [5]int{1, 0, 0, 0, 1} {
		t.Fatal("project response/effects changed", string(response), err, counts())
	}
	project := envelope.Data
	replay := request(newServer(), "POST", "/v1/projects", "create-project", body, 201)
	var originalJSON, replayJSON any
	if err := json.Unmarshal(response, &originalJSON); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(replay, &replayJSON); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(originalJSON, replayJSON) || counts() != [5]int{1, 0, 0, 0, 1} {
		t.Fatal("fresh-instance replay repeated project creation", string(replay), counts())
	}
	read := request(newServer(), "GET", "/v1/projects/"+project.ID, "", nil, 200)
	if err := json.Unmarshal(read, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Data.CreatedAt = envelope.Data.CreatedAt.UTC()
	if !reflect.DeepEqual(envelope.Data, project) {
		t.Fatal("project point read changed metadata", string(read))
	}
	handler := newServer()
	request(handler, "POST", "/v1/projects", "create-project", append(body, ' '), 409)
	for i, bad := range []string{
		`{`, `[]`, `null`, `{}`, string(body) + `{}`,
		`{"product_id":"product","name":"a","name":"b"}`,
		`{"product_id":null,"name":"Child"}`, `{"product_id":"product","name":null}`,
		`{"product_id":"product","name":123}`, `{"product_id":"product","name":" "}`,
		`{"product_id":"product","name":"Child","slug":"unsupported"}`,
		`{"product_id":"product","name":"bad\u0000name"}`,
		`{"product_id":"bad\u0000parent","name":"Child"}`,
		`{"product_id":"product","name":"` + strings.Repeat("界", 22000) + `"}`,
		`{"product_id":"` + strings.Repeat("x", 1025) + `","name":"Child"}`,
	} {
		request(handler, "POST", "/v1/projects", fmt.Sprintf("invalid-project-%d", i), []byte(bad), 400)
	}
	auth.actor.TenantID = "other"
	request(handler, "POST", "/v1/projects", "foreign-product", body, 404)
	request(handler, "GET", "/v1/projects/"+project.ID, "", nil, 404)
	auth.actor = domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"project:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: project.ID, Scopes: []string{"project:write"}}}}
	request(handler, "POST", "/v1/projects", "wrong-level-grant", body, 403)
	if counts() != [5]int{1, 0, 0, 0, 1} {
		t.Fatal("invalid/denied project requests wrote effects", counts())
	}
	auth.actor = actor
	build := request(newServer(), "POST", "/v1/builds", "project-build", []byte(`{"project_id":"`+project.ID+`","release_id":"release","provider":"generic_ci","commit_sha":"`+strings.Repeat("b", 40)+`","status":"passed","started_at":"2026-10-02T12:00:00Z"}`), 201)
	evidence := request(newServer(), "POST", "/v1/evidence", "project-evidence", []byte(`{"project_id":"`+project.ID+`","type":"manual","title":"Review","payload_hash":"sha256:`+strings.Repeat("a", 64)+`","payload_size":1}`), 201)
	source := request(newServer(), "POST", "/v1/source/repositories", "project-source", []byte(`{"project_id":"`+project.ID+`","provider":"github","full_name":"org/api","clone_url":"https://example.test/org/api.git","default_branch":"main"}`), 201)
	for _, consumer := range [][]byte{build, evidence, source} {
		if !bytes.Contains(consumer, []byte(`"project_id":"`+project.ID+`"`)) {
			t.Fatal("focused consumer lost project", string(consumer))
		}
	}
	if counts() != [5]int{1, 1, 1, 1, 4} {
		t.Fatal("focused consumers wrote incorrect effects", counts())
	}
	auth.actor = domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"project:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"project:write"}}}}
	request(newServer(), "POST", "/v1/projects", "granted-project", body, 201)
	auth.actor = actor
	exec(`UPDATE products SET slug=repeat('界',22000)WHERE id='product'`)
	request(handler, "POST", "/v1/projects", "oversized-parent", body, 409)
	exec(`UPDATE products SET slug='product'WHERE id='product'`)
	for _, table := range []string{"projects", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_http_project()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private project SQL';END$$`)
		exec(`CREATE TRIGGER reject_http_project BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_http_project()`)
		request(handler, "POST", "/v1/projects", "failed-project-"+table, body, 500)
		if counts() != [5]int{2, 1, 1, 1, 5} {
			t.Fatal("failed project/audit insert committed effects", table, counts())
		}
		exec(`DROP TRIGGER reject_http_project ON ` + table)
		request(handler, "POST", "/v1/projects", "failed-project-"+table, body, 409)
	}
}

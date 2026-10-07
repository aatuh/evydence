package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresProductHTTPAndConsumersDoNotRequireLedgerProducts(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Product HTTP'),('other','Other')`)
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"product:read", "product:write", "project:write", "release:write", "deployment:write"}}
	auth := &attestationHTTPActor{actor: actor}
	var servers []*httpapi.Server
	newServer := func() http.Handler {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.ProductCommands == nil || opts.ProjectCommands == nil || opts.ReleaseCreationCommands == nil || opts.DeploymentEnvironmentCommands == nil {
			t.Fatal("focused product chain not composed", err)
		}
		opts.Authenticator = auth
		_ = newAggregateLoadCanary(t, ctx, store)
		server, err := newNativeHTTPFixture(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		servers = append(servers, server)
		return server.Handler()
	}
	request := func(method, path, key string, body []byte, want int) []byte {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		rec := httptest.NewRecorder()
		newServer().ServeHTTP(rec, req)
		if rec.Code != want || strings.Contains(rec.Body.String(), "private product SQL") {
			t.Fatalf("HTTP %s %s got %d want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		return append([]byte(nil), rec.Body.Bytes()...)
	}
	decode := func(body []byte) domain.Product {
		t.Helper()
		var v struct {
			Data domain.Product `json:"data"`
		}
		if err := json.Unmarshal(body, &v); err != nil {
			t.Fatal(err)
		}
		v.Data.CreatedAt = v.Data.CreatedAt.UTC()
		return v.Data
	}
	counts := func() [5]int {
		t.Helper()
		var n [5]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM products),(SELECT count(*)FROM projects),(SELECT count(*)FROM releases),(SELECT count(*)FROM deployment_environments),(SELECT count(*)FROM audit_chain_entries)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	assertCounts := func(want [5]int) {
		t.Helper()
		if got := counts(); got != want {
			t.Fatal("product/consumer effects changed", got, want)
		}
	}
	body := []byte(`{"name":" Product ","slug":" product "}`)
	response := request("POST", "/v1/products", "create-product", body, 201)
	product := decode(response)
	if product.ID == "" || product.TenantID != "tenant" || product.Name != "Product" || product.Slug != "product" || product.CreatedAt.IsZero() || product.CreatedAt.Nanosecond()%1000 != 0 {
		t.Fatal("product response fields/time changed", string(response))
	}
	assertCounts([5]int{1, 0, 0, 0, 1})
	var originalJSON, replayJSON any
	if err := json.Unmarshal(response, &originalJSON); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(request("POST", "/v1/products", "create-product", body, 201), &replayJSON); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(originalJSON, replayJSON) {
		t.Fatal("fresh-server replay changed product", originalJSON, replayJSON)
	}
	if p := decode(request("GET", "/v1/products/"+product.ID, "", nil, 200)); !reflect.DeepEqual(p, product) {
		t.Fatal("point read changed product metadata", p, product)
	}
	var list struct {
		Data []domain.Product `json:"data"`
	}
	if err := json.Unmarshal(request("GET", "/v1/products", "", nil, 200), &list); err != nil || len(list.Data) != 1 {
		t.Fatal("durable product list changed", list, err)
	}
	list.Data[0].CreatedAt = list.Data[0].CreatedAt.UTC()
	if !reflect.DeepEqual(list.Data[0], product) {
		t.Fatal("list fields differ from creation", list.Data[0], product)
	}
	request("POST", "/v1/products", "create-product", append(body, ' '), 409)
	request("POST", "/v1/products", "duplicate-product", body, 409)
	for i, bad := range []string{`{`, `{} {}`, `[]`, `null`, `{}`, `{"name":null,"slug":"new"}`, `{"name":"Product","slug":null}`, `{"name":1,"slug":"new"}`, `{"name":"Product","name":"Other","slug":"new"}`, `{"name":"Product","slug":"new","tenant_id":"other"}`, `{"name":" ","slug":"new"}`, `{"name":"Product","slug":" "}`, `{"name":"bad\u0000name","slug":"new"}`, `{"name":"Product","slug":"bad\u0000slug"}`, `{"name":"Product","slug":"` + strings.Repeat("x", 1025) + `"}`} {
		request("POST", "/v1/products", fmt.Sprintf("invalid-product-%d", i), []byte(bad), 400)
	}
	request("POST", "/v1/products", "oversized-body", []byte(strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1)), 400)
	assertCounts([5]int{1, 0, 0, 0, 1})
	auth.actor = actor
	auth.actor.TenantID = "other"
	request("GET", "/v1/products/"+product.ID, "", nil, 404)
	if foreign := decode(request("POST", "/v1/products", "other-product", body, 201)); foreign.TenantID != "other" || foreign.ID == product.ID {
		t.Fatal("product tenant ownership crossed", foreign)
	}
	auth.actor = actor
	if err := json.Unmarshal(request("GET", "/v1/products", "", nil, 200), &list); err != nil || len(list.Data) != 1 || list.Data[0].ID != product.ID || list.Data[0].TenantID != actor.TenantID {
		t.Fatal("product list exposed another tenant", list, err)
	}
	auth.actor = actor
	auth.actor.KeyID = ""
	auth.actor.UserID = "human"
	auth.actor.ResourceGrants = nil
	request("POST", "/v1/products", "removed-product-grant", []byte(`{"name":"Denied","slug":"new"}`), 403)
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: product.ID, Scopes: []string{"product:write"}}}
	request("POST", "/v1/products", "wrong-product-grant", []byte(`{"name":"Denied","slug":"new"}`), 403)
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "other", Scopes: []string{"product:write"}}}
	request("POST", "/v1/products", "wrong-tenant-grant", []byte(`{"name":"Denied","slug":"new"}`), 403)
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"product:write"}}}
	humanProduct := decode(request("POST", "/v1/products", "human-product", []byte(`{"name":"Human","slug":"human"}`), 201))
	if humanProduct.TenantID != "tenant" || humanProduct.ID == "" {
		t.Fatal("tenant grant not honored", humanProduct)
	}
	auth.actor = actor
	request("POST", "/v1/projects", "product-project", []byte(`{"product_id":"`+product.ID+`","name":"Project"}`), 201)
	request("POST", "/v1/releases", "product-release", []byte(`{"product_id":"`+product.ID+`","version":"1.0.0"}`), 201)
	request("POST", "/v1/environments", "product-environment", []byte(`{"product_id":"`+product.ID+`","name":"Production","kind":"production"}`), 201)
	assertCounts([5]int{3, 1, 1, 1, 6})
	for _, server := range servers {
		assertNativeHTTPHasNoAggregate(t, server)
	}
	for _, table := range []string{"products", "audit_chain_entries"} {
		exec(`CREATE FUNCTION reject_product()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private product SQL';END$$;CREATE TRIGGER reject_product BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_product()`)
		request("POST", "/v1/products", "fail-"+table, []byte(`{"name":"Failure","slug":"failure"}`), 500)
		exec(`DROP TRIGGER reject_product ON ` + table + `;DROP FUNCTION reject_product()`)
		request("POST", "/v1/products", "fail-"+table, []byte(`{"name":"Failure","slug":"failure"}`), 409)
		assertCounts([5]int{3, 1, 1, 1, 6})
	}
}

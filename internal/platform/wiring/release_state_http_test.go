package wiring

import (
	"context"
	"encoding/json"
	"errors"
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

func TestPostgresReleaseStateHTTPDoesNotRequireLedgerState(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Release state HTTP'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product');INSERT INTO releases(id,tenant_id,product_id,version,state,revision)VALUES('release','tenant','product','1.0.0','draft',1),('failure','tenant','product','2.0.0','draft',1)`)
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:read", "release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"release:read", "release:write"}}, {ResourceType: "release", ResourceID: "failure", Scopes: []string{"release:read", "release:write"}}}}
	auth := &attestationHTTPActor{actor: actor}
	newServer := func() http.Handler {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.ReleaseStateCommands == nil {
			t.Fatal("release transitions not composed", err)
		}
		opts.Authenticator = auth
		ledger, err := newLegacyLedgerFixtureWithContext(ctx, app.Config{UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.GetRelease(ctx, domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"release:read"}}, "release"); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("HTTP harness has cached releases", err)
		}
		server, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		return server.Handler()
	}
	request := func(method, path, key, tag string, want int) string {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		if tag != "" {
			req.Header.Set("If-Match", tag)
		}
		rec := httptest.NewRecorder()
		newServer().ServeHTTP(rec, req)
		if rec.Code != want || strings.Contains(rec.Body.String(), "private transition SQL") {
			t.Fatalf("HTTP %s %s got %d want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		return rec.Body.String()
	}
	decode := func(body string) domain.Release {
		t.Helper()
		var v struct {
			Data domain.Release `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatal(err)
		}
		v.Data.CreatedAt = v.Data.CreatedAt.UTC()
		if v.Data.FrozenAt != nil {
			at := v.Data.FrozenAt.UTC()
			v.Data.FrozenAt = &at
		}
		if v.Data.ApprovedAt != nil {
			at := v.Data.ApprovedAt.UTC()
			v.Data.ApprovedAt = &at
		}
		return v.Data
	}
	counts := func(wantRevision int64, wantAudits int) {
		t.Helper()
		var rev int64
		var n int
		if err := pool.QueryRow(ctx, `SELECT revision,(SELECT count(*)FROM audit_chain_entries)FROM releases WHERE id='release'`).Scan(&rev, &n); err != nil || rev != wantRevision || n != wantAudits {
			t.Fatal("release state/audit effects changed", rev, n, err)
		}
	}
	initial := decode(request("GET", "/v1/releases/release", "", "", 200))
	counts(1, 0)
	for i, tag := range []string{"", `W/"1"`, `"01"`, `"+1"`, `"0"`, `"-1"`, `"1", "2"`, `"9223372036854775808"`} {
		request("POST", "/v1/releases/release/freeze", fmt.Sprintf("bad-tag-%d", i), tag, 400)
	}
	if body := request("POST", "/v1/releases/release/approve", "wrong-state", `"1"`, 409); strings.Contains(body, `"current_revision"`) {
		t.Fatal("ordinary state conflict exposed revision", body)
	}
	frozen := decode(request("POST", "/v1/releases/release/freeze", "freeze", `"1"`, 200))
	if frozen.ID != initial.ID || frozen.TenantID != initial.TenantID || frozen.ProductID != initial.ProductID || frozen.Version != initial.Version || !frozen.CreatedAt.Equal(initial.CreatedAt) || frozen.Revision != 2 || frozen.State != "frozen" || frozen.FrozenAt == nil || frozen.ApprovedAt != nil {
		t.Fatal("frozen DTO/lifecycle changed", frozen)
	}
	counts(2, 1)
	if replay := decode(request("POST", "/v1/releases/release/freeze", "freeze", `"1"`, 200)); !reflect.DeepEqual(replay, frozen) {
		t.Fatal("fresh-server freeze replay changed", replay, frozen)
	}
	request("POST", "/v1/releases/release/freeze", "freeze", `"2"`, 409)
	request("POST", "/v1/releases/release/freeze", "freeze", "", 400)
	if read := decode(request("GET", "/v1/releases/release", "", "", 200)); !reflect.DeepEqual(read, frozen) {
		t.Fatal("fresh-server frozen point read changed", read, frozen)
	}
	stale := request("POST", "/v1/releases/release/approve", "stale-approve", `"1"`, 409)
	if !strings.Contains(stale, `"code":"VERSION_CONFLICT"`) || !strings.Contains(stale, `"current_revision":2`) {
		t.Fatal("stale revision metadata lost", stale)
	}
	auth.actor = actor
	auth.actor.TenantID = "other"
	if body := request("POST", "/v1/releases/release/approve", "foreign", `"1"`, 404); strings.Contains(body, `"current_revision"`) {
		t.Fatal("foreign tenant saw revision", body)
	}
	auth.actor = actor
	auth.actor.ResourceGrants = nil
	if body := request("POST", "/v1/releases/release/approve", "removed-grant", `"1"`, 403); strings.Contains(body, `"current_revision"`) {
		t.Fatal("ungranted actor saw revision", body)
	}
	auth.actor = actor
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "product", Scopes: []string{"release:write"}}}
	request("POST", "/v1/releases/release/approve", "wrong-level", `"2"`, 403)
	auth.actor = actor
	approved := decode(request("POST", "/v1/releases/release/approve", "approve", `"2"`, 200))
	if approved.ID != frozen.ID || approved.TenantID != frozen.TenantID || approved.ProductID != frozen.ProductID || approved.Version != frozen.Version || !approved.CreatedAt.Equal(frozen.CreatedAt) || approved.Revision != 3 || approved.State != "approved" || approved.FrozenAt == nil || !approved.FrozenAt.Equal(*frozen.FrozenAt) || approved.ApprovedAt == nil {
		t.Fatal("approved DTO/lifecycle changed", approved)
	}
	if replay := decode(request("POST", "/v1/releases/release/approve", "approve", `"2"`, 200)); !reflect.DeepEqual(replay, approved) {
		t.Fatal("approval replay changed", replay)
	}
	if read := decode(request("GET", "/v1/releases/release", "", "", 200)); !reflect.DeepEqual(read, approved) {
		t.Fatal("approved point read changed", read)
	}
	counts(3, 2)
	for _, table := range []string{"releases", "audit_chain_entries"} {
		event := "INSERT"
		if table == "releases" {
			event = "UPDATE"
		}
		exec(`CREATE FUNCTION reject_transition()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private transition SQL';END$$;CREATE TRIGGER reject_transition BEFORE ` + event + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_transition()`)
		request("POST", "/v1/releases/failure/freeze", "fail-"+table, `"1"`, 500)
		exec(`DROP TRIGGER reject_transition ON ` + table + `;DROP FUNCTION reject_transition()`)
		if read := decode(request("GET", "/v1/releases/failure", "", "", 200)); read.Revision != 1 || read.State != "draft" || read.FrozenAt != nil {
			t.Fatal("failed transition escaped rollback", read)
		}
		request("POST", "/v1/releases/failure/freeze", "fail-"+table, `"1"`, 409)
		counts(3, 2)
	}
}

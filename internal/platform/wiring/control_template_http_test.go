package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestPostgresControlTemplateHTTPUsesFocusedInstallationAndFreshReads(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Templates'),('other','Other')`)
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"controls:admin", "controls:read", "report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"controls:admin", "controls:read", "report:read"}}}}
	auth := &attestationHTTPActor{actor: actor}
	var servers []*httpapi.Server
	request := func(method, path, key, body string, want int) string {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		opts.Authenticator = auth
		noReload := newAggregateLoadCanary(t, ctx, store)
		server, err := newNativeHTTPFixture(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		servers = append(servers, server)
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != want || !noReload.Intact(ctx) || strings.Contains(rec.Body.String(), "private template SQL") {
			t.Fatalf("%s %s got %d want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		return rec.Body.String()
	}
	decode := func(body string) domain.ControlFramework {
		t.Helper()
		var v struct {
			Data domain.ControlFramework `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatal(err)
		}
		v.Data.CreatedAt = v.Data.CreatedAt.UTC()
		return v.Data
	}
	counts := func(wf, wc, wa int) {
		t.Helper()
		var f, c, a int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM control_frameworks),(SELECT count(*)FROM security_controls),(SELECT count(*)FROM audit_chain_entries)`).Scan(&f, &c, &a); err != nil || f != wf || c != wc || a != wa {
			t.Fatal("template HTTP effects changed", f, c, a, err)
		}
	}
	pack := riskdomain.BuiltinTemplatePacks()[0]
	path := "/v1/control-framework-template-packs/" + pack.Slug + "/install"
	fw := decode(request("POST", path, "install", "", 201))
	if fw.ID == "" || fw.TenantID != actor.TenantID || fw.Name != pack.Name || fw.Slug != pack.Slug || fw.Version != pack.Version || fw.Description != pack.Description || fw.Status != "active" || fw.SchemaVersion != domain.ControlFrameworkSchemaVersion || fw.CreatedAt.IsZero() || fw.CreatedAt.Nanosecond()%1000 != 0 {
		t.Fatal("installed framework fields changed", fw)
	}
	var actorType, actorID string
	if err := pool.QueryRow(ctx, `SELECT actor_type,actor_id FROM audit_chain_entries WHERE subject_id=$1`, fw.ID).Scan(&actorType, &actorID); err != nil || actorType != "human_user" || actorID != "human" {
		t.Fatal("human installer audit lost its principal", actorType, actorID, err)
	}
	counts(1, len(pack.Controls), 1)
	if got := decode(request("POST", path, "install", "", 201)); !reflect.DeepEqual(got, fw) {
		t.Fatal("fresh install replay differs", got, fw)
	}
	request("POST", path, "install", " ", 409)
	request("POST", path, "duplicate-install", "", 409)
	var page struct {
		Data []domain.ControlFramework `json:"data"`
	}
	if err := json.Unmarshal([]byte(request("GET", "/v1/control-frameworks", "", "", 200)), &page); err != nil || len(page.Data) != 1 {
		t.Fatal("installed framework missing from durable page", page, err)
	}
	page.Data[0].CreatedAt = page.Data[0].CreatedAt.UTC()
	if !reflect.DeepEqual(page.Data[0], fw) {
		t.Fatal("installed framework page loses fields", page.Data[0], fw)
	}
	for _, template := range pack.Controls {
		var id string
		if err := pool.QueryRow(ctx, `SELECT id FROM security_controls WHERE tenant_id=$1 AND framework_id=$2 AND code=$3`, actor.TenantID, fw.ID, template.Code).Scan(&id); err != nil {
			t.Fatal(err)
		}
		var child struct {
			Data domain.SecurityControl `json:"data"`
		}
		if err := json.Unmarshal([]byte(request("GET", "/v1/controls/"+id, "", "", 200)), &child); err != nil || child.Data.FrameworkID != fw.ID || child.Data.Code != template.Code || child.Data.Title != template.Title || child.Data.Objective != template.Objective || child.Data.SchemaVersion != domain.SecurityControlSchemaVersion || len(child.Data.EvidenceRequirements) != len(template.EvidenceRequirements) {
			t.Fatal("installed control missing from durable point", child, err)
		}
		for _, server := range servers {
			assertNativeHTTPHasNoAggregate(t, server)
		}
	}
	var report struct {
		Data domain.ControlCoverageReport `json:"data"`
	}
	if err := json.Unmarshal([]byte(request("GET", "/v1/reports/control-coverage?framework_id="+fw.ID, "", "", 200)), &report); err != nil || report.Data.FrameworkID != fw.ID || len(report.Data.Controls) != len(pack.Controls) || report.Data.Result != "failed" {
		t.Fatal("template not visible to downstream report", report, err)
	}
	for _, server := range servers {
		assertNativeHTTPHasNoAggregate(t, server)
	}
	request("POST", "/v1/control-framework-template-packs/unknown/install", "unknown", "", 404)
	request("POST", "/v1/control-framework-template-packs/%20/install", "blank", "", 404)
	request("POST", "/v1/control-framework-template-packs/bad%00slug/install", "nul", "", 400)
	request("POST", "/v1/control-framework-template-packs/%FF/install", "invalid-utf8", "", 400)
	request("POST", "/v1/control-framework-template-packs/"+strings.Repeat("x", 1025)+"/install", "long-slug", "", 400)
	request("POST", path, "oversized-body", strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1), 400)
	secondPack := riskdomain.BuiltinTemplatePacks()[1]
	secondPath := "/v1/control-framework-template-packs/" + secondPack.Slug + "/install"
	auth.actor = actor
	auth.actor.ResourceGrants = nil
	request("POST", secondPath, "removed-template-grant", "", 403)
	auth.actor = actor
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "unrelated", Scopes: actor.Scopes}}
	request("POST", secondPath, "restricted-template-grant", "", 403)
	auth.actor = actor
	for _, table := range []string{"control_frameworks", "security_controls", "audit_chain_entries"} {
		exec(`CREATE FUNCTION reject_template_http_insert() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private template SQL';END$$`)
		exec(`CREATE TRIGGER reject_template_http_insert BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_template_http_insert()`)
		request("POST", secondPath, "failure-"+table, "", 500)
		request("POST", secondPath, "failure-"+table, "", 409)
		counts(1, len(pack.Controls), 1)
		exec(`DROP TRIGGER reject_template_http_insert ON ` + table)
		exec(`DROP FUNCTION reject_template_http_insert()`)
	}
	for i, bad := range []string{"{not-json", "[]", "null", `{"tenant_id":"other"}`, "{} {}"} {
		request("POST", secondPath, fmt.Sprintf("bad-install-body-%d", i), bad, 400)
	}
	secondFW := decode(request("POST", secondPath, "empty-object", "{}", 201))
	if got := decode(request("POST", secondPath, "empty-object", "{}", 201)); !reflect.DeepEqual(got, secondFW) {
		t.Fatal("empty-object replay changed", got, secondFW)
	}
	request("POST", secondPath, "empty-object", " {} ", 409)
	auth.actor = actor
	auth.actor.TenantID = "other"
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "other", Scopes: actor.Scopes}}
	other := decode(request("POST", path, "other-install", "", 201))
	if other.TenantID != "other" || other.ID == fw.ID {
		t.Fatal("cross-tenant template identity reused", other, fw)
	}
	var otherPage struct {
		Data []domain.ControlFramework `json:"data"`
	}
	if err := json.Unmarshal([]byte(request("GET", "/v1/control-frameworks", "", "", 200)), &otherPage); err != nil || len(otherPage.Data) != 1 || otherPage.Data[0].ID != other.ID {
		t.Fatal("foreign framework page leaked", otherPage, err)
	}
	counts(3, 2*len(pack.Controls)+len(secondPack.Controls), 3)
}

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

func TestPostgresControlCreationHTTPUsesFreshDurableStateWithoutLedgerMaps(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Controls'),('other','Other')`)
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"controls:admin", "controls:read", "report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"controls:admin", "controls:read", "report:read"}}}}
	auth := &attestationHTTPActor{actor: actor}
	var ledgers []*app.Ledger
	var reloads []*decisionHTTPNoReloadStore
	newServer := func() http.Handler {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		opts.Authenticator = auth
		noReload := &decisionHTTPNoReloadStore{}
		reloads = append(reloads, noReload)
		ledger, err := newLegacyLedgerFixtureWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		ledgers = append(ledgers, ledger)
		server, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		return server.Handler()
	}
	request := func(method, path, key, body string, want int) string {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		rec := httptest.NewRecorder()
		newServer().ServeHTTP(rec, req)
		if rec.Code != want || reloads[len(reloads)-1].loads != 1 || strings.Contains(rec.Body.String(), "private control SQL") {
			t.Fatalf("HTTP %s %s got %d want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		return rec.Body.String()
	}
	decodeF := func(body string) domain.ControlFramework {
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
	decodeC := func(body string) domain.SecurityControl {
		t.Helper()
		var v struct {
			Data domain.SecurityControl `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatal(err)
		}
		v.Data.CreatedAt = v.Data.CreatedAt.UTC()
		return v.Data
	}
	counts := func(wantF, wantC, wantA int) {
		t.Helper()
		var f, c, a int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM control_frameworks),(SELECT count(*)FROM security_controls),(SELECT count(*)FROM audit_chain_entries)`).Scan(&f, &c, &a); err != nil || f != wantF || c != wantC || a != wantA {
			t.Fatal("control effects changed", f, c, a, err)
		}
	}
	fBody := `{"name":" Framework ","version":" 1 ","description":" Description "}`
	fw := decodeF(request("POST", "/v1/control-frameworks", "framework", fBody, 201))
	if fw.ID == "" || fw.TenantID != "tenant" || fw.Name != "Framework" || fw.Slug != "framework" || fw.Version != "1" || fw.Description != "Description" || fw.Status != "active" || fw.SchemaVersion != domain.ControlFrameworkSchemaVersion || fw.CreatedAt.IsZero() || fw.CreatedAt.Nanosecond()%1000 != 0 {
		t.Fatal("framework response fields changed", fw)
	}
	cBody := `{"framework_id":"` + fw.ID + `","code":" C-1 ","title":" Title ","objective":" Objective ","evidence_requirements":[{"type":" sbom ","freshness_days":90,"required":true}],"applicability":[" z ",""," a ","a"],"limitations":[" second "," "," first ","first"]}`
	control := decodeC(request("POST", "/v1/controls", "control", cBody, 201))
	if control.ID == "" || control.TenantID != "tenant" || control.FrameworkID != fw.ID || control.Code != "C-1" || control.Title != "Title" || control.Objective != "Objective" || control.SchemaVersion != domain.SecurityControlSchemaVersion || control.CreatedAt.IsZero() || control.CreatedAt.Nanosecond()%1000 != 0 || !reflect.DeepEqual(control.EvidenceRequirements, []domain.ControlEvidenceRequirement{{Type: "sbom", FreshnessDays: 90, Required: true}}) || !reflect.DeepEqual(control.Applicability, []string{"", "a", "a", "z"}) || !reflect.DeepEqual(control.Limitations, []string{"second", "first", "first"}) {
		t.Fatal("control response fields changed", control)
	}
	counts(1, 1, 2)
	if got := decodeF(request("POST", "/v1/control-frameworks", "framework", fBody, 201)); !reflect.DeepEqual(got, fw) {
		t.Fatal("framework replay changed", got, fw)
	}
	if got := decodeC(request("POST", "/v1/controls", "control", cBody, 201)); !reflect.DeepEqual(got, control) {
		t.Fatal("control replay changed", got, control)
	}
	request("POST", "/v1/control-frameworks", "framework", fBody+" ", 409)
	request("POST", "/v1/controls", "control", cBody+" ", 409)
	request("POST", "/v1/control-frameworks", "duplicate-framework", fBody, 409)
	request("POST", "/v1/controls", "duplicate-control", cBody, 409)
	if got := decodeC(request("GET", "/v1/controls/"+control.ID, "", "", 200)); !reflect.DeepEqual(got, control) {
		t.Fatal("durable control point differs", got, control)
	}
	var page struct {
		Data []domain.ControlFramework `json:"data"`
	}
	if err := json.Unmarshal([]byte(request("GET", "/v1/control-frameworks", "", "", 200)), &page); err != nil || len(page.Data) != 1 {
		t.Fatal("durable framework page changed", page, err)
	}
	page.Data[0].CreatedAt = page.Data[0].CreatedAt.UTC()
	if !reflect.DeepEqual(page.Data[0], fw) {
		t.Fatal("durable framework DTO differs", page.Data[0], fw)
	}
	var report struct {
		Data domain.ControlCoverageReport `json:"data"`
	}
	if err := json.Unmarshal([]byte(request("GET", "/v1/reports/control-coverage?framework_id="+fw.ID, "", "", 200)), &report); err != nil || report.Data.FrameworkID != fw.ID || len(report.Data.Controls) != 1 || report.Data.Controls[0].ControlID != control.ID || report.Data.Controls[0].Status != "missing" || report.Data.Result != "failed" {
		t.Fatal("new control not visible to durable downstream report", report, err)
	}
	for _, ledger := range ledgers {
		if _, err := ledger.GetSecurityControl(ctx, actor, control.ID); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("focused control published an authoritative cache", err)
		}
		if inventory, err := ledger.ListControlFrameworks(ctx, actor); err != nil || len(inventory) != 0 {
			t.Fatal("focused framework published an authoritative cache", inventory, err)
		}
	}
	for i, bad := range []string{`{`, `{} {}`, `[]`, `null`, `{}`, `{"name":null,"version":"1"}`, `{"name":1,"version":"1"}`, `{"name":"X","version":null}`, `{"name":"X","version":"1","name":"Y"}`, `{"name":"X","version":"1","tenant_id":"other"}`, `{"name":" ","version":"1"}`, `{"name":"bad\u0000","version":"1"}`, `{"name":"X","slug":"` + strings.Repeat("x", 1024) + `","version":"1"}`} {
		request("POST", "/v1/control-frameworks", fmt.Sprintf("bad-framework-%d", i), bad, 400)
	}
	for i, field := range []string{"slug", "description"} {
		request("POST", "/v1/control-frameworks", fmt.Sprintf("null-framework-%d", i), `{"name":"X","version":"1","`+field+`":null}`, 400)
	}
	base := `"framework_id":"` + fw.ID + `","code":"C-2","title":"T","objective":"O"`
	for i, bad := range []string{`{`, `{} {}`, `[]`, `null`, `{}`, `{"framework_id":null,"code":"C","title":"T","objective":"O"}`, `{` + base + `,"title":"Repeated"}`, `{` + base + `,"tenant_id":"other"}`, `{` + base + `,"evidence_requirements":[null]}`, `{` + base + `,"evidence_requirements":[{"type":"other","required":true}]}`, `{` + base + `,"evidence_requirements":[{"type":"sbom","freshness_days":3651,"required":true}]}`, `{` + base + `,"evidence_requirements":[{"type":"sbom","required":true},{"type":" sbom ","required":false}]}`, `{` + base + `,"applicability":[null]}`, `{` + base + `,"limitations":[1]}`, `{` + base + `,"limitations":["bad\u0000"]}`} {
		request("POST", "/v1/controls", fmt.Sprintf("bad-control-%d", i), bad, 400)
	}
	for i, field := range []string{"evidence_requirements", "applicability", "limitations"} {
		request("POST", "/v1/controls", fmt.Sprintf("null-control-array-%d", i), `{`+base+`,"`+field+`":null}`, 400)
	}
	for i, requirement := range []string{`{"type":"sbom"}`, `{"type":"sbom","required":null}`, `{"type":"sbom","required":true,"freshness_days":null}`, `{"type":"sbom","required":true,"freshness_days":-1}`, `{"type":"sbom","required":true,"freshness_days":1.5}`, `{"type":"sbom","required":true,"freshness_days":9999999999999999999999}`, `{"type":"sbom","required":true,"unknown":1}`, `{"type":"sbom","type":"build","required":true}`} {
		request("POST", "/v1/controls", fmt.Sprintf("bad-control-requirement-%d", i), `{`+base+`,"evidence_requirements":[`+requirement+`]}`, 400)
	}
	tooMany, err := json.Marshal(map[string]any{"framework_id": fw.ID, "code": "C-2", "title": "T", "objective": "O", "applicability": make([]string, 1025)})
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(tooMany)) >= app.SmallJSONRequestLimit {
		t.Fatal("list-count regression exceeds HTTP body limit")
	}
	request("POST", "/v1/controls", "too-many-applicability", string(tooMany), 400)
	request("POST", "/v1/control-frameworks", "oversized-framework", strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1), 400)
	request("POST", "/v1/controls", "oversized-control", strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1), 400)
	request("POST", "/v1/controls", "missing-framework", `{"framework_id":"missing","code":"C","title":"T","objective":"O"}`, 404)
	auth.actor = actor
	auth.actor.TenantID = "other"
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "other", Scopes: actor.Scopes}}
	request("POST", "/v1/controls", "foreign-framework", cBody, 404)
	request("GET", "/v1/controls/"+control.ID, "", "", 404)
	var foreignPage struct {
		Data []domain.ControlFramework `json:"data"`
	}
	if err := json.Unmarshal([]byte(request("GET", "/v1/control-frameworks", "", "", 200)), &foreignPage); err != nil || len(foreignPage.Data) != 0 {
		t.Fatal("foreign list leaked", foreignPage, err)
	}
	auth.actor = actor
	auth.actor.ResourceGrants = nil
	request("POST", "/v1/control-frameworks", "removed-framework-grant", fBody, 403)
	request("POST", "/v1/controls", "removed-control-grant", cBody, 403)
	auth.actor = actor
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "unrelated", Scopes: actor.Scopes}}
	request("POST", "/v1/control-frameworks", "restricted-framework-grant", fBody, 403)
	request("POST", "/v1/controls", "restricted-control-grant", cBody, 403)
	auth.actor = actor
	counts(1, 1, 2)
	for _, table := range []string{"control_frameworks", "security_controls", "audit_chain_entries"} {
		exec(`CREATE FUNCTION reject_control_http_insert() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private control SQL';END$$`)
		exec(`CREATE TRIGGER reject_control_http_insert BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_control_http_insert()`)
		path, body := "/v1/control-frameworks", `{"name":"Failure","version":"1"}`
		if table == "security_controls" {
			path, body = "/v1/controls", `{`+base+`}`
		}
		key := "fail-" + table
		request("POST", path, key, body, 500)
		request("POST", path, key, body, 409)
		counts(1, 1, 2)
		exec(`DROP TRIGGER reject_control_http_insert ON ` + table)
		exec(`DROP FUNCTION reject_control_http_insert()`)
	}
	optional := decodeC(request("POST", "/v1/controls", "optional-requirement", `{"framework_id":"`+fw.ID+`","code":"C-2","title":"Optional","objective":"Record optional evidence","evidence_requirements":[{"type":"build","required":false}]}`, 201))
	if len(optional.EvidenceRequirements) != 1 || optional.EvidenceRequirements[0].Required || optional.EvidenceRequirements[0].Type != "build" || optional.EvidenceRequirements[0].FreshnessDays != 0 {
		t.Fatal("explicit false/omitted optional fields changed", optional)
	}
	counts(1, 2, 3)
}

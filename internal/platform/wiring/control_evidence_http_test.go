package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresControlEvidenceHTTPUsesFreshDurableStateWithoutLedgerMaps(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"controls:write", "controls:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"controls:write", "controls:read"}}}}
	auth := &attestationHTTPActor{actor: actor}
	var ledgers []*app.Ledger
	request := func(method, path, key, body string, want int) string {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		opts.Authenticator = auth
		noReload := &decisionHTTPNoReloadStore{}
		ledger, err := app.NewLedgerWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		ledgers = append(ledgers, ledger)
		server, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != want || noReload.loads != 1 || strings.Contains(rec.Body.String(), "private link HTTP SQL") {
			t.Fatalf("%s %s got %d want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		if want >= 400 && !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
			t.Fatal("link error lost Problem Details", rec.Header())
		}
		return rec.Body.String()
	}
	decode := func(body string) domain.ControlEvidence {
		t.Helper()
		var v struct {
			Data domain.ControlEvidence `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatal(err)
		}
		v.Data.CreatedAt = v.Data.CreatedAt.UTC()
		return v.Data
	}
	counts := func(want int) {
		t.Helper()
		var l, a int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM control_evidence),(SELECT count(*)FROM audit_chain_entries WHERE entry_type='control_evidence.linked')`).Scan(&l, &a); err != nil || l != want || a != want {
			t.Fatal("HTTP link/audit effects changed", l, a, err)
		}
	}
	path := "/v1/controls/control/evidence"
	subjects := []struct{ typ, id string }{{"evidence", "ev-sbom"}, {"evidence_item", "ev-sbom"}, {"product", "product"}, {"release", "release"}, {"artifact", "artifact"}, {"sbom", "sbom"}, {"vulnerability_scan", "scan"}, {"vex", "vex"}, {"vulnerability_decision", "decision"}, {"finding", "finding"}, {"vulnerability_finding", "finding"}, {"exception", "exception"}, {"build", "build"}, {"build_attestation", "attestation"}, {"openapi_contract", "contract"}, {"release_bundle", "bundle"}}
	created := map[string]domain.ControlEvidence{}
	for i, subject := range subjects {
		body := fmt.Sprintf(`{"evidence_type":" sbom ","subject_type":%q,"subject_id":%q,"product_id":" product ","confidence":" high ","notes":" reviewed "}`, subject.typ, subject.id)
		key := fmt.Sprintf("link-%d", i)
		link := decode(request("POST", path, key, body, 201))
		if link.ID == "" || link.TenantID != "tenant" || link.ControlID != "control" || link.EvidenceType != "sbom" || link.SubjectType != subject.typ || link.SubjectID != subject.id || link.ProductID != "product" || link.ReleaseID != "" || link.Confidence != "high" || link.Notes != "reviewed" || link.SchemaVersion != domain.ControlEvidenceSchemaVersion || link.CreatedAt.IsZero() || link.CreatedAt.Nanosecond()%1000 != 0 {
			t.Fatal("HTTP link fields changed", link)
		}
		created[link.ID] = link
		if got := decode(request("POST", path, key, body, 201)); got != link {
			t.Fatal("fresh-server HTTP replay changed", got, link)
		}
		request("POST", path, key, body+" ", 409)
		duplicate := strings.ReplaceAll(strings.ReplaceAll(body, "reviewed", "changed"), " high ", "low")
		if got := decode(request("POST", path, key+"-duplicate", duplicate, 201)); got != link {
			t.Fatal("natural duplicate changed append-only link", got, link)
		}
	}
	counts(len(subjects))
	var page struct {
		Data []domain.ControlEvidence `json:"data"`
	}
	if err := json.Unmarshal([]byte(request("GET", "/v1/control-evidence?control_id=control&page_size=100", "", "", 200)), &page); err != nil || len(page.Data) != len(subjects) {
		t.Fatal("fresh durable list lost linked subjects", len(page.Data), err)
	}
	for _, link := range page.Data {
		link.CreatedAt = link.CreatedAt.UTC()
		if link != created[link.ID] {
			t.Fatal("durable list changed link DTO", link)
		}
	}
	for _, ledger := range ledgers {
		if links, err := ledger.ListControlEvidence(ctx, actor, "control", "", ""); err != nil || len(links) != 0 {
			t.Fatal("HTTP binding published authoritative Ledger links", len(links), err)
		}
	}
	base := `"evidence_type":"sbom","subject_type":"product","subject_id":"product","confidence":"high"`
	for i, bad := range []string{`{`, `{} {}`, `[]`, `null`, `{}`, `{` + base + `,"subject_id":"other-product"}`, `{` + base + `,"tenant_id":"other"}`, `{` + base + `,"notes":1}`, `{` + base + `,"notes":"bad\u0000"}`, strings.ReplaceAll(`{`+base+`}`, `"high"`, `"invalid"`), strings.ReplaceAll(`{`+base+`}`, `"sbom"`, `"invalid"`), `{` + base + `,"product_id":"` + strings.Repeat("x", 1025) + `"}`} {
		request("POST", path, fmt.Sprintf("bad-link-%d", i), bad, 400)
	}
	for i, field := range []string{"evidence_type", "subject_type", "subject_id", "confidence", "product_id", "release_id", "notes"} {
		body := map[string]any{"evidence_type": "sbom", "subject_type": "product", "subject_id": "product", "confidence": "high"}
		body[field] = nil
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request("POST", path, fmt.Sprintf("null-link-%d", i), string(encoded), 400)
	}
	for i, field := range []string{"evidence_type", "subject_type", "subject_id", "confidence"} {
		body := map[string]any{"evidence_type": "sbom", "subject_type": "product", "subject_id": "product", "confidence": "high"}
		delete(body, field)
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request("POST", path, fmt.Sprintf("missing-field-%d", i), string(encoded), 400)
	}
	request("POST", path, "missing-key-unused", strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1), 400)
	request("POST", path, "", `{`+base+`}`, 400)
	request("POST", "/v1/controls/missing/evidence", "missing-control", `{`+base+`}`, 404)
	request("POST", path, "foreign-subject", `{"evidence_type":"sbom","subject_type":"product","subject_id":"other-product","confidence":"high"}`, 404)
	request("POST", path, "foreign-scope", `{`+base+`,"product_id":"other-product"}`, 404)
	request("POST", path, "unknown-subject", `{"evidence_type":"sbom","subject_type":"unknown","subject_id":"product","confidence":"high"}`, 404)
	for i, id := range []string{"bad%00id", "%FF", strings.Repeat("x", 1025)} {
		request("POST", "/v1/controls/"+id+"/evidence", fmt.Sprintf("bad-path-%d", i), `{`+base+`}`, 400)
	}
	auth.actor = actor
	auth.actor.ResourceGrants = nil
	request("POST", path, "removed-grant", `{`+base+`}`, 403)
	auth.actor = actor
	auth.actor.Scopes = []string{"controls:read"}
	request("POST", path, "missing-write-scope", `{`+base+`}`, 403)
	auth.actor = actor
	auth.actor.TenantID = "other"
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "other", Scopes: actor.Scopes}}
	request("POST", path, "foreign-control", `{`+base+`}`, 404)
	auth.actor = actor
	counts(len(subjects))
	for _, table := range []string{"control_evidence", "audit_chain_entries"} {
		if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_link_http_insert() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private link HTTP SQL';END$$;CREATE TRIGGER reject_link_http_insert BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION reject_link_http_insert()`); err != nil {
			t.Fatal(err)
		}
		request("POST", path, "failure-"+table, strings.ReplaceAll(`{`+base+`}`, `"sbom"`, `"artifact"`), 500)
		request("POST", path, "failure-"+table, strings.ReplaceAll(`{`+base+`}`, `"sbom"`, `"artifact"`), 409)
		counts(len(subjects))
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_link_http_insert ON `+table+`;DROP FUNCTION reject_link_http_insert()`); err != nil {
			t.Fatal(err)
		}
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*)FROM audit_chain_entries WHERE entry_type='control_evidence.linked' AND actor_type='human_user' AND actor_id='human'`).Scan(&audits); err != nil || audits != len(subjects) {
		t.Fatal("HTTP link audit lost authenticated human", audits, err)
	}
}

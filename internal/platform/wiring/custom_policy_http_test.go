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
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresCustomPolicyHTTPUsesFocusedDurableTransactions(t *testing.T) {
	if _, err := BuildCustomPolicyCommands(nil); err == nil {
		t.Fatal("nil policy transactions accepted")
	}
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO custom_policies(id,tenant_id,name,version,description,rules,schema_version,created_at)VALUES('unrelated','tenant','Unrelated','1',repeat('x',9000000),'[]','custom-policy.v1.0.0',now());UPDATE evidence_items SET metadata=jsonb_build_object('large',repeat('x',9000000)) WHERE id='ev-sbom'`); err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"policy:write", "policy:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"policy:write"}}, {ResourceType: "release", ResourceID: "release", Scopes: []string{"policy:read"}}}}
	auth := &attestationHTTPActor{actor: actor}
	request := func(path, key, body string, want int) []byte {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		if opts.CustomPolicyCommands == nil || opts.DurableCommandExecutor == nil {
			t.Fatal("focused policy composition missing")
		}
		opts.Authenticator = auth
		noReload := &decisionHTTPNoReloadStore{}
		ledger, err := app.NewLedgerWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		server, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != want || noReload.loads != 1 || strings.Contains(rec.Body.String(), "private policy SQL") {
			t.Fatalf("policy got %d want %d loads=%d: %s", rec.Code, want, noReload.loads, rec.Body.String())
		}
		if want >= 400 && !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
			t.Fatal("unsafe policy error")
		}
		if want < 400 && rec.Header().Get("Idempotency-Key") != key {
			t.Fatal("missing replay key")
		}
		return rec.Body.Bytes()
	}
	counts := func(policies, evaluations, audits int) {
		t.Helper()
		var p, e, a int
		err := pool.QueryRow(ctx, `SELECT(SELECT count(*) FROM custom_policies),(SELECT count(*) FROM custom_policy_evaluations),(SELECT count(*) FROM audit_chain_entries WHERE entry_type LIKE 'custom_policy.%')`).Scan(&p, &e, &a)
		if err != nil || p != policies || e != evaluations || a != audits {
			t.Fatal("policy effects leaked", p, e, a, err)
		}
	}
	body := `{"name":" Policy ","version":" 1 ","description":" Description ","rules":[{"name":" SBOM ","evidence_type":"sbom","severity":" custom ","required":true},{"name":"missing","evidence_type":"threat_model","severity":"arbitrary","required":true},{"name":"optional","evidence_type":"dast","severity":"low"},{"name":"metadata","severity":"note"}]}`
	original := request("/v1/custom-policies", "create", body, 201)
	var created struct {
		Data domain.CustomPolicy `json:"data"`
	}
	if err := json.Unmarshal(original, &created); err != nil {
		t.Fatal(err)
	}
	p := created.Data
	if p.ID == "" || p.Name != "Policy" || p.Version != "1" || p.Description != "Description" || p.Rules[0].Name != " SBOM " || p.Rules[0].Severity != " custom " || p.SchemaVersion != domain.CustomPolicySchemaVersion {
		t.Fatal("policy DTO", p)
	}
	var replayedPolicy struct {
		Data domain.CustomPolicy `json:"data"`
	}
	if err := json.Unmarshal(request("/v1/custom-policies", "create", body, 201), &replayedPolicy); err != nil || !reflect.DeepEqual(replayedPolicy.Data, p) {
		t.Fatal("create replay changed", err)
	}
	request("/v1/custom-policies", "duplicate", body, 409)
	counts(2, 0, 1)
	evalPath := "/v1/custom-policies/" + p.ID + "/evaluate"
	evalBody := `{"release_id":"release"}`
	raw := request(evalPath, "evaluate", evalBody, 201)
	var evaluated struct {
		Data domain.CustomPolicyEvaluation `json:"data"`
	}
	if err := json.Unmarshal(raw, &evaluated); err != nil {
		t.Fatal(err)
	}
	e := evaluated.Data
	wantChecks := []domain.PolicyCheck{{Name: " SBOM ", Severity: " custom ", Result: "passed", Explanation: "sbom evidence exists"}, {Name: "missing", Severity: "arbitrary", Result: "failed", Missing: []string{"threat_model"}, Explanation: "threat_model evidence is missing"}, {Name: "optional", Severity: "low", Result: "passed", Explanation: "optional evidence not present"}, {Name: "metadata", Severity: "note", Result: "passed", Explanation: "metadata-only custom policy rule recorded"}}
	expectedHash, err := application.NormalizedJSONHash(map[string]any{"policy": p, "release_id": "release", "checks": wantChecks})
	if err != nil {
		t.Fatal(err)
	}
	if e.ID == "" || e.PolicyID != p.ID || e.ReleaseID != "release" || e.TenantID != "tenant" || e.Result != "failed" || !reflect.DeepEqual(e.Checks, wantChecks) || e.InputHash != expectedHash || e.SchemaVersion != domain.CustomPolicyEvalSchemaVersion || e.CreatedAt.Nanosecond()%1000 != 0 {
		t.Fatal("evaluation/hash contract", e, expectedHash)
	}
	var replayedEvaluation struct {
		Data domain.CustomPolicyEvaluation `json:"data"`
	}
	if err := json.Unmarshal(request(evalPath, "evaluate", evalBody, 201), &replayedEvaluation); err != nil || !reflect.DeepEqual(replayedEvaluation.Data, e) {
		t.Fatal("evaluation replay changed", err)
	}
	request(evalPath, "evaluate", evalBody+" ", 409)
	counts(2, 1, 2)
	auth.actor.ResourceGrants = nil
	request("/v1/custom-policies", "create", body, 403)
	request(evalPath, "evaluate", evalBody, 403)
	request(evalPath, "denied", evalBody, 403)
	auth.actor = actor
	auth.actor.TenantID = "other"
	request(evalPath, "foreign", evalBody, 404)
	auth.actor = actor
	for i, bad := range []string{`null`, `[]`, `{} {}`, `{"name":"x","name":"y"}`, `{"name":null}`, `{"name":"x","version":"1","rules":null}`, `{"name":"x","version":"1","rules":[null]}`, `{"name":"x","version":"1","rules":[{"name":"r","severity":"low","required":null}]}`, `{"name":"x","version":"1","rules":[{"name":"r","severity":"low","evidence_type":" sbom "}]}`, `{"name":"x","version":"1","rules":[{"name":"r","severity":"low","extra":1}]}`, `{"name":"x","version":"1","rules":[{"name":"r","name":"dup","severity":"low"}]}`, `{"name":"x\u0000","version":"1","rules":[{"name":"r","severity":"low"}]}`} {
		request("/v1/custom-policies", fmt.Sprintf("bad-%d", i), bad, 400)
	}
	request(evalPath, "null-release", `{"release_id":null}`, 400)
	request(evalPath, "foreign-release", `{"release_id":"other-release"}`, 404)
	counts(2, 1, 2)
	// Saved replay must not load rules, while a new evaluation fails rather than truncating.
	if _, err := pool.Exec(ctx, `UPDATE custom_policies SET rules=jsonb_build_array(jsonb_build_object('name',repeat('x',9000000),'severity','low')) WHERE id=$1`, p.ID); err != nil {
		t.Fatal(err)
	}
	request(evalPath, "evaluate", evalBody, 201)
	request(evalPath, "oversized-policy", evalBody, 400)
	if _, err := pool.Exec(ctx, `UPDATE products SET tenant_id='other' WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	request(evalPath, "evaluate", evalBody, 404)
	request(evalPath, "changed-parent", evalBody, 404)
	counts(2, 1, 2)
	rules, err := json.Marshal(p.Rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE products SET tenant_id='tenant' WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE custom_policies SET rules=$1 WHERE id=$2`, rules, p.ID); err != nil {
		t.Fatal(err)
	}
	for _, create := range []bool{true, false} {
		for _, stage := range []string{"record", "audit_chain_entries", "idempotency_records", "commit"} {
			table, op := "custom_policy_evaluations", "INSERT"
			if create {
				table = "custom_policies"
			}
			if stage != "record" && stage != "commit" {
				table = stage
			}
			if stage == "idempotency_records" {
				op = "UPDATE"
			}
			trigger := `CREATE TRIGGER reject_policy_http BEFORE ` + op + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_policy_http()`
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_policy_http AFTER INSERT ON ` + table + ` DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_policy_http()`
			}
			if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_policy_http() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private policy SQL';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			path, b := evalPath, evalBody
			key := fmt.Sprintf("failure-%v-%s", create, stage)
			if create {
				path = "/v1/custom-policies"
				b = `{"name":"Failure","version":"1","rules":[{"name":"r","severity":"low"}]}`
			}
			request(path, key, b, 500)
			counts(2, 1, 2)
			if _, err := pool.Exec(ctx, `DROP TRIGGER reject_policy_http ON `+table+`;DROP FUNCTION reject_policy_http()`); err != nil {
				t.Fatal(err)
			}
		}
	}
	request(evalPath, "failure-false-commit", evalBody, 201)
	counts(2, 2, 3)
	request("/v1/custom-policies", "failure-true-commit", `{"name":"Failure","version":"1","rules":[{"name":"r","severity":"low"}]}`, 201)
	counts(3, 2, 4)
}

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
)

func TestPostgresContractDiffHTTPUsesFocusedDurableTransactions(t *testing.T) {
	if _, err := BuildContractDiffCommands(nil); err == nil {
		t.Fatal("nil transactions accepted")
	}
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	if _, err := pool.Exec(ctx, `UPDATE openapi_contracts SET path_count=1,operations='[{"path":"/a","method":"GET","response_statuses":["200"]}]' WHERE id='contract';INSERT INTO evidence_items SELECT(jsonb_populate_record(NULL::evidence_items,to_jsonb(e)||'{"id":"ev-contract-target"}'::jsonb)).* FROM evidence_items e WHERE id='ev-contract';INSERT INTO openapi_contracts SELECT(jsonb_populate_record(NULL::openapi_contracts,to_jsonb(c)||jsonb_build_object('id','target','evidence_id','ev-contract-target','hash','sha256:'||repeat('b',64),'operations','[{"path":"/a","method":"GET","request_body_required":true,"response_statuses":["200","201"]}]'::jsonb))).* FROM openapi_contracts c WHERE id='contract';INSERT INTO releases SELECT(jsonb_populate_record(NULL::releases,to_jsonb(r)||'{"id":"requested","version":"requested"}'::jsonb)).* FROM releases r WHERE id='release';UPDATE evidence_items SET metadata=jsonb_build_object('private',repeat('x',9000000))`); err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"evidence:read"}}}}
	auth := &attestationHTTPActor{actor: a}
	body := `{"base_contract_id":"contract","target_contract_id":"target","release_id":"requested"}`
	request := func(key, body string, want int) domain.ContractDiff {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		if opts.ContractDiffCommands == nil || opts.DurableCommandExecutor == nil {
			t.Fatal("contract diff remains Ledger-backed")
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
		r := httptest.NewRequest("POST", "/v1/openapi-diffs", strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer isolated-auth")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private contract diff SQL") {
			t.Fatalf("got %d want %d loads=%d: %s", w.Code, want, noReload.loads, w.Body.String())
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("unsafe problem")
			}
			return domain.ContractDiff{}
		}
		if w.Header().Get("Idempotency-Key") != key {
			t.Fatal("missing replay key")
		}
		var result struct {
			Data domain.ContractDiff `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Data
	}
	counts := func(want int) {
		t.Helper()
		var d, a, i int
		err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM contract_diffs),(SELECT count(*)FROM audit_chain_entries WHERE entry_type='openapi_contract.diffed' AND actor_id='human'),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&d, &a, &i)
		if err != nil || d != want || a != want || i != want {
			t.Fatal("partial effects", d, a, i, err)
		}
	}
	v := request("diff", body, 201)
	if v.ID == "" || v.TenantID != "tenant" || v.ProductID != "product" || v.BaseContractID != "contract" || v.TargetContractID != "target" || v.ReleaseID != "requested" || v.Result != "breaking" || v.SchemaVersion != domain.ContractDiffSchemaVersion || v.CreatedAt.IsZero() || v.CreatedAt.Nanosecond()%1000 != 0 || !reflect.DeepEqual(v.BreakingChanges, []string{"request body became required: GET /a"}) || !reflect.DeepEqual(v.NonBreakingChanges, []string{"response statuses added for GET /a: 201"}) {
		t.Fatal(v)
	}
	if replay := request("diff", body, 201); !reflect.DeepEqual(replay, v) {
		t.Fatal("fresh replay changed", replay, v)
	}
	request("diff", body+" ", 409)
	counts(1)
	auth.actor.ResourceGrants = nil
	request("diff", body, 403)
	request("denied", body, 403)
	auth.actor = a
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"evidence:read"}}}
	request("diff", body, 403)
	request("denied-requested-release", body, 403)
	auth.actor = a
	auth.actor.TenantID = "other"
	request("foreign", body, 404)
	auth.actor = a
	for i, bad := range []string{`{`, `null`, `[]`, `{}`, `{} {}`, `{"base_contract_id":null,"target_contract_id":"target"}`, `{"base_contract_id":"contract","target_contract_id":null}`, `{"base_contract_id":"contract","target_contract_id":"target","release_id":null}`, `{"base_contract_id":"contract","base_contract_id":"contract","target_contract_id":"target"}`, `{"base_contract_id":42,"target_contract_id":"target"}`, `{"base_contract_id":"contract","target_contract_id":"contract"}`, `{"base_contract_id":"bad\u0000","target_contract_id":"target"}`, `{"base_contract_id":"` + strings.Repeat("x", 1025) + `","target_contract_id":"target"}`, `{"base_contract_id":"contract","target_contract_id":"target","unknown":true}`} {
		request(fmt.Sprintf("invalid-%d", i), bad, 400)
	}
	request("missing", strings.Replace(body, `"contract"`, `"missing"`, 1), 404)
	request("missing-release", strings.Replace(body, `"requested"`, `"missing"`, 1), 404)
	counts(1)
	for i, bad := range []string{`'{}'::jsonb`, `'[null]'::jsonb`, `'[{"path":true,"method":"GET"}]'::jsonb`, `'[{"path":"/a","method":"GET","response_statuses":{}}]'::jsonb`, `jsonb_build_array(jsonb_build_object('path',repeat('x',33554433),'method','GET'))`} {
		if _, err := pool.Exec(ctx, `UPDATE openapi_contracts SET operations=`+bad+` WHERE id='target'`); err != nil {
			t.Fatal(err)
		}
		request("diff", body, 201)
		request(fmt.Sprintf("malformed-%d", i), body, 400)
		counts(1)
	}
	if _, err := pool.Exec(ctx, `UPDATE openapi_contracts SET operations='[{"path":"/a","method":"GET","request_body_required":true,"response_statuses":["200","201"]}]' WHERE id='target'`); err != nil {
		t.Fatal(err)
	}
	for i, mutation := range []string{`UPDATE products SET tenant_id='other' WHERE id='product'`, `UPDATE evidence_items SET type='vex' WHERE id='ev-contract-target'`, `UPDATE evidence_items SET build_id='missing' WHERE id='ev-contract-target'`, `UPDATE evidence_items SET deployment_id='missing' WHERE id='ev-contract-target'`, `UPDATE releases SET product_id='other-product' WHERE id='requested'`, `UPDATE openapi_contracts SET release_id=NULL WHERE id='target'`} {
		if _, err := pool.Exec(ctx, mutation); err != nil {
			t.Fatal(err)
		}
		request("diff", body, 404)
		request(fmt.Sprintf("bad-parent-%d", i), body, 404)
		counts(1)
		if _, err := pool.Exec(ctx, `UPDATE products SET tenant_id='tenant' WHERE id='product';UPDATE evidence_items SET type='openapi_contract',build_id=NULL,deployment_id=NULL WHERE id='ev-contract-target';UPDATE releases SET product_id='product' WHERE id='requested';UPDATE openapi_contracts SET release_id='release' WHERE id='target'`); err != nil {
			t.Fatal(err)
		}
	}
	for _, stage := range []string{"contract_diffs", "audit_chain_entries", "idempotency_records", "commit"} {
		table, op := stage, "INSERT"
		if stage == "idempotency_records" {
			op = "UPDATE"
		}
		trigger := `CREATE TRIGGER reject_contract_diff BEFORE ` + op + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_contract_diff()`
		if stage == "commit" {
			table = "contract_diffs"
			trigger = `CREATE CONSTRAINT TRIGGER reject_contract_diff AFTER INSERT ON contract_diffs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_contract_diff()`
		}
		if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_contract_diff()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private contract diff SQL';END$$;`+trigger); err != nil {
			t.Fatal(err)
		}
		request("fault-"+stage, body, 500)
		counts(1)
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_contract_diff ON `+table+`;DROP FUNCTION reject_contract_diff()`); err != nil {
			t.Fatal(err)
		}
	}
	request("fault-commit", body, 201)
	counts(2)
}

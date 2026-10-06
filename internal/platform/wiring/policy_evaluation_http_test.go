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
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestPostgresPolicyEvaluationHTTPUsesFocusedDurableTransactions(t *testing.T) {
	if _, err := BuildPolicyEvaluationCommands(nil); err == nil {
		t.Fatal("nil policy evaluation transactions accepted")
	}
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	if _, err := pool.Exec(ctx, `UPDATE vulnerability_scans SET findings='[{"id":"finding","severity":"high","state":"open","vulnerability":"CVE-TEST"}]';UPDATE evidence_items SET metadata=jsonb_build_object('notes',repeat('x',9000000));INSERT INTO policy_evaluations(id,tenant_id,release_id,result,policy_set,checks,created_at)VALUES('old','tenant','release','failed','policy-set.v1.0.0',jsonb_build_array(jsonb_build_object('name',repeat('x',9000000))),now())`); err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"verify:read"}}}}
	auth := &attestationHTTPActor{actor: actor}
	path, body := "/v1/policies/evaluate", `{"release_id":"release"}`
	request := func(key, b string, want int) domain.PolicyEvaluation {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		if opts.PolicyEvaluationCommands == nil || opts.DurableCommandExecutor == nil {
			t.Fatal("policy evaluation still bound to Ledger")
		}
		opts.Authenticator = auth
		noReload := &decisionHTTPNoReloadStore{}
		ledger, err := newLegacyLedgerFixtureWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		server, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", path, strings.NewReader(b)).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != want || noReload.loads != 1 || strings.Contains(rec.Body.String(), "private policy evaluation SQL") {
			t.Fatalf("policy evaluation got %d want %d loads=%d: %s", rec.Code, want, noReload.loads, rec.Body.String())
		}
		if want >= 400 {
			if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("unsafe policy problem")
			}
			return domain.PolicyEvaluation{}
		}
		if rec.Header().Get("Idempotency-Key") != key {
			t.Fatal("missing replay key")
		}
		var result struct {
			Data domain.PolicyEvaluation `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Data
	}
	counts := func(evaluations, audits int) {
		t.Helper()
		var e, a int
		err := pool.QueryRow(ctx, `SELECT(SELECT count(*) FROM policy_evaluations),(SELECT count(*) FROM audit_chain_entries WHERE entry_type='policy.evaluated' AND actor_id='human')`).Scan(&e, &a)
		if err != nil || e != evaluations || a != audits {
			t.Fatal("policy evaluation effects leaked", e, a, err)
		}
	}
	snapshot, err := store.ReadReleaseReadinessSnapshot(ctx, "tenant", "release")
	if err != nil {
		t.Fatal(err)
	}
	expected, err := riskapp.EvaluateReadinessSnapshot(snapshot, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	v := request("evaluate", body, 201)
	if v.ID == "" || v.TenantID != "tenant" || v.ReleaseID != "release" || v.PolicySet != domain.PolicySetVersion || v.Result != expected.Result || !reflect.DeepEqual(v.Checks, domain.CustomPolicyChecksFromContext(expected.Checks)) || len(v.Checks) != 13 || v.CreatedAt.IsZero() || v.CreatedAt.Nanosecond()%1000 != 0 {
		t.Fatal("canonical policy contract changed", v)
	}
	if replay := request("evaluate", body, 201); !reflect.DeepEqual(replay, v) {
		t.Fatal("fresh-server replay changed", replay, v)
	}
	request("evaluate", body+" ", 409)
	counts(2, 1)
	auth.actor.ResourceGrants = nil
	request("evaluate", body, 403)
	request("denied", body, 403)
	auth.actor = actor
	auth.actor.TenantID = "other"
	request("foreign", body, 404)
	auth.actor = actor
	for i, bad := range []string{`{`, `null`, `[]`, `{} {}`, `{}`, `{"release_id":null}`, `{"release_id":true}`, `{"release_id":" "}`, `{"release_id":"bad\u0000"}`, `{"release_id":"release","release_id":"release"}`, `{"release_id":"release","unknown":true}`, `{"release_id":"` + strings.Repeat("x", 1025) + `"}`} {
		request(fmt.Sprintf("bad-%d", i), bad, 400)
	}
	request("missing", `{"release_id":"missing"}`, 404)
	counts(2, 1)
	if _, err := pool.Exec(ctx, `UPDATE vulnerability_scans SET findings='{}'::jsonb WHERE id='scan'`); err != nil {
		t.Fatal(err)
	}
	request("evaluate", body, 201)
	request("malformed-facts", body, 400)
	if _, err := pool.Exec(ctx, `UPDATE vulnerability_scans SET findings='[{"id":"finding","severity":"high","state":"open","vulnerability":"CVE-TEST"}]' WHERE id='scan';UPDATE products SET tenant_id='other' WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	request("evaluate", body, 404)
	request("changed-parent", body, 404)
	if _, err := pool.Exec(ctx, `UPDATE products SET tenant_id='tenant' WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"policy_evaluations", "audit_chain_entries", "idempotency_records", "commit"} {
		table, op := stage, "INSERT"
		if stage == "idempotency_records" {
			op = "UPDATE"
		}
		trigger := `CREATE TRIGGER reject_policy_evaluation_http BEFORE ` + op + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_policy_evaluation_http()`
		if stage == "commit" {
			table = "policy_evaluations"
			trigger = `CREATE CONSTRAINT TRIGGER reject_policy_evaluation_http AFTER INSERT ON policy_evaluations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_policy_evaluation_http()`
		}
		if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_policy_evaluation_http() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private policy evaluation SQL';END$$;`+trigger); err != nil {
			t.Fatal(err)
		}
		request("failure-"+stage, body, 500)
		counts(2, 1)
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_policy_evaluation_http ON `+table+`;DROP FUNCTION reject_policy_evaluation_http()`); err != nil {
			t.Fatal(err)
		}
	}
	request("failure-commit", body, 201)
	counts(3, 2)
}

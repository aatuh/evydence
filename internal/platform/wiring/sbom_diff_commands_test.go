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

func TestPostgresSBOMDiffHTTPUsesFocusedDurableTransactions(t *testing.T) {
	if _, err := BuildSBOMDiffCommands(nil); err == nil {
		t.Fatal("nil transactions accepted")
	}
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	if _, err := pool.Exec(ctx, `UPDATE sboms SET component_count=2,components='[{"name":"same","version":"1"},{"name":"gone","version":"1"}]' WHERE id='sbom';INSERT INTO evidence_items SELECT(jsonb_populate_record(NULL::evidence_items,to_jsonb(e)||'{"id":"ev-target"}'::jsonb)).* FROM evidence_items e WHERE id='ev-sbom';INSERT INTO sboms SELECT(jsonb_populate_record(NULL::sboms,to_jsonb(s)||'{"id":"target","evidence_id":"ev-target","components":[{"name":"same","version":"1"},{"name":"new","version":"2"}]}'::jsonb)).* FROM sboms s WHERE id='sbom';UPDATE evidence_items SET metadata=jsonb_build_object('private',repeat('x',9000000))`); err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"evidence:read"}}}}
	auth := &attestationHTTPActor{actor: a}
	body := `{"base_sbom_id":"sbom","target_sbom_id":"target","release_id":"release"}`
	request := func(key, body string, want int) domain.SBOMDiff {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		if opts.SBOMDiffCommands == nil || opts.DurableCommandExecutor == nil {
			t.Fatal("SBOM diff still bound to Ledger")
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
		r := httptest.NewRequest("POST", "/v1/sbom-diffs", strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer isolated-auth")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private SBOM diff SQL") {
			t.Fatalf("got %d want %d loads=%d: %s", w.Code, want, noReload.loads, w.Body.String())
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("unsafe problem")
			}
			return domain.SBOMDiff{}
		}
		if w.Header().Get("Idempotency-Key") != key {
			t.Fatal("missing replay key")
		}
		var result struct {
			Data domain.SBOMDiff `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Data
	}
	counts := func(diffs, changes, audits int) {
		t.Helper()
		var d, c, a int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM sbom_diffs),(SELECT count(*)FROM dependency_changes),(SELECT count(*)FROM audit_chain_entries WHERE entry_type='sbom.diffed' AND actor_id='human')`).Scan(&d, &c, &a); err != nil || d != diffs || c != changes || a != audits {
			t.Fatal("partial effects", d, c, a, err)
		}
	}
	v := request("diff", body, 201)
	if v.ID == "" || v.TenantID != "tenant" || v.BaseSBOMID != "sbom" || v.TargetSBOMID != "target" || v.ReleaseID != "release" || v.UnchangedCount != 1 || v.SchemaVersion != domain.SBOMDiffSchemaVersion || v.CreatedAt.IsZero() || v.CreatedAt.Nanosecond()%1000 != 0 || len(v.AddedComponents) != 1 || v.AddedComponents[0].Name != "new" || len(v.RemovedComponents) != 1 || v.RemovedComponents[0].Name != "gone" || len(v.DependencyChanges) != 2 {
		t.Fatal("diff contract changed", v)
	}
	if replay := request("diff", body, 201); !reflect.DeepEqual(replay, v) {
		t.Fatal("fresh replay changed", replay, v)
	}
	request("diff", body+" ", 409)
	counts(1, 2, 1)
	auth.actor.ResourceGrants = nil
	request("diff", body, 403)
	request("denied", body, 403)
	auth.actor = a
	auth.actor.TenantID = "other"
	request("foreign", body, 404)
	auth.actor = a
	for i, bad := range []string{`{`, `null`, `[]`, `{}`, `{} {}`, `{"base_sbom_id":null,"target_sbom_id":"target"}`, `{"base_sbom_id":"sbom","target_sbom_id":null}`, `{"base_sbom_id":"sbom","target_sbom_id":"target","release_id":null}`, `{"base_sbom_id":"sbom","base_sbom_id":"sbom","target_sbom_id":"target"}`, `{"base_sbom_id":42,"target_sbom_id":"target"}`, `{"base_sbom_id":"sbom","target_sbom_id":"sbom"}`, `{"base_sbom_id":"bad\u0000","target_sbom_id":"target"}`, `{"base_sbom_id":"` + strings.Repeat("x", 1025) + `","target_sbom_id":"target"}`, `{"base_sbom_id":"sbom","target_sbom_id":"target","unknown":true}`, `{"base_sbom_id":"sbom","target_sbom_id":"target","release_id":"unrelated"}`} {
		request(fmt.Sprintf("invalid-%d", i), bad, 400)
	}
	request("missing", strings.Replace(body, `"sbom"`, `"missing"`, 1), 404)
	counts(1, 2, 1)
	for i, bad := range []string{`'[null]'::jsonb`, `'[{"name":null}]'::jsonb`, `'[{"name":true}]'::jsonb`, `'[{"name":"x","version":4}]'::jsonb`, `'[{"name":"x","purl":[]}]'::jsonb`, `jsonb_build_array(jsonb_build_object('name',repeat('x',1048577)))`} {
		if _, err := pool.Exec(ctx, `UPDATE sboms SET component_count=1,components=`+bad+` WHERE id='target'`); err != nil {
			t.Fatal(err)
		}
		request(fmt.Sprintf("malformed-element-%d", i), body, 400)
		counts(1, 2, 1)
	}
	if _, err := pool.Exec(ctx, `UPDATE sboms SET component_count=2 WHERE id='target'`); err != nil {
		t.Fatal(err)
	}
	for i, bad := range []string{`'{}'::jsonb`, `'[null]'::jsonb`, `'[{"name":null}]'::jsonb`, `'[{"name":true}]'::jsonb`, `'[{"name":"x"}]'::jsonb`, `jsonb_build_array(jsonb_build_object('name',repeat('x',1048577)))`, `(SELECT jsonb_agg(jsonb_build_object('name','x'))FROM generate_series(1,100001))`} {
		if _, err := pool.Exec(ctx, `UPDATE sboms SET components=`+bad+` WHERE id='target'`); err != nil {
			t.Fatal(err)
		}
		request("diff", body, 201)
		request(fmt.Sprintf("malformed-%d", i), body, 400)
		counts(1, 2, 1)
	}
	if _, err := pool.Exec(ctx, `UPDATE sboms SET components='[{"name":"same","version":"1"},{"name":"new","version":"2"}]' WHERE id='target';UPDATE products SET tenant_id='other' WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	request("diff", body, 404)
	request("bad-parent", body, 404)
	if _, err := pool.Exec(ctx, `UPDATE products SET tenant_id='tenant' WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	for i, mutation := range []string{`UPDATE evidence_items SET type='vex' WHERE id='ev-target'`, `UPDATE evidence_items SET release_id=NULL WHERE id='ev-target'`, `UPDATE evidence_items SET build_id='missing' WHERE id='ev-target'`, `UPDATE evidence_items SET deployment_id='missing' WHERE id='ev-target'`, `UPDATE sboms SET artifact_id='artifact' WHERE id='target'`, `UPDATE sboms SET artifact_id=NULL WHERE id='target';UPDATE evidence_items SET subject_refs='[{"type":"artifact","id":"artifact"}]' WHERE id='ev-target'`} {
		if _, err := pool.Exec(ctx, mutation); err != nil {
			t.Fatal(err)
		}
		request("diff", body, 404)
		request(fmt.Sprintf("inconsistent-parent-%d", i), body, 404)
		counts(1, 2, 1)
		if _, err := pool.Exec(ctx, `UPDATE sboms SET artifact_id=NULL WHERE id='target';UPDATE evidence_items SET type='sbom',release_id='release',build_id=NULL,deployment_id=NULL,subject_refs='[]' WHERE id='ev-target'`); err != nil {
			t.Fatal(err)
		}
	}
	// A valid source artifact agreement exercises identifier-only association
	// authorization even though the stored artifact name is deliberately huge.
	if _, err := pool.Exec(ctx, `UPDATE sboms SET artifact_id='artifact' WHERE id='target';UPDATE evidence_items SET subject_refs='[{"type":"artifact","id":"artifact"}]' WHERE id='ev-target'`); err != nil {
		t.Fatal(err)
	}
	request("diff", body, 201)
	for _, stage := range []string{"sbom_diffs", "dependency_changes", "audit_chain_entries", "idempotency_records", "commit"} {
		table, op := stage, "INSERT"
		if stage == "idempotency_records" {
			op = "UPDATE"
		}
		trigger := `CREATE TRIGGER reject_sbom_diff BEFORE ` + op + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_sbom_diff()`
		if stage == "commit" {
			table = "sbom_diffs"
			trigger = `CREATE CONSTRAINT TRIGGER reject_sbom_diff AFTER INSERT ON sbom_diffs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_sbom_diff()`
		}
		if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_sbom_diff()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private SBOM diff SQL';END$$;`+trigger); err != nil {
			t.Fatal(err)
		}
		request("fault-"+stage, body, 500)
		counts(1, 2, 1)
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_sbom_diff ON `+table+`;DROP FUNCTION reject_sbom_diff()`); err != nil {
			t.Fatal(err)
		}
	}
	request("fault-commit", body, 201)
	counts(2, 4, 2)
}

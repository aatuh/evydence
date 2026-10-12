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

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresWaiverHTTPUsesBoundedTransactionsAndDurableReplay(t *testing.T) {
	if _, err := BuildWaiverCommands(nil); err == nil {
		t.Fatal("nil waiver transactions accepted")
	}
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	seedApprovalSubjects(t, ctx, store, pool)
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"policy:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"policy:write"}}}}
	auth := &attestationHTTPActor{actor: actor}
	request := func(path, key, body string, want int) domain.Waiver {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		if opts.WaiverCommands == nil || opts.DurableCommandExecutor == nil {
			t.Fatal("production waiver composition missing")
		}
		opts.Authenticator = auth
		noReload := newAggregateLoadCanary(t, ctx, store)
		server, err := newNativeHTTPFixture(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != want || !noReload.Intact(ctx) || strings.Contains(rec.Body.String(), "private waiver SQL") {
			t.Fatalf("waiver got %d want %d canary=%t: %s", rec.Code, want, noReload.Intact(ctx), rec.Body.String())
		}
		if want >= 400 {
			if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("unsafe waiver problem response")
			}
			return domain.Waiver{}
		}
		var v struct {
			Data domain.Waiver `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v.Data
	}
	create := func(scope, id string) string {
		return fmt.Sprintf(`{"scope_type":%q,"scope_id":%q,"control_id":"control","policy_id":"policy","owner":"Owner","risk":"low","reason":"Reviewed","expires_at":%q}`, scope, id, time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond).Format(time.RFC3339Nano))
	}
	counts := func(wantRecords, wantAudits int) {
		t.Helper()
		var records, audits int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*) FROM waivers),(SELECT count(*) FROM audit_chain_entries WHERE entry_type IN ('waiver.created','waiver.approved') AND actor_id='human')`).Scan(&records, &audits); err != nil || records != wantRecords || audits != wantAudits {
			t.Fatal("waiver effects leaked", records, audits, wantRecords, wantAudits, err)
		}
	}
	for i, scope := range []string{"release", "finding", "control", "policy"} {
		body := create(scope, scope)
		key := "create-" + scope
		v := request("/v1/waivers", key, body, 201)
		if v.ID == "" || v.TenantID != "tenant" || v.ScopeType != scope || v.ScopeID != scope || v.ControlID != "control" || v.PolicyID != "policy" || v.Reason != "Reviewed" || v.Owner != "Owner" || v.Risk != "low" || v.Approved || v.ApprovedAt != nil || v.SchemaVersion != domain.WaiverSchemaVersion || v.CreatedAt.IsZero() || v.CreatedAt.Nanosecond()%1000 != 0 {
			t.Fatal("waiver DTO changed", v)
		}
		if replay := request("/v1/waivers", key, body, 201); !reflect.DeepEqual(replay, v) {
			t.Fatal("fresh-server create replay changed", replay, v)
		}
		request("/v1/waivers", key, body+" ", 409)
		path := "/v1/waivers/" + v.ID + "/approve"
		approved := request(path, "approve-"+scope, `{}`, 200)
		want := v
		want.Approved = true
		want.ApprovedBy = "human"
		want.ApprovedAt = approved.ApprovedAt
		if approved.ApprovedAt == nil || !reflect.DeepEqual(approved, want) {
			t.Fatal("approval changed immutable waiver fields", approved, want)
		}
		if replay := request(path, "approve-"+scope, `{}`, 200); !reflect.DeepEqual(replay, approved) {
			t.Fatal("approval replay changed", replay, approved)
		}
		request(path, "second-approval-"+scope, `{}`, 409)
		auth.actor.ResourceGrants = nil
		request("/v1/waivers", key, body, 403)
		request(path, "approve-"+scope, `{}`, 403)
		auth.actor = actor
		auth.actor.TenantID = "other"
		request("/v1/waivers", "foreign-create-"+scope, body, 404)
		request(path, "foreign-approve-"+scope, `{}`, 404)
		auth.actor = actor
		counts(2+i, 2*(i+1))
	}
	body := create("release", "release")
	body = strings.TrimSuffix(body, "}") + `,"supersedes":"waiver"}`
	v := request("/v1/waivers", "supersede", body, 201)
	if v.Supersedes != "waiver" {
		t.Fatal("supersession reference lost", v)
	}
	var unchanged bool
	if err := pool.QueryRow(ctx, `SELECT reason=repeat('x',9000000) AND superseded_by=$1 FROM waivers WHERE id='waiver'`, v.ID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("supersession read/enriched historical reason", err)
	}
	if replay := request("/v1/waivers", "supersede", body, 201); !reflect.DeepEqual(replay, v) {
		t.Fatal("supersession replay rejected its own transition", replay, v)
	}
	request("/v1/waivers", "second-supersede", body, 409)
	counts(6, 9)
	base := create("release", "release")
	for i, bad := range []string{`{`, `null`, `[]`, base + ` {}`, strings.ReplaceAll(base, `"release","scope_id"`, `"product","scope_id"`), strings.ReplaceAll(base, `"Reviewed"`, `"bad\u0000"`), strings.ReplaceAll(base, `"Reviewed"`, `"`+strings.Repeat("x", 65537)+`"`), strings.ReplaceAll(base, `"scope_id":"release"`, `"scope_id":"release","scope_id":"release"`)} {
		request("/v1/waivers", fmt.Sprintf("bad-%d", i), bad, 400)
	}
	for i, field := range []string{"scope_type", "scope_id", "control_id", "policy_id", "owner", "risk", "reason", "expires_at", "supersedes"} {
		var fields map[string]any
		if err := json.Unmarshal([]byte(base), &fields); err != nil {
			t.Fatal(err)
		}
		fields[field] = nil
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		request("/v1/waivers", fmt.Sprintf("null-%d", i), string(raw), 400)
	}
	request("/v1/waivers/bad%00/approve", "bad-id", `{}`, 400)
	for _, table := range []string{"waivers", "audit_chain_entries", "idempotency_records"} {
		op := "INSERT"
		if table == "idempotency_records" {
			op = "UPDATE"
		}
		if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_waiver_http() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private waiver SQL';END$$;CREATE TRIGGER reject_waiver_http BEFORE `+op+` ON `+table+` FOR EACH ROW EXECUTE FUNCTION reject_waiver_http()`); err != nil {
			t.Fatal(err)
		}
		request("/v1/waivers", "failure-"+table, base, 500)
		counts(6, 9)
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_waiver_http ON `+table+`;DROP FUNCTION reject_waiver_http()`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_waiver_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private waiver SQL';END$$;CREATE CONSTRAINT TRIGGER reject_waiver_commit AFTER INSERT ON waivers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_waiver_commit()`); err != nil {
		t.Fatal(err)
	}
	request("/v1/waivers", "failure-commit", base, 500)
	counts(6, 9)
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_waiver_commit ON waivers;DROP FUNCTION reject_waiver_commit()`); err != nil {
		t.Fatal(err)
	}
	request("/v1/waivers", "failure-commit", base, 201)
	counts(7, 10)
	records, audits := 7, 10
	for _, stage := range []string{"waivers", "audit_chain_entries", "idempotency_records", "commit"} {
		pending := request("/v1/waivers", "approval-fixture-"+stage, base, 201)
		records++
		audits++
		op := "INSERT"
		if stage == "waivers" || stage == "idempotency_records" {
			op = "UPDATE"
		}
		trigger := `CREATE TRIGGER reject_waiver_approval BEFORE ` + op + ` ON ` + stage + ` FOR EACH ROW EXECUTE FUNCTION reject_waiver_approval()`
		table := stage
		if stage == "commit" {
			table = "waivers"
			trigger = `CREATE CONSTRAINT TRIGGER reject_waiver_approval AFTER UPDATE ON waivers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_waiver_approval()`
		}
		if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_waiver_approval() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private waiver SQL';END$$;`+trigger); err != nil {
			t.Fatal(err)
		}
		path := "/v1/waivers/" + pending.ID + "/approve"
		key := "approval-failure-" + stage
		request(path, key, `{}`, 500)
		counts(records, audits)
		var unapproved bool
		if err := pool.QueryRow(ctx, `SELECT NOT approved AND approved_by IS NULL AND approved_at IS NULL FROM waivers WHERE id=$1`, pending.ID).Scan(&unapproved); err != nil || !unapproved {
			t.Fatal("failed approval mutated lifecycle state", stage, err)
		}
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_waiver_approval ON `+table+`;DROP FUNCTION reject_waiver_approval()`); err != nil {
			t.Fatal(err)
		}
		if stage == "commit" || stage == "idempotency_records" {
			request(path, key, `{}`, 200)
		} else {
			request(path, key, `{}`, 409)
			request(path, key+"-retry", `{}`, 200)
		}
		audits++
		counts(records, audits)
	}
}

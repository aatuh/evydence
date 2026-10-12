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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type exceptionHTTPFixture struct {
	t     *testing.T
	ctx   context.Context
	store *postgres.Store
	pool  *pgxpool.Pool
	auth  *attestationHTTPActor
}

func newExceptionHTTPFixture(t *testing.T) *exceptionHTTPFixture {
	t.Helper()
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	t.Cleanup(cancel)
	seedControlEvidenceSubjects(t, ctx, store, pool)
	if _, err := pool.Exec(ctx, `UPDATE vulnerability_scans SET findings='[{"id":"finding","vulnerability":"CVE-TEST"}]'`); err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"release:write"}}}}
	return &exceptionHTTPFixture{t, ctx, store, pool, &attestationHTTPActor{actor: actor}}
}
func (f *exceptionHTTPFixture) request(path, key, body string, want int) domain.Exception {
	f.t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: f.store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: f.store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return f.store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil {
		f.t.Fatal(err)
	}
	if opts.ExceptionCommands == nil || opts.DurableCommandExecutor == nil {
		f.t.Fatal("production exception composition missing")
	}
	opts.Authenticator = f.auth
	noReload := newAggregateLoadCanary(f.t, f.ctx, f.store)
	server, err := newNativeHTTPFixture(f.ctx, opts)
	if err != nil {
		f.t.Fatal(err)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer isolated-auth")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", key)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want || !noReload.Intact(f.ctx) || strings.Contains(rec.Body.String(), "private exception SQL") {
		f.t.Fatalf("exception got %d want %d canary=%t: %s", rec.Code, want, noReload.Intact(f.ctx), rec.Body.String())
	}
	if want >= 400 {
		if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
			f.t.Fatal("unsafe exception problem response")
		}
		return domain.Exception{}
	}
	if rec.Header().Get("Idempotency-Key") != key {
		f.t.Fatal("missing exception replay key")
	}
	var v struct {
		Data domain.Exception `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		f.t.Fatal(err)
	}
	return v.Data
}
func (f *exceptionHTTPFixture) counts(wantRecords, wantAudits int) {
	f.t.Helper()
	var records, audits int
	err := f.pool.QueryRow(f.ctx, `SELECT(SELECT count(*) FROM exceptions),(SELECT count(*) FROM audit_chain_entries WHERE entry_type IN ('exception.created','exception.approved') AND actor_id='human')`).Scan(&records, &audits)
	if err != nil || records != wantRecords || audits != wantAudits {
		f.t.Fatal("exception effects leaked", records, audits, wantRecords, wantAudits, err)
	}
}
func exceptionHTTPBody(finding, control string) string {
	return fmt.Sprintf(`{"release_id":"release","finding_id":%q,"control_id":%q,"owner":"Owner","reason":"Reviewed","expires_at":%q}`, finding, control, time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond).Format(time.RFC3339Nano))
}
func TestPostgresExceptionHTTPUsesBoundedTransactionsAndDurableReplay(t *testing.T) {
	if _, err := BuildExceptionCommands(nil); err == nil {
		t.Fatal("nil exception transactions accepted")
	}
	f := newExceptionHTTPFixture(t)
	actor := f.auth.actor
	for i, refs := range [][2]string{{"", ""}, {"finding", ""}, {"", "control"}, {"finding", "control"}} {
		body, key := exceptionHTTPBody(refs[0], refs[1]), fmt.Sprintf("create-%d", i)
		v := f.request("/v1/exceptions", key, body, 201)
		if v.ID == "" || v.TenantID != "tenant" || v.ReleaseID != "release" || v.FindingID != refs[0] || v.ControlID != refs[1] || v.Owner != "Owner" || v.Reason != "Reviewed" || v.Approved || v.ApprovedBy != "" || v.ApprovedAt != nil || v.CreatedAt.IsZero() || v.CreatedAt.Nanosecond()%1000 != 0 || !v.ExpiresAt.After(v.CreatedAt) {
			t.Fatal("exception DTO changed", v)
		}
		if replay := f.request("/v1/exceptions", key, body, 201); !reflect.DeepEqual(replay, v) {
			t.Fatal("create replay changed", replay, v)
		}
		f.request("/v1/exceptions", key, body+" ", 409)
		path := "/v1/exceptions/" + v.ID + "/approve"
		approved := f.request(path, key+"-approve", `{}`, 200)
		want := v
		want.Approved = true
		want.ApprovedBy = "human"
		want.ApprovedAt = approved.ApprovedAt
		if approved.ApprovedAt == nil || !reflect.DeepEqual(approved, want) {
			t.Fatal("approval changed immutable exception core", approved, want)
		}
		for _, retryKey := range []string{key + "-approve", key + "-again"} {
			if replay := f.request(path, retryKey, `{}`, 200); !reflect.DeepEqual(replay, approved) {
				t.Fatal("natural approval idempotency changed", replay, approved)
			}
		}
		f.auth.actor.ResourceGrants = nil
		f.request("/v1/exceptions", key, body, 403)
		f.request(path, key+"-approve", `{}`, 403)
		f.request(path, key+"-denied", `{}`, 403)
		f.auth.actor = actor
		f.auth.actor.TenantID = "other"
		f.request("/v1/exceptions", key+"-foreign", body, 404)
		f.request(path, key+"-foreign", `{}`, 404)
		f.auth.actor = actor
		f.counts(2+i, 2*(i+1))
	}
	base := exceptionHTTPBody("finding", "control")
	for i, bad := range []string{`{`, `null`, `[]`, base + ` {}`, strings.ReplaceAll(base, `"Reviewed"`, `"bad\u0000"`), strings.ReplaceAll(base, `"Reviewed"`, `"`+strings.Repeat("x", 65537)+`"`), strings.ReplaceAll(base, `"release_id":"release"`, `"release_id":"release","release_id":"release"`), strings.TrimSuffix(base, "}") + `,"unknown":true}`} {
		f.request("/v1/exceptions", fmt.Sprintf("bad-%d", i), bad, 400)
	}
	for i, field := range []string{"release_id", "finding_id", "control_id", "owner", "reason", "expires_at"} {
		var fields map[string]any
		if err := json.Unmarshal([]byte(base), &fields); err != nil {
			t.Fatal(err)
		}
		fields[field] = nil
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		f.request("/v1/exceptions", fmt.Sprintf("null-%d", i), string(raw), 400)
	}
	f.request("/v1/exceptions/bad%00/approve", "bad-id", `{}`, 400)
	f.counts(5, 8)
	// Current parent ownership is rechecked before both writes and saved replay.
	v := f.request("/v1/exceptions", "parent-fixture", base, 201)
	if _, err := f.pool.Exec(f.ctx, `UPDATE exceptions SET control_id='foreign' WHERE id=$1`, v.ID); err != nil {
		t.Fatal(err)
	}
	f.request("/v1/exceptions/"+v.ID+"/approve", "missing-parent", `{}`, 404)
	f.request("/v1/exceptions", "missing-control", strings.ReplaceAll(base, `"control_id":"control"`, `"control_id":"foreign"`), 404)
	f.counts(6, 9)
}

func TestPostgresExceptionHTTPRollsBackWriteAuditCompletionAndCommitFailures(t *testing.T) {
	f := newExceptionHTTPFixture(t)
	base := exceptionHTTPBody("finding", "control")
	records, audits := 1, 0
	for _, approval := range []bool{false, true} {
		for _, stage := range []string{"exceptions", "audit_chain_entries", "idempotency_records", "commit"} {
			path, key := "/v1/exceptions", fmt.Sprintf("failure-%t-%s", approval, stage)
			var pending domain.Exception
			body := base
			if approval {
				pending = f.request(path, "fixture-"+key, base, 201)
				records++
				audits++
				path = "/v1/exceptions/" + pending.ID + "/approve"
				body = `{}`
			}
			op, table := "INSERT", stage
			if stage == "idempotency_records" || approval && stage == "exceptions" {
				op = "UPDATE"
			}
			trigger := `CREATE TRIGGER reject_exception_http BEFORE ` + op + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_exception_http()`
			if stage == "commit" {
				table = "exceptions"
				if approval {
					op = "UPDATE"
				}
				trigger = `CREATE CONSTRAINT TRIGGER reject_exception_http AFTER ` + op + ` ON exceptions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_exception_http()`
			}
			if _, err := f.pool.Exec(f.ctx, `CREATE FUNCTION reject_exception_http() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private exception SQL';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			f.request(path, key, body, 500)
			f.counts(records, audits)
			if approval {
				var unchanged bool
				if err := f.pool.QueryRow(f.ctx, `SELECT NOT approved AND approved_by IS NULL AND approved_at IS NULL FROM exceptions WHERE id=$1`, pending.ID).Scan(&unchanged); err != nil || !unchanged {
					t.Fatal("failed approval leaked metadata", stage, err)
				}
			}
			if _, err := f.pool.Exec(f.ctx, `DROP TRIGGER reject_exception_http ON `+table+`;DROP FUNCTION reject_exception_http()`); err != nil {
				t.Fatal(err)
			}
			status := 201
			if approval {
				status = 200
			}
			if stage != "commit" && stage != "idempotency_records" {
				f.request(path, key, body, 409)
				key += "-retry"
			}
			f.request(path, key, body, status)
			audits++
			if !approval {
				records++
			}
			f.counts(records, audits)
		}
	}
}

func TestPostgresExceptionHTTPReplayRequiresCurrentParentsButSurvivesExpiry(t *testing.T) {
	f := newExceptionHTTPFixture(t)
	body := exceptionHTTPBody("finding", "control")
	v := f.request("/v1/exceptions", "create", body, 201)
	path := "/v1/exceptions/" + v.ID + "/approve"
	approved := f.request(path, "approve", `{}`, 200)
	for _, test := range []struct{ name, change, restore string }{
		{"product ownership", `UPDATE products SET tenant_id='other' WHERE id='product'`, `UPDATE products SET tenant_id='tenant' WHERE id='product'`},
		{"finding linkage", `UPDATE vulnerability_scans SET release_id='missing' WHERE id='scan'`, `UPDATE vulnerability_scans SET release_id='release' WHERE id='scan'`},
		{"control ownership", `UPDATE security_controls SET tenant_id='other' WHERE id='control'`, `UPDATE security_controls SET tenant_id='tenant' WHERE id='control'`},
		{"framework ownership", `UPDATE control_frameworks SET tenant_id='other' WHERE id='fw'`, `UPDATE control_frameworks SET tenant_id='tenant' WHERE id='fw'`},
	} {
		if _, err := f.pool.Exec(f.ctx, test.change); err != nil {
			t.Fatal(err)
		}
		f.request("/v1/exceptions", "create", body, 404)
		f.request(path, "approve", `{}`, 404)
		f.request(path, "new-"+test.name, `{}`, 404)
		f.counts(2, 2)
		if _, err := f.pool.Exec(f.ctx, test.restore); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE exceptions SET expires_at=now()-interval '1 hour' WHERE id=$1`, v.ID); err != nil {
		t.Fatal(err)
	}
	if replay := f.request(path, "approve", `{}`, 200); !reflect.DeepEqual(replay, approved) {
		t.Fatal("completed approval replay lost saved response after expiry", replay, approved)
	}
	f.request(path, "expired-new", `{}`, 409)
	f.counts(2, 2)
}

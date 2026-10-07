package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresApprovalHTTPUsesCurrentSubjectsAndAtomicReplayWithoutLedger(t *testing.T) {
	if _, err := BuildApprovalCommands(nil); err == nil {
		t.Fatal("nil approval factory accepted")
	}
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	seedApprovalSubjects(t, ctx, store, pool)
	// The identifier-only command fixture omits severity, which the release
	// summary correctly requires. Supply it without shrinking hostile documents.
	if _, err := pool.Exec(ctx, `UPDATE vulnerability_scans SET findings='[{"id":"finding","vulnerability":"CVE-TEST","severity":"high","state":"open"}]'`); err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"release:write"}}}}
	auth := &attestationHTTPActor{actor: actor}
	request := func(key, body string, want int) string {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		if opts.ApprovalCommands == nil || opts.DurableCommandExecutor == nil {
			t.Fatal("production approval composition missing")
		}
		opts.Authenticator = auth
		noReload := newAggregateLoadCanary(t, ctx, store)
		server, err := newNativeHTTPFixture(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/v1/approvals", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != want || !noReload.Intact(ctx) || strings.Contains(rec.Body.String(), "private approval SQL") {
			t.Fatalf("approval got %d want %d canary=%t: %s", rec.Code, want, noReload.Intact(ctx), rec.Body.String())
		}
		if want >= 400 && !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
			t.Fatal("approval lost safe Problem Details")
		}
		return rec.Body.String()
	}
	decode := func(body string) domain.ApprovalRecord {
		t.Helper()
		var v struct {
			Data domain.ApprovalRecord `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatal(err)
		}
		return v.Data
	}
	count := 0
	counts := func() {
		t.Helper()
		var records, audits int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM approval_records),(SELECT count(*)FROM audit_chain_entries WHERE entry_type='approval.created' AND actor_id='human' AND actor_type='human_user')`).Scan(&records, &audits); err != nil || records != count || audits != count {
			t.Fatal("approval effects leaked", records, audits, count, err)
		}
	}
	lifecycle := func() [2]string {
		t.Helper()
		var hashes [2]string
		if err := pool.QueryRow(ctx, `SELECT md5(to_jsonb(r)::text),md5(to_jsonb(w)::text) FROM releases r,waivers w WHERE r.id='release' AND w.id='waiver'`).Scan(&hashes[0], &hashes[1]); err != nil {
			t.Fatal(err)
		}
		return hashes
	}
	beforeLifecycle := lifecycle()
	for i, subject := range []struct{ typ, id string }{{"release", "release"}, {"contract_diff", "diff"}, {"waiver", "waiver"}, {"security_review", "review"}, {"customer_package", "package"}} {
		body := fmt.Sprintf(`{"subject_type":%q,"subject_id":%q,"decision":"accepted","reason":"Reviewed"}`, subject.typ, subject.id)
		key := fmt.Sprintf("accepted-%d", i)
		v := decode(request(key, body, 201))
		count++
		if v.ID == "" || v.Decision != "accepted" || v.SubjectType != subject.typ || v.SubjectID != subject.id || v.ApproverID != "human" || v.Reason != "Reviewed" || v.SchemaVersion != domain.ApprovalRecordSchemaVersion || v.CreatedAt.IsZero() {
			t.Fatal("accepted decision was rejected or promoted", v)
		}
		if replay := decode(request(key, body, 201)); replay != v {
			t.Fatal("accepted replay changed immutable record", replay, v)
		}
		request(key, strings.ReplaceAll(body, `"accepted"`, `"approved"`), 409)
		auth.actor.ResourceGrants = nil
		request(key, body, 403)
		request(key+"-denied", body, 403)
		auth.actor = actor
		auth.actor.TenantID = "other"
		request(key+"-foreign", body, 404)
		auth.actor = actor
		counts()
	}
	if after := lifecycle(); after != beforeLifecycle {
		t.Fatal("accepted records changed waiver or release lifecycle", beforeLifecycle, after)
	}
	summary, err := store.ReadReleaseSecuritySummarySnapshot(ctx, "tenant", "release")
	if err != nil || summary.ApprovalSummary.Total != 1 || summary.ApprovalSummary.Approved != 0 {
		t.Fatal("accepted record was counted as an approved release", summary.ApprovalSummary, err)
	}
	for i, subject := range []struct{ typ, id string }{{"release", "release"}, {"contract_diff", "diff"}, {"waiver", "waiver"}, {"security_review", "review"}, {"customer_package", "package"}} {
		body := fmt.Sprintf(`{"subject_type":%q,"subject_id":%q,"decision":"approved","reason":"Reviewed","evidence_id":"ev-sbom"}`, subject.typ, subject.id)
		key := fmt.Sprintf("approval-%d", i)
		v := decode(request(key, body, 201))
		count++
		if v.ID == "" || v.TenantID != "tenant" || v.SubjectType != subject.typ || v.SubjectID != subject.id || v.Decision != "approved" || v.Reason != "Reviewed" || v.ApproverID != "human" || v.EvidenceID != "ev-sbom" || v.SchemaVersion != domain.ApprovalRecordSchemaVersion || v.CreatedAt.IsZero() || v.CreatedAt.Nanosecond()%1000 != 0 {
			t.Fatal("approval DTO changed", v)
		}
		if replay := decode(request(key, body, 201)); replay != v {
			t.Fatal("fresh-server replay changed immutable approval", replay, v)
		}
		request(key, body+" ", 409)
		counts()
	}
	body := `{"subject_type":"release","subject_id":"release","decision":"approved","reason":"Reviewed","evidence_id":"ev-sbom"}`
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"release:write"}}}
	request("approval-0", body, 201)
	auth.actor = actor
	if _, err := pool.Exec(ctx, `INSERT INTO evidence_items SELECT(jsonb_populate_record(NULL::evidence_items,to_jsonb(e)||'{"id":"unscoped-evidence","product_id":null,"release_id":null,"project_id":null}'::jsonb)).* FROM evidence_items e WHERE id='ev-sbom'`); err != nil {
		t.Fatal(err)
	}
	request("same-tenant-evidence", strings.ReplaceAll(body, "ev-sbom", "unscoped-evidence"), 201)
	count++
	counts()
	auth.actor.ResourceGrants = nil
	request("approval-0", body, 403)
	request("denied-new", body, 403)
	auth.actor = actor
	auth.actor.TenantID = "other"
	request("foreign-subject", body, 404)
	auth.actor = actor
	auth.actor.Scopes = []string{"release:read"}
	request("approval-0", body, 403)
	auth.actor = actor
	request("foreign-evidence", strings.ReplaceAll(body, "ev-sbom", "missing"), 404)
	for i, bad := range []string{`{`, `null`, `[]`, `{}`, body + ` {}`, strings.ReplaceAll(body, `"release","decision"`, `"release","subject_id":"release","decision"`), strings.ReplaceAll(body, `"approved"`, `"unknown"`), strings.ReplaceAll(body, `"Reviewed"`, `"bad\u0000"`), strings.ReplaceAll(body, `"release","subject_id"`, `"artifact","subject_id"`), strings.ReplaceAll(body, "Reviewed", strings.Repeat("x", 65537))} {
		request(fmt.Sprintf("bad-%d", i), bad, 400)
	}
	for i, field := range []string{"subject_type", "subject_id", "decision", "reason", "evidence_id"} {
		fields := map[string]any{"subject_type": "release", "subject_id": "release", "decision": "approved", "reason": "Reviewed", field: nil}
		encoded, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		request(fmt.Sprintf("null-%d", i), string(encoded), 400)
	}
	for i, scope := range []string{"control", "policy"} {
		if _, err := pool.Exec(ctx, `UPDATE waivers SET scope_type=$1,scope_id=$1 WHERE id='waiver'`, scope); err != nil {
			t.Fatal(err)
		}
		waiverBody := strings.ReplaceAll(strings.ReplaceAll(body, `"subject_type":"release"`, `"subject_type":"waiver"`), `"subject_id":"release"`, `"subject_id":"waiver"`)
		request(fmt.Sprintf("tenant-required-%d", i), waiverBody, 403)
		auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"release:write"}}}
		request(fmt.Sprintf("tenant-grant-%d", i), waiverBody, 201)
		count++
		counts()
		auth.actor = actor
	}
	for _, table := range []string{"approval_records", "audit_chain_entries", "idempotency_records"} {
		op := "INSERT"
		if table == "idempotency_records" {
			op = "UPDATE"
		}
		if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_approval_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private approval SQL';END$$;CREATE TRIGGER reject_approval_http BEFORE `+op+` ON `+table+` FOR EACH ROW EXECUTE FUNCTION reject_approval_http()`); err != nil {
			t.Fatal(err)
		}
		request("failure-"+table, body, 500)
		counts()
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_approval_http ON `+table+`;DROP FUNCTION reject_approval_http()`); err != nil {
			t.Fatal(err)
		}
		if table == "idempotency_records" {
			request("failure-"+table, body, 201)
			count++
		} else {
			request("failure-"+table, body, 409)
		}
		counts()
	}
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_approval_commit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private approval SQL';END$$;CREATE CONSTRAINT TRIGGER reject_approval_commit AFTER INSERT ON approval_records DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_approval_commit()`); err != nil {
		t.Fatal(err)
	}
	request("failure-commit", body, 500)
	counts()
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_approval_commit ON approval_records;DROP FUNCTION reject_approval_commit()`); err != nil {
		t.Fatal(err)
	}
	request("failure-commit", body, 201)
	count++
	counts()
}

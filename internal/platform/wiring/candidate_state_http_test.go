package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresCandidateStateHTTPDoesNotRequireLedgerCandidates(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Candidate HTTP'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product');INSERT INTO releases(id,tenant_id,product_id,version,state,revision)VALUES('release','tenant','product',repeat('v',65537),'draft',1);INSERT INTO release_candidates(id,tenant_id,release_id,name,state,snapshot_hash,document,schema_version,revision,created_at)VALUES('candidate','tenant','release','Snapshot','open','sha256:'||repeat('c',64),'{"build_ids":["build"],"artifact_ids":["artifact"],"sbom_ids":["sbom"],"scan_ids":["scan"],"vex_ids":["vex"],"contract_ids":["contract"],"bundle_ids":["bundle"]}','evydence.release-candidate.v1',1,now()),('failure','tenant','release','Failure','open','sha256:'||repeat('f',64),'{}','evydence.release-candidate.v1',1,now())`)
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:read", "release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"release:read", "release:write"}}}}
	auth := &attestationHTTPActor{actor: actor}
	newServer := func() http.Handler {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.CandidateStateCommands == nil {
			t.Fatal("candidate transition not composed", err)
		}
		opts.Authenticator = auth
		_ = newAggregateLoadCanary(t, ctx, store)
		server, err := newNativeHTTPFixture(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		return server.Handler()
	}
	request := func(method, path, key, tag, body string, want int) string {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		if tag != "" {
			req.Header.Set("If-Match", tag)
		}
		rec := httptest.NewRecorder()
		newServer().ServeHTTP(rec, req)
		if rec.Code != want || strings.Contains(rec.Body.String(), "private candidate SQL") {
			t.Fatalf("HTTP %s %s got %d want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		return rec.Body.String()
	}
	decode := func(body string) domain.ReleaseCandidate {
		t.Helper()
		var v struct {
			Data domain.ReleaseCandidate `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatal(err)
		}
		v.Data.CreatedAt = v.Data.CreatedAt.UTC()
		if v.Data.PromotedAt != nil {
			at := v.Data.PromotedAt.UTC()
			v.Data.PromotedAt = &at
		}
		if v.Data.RejectedAt != nil {
			at := v.Data.RejectedAt.UTC()
			v.Data.RejectedAt = &at
		}
		return v.Data
	}
	counts := func(id string, wantRev, wantAudits int) {
		t.Helper()
		var rev, audits int
		if err := pool.QueryRow(ctx, `SELECT revision,(SELECT count(*)FROM audit_chain_entries)FROM release_candidates WHERE id=$1`, id).Scan(&rev, &audits); err != nil || rev != wantRev || audits != wantAudits {
			t.Fatal("candidate state/audit effects wrong", rev, audits, err)
		}
	}
	initial := decode(request("GET", "/v1/release-candidates/candidate", "", "", "", 200))
	for i, bad := range []string{`{`, `{} {}`, `[]`, `null`, `{}`, `{"reason":null}`, `{"reason":1}`, `{"reason":" "}`, `{"reason":"bad\u0000reason"}`, `{"reason":"reviewed","reason":"other"}`, `{"reason":"reviewed","tenant_id":"other"}`} {
		request("POST", "/v1/release-candidates/candidate/promote", fmt.Sprintf("invalid-candidate-%d", i), `"1"`, bad, 400)
	}
	for i, tag := range []string{"", `W/"1"`, `"01"`, `"+1"`, `"0"`, `"1", "2"`} {
		request("POST", "/v1/release-candidates/candidate/promote", fmt.Sprintf("bad-candidate-tag-%d", i), tag, `{"reason":"reviewed"}`, 400)
	}
	counts("candidate", 1, 0)
	request("POST", "/v1/release-candidates/candidate/promote", "oversized-candidate-body", `"1"`, strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1), 400)
	promoted := decode(request("POST", "/v1/release-candidates/candidate/promote", "promote", `"1"`, `{"reason":"reviewed"}`, 200))
	want := initial
	want.State = "promoted"
	want.Revision = 2
	want.PromotedAt = promoted.PromotedAt
	if promoted.PromotedAt == nil || promoted.PromotedAt.Nanosecond()%1000 != 0 || !reflect.DeepEqual(promoted, want) {
		t.Fatal("candidate response changed immutable snapshot", promoted, want)
	}
	if replay := decode(request("POST", "/v1/release-candidates/candidate/promote", "promote", `"1"`, `{"reason":"reviewed"}`, 200)); !reflect.DeepEqual(replay, promoted) {
		t.Fatal("candidate replay changed", replay, promoted)
	}
	request("POST", "/v1/release-candidates/candidate/promote", "promote", `"2"`, `{"reason":"reviewed"}`, 409)
	request("POST", "/v1/release-candidates/candidate/promote", "promote", `"1"`, `{"reason":"other"}`, 409)
	request("POST", "/v1/release-candidates/candidate/promote", "promote", "", `{"reason":"reviewed"}`, 400)
	if read := decode(request("GET", "/v1/release-candidates/candidate", "", "", "", 200)); !reflect.DeepEqual(read, promoted) {
		t.Fatal("candidate durable read changed", read, promoted)
	}
	var list struct {
		Data []domain.ReleaseCandidate `json:"data"`
	}
	if err := json.Unmarshal([]byte(request("GET", "/v1/release-candidates", "", "", "", 200)), &list); err != nil || len(list.Data) != 2 {
		t.Fatal("candidate list changed", list, err)
	}
	found := false
	for _, v := range list.Data {
		if v.ID == promoted.ID {
			v.CreatedAt = v.CreatedAt.UTC()
			if v.PromotedAt != nil {
				at := v.PromotedAt.UTC()
				v.PromotedAt = &at
			}
			if !reflect.DeepEqual(v, promoted) {
				t.Fatal("candidate list lost snapshot", v, promoted)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("promoted candidate absent from durable list")
	}
	if body := request("POST", "/v1/release-candidates/candidate/reject", "terminal", `"2"`, `{"reason":"reviewed"}`, 409); strings.Contains(body, "current_revision") {
		t.Fatal("terminal-state conflict exposed revision", body)
	}
	stale := request("POST", "/v1/release-candidates/candidate/reject", "stale", `"1"`, `{"reason":"reviewed"}`, 409)
	if !strings.Contains(stale, `"code":"VERSION_CONFLICT"`) || !strings.Contains(stale, `"current_revision":2`) {
		t.Fatal("candidate revision mapping lost", stale)
	}
	auth.actor = actor
	auth.actor.TenantID = "other"
	if body := request("POST", "/v1/release-candidates/candidate/reject", "foreign", `"1"`, `{"reason":"reviewed"}`, 404); strings.Contains(body, "current_revision") {
		t.Fatal("foreign actor saw revision", body)
	}
	auth.actor = actor
	auth.actor.ResourceGrants = nil
	if body := request("POST", "/v1/release-candidates/candidate/reject", "revoked", `"1"`, `{"reason":"reviewed"}`, 403); strings.Contains(body, "current_revision") {
		t.Fatal("revoked grant saw revision", body)
	}
	auth.actor = actor
	counts("candidate", 2, 1)
	for _, table := range []string{"release_candidates", "audit_chain_entries"} {
		event := "UPDATE"
		if table == "audit_chain_entries" {
			event = "INSERT"
		}
		exec(`CREATE FUNCTION reject_candidate_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private candidate SQL';END$$;CREATE TRIGGER reject_candidate_http BEFORE ` + event + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_candidate_http()`)
		request("POST", "/v1/release-candidates/failure/reject", "fail-"+table, `"1"`, `{"reason":"reviewed"}`, 500)
		exec(`DROP TRIGGER reject_candidate_http ON ` + table + `;DROP FUNCTION reject_candidate_http()`)
		request("POST", "/v1/release-candidates/failure/reject", "fail-"+table, `"1"`, `{"reason":"reviewed"}`, 409)
		counts("failure", 1, 1)
	}
	rejected := decode(request("POST", "/v1/release-candidates/failure/reject", "reject", `"1"`, `{"reason":"reviewed"}`, 200))
	if rejected.ID != "failure" || rejected.State != "rejected" || rejected.Revision != 2 || rejected.RejectedAt == nil || rejected.PromotedAt != nil {
		t.Fatal("candidate rejection failed", rejected)
	}
	counts("failure", 2, 2)
}

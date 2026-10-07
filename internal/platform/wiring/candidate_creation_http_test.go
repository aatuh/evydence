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

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresCandidateCreationHTTPAndTransitionsDoNotRequireLedgerCandidates(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Candidate HTTP'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product');INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product','Project');INSERT INTO releases(id,tenant_id,product_id,version,state,revision)VALUES('release','tenant','product','1','draft',1)`)
	if err := app.ExecuteUnitOfWork(ctx, store, candidateReferenceFixture); err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:read", "release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"release:read", "release:write"}}}}
	auth := &attestationHTTPActor{actor: actor}
	var servers []*httpapi.Server
	newServer := func() http.Handler {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.CandidateCommands == nil || opts.CandidateStateCommands == nil {
			t.Fatal("candidate commands not composed", err)
		}
		opts.Authenticator = auth
		_ = newAggregateLoadCanary(t, ctx, store)
		server, err := newNativeHTTPFixture(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		servers = append(servers, server)
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
		return v.Data
	}
	counts := func(wantCandidates, wantAudits int) {
		t.Helper()
		var c, a int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM release_candidates),(SELECT count(*)FROM audit_chain_entries)`).Scan(&c, &a); err != nil || c != wantCandidates || a != wantAudits {
			t.Fatal("candidate effects changed", c, a, err)
		}
	}
	body := `{"release_id":" release ","name":" Snapshot ","build_ids":[" build "],"artifact_ids":["artifact"],"sbom_ids":["sbom"],"scan_ids":["scan"],"vex_ids":["vex"],"contract_ids":["contract"],"bundle_ids":["bundle"]}`
	created := decode(request("POST", "/v1/release-candidates", "create-candidate", "", body, 201))
	if created.ID == "" || created.TenantID != "tenant" || created.ReleaseID != "release" || created.Name != "Snapshot" || created.State != "open" || created.Revision != 1 || created.SchemaVersion != domain.ReleaseCandidateSchemaVersion || created.CreatedAt.IsZero() || created.CreatedAt.Nanosecond()%1000 != 0 || created.PromotedAt != nil || created.RejectedAt != nil || !strings.HasPrefix(created.SnapshotHash, "sha256:") {
		t.Fatal("candidate creation fields changed", created)
	}
	for _, ref := range []struct {
		ids []string
		id  string
	}{{created.BuildIDs, "build"}, {created.ArtifactIDs, "artifact"}, {created.SBOMIDs, "sbom"}, {created.ScanIDs, "scan"}, {created.VEXIDs, "vex"}, {created.ContractIDs, "contract"}, {created.BundleIDs, "bundle"}} {
		if !reflect.DeepEqual(ref.ids, []string{ref.id}) {
			t.Fatal("snapshot reference list changed", ref)
		}
	}
	counts(1, 1)
	if replay := decode(request("POST", "/v1/release-candidates", "create-candidate", "", body, 201)); !reflect.DeepEqual(replay, created) {
		t.Fatal("fresh-server create replay changed", replay, created)
	}
	request("POST", "/v1/release-candidates", "create-candidate", "", body+" ", 409)
	if read := decode(request("GET", "/v1/release-candidates/"+created.ID, "", "", "", 200)); !reflect.DeepEqual(read, created) {
		t.Fatal("created candidate durable read changed", read, created)
	}
	var list struct {
		Data []domain.ReleaseCandidate `json:"data"`
	}
	if err := json.Unmarshal([]byte(request("GET", "/v1/release-candidates", "", "", "", 200)), &list); err != nil || len(list.Data) != 1 {
		t.Fatal("created candidate list changed", list, err)
	}
	list.Data[0].CreatedAt = list.Data[0].CreatedAt.UTC()
	if !reflect.DeepEqual(list.Data[0], created) {
		t.Fatal("created candidate list lost metadata", list.Data[0], created)
	}
	for i, bad := range []string{`{`, `{} {}`, `[]`, `null`, `{}`, `{"release_id":null,"name":"Snapshot"}`, `{"release_id":"release","name":null}`, `{"release_id":"release","name":1}`, `{"release_id":"release","name":"Snapshot","name":"Other"}`, `{"release_id":"release","name":"Snapshot","tenant_id":"other"}`, `{"release_id":"release","name":" "}`, `{"release_id":"release","name":"bad\u0000name"}`, `{"release_id":"release","name":"Snapshot","build_ids":[null]}`, `{"release_id":"release","name":"Snapshot","build_ids":["bad\u0000id"]}`, `{"release_id":"release","name":"Snapshot","build_ids":[1]}`} {
		request("POST", "/v1/release-candidates", fmt.Sprintf("invalid-candidate-create-%d", i), "", bad, 400)
	}
	request("POST", "/v1/release-candidates", "oversized-candidate-create", "", strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1), 400)
	request("POST", "/v1/release-candidates", "oversized-candidate-reference", "", `{"release_id":"release","name":"Snapshot","build_ids":["`+strings.Repeat("x", 1025)+`"]}`, 400)
	ids := make([]string, 4097)
	for i := range ids {
		ids[i] = "build"
	}
	tooMany, err := json.Marshal(map[string]any{"release_id": "release", "name": "Snapshot", "build_ids": ids})
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(tooMany)) >= app.SmallJSONRequestLimit {
		t.Fatal("reference-count regression must remain below HTTP byte limit")
	}
	request("POST", "/v1/release-candidates", "too-many-candidate-references", "", string(tooMany), 400)
	request("POST", "/v1/release-candidates", "missing-reference", "", `{"release_id":"release","name":"Snapshot","sbom_ids":["missing"]}`, 404)
	auth.actor = actor
	auth.actor.TenantID = "other"
	request("POST", "/v1/release-candidates", "foreign-candidate", "", body, 404)
	auth.actor = actor
	auth.actor.ResourceGrants = nil
	request("POST", "/v1/release-candidates", "removed-candidate-grant", "", body, 403)
	auth.actor = actor
	counts(1, 1)
	promoted := decode(request("POST", "/v1/release-candidates/"+created.ID+"/promote", "promote-created-candidate", `"1"`, `{"reason":"reviewed"}`, 200))
	want := created
	want.State = "promoted"
	want.Revision = 2
	want.PromotedAt = promoted.PromotedAt
	if promoted.PromotedAt == nil || !reflect.DeepEqual(promoted, want) {
		t.Fatal("newly created candidate transition changed snapshot", promoted, want)
	}
	counts(1, 2)
	for _, server := range servers {
		assertNativeHTTPHasNoAggregate(t, server)
	}
	for _, table := range []string{"release_candidates", "audit_chain_entries"} {
		exec(`CREATE FUNCTION reject_candidate_create_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private candidate SQL';END$$;CREATE TRIGGER reject_candidate_create_http BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_candidate_create_http()`)
		request("POST", "/v1/release-candidates", "fail-candidate-"+table, "", body, 500)
		exec(`DROP TRIGGER reject_candidate_create_http ON ` + table + `;DROP FUNCTION reject_candidate_create_http()`)
		request("POST", "/v1/release-candidates", "fail-candidate-"+table, "", body, 409)
		counts(1, 2)
	}
}

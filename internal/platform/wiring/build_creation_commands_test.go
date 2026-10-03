package wiring

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestPostgresBuildCreationSeesPendingParentsAndArtifactGrant(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Pending');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildBuildCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"build:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"build:write"}}}}
	digest := "sha256:" + strings.Repeat("a", 64)
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	counts := func() [5]int {
		t.Helper()
		var n [5]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM projects),(SELECT count(*)FROM releases),(SELECT count(*)FROM artifacts),(SELECT count(*)FROM build_runs),(SELECT count(*)FROM audit_chain_entries)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	run := func(fail bool) app.IdempotentUnitOfWorkCommand {
		return func(txCtx context.Context, repos app.Repositories) (int, any, error) {
			if err := repos.ReleaseCatalog.InsertProject(txCtx, domain.Project{ID: "project", TenantID: "tenant", ProductID: "product", Name: "Project", CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertRelease(txCtx, domain.Release{ID: "release", TenantID: "tenant", ProductID: "product", Version: "1", State: "draft", Revision: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertArtifact(txCtx, domain.Artifact{ID: "artifact", TenantID: "tenant", Name: "Artifact", MediaType: "application/octet-stream", Digest: digest, Size: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.Builds.InsertBuildRun(txCtx, domain.BuildRun{ID: "seed-build", TenantID: "tenant", ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: at, CreatedAt: at, SchemaVersion: "v1", Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: digest}}}); err != nil {
				return 0, nil, err
			}
			build, err := commands.CreateBuildRun(txCtx, actor, releaseapp.CreateBuildRunInput{ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: at, Outputs: []releasedomain.BuildOutput{{ArtifactID: "artifact", Digest: digest}}})
			if err != nil {
				return 0, nil, err
			}
			if fail {
				return 0, nil, errors.New("rollback compound build")
			}
			return 201, build, nil
		}
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/builds", "pending-rollback", []byte("{}"), run(true)); err == nil || err.Error() != "rollback compound build" || counts() != [5]int{} {
		t.Fatal("pending read or compound rollback failed", err, counts())
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/builds", "pending-success", []byte("{}"), run(false)); err != nil || counts() != [5]int{1, 1, 1, 2, 1} {
		t.Fatal("pending coordinates or grant not visible", err, counts())
	}
}

func TestPostgresBuildCreationHTTPAndConsumersUseDurableStateWithoutLedgerBuild(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Build HTTP'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000))`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft')`)
	digest := "sha256:" + strings.Repeat("a", 64)
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('artifact','tenant',repeat('x',9000000),repeat('x',9000000),$1,1)`, digest)
	objects, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"build:write", "build:read", "evidence:write"}}
	auth := &attestationHTTPActor{actor: actor}
	newServer := func() http.Handler {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Objects: objects}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		if opts.BuildCommands == nil || opts.EvidenceCreationCommands == nil || opts.BuildAttestationCommands == nil {
			t.Fatal("missing focused build chain")
		}
		opts.Authenticator = auth
		ledger, err := app.NewLedgerWithContext(ctx, app.Config{UnitOfWork: store, ObjectStore: objects})
		if err != nil {
			t.Fatal(err)
		}
		probe := actor
		probe.Scopes = []string{"project:read"}
		if _, err := ledger.GetProject(ctx, probe, "project"); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("HTTP harness has cached parents", err)
		}
		server, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		return server.Handler()
	}
	request := func(h http.Handler, method, path, key string, body []byte, want int) []byte {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("HTTP %s %s status %d want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		return append([]byte(nil), rec.Body.Bytes()...)
	}
	counts := func() [5]int {
		t.Helper()
		var n [5]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM build_runs),(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM build_attestations),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	body := []byte(`{"project_id":"project","release_id":"release","provider":"generic_ci","commit_sha":"` + strings.Repeat("b", 40) + `","status":"passed","started_at":"2026-10-02T12:00:00Z","provider_metadata":{"oidc_verified":true,"custom":{"ok":true}},"outputs":[{"artifact_id":"artifact","digest":"` + digest + `"}]}`)
	response := request(newServer(), http.MethodPost, "/v1/builds", "create-build", body, http.StatusCreated)
	var envelope struct {
		Data domain.BuildRun `json:"data"`
	}
	if err := json.Unmarshal(response, &envelope); err != nil || envelope.Data.ID == "" || envelope.Data.SourceIdentity["oidc_verified"] != false || counts() != [5]int{1, 0, 0, 1, 0} {
		t.Fatal("build create response/effects", string(response), err, counts())
	}
	build := envelope.Data
	replay := request(newServer(), http.MethodPost, "/v1/builds", "create-build", body, http.StatusCreated)
	var originalJSON, replayJSON any
	if err := json.Unmarshal(response, &originalJSON); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(replay, &replayJSON); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(originalJSON, replayJSON) || counts() != [5]int{1, 0, 0, 1, 0} {
		t.Fatal("build restart replay changed response/effects", string(replay), counts())
	}
	request(newServer(), http.MethodPost, "/v1/builds", "create-build", append(body, ' '), http.StatusConflict)
	got := request(newServer(), http.MethodGet, "/v1/builds/"+build.ID, "", nil, http.StatusOK)
	var read struct {
		Data domain.BuildRun `json:"data"`
	}
	if err := json.Unmarshal(got, &read); err != nil || read.Data.ID != build.ID || read.Data.ReleaseID != build.ReleaseID || read.Data.SourceIdentity["oidc_verified"] != false {
		t.Fatal("durable build read", string(got), err)
	}
	evidenceBody := []byte(`{"build_id":"` + build.ID + `","type":"manual","title":"Build review","payload_hash":"` + digest + `","payload_size":1}`)
	evidence := request(newServer(), http.MethodPost, "/v1/evidence", "build-evidence", evidenceBody, http.StatusCreated)
	if !bytes.Contains(evidence, []byte(`"build_id":"`+build.ID+`"`)) {
		t.Fatal("evidence lost build link", string(evidence))
	}
	statement, err := os.ReadFile("../../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	dsse := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"` + base64.StdEncoding.EncodeToString(statement) + `","signatures":[{"sig":"untrusted"}]}`)
	attestation := request(newServer(), http.MethodPost, "/v1/builds/"+build.ID+"/attestations", "attest-build", dsse, http.StatusCreated)
	if !bytes.Contains(attestation, []byte(`"build_id":"`+build.ID+`"`)) || !bytes.Contains(attestation, []byte(`"verification_status":"structurally_valid"`)) || counts() != [5]int{1, 2, 1, 4, 2} {
		t.Fatal("durable consumers", string(attestation), counts())
	}
	baseline := counts()
	handler := newServer()
	request(handler, http.MethodPost, "/v1/builds", "nul-provider", []byte(strings.Replace(string(body), `"provider":"generic_ci"`, `"provider":"bad\u0000provider"`, 1)), http.StatusBadRequest)
	request(handler, http.MethodPost, "/v1/builds", "nul-metadata", []byte(strings.Replace(string(body), `"custom":{"ok":true}`, `"custom":{"ok":"bad\u0000metadata"}`, 1)), http.StatusBadRequest)
	for i, bad := range [][]byte{[]byte(`{`), []byte(`[]`), append(append([]byte(nil), body...), []byte(`{}`)...), []byte(strings.Replace(string(body), `"status":"passed"`, `"status":"unknown"`, 1)), []byte(strings.Replace(string(body), digest, "sha256:bad", 1))} {
		request(handler, http.MethodPost, "/v1/builds", "bad-build-"+string(rune('a'+i)), bad, http.StatusBadRequest)
	}
	auth.actor.TenantID = "other"
	request(handler, http.MethodPost, "/v1/builds", "foreign-build", body, http.StatusNotFound)
	auth.actor = domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"build:write"}}
	request(handler, http.MethodPost, "/v1/builds", "no-grant", body, http.StatusForbidden)
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"build:write"}}}
	request(handler, http.MethodPost, "/v1/builds", "human-build", body, http.StatusCreated)
	if counts() != [5]int{baseline[0] + 1, baseline[1], baseline[2], baseline[3] + 1, baseline[4]} {
		t.Fatal("denied requests wrote effects", counts(), baseline)
	}
	auth.actor = actor
	baseline = counts()
	for _, table := range []string{"build_runs", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_http_build()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private SQL secret';END$$`)
		exec(`CREATE TRIGGER reject_http_build BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_http_build()`)
		failure := request(handler, http.MethodPost, "/v1/builds", "failure-"+table, body, http.StatusInternalServerError)
		if bytes.Contains(failure, []byte("private SQL")) || counts() != baseline {
			t.Fatal("failure leaked or committed effects", string(failure), counts())
		}
		exec(`DROP TRIGGER reject_http_build ON ` + table)
		request(handler, http.MethodPost, "/v1/builds", "failure-"+table, body, http.StatusConflict)
	}
}

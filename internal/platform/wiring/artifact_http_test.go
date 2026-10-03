package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresArtifactHTTPAndConsumersDoNotRequireLedgerArtifacts(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Artifact HTTP'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product');INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000));INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft')`)
	digest := "sha256:" + strings.Repeat("a", 64)
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:write", "evidence:read", "build:write"}}
	auth := &attestationHTTPActor{actor: actor}
	newServer := func() http.Handler {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.ArtifactCommands == nil || opts.BuildCommands == nil || opts.EvidenceCreationCommands == nil || opts.ContainerImageCommands == nil {
			t.Fatal("focused artifact chain missing", err)
		}
		opts.Authenticator = auth
		ledger, err := app.NewLedgerWithContext(ctx, app.Config{UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.GetProject(ctx, domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"project:read"}}, "project"); !errors.Is(err, app.ErrNotFound) {
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
		if rec.Code != want || bytes.Contains(rec.Body.Bytes(), []byte("private artifact SQL")) {
			t.Fatalf("HTTP %s %s got %d want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		return append([]byte(nil), rec.Body.Bytes()...)
	}
	counts := func() [5]int {
		t.Helper()
		var n [5]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM artifacts),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM build_runs),(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM container_images)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	body := []byte(`{"name":"Original","media_type":"application/octet-stream","digest":"` + digest + `","size":123}`)
	response := request(newServer(), "POST", "/v1/artifacts", "create-artifact", body, 201)
	var envelope struct {
		Data domain.Artifact `json:"data"`
	}
	if err := json.Unmarshal(response, &envelope); err != nil || envelope.Data.ID == "" || envelope.Data.TenantID != "tenant" || envelope.Data.Name != "Original" || envelope.Data.MediaType != "application/octet-stream" || envelope.Data.Digest != digest || envelope.Data.Size != 123 || envelope.Data.CreatedAt.IsZero() || counts() != [5]int{1, 1, 0, 0, 0} {
		t.Fatal("artifact response/effects changed", string(response), err, counts())
	}
	artifact := envelope.Data
	for _, replay := range [][]byte{
		request(newServer(), "POST", "/v1/artifacts", "create-artifact", body, 201),
		request(newServer(), "POST", "/v1/artifacts", "reuse-artifact", []byte(strings.Replace(string(body), `"name":"Original"`, `"name":"Ignored"`, 1)), 201),
	} {
		var originalJSON, replayJSON any
		if err := json.Unmarshal(response, &originalJSON); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(replay, &replayJSON); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(originalJSON, replayJSON) || counts() != [5]int{1, 1, 0, 0, 0} {
			t.Fatal("fresh-instance replay/reuse/read changed immutable metadata", string(replay), counts())
		}
	}
	read := request(newServer(), "GET", "/v1/artifacts/"+artifact.ID, "", nil, 200)
	var readEnvelope struct {
		Data domain.Artifact `json:"data"`
	}
	if err := json.Unmarshal(read, &readEnvelope); err != nil {
		t.Fatal(err)
	}
	// The existing point query preserves the database timestamp offset. Compare
	// the instant while still checking every immutable metadata field.
	readEnvelope.Data.CreatedAt = readEnvelope.Data.CreatedAt.UTC()
	if !reflect.DeepEqual(readEnvelope.Data, artifact) || counts() != [5]int{1, 1, 0, 0, 0} {
		t.Fatal("durable read changed artifact metadata", string(read), counts())
	}
	handler := newServer()
	request(handler, "POST", "/v1/artifacts", "create-artifact", append(body, ' '), 409)
	for i, bad := range [][]byte{
		[]byte(`{`), []byte(`[]`), []byte(`null`), []byte(`{}`), append(append([]byte(nil), body...), []byte(`{}`)...),
		[]byte(strings.Replace(string(body), `"name":"Original"`, `"name":"a","name":"b"`, 1)),
		[]byte(strings.Replace(string(body), `"name":"Original"`, `"name":null`, 1)),
		[]byte(strings.Replace(string(body), `"size":123`, `"size":-1`, 1)),
		[]byte(strings.Replace(string(body), `"size":123`, `"size":9223372036854775808`, 1)),
		[]byte(strings.Replace(string(body), `"size":123`, `"size":"123"`, 1)),
		[]byte(strings.Replace(string(body), `"size":123`, `"unknown":true`, 1)),
		[]byte(strings.Replace(string(body), digest, "sha256:bad", 1)),
		[]byte(strings.Replace(string(body), `"media_type":"application/octet-stream"`, `"media_type":" "`, 1)),
	} {
		request(handler, "POST", "/v1/artifacts", fmt.Sprintf("invalid-artifact-%d", i), bad, 400)
	}
	freshBody := strings.Replace(string(body), digest, "sha256:"+strings.Repeat("b", 64), 1)
	for i, bad := range []string{
		strings.Replace(freshBody, `"name":"Original"`, `"name":"bad\u0000name"`, 1),
		strings.Replace(freshBody, `"media_type":"application/octet-stream"`, `"media_type":"bad\u0000media"`, 1),
		strings.Replace(freshBody, `"name":"Original"`, `"name":"`+strings.Repeat("界", 22000)+`"`, 1),
	} {
		request(handler, "POST", "/v1/artifacts", fmt.Sprintf("bad-artifact-storage-%d", i), []byte(bad), 400)
	}
	auth.actor = domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:write"}}
	request(handler, "POST", "/v1/artifacts", "ungranted-reuse", body, 403)
	if counts() != [5]int{1, 1, 0, 0, 0} {
		t.Fatal("invalid or denied requests wrote effects", counts())
	}
	auth.actor = actor
	build := request(newServer(), "POST", "/v1/builds", "artifact-build", []byte(`{"project_id":"project","release_id":"release","provider":"generic_ci","commit_sha":"`+strings.Repeat("b", 40)+`","status":"passed","started_at":"2026-10-02T12:00:00Z","outputs":[{"artifact_id":"`+artifact.ID+`","digest":"`+digest+`"}]}`), 201)
	if !bytes.Contains(build, []byte(`"artifact_id":"`+artifact.ID+`"`)) {
		t.Fatal("build lost artifact output", string(build))
	}
	evidence := request(newServer(), "POST", "/v1/evidence", "artifact-evidence", []byte(`{"release_id":"release","subject_refs":[{"type":"artifact","id":"`+artifact.ID+`","digest":"`+digest+`"}],"type":"manual","title":"Review","payload_hash":"`+digest+`","payload_size":1}`), 201)
	image := request(newServer(), "POST", "/v1/container-images", "artifact-image", []byte(`{"artifact_id":"`+artifact.ID+`","repository":"registry.example.test/api","digest":"`+digest+`"}`), 201)
	if !bytes.Contains(evidence, []byte(`"type":"artifact","id":"`+artifact.ID+`"`)) || !bytes.Contains(image, []byte(`"artifact_id":"`+artifact.ID+`"`)) || counts() != [5]int{1, 4, 1, 1, 1} {
		t.Fatal("focused artifact consumers failed", string(evidence), string(image), counts())
	}
	auth.actor = domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"evidence:write"}}}}
	request(newServer(), "POST", "/v1/artifacts", "granted-reuse", body, 201)
	auth.actor = actor
	auth.actor.TenantID = "other"
	request(handler, "GET", "/v1/artifacts/"+artifact.ID, "", nil, 404)
	foreign := request(handler, "POST", "/v1/artifacts", "own-tenant-artifact", body, 201)
	if bytes.Contains(foreign, []byte(`"id":"`+artifact.ID+`"`)) || !bytes.Contains(foreign, []byte(`"tenant_id":"other"`)) || counts() != [5]int{2, 5, 1, 1, 1} {
		t.Fatal("same digest crossed tenant boundary", string(foreign), counts())
	}
	auth.actor = actor
	for _, table := range []string{"artifacts", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_http_artifact()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private artifact SQL';END$$`)
		exec(`CREATE TRIGGER reject_http_artifact BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_http_artifact()`)
		request(handler, "POST", "/v1/artifacts", "failed-artifact-"+table, []byte(freshBody), 500)
		if counts() != [5]int{2, 5, 1, 1, 1} {
			t.Fatal("failed artifact insert committed effects", table, counts())
		}
		exec(`DROP TRIGGER reject_http_artifact ON ` + table)
		request(handler, "POST", "/v1/artifacts", "failed-artifact-"+table, []byte(freshBody), 409)
	}
	t.Run("concurrent absent digest reuses one immutable record", func(t *testing.T) {
		handlers := []http.Handler{newServer(), newServer()}
		concurrentBody := []byte(strings.Replace(string(body), digest, "sha256:"+strings.Repeat("c", 64), 1))
		start := make(chan struct{})
		type result struct {
			status int
			body   []byte
		}
		results := make(chan result, 2)
		for i, h := range handlers {
			go func() {
				<-start
				req := httptest.NewRequest("POST", "/v1/artifacts", bytes.NewReader(concurrentBody))
				req.Header.Set("Authorization", "Bearer isolated-auth")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Idempotency-Key", fmt.Sprintf("concurrent-artifact-%d", i))
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				results <- result{status: rec.Code, body: append([]byte(nil), rec.Body.Bytes()...)}
			}()
		}
		close(start)
		first, second := <-results, <-results
		if first.status != 201 || second.status != 201 || !bytes.Equal(first.body, second.body) || counts() != [5]int{3, 6, 1, 1, 1} {
			t.Fatal("concurrent registration changed metadata or duplicated effects", first.status, second.status, string(first.body), string(second.body), counts())
		}
	})
}

package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresContainerImageHTTPUsesDurableArtifactsAndImmutableReplay(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Image HTTP'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product');INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000));INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft')`)
	digest := "sha256:" + strings.Repeat("a", 64)
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('artifact','tenant',repeat('x',9000000),repeat('x',9000000),$1,1)`, digest)
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:write"}}
	auth := &attestationHTTPActor{actor: actor}
	newServer := func() http.Handler {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.ContainerImageCommands == nil {
			t.Fatal("missing durable image binding", err)
		}
		opts.Authenticator = auth
		_ = newAggregateLoadCanary(t, ctx, store)
		server, err := newNativeHTTPFixture(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		return server.Handler()
	}
	request := func(h http.Handler, key string, body []byte, want int) []byte {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/container-images", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want || bytes.Contains(rec.Body.Bytes(), []byte("private image SQL")) {
			t.Fatalf("image HTTP status %d want %d: %s", rec.Code, want, rec.Body.String())
		}
		return append([]byte(nil), rec.Body.Bytes()...)
	}
	counts := func() [2]int {
		t.Helper()
		var n [2]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM container_images),(SELECT count(*)FROM audit_chain_entries)`).Scan(&n[0], &n[1]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	body := []byte(`{"artifact_id":"artifact","repository":"registry.example.test/api","tag":"v1","digest":"` + digest + `","platform":"linux/amd64"}`)
	response := request(newServer(), "create-image", body, 201)
	var envelope struct {
		Data domain.ContainerImage `json:"data"`
	}
	if err := json.Unmarshal(response, &envelope); err != nil || envelope.Data.ID == "" || envelope.Data.ArtifactID != "artifact" || envelope.Data.Digest != digest || envelope.Data.Tag != "v1" || envelope.Data.Platform != "linux/amd64" || counts() != [2]int{1, 1} {
		t.Fatal("durable image fields or effects", string(response), err, counts())
	}
	image := envelope.Data
	for _, replay := range [][]byte{
		request(newServer(), "create-image", body, 201),
		request(newServer(), "reuse-image", []byte(strings.Replace(string(body), `"tag":"v1"`, `"tag":"ignored"`, 1)), 201),
	} {
		var originalJSON, replayJSON any
		if err := json.Unmarshal(response, &originalJSON); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(replay, &replayJSON); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(originalJSON, replayJSON) || counts() != [2]int{1, 1} {
			t.Fatal("restart replay or immutable reuse changed response/effects", string(replay), counts())
		}
	}
	handler := newServer()
	request(handler, "create-image", append(body, ' '), 409)
	invalid := [][]byte{[]byte(`{`), []byte(`[]`), []byte(`null`), []byte(`{}`), append(append([]byte(nil), body...), []byte(`{}`)...), []byte(`{"repository":"a","repository":"b","digest":"` + digest + `"}`), []byte(strings.Replace(string(body), `"tag":"v1"`, `"unknown":true`, 1)), []byte(strings.Replace(string(body), digest, "sha256:bad", 1))}
	for i, bad := range invalid {
		request(handler, fmt.Sprintf("invalid-image-%d", i), bad, 400)
	}
	for _, tc := range []struct {
		name string
		body string
	}{
		{"NUL repository", `{"repository":"bad\u0000repository","digest":"` + digest + `"}`},
		{"NUL tag", `{"repository":"registry.example.test/new","tag":"bad\u0000tag","digest":"` + digest + `"}`},
		{"oversized platform", `{"repository":"registry.example.test/new","platform":"` + strings.Repeat("界", 22000) + `","digest":"` + digest + `"}`},
	} {
		request(handler, "bad-text-"+tc.name, []byte(tc.body), 400)
	}
	auth.actor.TenantID = "other"
	request(handler, "foreign-artifact", body, 404)
	auth.actor = domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:write"}}
	omitted := []byte(`{"repository":"registry.example.test/api","digest":"` + digest + `"}`)
	request(handler, "no-grant", omitted, 403)
	auth.actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"evidence:write"}}}
	exec(`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,source_identity,schema_version)VALUES('build','tenant','project','release','generic_ci','0123456789abcdef','passed',now(),jsonb_build_array(jsonb_build_object('artifact_id','artifact','digest',$1::text)),'{}','v1')`, digest)
	reuse := request(handler, "current-grant", omitted, 201)
	if !bytes.Contains(reuse, []byte(`"id":"`+image.ID+`"`)) || counts() != [2]int{1, 1} {
		t.Fatal("current association not authorized without cache", string(reuse), counts())
	}
	auth.actor = actor
	for _, table := range []string{"container_images", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_http_image()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private image SQL';END$$`)
		exec(`CREATE TRIGGER reject_http_image BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_http_image()`)
		fresh := []byte(strings.Replace(string(body), "registry.example.test/api", "registry.example.test/failed", 1))
		request(handler, "failed-"+table, fresh, 500)
		if counts() != [2]int{1, 1} {
			t.Fatal("failed image request committed partial effects", table, counts())
		}
		exec(`DROP TRIGGER reject_http_image ON ` + table)
		request(handler, "failed-"+table, fresh, 409)
	}
}

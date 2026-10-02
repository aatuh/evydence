package wiring

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

// Authentication is isolated here; the real auth service has its own current-
// credential tests. Ingestion, HTTP replay, composition and persistence are real.
type attestationHTTPActor struct{ actor domain.Actor }

func (a *attestationHTTPActor) Authenticate(context.Context, string) (domain.Actor, error) {
	return a.actor, nil
}

func TestPostgresBuildAttestationIngestionCommitsAtomicEvidencePayloadJobsAndReplay(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Attestations'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000))`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft')`)
	digest := "sha256:" + strings.Repeat("a", 64)
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('artifact','tenant',repeat('x',9000000),repeat('x',9000000),$1,1)`, digest)
	exec(`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,source_identity,schema_version)VALUES('build','tenant','project','release','generic_ci','0123456789abcdef','passed',now(),jsonb_build_array(jsonb_build_object('artifact_id','artifact','digest',$1::text)),'{"source":"api","oidc_verified":false}','v1')`, digest)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects := &countedSignatureStager{Store: fs}
	commands, err := BuildBuildAttestationCommands(store, objects, true)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"build:write"}}
	statement, err := os.ReadFile("../../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"` + base64.StdEncoding.EncodeToString(statement) + `","signatures":[{"sig":"untrusted"}]}`)
	counts := func() [5]int {
		t.Helper()
		var n [5]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM build_attestations),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM object_payloads),(SELECT count(*)FROM outbox_jobs)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	v, err := commands.UploadBuildAttestation(ctx, actor, "build", raw)
	if err != nil || v.ID == "" || v.EvidenceID == "" || v.VerificationStatus != "structurally_valid" || counts() != [5]int{1, 1, 2, 1, 2} {
		t.Fatal(v, err, counts())
	}
	var status, payloadType string
	if err := pool.QueryRow(ctx, `SELECT verification_status,payload_type FROM build_attestations WHERE id=$1`, v.ID).Scan(&status, &payloadType); err != nil || status != "accepted" || payloadType != "" {
		t.Fatal("worker ownership", status, payloadType, err)
	}
	var encoded []byte
	if err := pool.QueryRow(ctx, `SELECT to_jsonb(e)FROM evidence_items e WHERE id=$1`, v.EvidenceID).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	var item domain.EvidenceItem
	if err := json.Unmarshal(encoded, &item); err != nil {
		t.Fatal(err)
	}
	// to_jsonb(timestamptz) uses the server zone. The durable verification
	// reader restores UTC before applying the canonicalization contract.
	item.ObservedAt = item.ObservedAt.UTC()
	item.CreatedAt = item.CreatedAt.UTC()
	hash, err := (evidenceCanonicalHasher{}).HashEvidence(ctx, domain.EvidenceToContextModel(item))
	if err != nil || hash != item.CanonicalHash || item.VerificationStatus != "pending" || item.SourceIdentity["oidc_verified"] != false {
		t.Fatal("durable commitment mismatch or trust assigned", item, hash, err)
	}
	baseline := counts()
	for _, table := range []string{"object_payloads", "outbox_jobs", "evidence_items", "build_attestations", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_attestation_write()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected attestation failure';END$$`)
		exec(`CREATE TRIGGER reject_attestation_write BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_attestation_write()`)
		failed, err := commands.UploadBuildAttestation(ctx, actor, "build", raw)
		if err == nil || failed.ID != "" || counts() != baseline {
			t.Fatal("partial attestation transaction", table, failed, err, counts())
		}
		exec(`DROP TRIGGER reject_attestation_write ON ` + table)
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	calls := 0
	for i := 0; i < 2; i++ {
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/builds/build/attestations", "replay", raw, func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			v, err := commands.UploadBuildAttestation(ctx, actor, "build", raw)
			return 201, v, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || counts() != [5]int{2, 2, 4, 1, 3} {
		t.Fatal("replay effects", calls, counts())
	}
	stages := objects.stages
	foreign := actor
	foreign.TenantID = "other"
	if _, err := commands.UploadBuildAttestation(ctx, foreign, "build", raw); !errors.Is(err, releaseapp.ErrNotFound) {
		t.Fatal("foreign build accepted", err)
	}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"build:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "wrong", Scopes: []string{"build:write"}}}}
	if _, err := commands.UploadBuildAttestation(ctx, human, "build", raw); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("wrong grant accepted", err)
	}
	if stages != objects.stages {
		t.Fatal("denied request staged payload")
	}
	human.ResourceGrants[0].ResourceID = "project"
	if _, err := commands.UploadBuildAttestation(ctx, human, "build", raw); err != nil {
		t.Fatal("current linked project grant denied", err)
	}
	payload, err := store.GetObjectPayload(ctx, actor.TenantID, v.PayloadHash)
	if err != nil || payload.Status != app.ObjectPayloadStaged || payload.Size != int64(len(raw)) || payload.Reference() != v.PayloadRef {
		t.Fatal("staged lifecycle", payload, err)
	}
	if _, err := objects.Get(ctx, payload.FinalKey); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("finalized before worker", err)
	}
	if err := app.FinalizeStagedObjectPayload(ctx, store, objects, actor.TenantID, v.PayloadHash); err != nil {
		t.Fatal(err)
	}
	storedBytes, err := objects.Get(ctx, payload.FinalKey)
	if err != nil || !bytes.Equal(storedBytes.Bytes, raw) || storedBytes.Digest != v.PayloadHash || storedBytes.TenantID != actor.TenantID {
		t.Fatal("finalized bytes mismatch", err)
	}
	// A new command instance uses durable coordinates and can reuse a finalized
	// payload. Inline mode still preserves the parsed persistent projection.
	inline, err := BuildBuildAttestationCommands(store, objects, false)
	if err != nil {
		t.Fatal(err)
	}
	inlineResult, err := inline.UploadBuildAttestation(ctx, actor, "build", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT verification_status,payload_type FROM build_attestations WHERE id=$1`, inlineResult.ID).Scan(&status, &payloadType); err != nil || status != "structurally_valid" || payloadType != "application/vnd.in-toto+json" {
		t.Fatal("inline projection", status, payloadType, err)
	}
	// Exercise the actual composition root and HTTP route with an empty Ledger:
	// that compatibility harness owns only the transitional replay envelope.
	auth := &attestationHTTPActor{actor: actor}
	newServer := func() http.Handler {
		t.Helper()
		options, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Objects: objects, WorkerOwnedParsers: true}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		options.Authenticator = auth
		ledger, err := app.NewLedgerWithContext(ctx, app.Config{UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		cacheProbe := actor
		cacheProbe.Scopes = []string{"build:read"}
		if _, err := ledger.GetBuildRun(ctx, cacheProbe, "build"); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("HTTP harness must have no cached build", err)
		}
		server, err := httpapi.NewServerWithOptionsContext(ctx, ledger, options)
		if err != nil {
			t.Fatal(err)
		}
		return server.Handler()
	}
	post := func(handler http.Handler, key string, body []byte, want int) []byte {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/builds/build/attestations", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != want {
			t.Fatalf("HTTP status %d want %d: %s", recorder.Code, want, recorder.Body.String())
		}
		return append([]byte(nil), recorder.Body.Bytes()...)
	}
	handler := newServer()
	baseline = counts()
	response := post(handler, "http-replay", raw, http.StatusCreated)
	var result struct {
		Data domain.BuildAttestation `json:"data"`
	}
	if err := json.Unmarshal(response, &result); err != nil || result.Data.ID == "" || result.Data.EvidenceID == "" || result.Data.VerificationStatus != "structurally_valid" {
		t.Fatal("HTTP response", string(response), err)
	}
	if got := counts(); got != [5]int{baseline[0] + 1, baseline[1] + 1, baseline[2] + 2, baseline[3], baseline[4] + 1} {
		t.Fatal("HTTP durable effects", got, baseline)
	}
	baseline = counts()
	stages = objects.stages
	replay := post(newServer(), "http-replay", raw, http.StatusCreated)
	// Durable replay stores normalized, privacy-filtered JSON. Only the
	// established payload_ref omission and member ordering may differ.
	var originalJSON, replayJSON any
	if err := json.Unmarshal(response, &originalJSON); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(replay, &replayJSON); err != nil {
		t.Fatal(err)
	}
	originalData := originalJSON.(map[string]any)["data"].(map[string]any)
	replayData := replayJSON.(map[string]any)["data"].(map[string]any)
	if originalData["payload_ref"] != v.PayloadRef {
		t.Fatal("initial payload reference changed", originalData)
	}
	if _, exposed := replayData["payload_ref"]; exposed {
		t.Fatal("replay retained private payload reference", replayData)
	}
	delete(originalData, "payload_ref")
	if !reflect.DeepEqual(originalJSON, replayJSON) || counts() != baseline || objects.stages != stages {
		t.Fatal("HTTP restart replay changed response or effects", string(response), string(replay), counts(), baseline, objects.stages, stages)
	}
	post(handler, "http-replay", append(append([]byte(nil), raw...), ' '), http.StatusConflict)
	for i, invalid := range [][]byte{nil, []byte(`null`), []byte(`{"payloadType":false}`), append(append([]byte(nil), raw...), []byte(`{}`)...)} {
		post(handler, fmt.Sprintf("malformed-%d", i), invalid, http.StatusBadRequest)
	}
	if counts() != baseline || objects.stages != stages {
		t.Fatal("bad HTTP request added effects", counts())
	}
	auth.actor.TenantID = "other"
	post(handler, "foreign-http", raw, http.StatusNotFound)
	auth.actor = human
	auth.actor.ResourceGrants = nil
	post(handler, "revoked-http", raw, http.StatusForbidden)
	if counts() != baseline || objects.stages != stages {
		t.Fatal("denied HTTP request added effects", counts())
	}
	auth.actor = actor
	exec(`CREATE TRIGGER reject_attestation_write BEFORE INSERT ON evidence_items FOR EACH ROW EXECUTE FUNCTION reject_attestation_write()`)
	failureBody := post(handler, "http-retry", raw, http.StatusInternalServerError)
	if bytes.Contains(failureBody, []byte("injected attestation")) || counts() != baseline {
		t.Fatal("failed HTTP write leaked or committed", string(failureBody), counts())
	}
	exec(`DROP TRIGGER reject_attestation_write ON evidence_items`)
	// Failed replay records are terminal under the existing idempotency
	// contract; removing the fault does not authorize reusing that key.
	post(handler, "http-retry", raw, http.StatusConflict)
	if counts() != baseline {
		t.Fatal("terminal failed replay wrote effects", counts())
	}
	post(handler, "http-retry-new-key", raw, http.StatusCreated)
}

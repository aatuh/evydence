package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestEvidenceCreationCommandsRejectMissingTransactions(t *testing.T) {
	if _, err := BuildEvidenceCreationCommands(nil); err == nil {
		t.Fatal("missing transactions accepted")
	}
}

func TestPostgresEvidenceCreationUsesBoundedCurrentParentsAndAtomicEffects(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Evidence'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product'),('elsewhere','tenant','Elsewhere','elsewhere')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000)),('other-project','tenant','elsewhere','Other')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft'),('other-release','tenant','elsewhere','2','draft')`)
	digest := "sha256:" + strings.Repeat("a", 64)
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('artifact','tenant',repeat('x',9000000),repeat('x',9000000),$1,1)`, digest)
	exec(`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,schema_version)VALUES('build','tenant','project','release','generic_ci','0123456789abcdef','passed',now(),jsonb_build_array(jsonb_build_object('artifact_id','artifact','digest',$1::text)),'v1')`, digest)
	commands, err := BuildEvidenceCreationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := (evidenceCreationReads{store}).ValidateArtifactReference(ctx, "tenant", "artifact", ""); err != nil {
		t.Fatal("ID-only artifact references must remain supported", err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"evidence:write"}}}}
	in := evidenceapp.CreateEvidenceInput{BuildID: "build", Type: "manual", Title: "Evidence", PayloadHash: digest, PayloadSize: 1, ObservedAt: time.Date(2026, 10, 2, 12, 1, 2, 123456789, time.FixedZone("offset", 7200)), SubjectRefs: []evidencedomain.SubjectRef{{Type: "artifact", ID: "artifact", Digest: digest}}, Metadata: map[string]any{"nested": map[string]any{"ok": true}}}
	counts := func() [4]int {
		t.Helper()
		var n [4]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM object_payloads),(SELECT count(*)FROM outbox_jobs)`).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	v, err := commands.CreateEvidence(ctx, actor, in)
	if err != nil || v.ID == "" || v.ChainEntryID == "" || v.ProductID != "" || v.BuildID != "build" || counts() != [4]int{1, 1, 0, 0} {
		t.Fatal(v, err, counts())
	}
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT to_jsonb(e)FROM evidence_items e WHERE id=$1`, v.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var durable domain.EvidenceItem
	if err := json.Unmarshal(raw, &durable); err != nil {
		t.Fatal(err)
	}
	durable.ObservedAt = durable.ObservedAt.UTC()
	durable.CreatedAt = durable.CreatedAt.UTC()
	hash, err := (evidenceCanonicalHasher{}).HashEvidence(ctx, domain.EvidenceToContextModel(durable))
	if err != nil || hash != v.CanonicalHash || durable.CanonicalHash != hash || durable.VerificationStatus != "pending" || !durable.ObservedAt.Equal(in.ObservedAt.Truncate(time.Microsecond)) {
		t.Fatal("canonical commitment drift", hash, err, durable)
	}
	baseline := counts()
	foreign := actor
	foreign.TenantID = "other"
	if _, err := commands.CreateEvidence(ctx, foreign, in); !errors.Is(err, evidenceapp.ErrNotFound) {
		t.Fatal("foreign build accepted", err)
	}
	denied := actor
	denied.ResourceGrants = nil
	if _, err := commands.CreateEvidence(ctx, denied, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("missing grant accepted", err)
	}
	mixed := in
	mixed.ReleaseID = "other-release"
	if _, err := commands.CreateEvidence(ctx, actor, mixed); !errors.Is(err, evidenceapp.ErrNotFound) {
		t.Fatal("mixed product coordinates accepted", err)
	}
	badArtifact := in
	badArtifact.SubjectRefs = []evidencedomain.SubjectRef{{Type: "artifact", ID: "artifact", Digest: "sha256:" + strings.Repeat("b", 64)}}
	if _, err := commands.CreateEvidence(ctx, actor, badArtifact); !errors.Is(err, evidenceapp.ErrNotFound) {
		t.Fatal("wrong artifact digest accepted", err)
	}
	if counts() != baseline {
		t.Fatal("denied command wrote effects", counts())
	}
	// Prove inferred parent locks persist through the command transaction.
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/evidence", "lock-probe", []byte("{}"), func(txCtx context.Context, _ app.Repositories) (int, any, error) {
		if _, err := commands.CreateEvidence(txCtx, actor, in); err != nil {
			return 0, nil, err
		}
		for _, statement := range []string{`UPDATE products SET name='changed' WHERE id='product'`, `UPDATE projects SET product_id='elsewhere' WHERE id='project'`, `UPDATE releases SET product_id='elsewhere' WHERE id='release'`, `UPDATE build_runs SET project_id='other-project' WHERE id='build'`} {
			update, err := pool.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			_, err = update.Exec(bounded, statement)
			cancel()
			// Always roll back: a timed-out auto-commit statement could still
			// win a cancellation race as the command releases its locks.
			_ = update.Rollback(ctx)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("parent update did not block on its row lock", statement, err)
			}
		}
		return 0, nil, errors.New("rollback lock probe")
	}); err == nil {
		t.Fatal("lock probe committed")
	}
	if counts() != baseline {
		t.Fatal("lock probe leaked writes", counts())
	}
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bytesToStage := []byte("staged evidence")
	payload, err := app.StageObjectPayload(ctx, fs, actor.TenantID, "application/octet-stream", app.BytesPayloadSource(bytesToStage), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	staged := in
	staged.PayloadHash = payload.Digest
	staged.PayloadRef = payload.Reference()
	staged.PayloadSize = payload.Size
	staged.PayloadMediaType = payload.MediaType
	staged.StagedPayload = evidenceapp.StagedPayload{TenantID: payload.TenantID, Digest: payload.Digest, Size: payload.Size, MediaType: payload.MediaType, StagingKey: payload.StagingKey, FinalKey: payload.FinalKey, Status: string(payload.Status), CreatedAt: payload.CreatedAt, UpdatedAt: payload.UpdatedAt}
	for _, table := range []string{"object_payloads", "outbox_jobs", "audit_chain_entries", "evidence_items"} {
		exec(`CREATE OR REPLACE FUNCTION reject_creation_write()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected creation failure';END$$`)
		exec(`CREATE TRIGGER reject_creation_write BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_creation_write()`)
		failed, err := commands.CreateEvidence(ctx, actor, staged)
		if err == nil || !strings.Contains(err.Error(), "injected creation failure") || failed.ID != "" || counts() != baseline {
			t.Fatal("partial creation", table, failed, err, counts())
		}
		exec(`DROP TRIGGER reject_creation_write ON ` + table)
	}
	if _, err := commands.CreateEvidence(ctx, actor, staged); err != nil {
		t.Fatal(err)
	}
	if counts() != [4]int{2, 2, 1, 1} {
		t.Fatal("payload lifecycle not atomic", counts())
	}
	// Pending build coordinates must be visible in the enclosing replay UoW,
	// even though another connection cannot see the build until commit.
	pendingDigest := "sha256:" + strings.Repeat("c", 64)
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/compound-evidence-test", "pending-build", []byte("{}"), func(txCtx context.Context, repos app.Repositories) (int, any, error) {
		if err := repos.ReleaseCatalog.InsertArtifact(txCtx, domain.Artifact{ID: "pending-artifact", TenantID: "tenant", Name: "Pending", MediaType: "application/octet-stream", Digest: pendingDigest, Size: 1, CreatedAt: time.Now()}); err != nil {
			return 0, nil, err
		}
		if err := repos.Builds.InsertBuildRun(txCtx, domain.BuildRun{ID: "pending-build", TenantID: "tenant", ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: "0123456789abcdef", Status: "passed", StartedAt: time.Now(), CreatedAt: time.Now(), SchemaVersion: "v1", Outputs: []domain.BuildOutput{{ArtifactID: "pending-artifact", Digest: pendingDigest}}}); err != nil {
			return 0, nil, err
		}
		pending := in
		pending.BuildID = "pending-build"
		pending.SubjectRefs = []evidencedomain.SubjectRef{{Type: "artifact", ID: "pending-artifact", Digest: pendingDigest}}
		v, err := commands.CreateEvidence(txCtx, actor, pending)
		return http.StatusCreated, v, err
	}); err != nil {
		t.Fatal("pending build/artifact/grant not visible in enclosing transaction", err)
	}
	if counts() != [4]int{3, 3, 1, 1} {
		t.Fatal("compound creation effects", counts())
	}
	// All supported coordinate forms, including deployment-only references,
	// resolve current parents without changing the stored optional fields.
	exec(`INSERT INTO deployment_environments(id,tenant_id,product_id,name,kind,schema_version,created_at)VALUES('environment','tenant','product','Production',repeat('x',9000000),'v1',now())`)
	exec(`INSERT INTO deployment_events(id,tenant_id,environment_id,release_id,status,started_at,schema_version,created_at)VALUES('deployment','tenant','environment','release','succeeded',now(),'v1',now())`)
	for _, scope := range []evidenceapp.EvidenceScope{{ProductID: "product"}, {ProjectID: "project"}, {ReleaseID: "release"}, {DeploymentID: "deployment"}} {
		if err := (evidenceCreationReads{store}).ValidateScope(ctx, "tenant", scope); err != nil {
			t.Fatal("current coordinates rejected", scope, err)
		}
	}
	if err := (evidenceCreationReads{store}).ValidateScope(ctx, "tenant", evidenceapp.EvidenceScope{DeploymentID: "deployment", ReleaseID: "other-release"}); !errors.Is(err, evidenceapp.ErrNotFound) {
		t.Fatal("mixed deployment parents accepted", err)
	}
	// Oversized stored coordinates fail closed, never using a truncated grant.
	exec(`INSERT INTO projects(id,tenant_id,product_id,name)VALUES(repeat('j',1025),'tenant','product','Large ID')`)
	exec(`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,schema_version)VALUES('large-build','tenant',repeat('j',1025),'release','generic_ci','0123456789abcdef','passed',now(),'[]','v1')`)
	large := in
	large.BuildID = "large-build"
	if _, err := commands.CreateEvidence(ctx, actor, large); !errors.Is(err, evidenceapp.ErrConflict) {
		t.Fatal("oversized inferred parent accepted", err)
	}
	if counts() != [4]int{3, 3, 1, 1} {
		t.Fatal("scope validation created effects", counts())
	}
}

func TestPostgresEvidenceCreationHTTPUsesFocusedRootAndSafeReplay(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','HTTP'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','P','p');INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft')`); err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"evidence:write"}}}}
	auth := &attestationHTTPActor{actor: actor}
	newServer := func() http.Handler {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		if opts.EvidenceCreationCommands == nil {
			t.Fatal("missing focused evidence binding")
		}
		opts.Authenticator = auth
		_ = newAggregateLoadCanary(t, ctx, store)
		server, err := newNativeHTTPFixture(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		return server.Handler()
	}
	post := func(h http.Handler, key, body string, want int) []byte {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/evidence", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer isolated-auth")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("HTTP %d want %d: %s", rec.Code, want, rec.Body.String())
		}
		return rec.Body.Bytes()
	}
	body := `{"release_id":"release","type":"manual","title":"Evidence","payload_hash":"sha256:` + strings.Repeat("a", 64) + `","payload_ref":"opaque-private-reference","payload_size":7,"source_identity":{"nested":{"ok":true}},"metadata":{"number":42},"tags":["b","a"],"limitations":["record only"]}`
	first := post(newServer(), "create", body, http.StatusCreated)
	replayed := post(newServer(), "create", body, http.StatusCreated)
	var firstEnvelope, replayEnvelope struct {
		Data domain.EvidenceItem `json:"data"`
	}
	if err := json.Unmarshal(first, &firstEnvelope); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(replayed, &replayEnvelope); err != nil {
		t.Fatal(err)
	}
	v, replay := firstEnvelope.Data, replayEnvelope.Data
	if v.ID == "" || v.ReleaseID != "release" || v.PayloadRef != "opaque-private-reference" || replay.PayloadRef != "" {
		t.Fatal(v, replay)
	}
	v.PayloadRef = ""
	if !reflect.DeepEqual(v, replay) {
		t.Fatal("replay changed public evidence", v, replay)
	}
	post(newServer(), "create", strings.Replace(body, "Evidence", "Changed", 1), http.StatusConflict)
	handler := newServer()
	for i, bad := range []string{`{`, `[]`, body + `{}`, strings.Replace(body, `"payload_size":7`, `"payload_size":-1`, 1), strings.Replace(body, `"type":"manual"`, `"type":"parser_normalization"`, 1)} {
		post(handler, "bad-"+string(rune('a'+i)), bad, http.StatusBadRequest)
	}
	auth.actor.TenantID = "other"
	post(handler, "foreign", body, http.StatusNotFound)
	auth.actor = actor
	auth.actor.ResourceGrants = nil
	post(handler, "revoked", body, http.StatusForbidden)
	auth.actor = actor
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_http_creation()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private SQL secret';END$$;CREATE TRIGGER reject_http_creation BEFORE INSERT ON evidence_items FOR EACH ROW EXECUTE FUNCTION reject_http_creation()`); err != nil {
		t.Fatal(err)
	}
	failure := post(handler, "failure", body, http.StatusInternalServerError)
	if bytes.Contains(failure, []byte("private SQL")) {
		t.Fatal("backend error leaked", string(failure))
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_http_creation ON evidence_items`); err != nil {
		t.Fatal(err)
	}
	post(handler, "failure", body, http.StatusConflict)
	post(handler, "new-key", body, http.StatusCreated)
	var n, a int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM audit_chain_entries)`).Scan(&n, &a); err != nil || n != 2 || a != 2 {
		t.Fatal("HTTP replay/failure effects", n, a, err)
	}
}

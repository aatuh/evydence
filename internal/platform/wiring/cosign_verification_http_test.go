package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/verification/sigstore"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const cosignHTTPPolicy = `{"mode":"keyless","offline":true,"expected_identity":"foo!oidc.local","expected_issuer":"http://oidc.local:8080"}`

func seedCosignHTTP(t *testing.T, p *pgxpool.Pool) (*countedDSSEReader, *sigstore.Verifier) {
	t.Helper()
	seedProviderReceiptHTTP(t, p)
	raw, err := os.ReadFile("../../adapters/verification/sigstore/testdata/official-othername.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile("../../adapters/verification/sigstore/testdata/official-scaffolding.trusted-root.json")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sigstore.New(sigstore.Config{TrustedRootJSON: root, TrustRootVersion: "fixture-root.v1"})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects := &countedDSSEReader{Store: fs}
	hash := sha256DSSETest(raw)
	staging, final, err := app.CanonicalObjectPayloadKeys("tenant", hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := objects.Put(t.Context(), app.Object{Key: final, TenantID: "tenant", Digest: hash, MediaType: "application/json", Bytes: raw, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := p.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	digest := "sha256:bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b"
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('artifact','tenant','Artifact','application/json',$1,1),('foreign-artifact','other',repeat('private-foreign',700000),'application/json',$1,1)`, digest)
	exec(`INSERT INTO container_images(id,tenant_id,artifact_id,repository,digest,schema_version,created_at)VALUES('image-z','tenant','artifact','image-z',$1,'container-image.v1.0.0',now()),('image-a','tenant','artifact','image-a',$1,'container-image.v1.0.0',now())`, digest)
	exec(`INSERT INTO object_payloads(tenant_id,object_key,digest,media_type,size,staging_key,final_key,status,updated_at,finalized_at)VALUES('tenant',$1,$2,'application/json',$3,$4,$1,'finalized',now(),now())`, final, hash, len(raw), staging)
	exec(`INSERT INTO artifact_signatures(id,tenant_id,artifact_id,subject_digest,algorithm,signature,payload_ref,payload_hash,verification_status,schema_version,created_at)VALUES('signature','tenant','artifact',$1,'cosign',repeat('private-detached',600000),$2,$3,'recorded','artifact-signature.v1.0.0',now()),('foreign-signature','other','foreign-artifact',$1,'cosign','ignored',$2,$3,'recorded','artifact-signature.v1.0.0',now())`, digest, "object://"+final, hash)
	return objects, verifier
}

func cosignHTTP(t *testing.T, store *postgres.Store, objects *countedDSSEReader, verifier app.CosignPolicyVerifier, id, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Objects: objects, Cosign: verifier}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.CosignVerification == nil || opts.DurableCommandExecutor == nil {
		t.Fatal("native Cosign composition missing", err)
	}
	noReload := &decisionHTTPNoReloadStore{}
	l, err := app.NewLedgerWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/artifact-signatures/"+id+"/verify-cosign", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 200 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("unsafe/legacy Cosign route status=%d want=%d loads=%d body=%s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 200 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("missing replay key")
	}
	return w.Body.String()
}

func cosignHTTPCounts(t *testing.T, p *pgxpool.Pool) [6]int {
	t.Helper()
	var v [6]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM cosign_verifications WHERE tenant_id='tenant'),(SELECT count(*)FROM verification_results WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed'),(SELECT count(*)FROM outbox_jobs)`).Scan(&v[0], &v[1], &v[2], &v[3], &v[4], &v[5]); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPostgresCosignHTTPRestartReplayAndCurrentAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects, verifier := seedCosignHTTP(t, p)
	one := cosignHTTP(t, store, objects, verifier, "signature", "verify", cosignHTTPPolicy, 200)
	var envelope struct {
		Data domain.CosignVerification `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &envelope); err != nil {
		t.Fatal(err)
	}
	v := envelope.Data
	if v.Result != "passed" || v.ContainerImageID != "image-a" || v.VerifierLibraryVersion != sigstore.LibraryVersion || v.TrustRootVersion != "fixture-root.v1" || v.VerificationMode != "keyless" || len(v.Profile.RequiredChecks) != 7 || objects.reads != 1 || cosignHTTPCounts(t, p) != [6]int{1, 1, 1, 1, 0, 0} {
		t.Fatal("verification or effects changed", one, objects.reads)
	}
	var receipt, actor, kind, saved string
	if err := p.QueryRow(t.Context(), `SELECT r.id,a.actor_id,a.entry_type,i.response::text FROM verification_results r JOIN audit_chain_entries a ON a.subject_id=r.subject_id JOIN idempotency_records i ON i.idempotency_key='verify'WHERE r.id=$1`, v.ID).Scan(&receipt, &actor, &kind, &saved); err != nil || receipt != v.ID || actor != "user" || kind != "cosign_signature.verified" || strings.Contains(saved, "private-") {
		t.Fatal("receipt/audit/replay mismatch", err)
	}
	assertRetentionHTTPReplay(t, one, cosignHTTP(t, store, objects, verifier, "signature", "verify", cosignHTTPPolicy, 200))
	exec := func(sql string) {
		t.Helper()
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE artifact_signatures SET subject_digest=repeat('private-new-digest',600000),payload_ref=repeat('private-location',600000)WHERE id='signature';UPDATE artifacts SET digest='sha256:changed-current-digest'WHERE id='artifact';UPDATE container_images SET digest='sha256:changed-current-digest'WHERE tenant_id='tenant';UPDATE object_payloads SET status='staged'WHERE tenant_id='tenant'`)
	// Even a restart with no verifier must return the original successful reply;
	// ownership guards must not inspect current digest, image or payload state.
	assertRetentionHTTPReplay(t, one, cosignHTTP(t, store, objects, nil, "signature", "verify", cosignHTTPPolicy, 200))
	cosignHTTP(t, store, objects, nil, "signature", "verify", cosignHTTPPolicy+" ", 409)
	cosignHTTP(t, store, objects, nil, "foreign-signature", "foreign", cosignHTTPPolicy, 404)
	cosignHTTP(t, store, objects, nil, "missing", "missing", cosignHTTPPolicy, 404)
	for _, table := range []string{"artifact_signatures", "artifacts"} {
		id := "signature"
		if table == "artifacts" {
			id = "artifact"
		}
		if _, err := p.Exec(t.Context(), "UPDATE "+table+" SET tenant_id='other'WHERE id=$1", id); err != nil {
			t.Fatal(err)
		}
		cosignHTTP(t, store, objects, nil, "signature", "verify", cosignHTTPPolicy, 404)
		cosignHTTP(t, store, objects, nil, "signature", "fresh-foreign", cosignHTTPPolicy, 404)
		if _, err := p.Exec(t.Context(), "UPDATE "+table+" SET tenant_id='tenant'WHERE id=$1", id); err != nil {
			t.Fatal(err)
		}
	}
	for _, sql := range []string{`UPDATE role_bindings SET resource_type='product',resource_id='unrelated'WHERE id='grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='other'WHERE id='grant'`, `UPDATE role_bindings SET role='viewer',resource_type='tenant',resource_id='tenant'WHERE id='grant'`} {
		exec(sql)
		cosignHTTP(t, store, objects, verifier, "signature", "verify", cosignHTTPPolicy, 403)
		cosignHTTP(t, store, objects, verifier, "signature", "fresh-denied", cosignHTTPPolicy, 403)
	}
	exec(`UPDATE role_bindings SET role='tenant_admin'WHERE id='grant';UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`)
	cosignHTTP(t, store, objects, verifier, "signature", "verify", cosignHTTPPolicy, 401)
	if objects.reads != 1 || cosignHTTPCounts(t, p) != [6]int{1, 1, 1, 1, 0, 0} {
		t.Fatal("replay/denial reread payload or changed durable effects")
	}
}

func TestPostgresCosignHTTPFailuresRollbackReceiptsAuditAndReplay(t *testing.T) {
	for _, stage := range []string{"cosign", "result", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			objects, verifier := seedCosignHTTP(t, p)
			table := map[string]string{"cosign": "cosign_verifications", "result": "verification_results", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_cosign BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_cosign()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_cosign BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_cosign()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_cosign AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_cosign()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_cosign()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-cosign-write-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			cosignHTTP(t, store, objects, verifier, "signature", "failed", cosignHTTPPolicy, 500)
			want := [6]int{}
			if stage != "replay" && stage != "commit" {
				want[4] = 1
			}
			if cosignHTTPCounts(t, p) != want {
				t.Fatal("partial verification success", cosignHTTPCounts(t, p), want)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_cosign ON "+table); err != nil {
				t.Fatal(err)
			}
			retryKey := "failed"
			if want[4] == 1 {
				// The existing durable failure policy keeps this key failed. It
				// must not rerun inspection; recovery needs a new delivery key.
				before := objects.reads
				cosignHTTP(t, store, objects, verifier, "signature", "failed", cosignHTTPPolicy, 409)
				if objects.reads != before || cosignHTTPCounts(t, p) != want {
					t.Fatal("failed-key retry reread payload or rewrote failure")
				}
				retryKey = "recovered"
			}
			cosignHTTP(t, store, objects, verifier, "signature", retryKey, cosignHTTPPolicy, 200)
			if cosignHTTPCounts(t, p) != [6]int{1, 1, 1, 1, want[4], 0} {
				t.Fatal("rolled-back delivery prevented retry")
			}
		})
	}
}

func TestPostgresCosignHTTPFailedOrUnavailableInspectionNeverCommitsSuccess(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects, verifier := seedCosignHTTP(t, p)
	wrong := strings.Replace(cosignHTTPPolicy, "foo!oidc.local", "wrong-identity", 1)
	cosignHTTP(t, store, objects, verifier, "signature", "wrong", wrong, 422)
	cosignHTTP(t, store, objects, nil, "signature", "unavailable", cosignHTTPPolicy, 422)
	if cosignHTTPCounts(t, p) != [6]int{0, 0, 0, 0, 2, 0} || objects.reads != 1 {
		t.Fatal("failed inspection committed partial receipt or missing verifier read payload")
	}
}

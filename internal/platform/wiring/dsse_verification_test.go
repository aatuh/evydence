package wiring

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	securedsse "github.com/secure-systems-lab/go-securesystemslib/dsse"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type countedDSSEReader struct {
	*filesystem.Store
	reads int
}

func sha256DSSETest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (s *countedDSSEReader) GetBounded(ctx context.Context, key string, max int64) (app.Object, error) {
	s.reads++
	return s.Store.GetBounded(ctx, key, max)
}

func seedDSSEVerification(t *testing.T, pool *pgxpool.Pool, sessions bool) *countedDSSEReader {
	t.Helper()
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	if sessions {
		seedProviderReceiptHTTP(t, pool)
	} else {
		exec(`INSERT INTO tenants(id,name) VALUES('tenant','DSSE'),('other','Other')`)
	}
	exec(`INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','DSSE','dsse')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name) VALUES('project','tenant','product','DSSE')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('release','tenant','product','1','draft')`)
	digest := "sha256:" + strings.Repeat("a", 64)
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size) VALUES('artifact','tenant','Build','application/json',$1,1)`, digest)
	exec(`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,schema_version) VALUES('build','tenant','project','release','generic_ci',$1,'passed',now(),$2,'build-run.v1.0.0')`, strings.Repeat("1", 40), []map[string]string{{"artifact_id": "artifact", "digest": digest}})
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile("../../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []map[string]string{{"keyid": "root-1", "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(private, securedsse.PAE("application/vnd.in-toto+json", payload)))}}})
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
	if err := objects.Put(ctx, app.Object{Key: final, TenantID: "tenant", Digest: hash, MediaType: "application/vnd.dsse.envelope+json", Bytes: raw, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO object_payloads(tenant_id,object_key,digest,media_type,size,staging_key,final_key,status,updated_at,finalized_at) VALUES('tenant',$1,$2,'application/vnd.dsse.envelope+json',$3,$4,$1,'finalized',now(),now())`, final, hash, len(raw), staging)
	exec(`INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,build_id,type,title,source_system,observed_at,evidence_version,schema_version,payload_ref,payload_hash,payload_size,payload_media_type,canonical_hash,canonicalization,trust_level,verification_status,chain_entry_id,subject_refs) VALUES('evidence','tenant','product','project','release','build','build_attestation','Attestation','ci',now(),1,'evidence-item.v1.0.0',$1,$2,$3,'application/vnd.dsse.envelope+json','hash','evydence-c14n.v2.0.0','L2','pending','',$4)`, "object://"+final, hash, len(raw), []map[string]string{{"type": "artifact", "id": "artifact", "digest": "opaque-not-trusted"}})
	exec(`INSERT INTO build_attestations(id,tenant_id,build_id,evidence_id,payload_ref,payload_hash,payload_size,payload_type,predicate_type,subject_digests,materials_count,signature_count,verification_status,schema_version) VALUES('attestation','tenant','build','evidence',$1,$2,$3,'','','[]',0,0,'accepted','build-attestation.v1.0.0')`, "object://"+final, hash, len(raw))
	exec(`INSERT INTO dsse_trust_roots(id,tenant_id,name,key_id,algorithm,public_key,status,schema_version,created_at,allowed_predicate_types,expected_builder_ids,required_claims) VALUES('root','tenant','Root','root-1','Ed25519',$1,'active','dsse-trust-root.v2.0.0',now(),'["https://slsa.dev/provenance/v1"]','["https://github.com/actions/runner"]','["builder_id","build_type","external_parameters"]')`, base64.StdEncoding.EncodeToString(public))
	return objects
}

func TestPostgresDSSEVerificationReadsDurableFactsWithoutLedger(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	objects := seedDSSEVerification(t, pool, false)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	var hash string
	if err := pool.QueryRow(ctx, `SELECT payload_hash FROM build_attestations WHERE id='attestation'`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildDSSEVerificationCommands(store, objects)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"verify:read"}}}}
	result, err := commands.VerifyDSSEAttestationSignature(ctx, actor, "attestation")
	if err != nil || result.Result.String() != "passed" || len(result.Checks) != 7 {
		t.Fatal(result, err)
	}
	counts := func(want int) {
		t.Helper()
		var results, audits, jobs int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM verification_results),(SELECT count(*) FROM audit_chain_entries),(SELECT count(*) FROM outbox_jobs)`).Scan(&results, &audits, &jobs); err != nil || results != want || audits != want || jobs != want {
			t.Fatal("effects", results, audits, jobs, err)
		}
	}
	counts(1)
	denied := actor
	denied.ResourceGrants = nil
	before := objects.reads
	if _, err := commands.VerifyDSSEAttestationSignature(ctx, denied, "attestation"); !errors.Is(err, verificationapp.ErrForbidden) || objects.reads != before {
		t.Fatal("unauthorized payload access", err)
	}
	foreign := actor
	foreign.TenantID = "other"
	if _, err := commands.VerifyDSSEAttestationSignature(ctx, foreign, "attestation"); !errors.Is(err, verificationapp.ErrNotFound) || objects.reads != before {
		t.Fatal("foreign payload access", err)
	}
	// Signed subject claims are not enough without a registered release link.
	exec(`UPDATE evidence_items SET subject_refs='[]' WHERE id='evidence'`)
	result, err = commands.VerifyDSSEAttestationSignature(ctx, actor, "attestation")
	if !errors.Is(err, verificationapp.ErrVerificationFailed) || result.Result.String() != "failed" {
		t.Fatal("unregistered subject passed", result, err)
	}
	counts(2)
	exec(`UPDATE dsse_trust_roots SET status='legacy_untrusted' WHERE id='root'`)
	result, err = commands.VerifyDSSEAttestationSignature(ctx, actor, "attestation")
	if err != nil || result.Result.String() != "not_verified" {
		t.Fatal("missing root assigned trust", result, err)
	}
	counts(3)
	exec(`UPDATE object_payloads SET status='failed' WHERE digest=$1`, hash)
	before = objects.reads
	if result, err := commands.VerifyDSSEAttestationSignature(ctx, actor, "attestation"); err == nil || result.ID != "" || objects.reads != before {
		t.Fatal("unfinalized object read", err)
	}
	counts(3)
	exec(`UPDATE object_payloads SET status='finalized' WHERE digest=$1`, hash)
	exec(`CREATE FUNCTION reject_dsse_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced audit failure';END$$`)
	exec(`CREATE TRIGGER reject_dsse_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_dsse_audit()`)
	if result, err := commands.VerifyDSSEAttestationSignature(ctx, actor, "attestation"); err == nil || result.ID != "" {
		t.Fatal("audit failure published receipt", err)
	}
	counts(3)
	exec(`DROP TRIGGER reject_dsse_audit ON audit_chain_entries`)
	exec(`UPDATE dsse_trust_roots SET status='active' WHERE id='root'`)
	exec(`UPDATE evidence_items SET subject_refs='[{"type":"artifact","id":"artifact","digest":"opaque-not-trusted"}]' WHERE id='evidence'`)
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		reader := repos.Verification.(verificationapp.DSSEVerificationReader)
		subject, err := reader.ResolveDSSEVerificationSubject(ctx, "tenant", "attestation")
		if err != nil {
			return err
		}
		if _, err := reader.ReadDSSEVerification(ctx, subject); err != nil {
			return err
		}
		for _, sql := range []string{
			`UPDATE build_attestations SET build_id=build_id WHERE id='attestation'`,
			`UPDATE evidence_items SET release_id=release_id WHERE id='evidence'`,
			`UPDATE build_runs SET outputs=outputs WHERE id='build'`,
			`UPDATE artifacts SET digest=digest WHERE id='artifact'`,
			`UPDATE object_payloads SET status=status WHERE tenant_id='tenant'`,
			`UPDATE dsse_trust_roots SET status=status WHERE id='root'`,
			`UPDATE releases SET product_id=product_id WHERE id='release'`,
		} {
			other, err := pool.Begin(ctx)
			if err != nil {
				return err
			}
			if _, err := other.Exec(ctx, `SET LOCAL lock_timeout='50ms'`); err != nil {
				_ = other.Rollback(ctx)
				return err
			}
			_, blocked := other.Exec(ctx, sql)
			_ = other.Rollback(ctx)
			var pgError *pgconn.PgError
			if !errors.As(blocked, &pgError) || pgError.Code != "55P03" {
				t.Fatalf("verification input was not locked: %s err=%v", sql, blocked)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	actor.UserID, actor.KeyID = "", "key"
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	calls := 0
	for range 2 {
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "dsse-replay", []byte(`{"subject_type":"build_attestation","subject_id":"attestation"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			result, err := commands.VerifyDSSEAttestationSignature(ctx, actor, "attestation")
			return 200, verificationResultToLegacy(result), err
		}); err != nil {
			t.Fatal(err)
		}
	}
	counts(4)
	if calls != 1 {
		t.Fatal("replay re-inspected payload")
	}
	exec(`UPDATE evidence_items SET subject_refs='[]' WHERE id='evidence'`)
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "dsse-failed", []byte(`{"subject_type":"build_attestation","subject_id":"attestation"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		result, err := commands.VerifyDSSEAttestationSignature(ctx, actor, "attestation")
		return 200, verificationResultToLegacy(result), err
	}); !errors.Is(err, verificationapp.ErrVerificationFailed) {
		t.Fatal("failed POST did not propagate failure", err)
	}
	counts(4)
	// Stored claim projection does not supply expected artifact identity.
	exec(`UPDATE evidence_items SET subject_refs='[{"type":"artifact","id":"artifact"}]' WHERE id='evidence'`)
	exec(`UPDATE build_attestations SET verification_status='structurally_valid',payload_type='application/vnd.in-toto+json',predicate_type='https://slsa.dev/provenance/v1',subject_digests='["forged-projection"]',signature_count=1 WHERE id='attestation'`)
	if got, err := commands.VerifyDSSEAttestationSignature(ctx, actor, "attestation"); err != nil || got.Result.String() != "passed" {
		t.Fatal("trusted parsed claims instead of raw signed statement", got, err)
	}
	counts(5)
	for _, mutation := range []string{
		`UPDATE dsse_trust_roots SET expected_builder_ids='{}' WHERE id='root'`,
		`UPDATE dsse_trust_roots SET expected_builder_ids=jsonb_build_array(repeat('x',8388608)) WHERE id='root'`,
		`UPDATE dsse_trust_roots SET expected_builder_ids=(SELECT jsonb_agg('builder-'||n) FROM generate_series(1,4097)n) WHERE id='root'`,
	} {
		exec(mutation)
		before = objects.reads
		if got, err := commands.VerifyDSSEAttestationSignature(ctx, actor, "attestation"); !errors.Is(err, verificationapp.ErrConflict) || got.ID != "" || objects.reads != before {
			t.Fatal("bad trust projection accessed payload", err)
		}
		counts(5)
	}
	exec(`UPDATE dsse_trust_roots SET expected_builder_ids='["https://github.com/actions/runner"]' WHERE id='root'`)
	exec(`UPDATE build_runs SET outputs=(SELECT jsonb_agg(jsonb_build_object('artifact_id','artifact','digest',$1::text)) FROM generate_series(1,4097)) WHERE id='build'`, digest)
	before = objects.reads
	if _, err := commands.VerifyDSSEAttestationSignature(ctx, actor, "attestation"); !errors.Is(err, verificationapp.ErrConflict) || objects.reads != before {
		t.Fatal("unbounded build outputs accessed payload", err)
	}
	counts(5)
}

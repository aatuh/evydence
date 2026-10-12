package wiring

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/adapters/verification/sigstore"
	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresCosignVerificationUsesBoundedDurableFactsAndAtomicReceipts(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Cosign'),('other','Other')`)
	digest := "sha256:bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b"
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('artifact','tenant','Artifact','application/octet-stream',$1,1)`, digest)
	// Two eligible images select a deterministic ID; the third is foreign.
	exec(`INSERT INTO container_images(id,tenant_id,artifact_id,repository,digest,schema_version,created_at)VALUES('image-z','tenant','artifact','repo-z',$1,'container-image.v1.0.0',now()),('image-a','tenant','artifact','repo-a',$1,'container-image.v1.0.0',now()),('a-foreign','other','artifact','foreign',$1,'container-image.v1.0.0',now())`, digest)
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
	if err := objects.Put(ctx, app.Object{Key: final, TenantID: "tenant", Digest: hash, MediaType: "application/json", Bytes: raw, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO object_payloads(tenant_id,object_key,digest,media_type,size,staging_key,final_key,status,updated_at,finalized_at)VALUES('tenant',$1,$2,'application/json',$3,$4,$1,'finalized',now(),now())`, final, hash, len(raw), staging)
	exec(`INSERT INTO artifact_signatures(id,tenant_id,artifact_id,subject_digest,algorithm,signature,payload_ref,payload_hash,verification_status,schema_version,created_at)VALUES('signature','tenant','artifact',$1,'cosign','ignored-detached-text',$2,$3,'recorded','artifact-signature.v1.0.0',now())`, digest, "object://"+final, hash)
	commands, err := BuildCosignVerificationCommands(store, objects, verifier)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"verify:read"}}}}
	input := verificationapp.VerifyCosignInput{ArtifactSignatureID: "signature", ExpectedIdentity: "foo!oidc.local", ExpectedIssuer: "http://oidc.local:8080", Mode: verificationapp.CosignVerificationModeKeyless, Offline: true}
	result, err := commands.VerifyCosign(ctx, actor, input)
	if err != nil || result.Result != "passed" || result.ContainerImageID != "image-a" || result.VerifierLibraryVersion != sigstore.LibraryVersion || result.TrustRootVersion != "fixture-root.v1" {
		t.Fatal(result, err)
	}
	counts := func(want int) {
		t.Helper()
		var cosign, results, audits, jobs int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM cosign_verifications),(SELECT count(*)FROM verification_results),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&cosign, &results, &audits, &jobs); err != nil || cosign != want || results != want || audits != want || jobs != 0 {
			t.Fatal("partial effects", cosign, results, audits, jobs, err)
		}
	}
	counts(1)
	var library, version, mode string
	if err := pool.QueryRow(ctx, `SELECT verifier_library_version,trust_root_version,verification_mode FROM cosign_verifications WHERE id=$1`, result.ID).Scan(&library, &version, &mode); err != nil || library != result.VerifierLibraryVersion || version != result.TrustRootVersion || mode != string(input.Mode) {
		t.Fatalf("durable receipt lost verifier identity: %q %q %q err=%v", library, version, mode, err)
	}
	before := objects.reads
	denied := actor
	denied.ResourceGrants = nil
	if _, err := commands.VerifyCosign(ctx, denied, input); !errors.Is(err, verificationapp.ErrForbidden) || objects.reads != before {
		t.Fatal("unauthorized payload read", err)
	}
	denied.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "unrelated", Scopes: []string{"verify:read"}}}
	if _, err := commands.VerifyCosign(ctx, denied, input); !errors.Is(err, verificationapp.ErrForbidden) || objects.reads != before {
		t.Fatal("release grant authorized tenant artifact", err)
	}
	foreign := actor
	foreign.TenantID = "other"
	if _, err := commands.VerifyCosign(ctx, foreign, input); !errors.Is(err, verificationapp.ErrNotFound) || objects.reads != before {
		t.Fatal("foreign payload read", err)
	}
	counts(1)
	wrong := input
	wrong.ExpectedIdentity = "wrong identity"
	failed, err := commands.VerifyCosign(ctx, actor, wrong)
	if !errors.Is(err, verificationapp.ErrVerificationFailed) || failed.Result != "failed" {
		t.Fatal("wrong identity passed", failed, err)
	}
	counts(2)
	unavailable, err := BuildCosignVerificationCommands(store, objects, nil)
	if err != nil {
		t.Fatal(err)
	}
	before = objects.reads
	if got, err := unavailable.VerifyCosign(ctx, actor, input); !errors.Is(err, verificationapp.ErrFullVerificationUnavailable) || got.Result == "passed" || objects.reads != before {
		t.Fatal("missing verifier passed", got, err)
	}
	counts(3)
	exec(`UPDATE object_payloads SET status='staged' WHERE digest=$1`, hash)
	before = objects.reads
	if got, err := commands.VerifyCosign(ctx, actor, input); !errors.Is(err, verificationapp.ErrVerificationFailed) || got.Result != "failed" || objects.reads != before {
		t.Fatal("staged object read", got, err)
	}
	counts(4)
	exec(`UPDATE object_payloads SET status='finalized' WHERE digest=$1`, hash)
	exec(`CREATE FUNCTION reject_cosign_audit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced failure';END$$`)
	exec(`CREATE TRIGGER reject_cosign_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_cosign_audit()`)
	if got, err := commands.VerifyCosign(ctx, actor, input); err == nil || got.ID != "" {
		t.Fatal("audit failure published receipt", got, err)
	}
	counts(4)
	exec(`DROP TRIGGER reject_cosign_audit ON audit_chain_entries`)
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		reader := repos.Verification.(verificationapp.CosignSnapshotReader)
		s, err := reader.ResolveCosignSubject(ctx, "tenant", "signature")
		if err != nil {
			return err
		}
		if _, err := reader.ReadCosignSnapshot(ctx, s); err != nil {
			return err
		}
		for _, sql := range []string{`UPDATE tenants SET name=name WHERE id='tenant'`, `UPDATE artifacts SET digest=digest WHERE id='artifact'`, `UPDATE artifact_signatures SET payload_hash=payload_hash WHERE id='signature'`, `UPDATE object_payloads SET status=status WHERE tenant_id='tenant'`, `UPDATE container_images SET digest=digest WHERE id='image-a'`} {
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
			var pgErr *pgconn.PgError
			if !errors.As(blocked, &pgErr) || pgErr.Code != "55P03" {
				t.Fatalf("selected verification facts not locked: %s err=%v", sql, blocked)
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
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/artifact-signatures/signature/verify-cosign", "cosign-replay", []byte(`{"mode":"keyless","offline":true}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			r, err := commands.VerifyCosign(ctx, actor, input)
			return 200, cosignVerificationToLegacy(r), err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("replay reverified bundle")
	}
	counts(5)
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/artifact-signatures/signature/verify-cosign", "cosign-failure", []byte(`{"mode":"keyless","offline":true,"expected_identity":"wrong"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		r, err := commands.VerifyCosign(ctx, actor, wrong)
		return 200, cosignVerificationToLegacy(r), err
	}); !errors.Is(err, verificationapp.ErrVerificationFailed) {
		t.Fatal(err)
	}
	counts(5)
	// Fields unused by bundle verification never enter the projection budget.
	exec(`UPDATE artifact_signatures SET signature=repeat('x',5000000) WHERE id='signature'`)
	if got, err := commands.VerifyCosign(ctx, actor, input); err != nil || got.Result != "passed" {
		t.Fatal("detached text influenced bundle verification", got, err)
	}
	counts(6)
	exec(`UPDATE artifact_signatures SET payload_ref=$1 WHERE id='signature'`, strings.Repeat("x", 4097))
	before = objects.reads
	if got, err := commands.VerifyCosign(ctx, actor, input); !errors.Is(err, verificationapp.ErrConflict) || got.ID != "" || objects.reads != before {
		t.Fatal("unbounded payload coordinate", got, err)
	}
	counts(6)
}

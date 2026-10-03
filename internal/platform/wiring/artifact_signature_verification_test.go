package wiring

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresArtifactSignatureVerificationIsDurableMetadataOnly(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Metadata'),('other','Other')`)
	digest := "sha256:" + strings.Repeat("a", 64)
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('artifact','tenant','Artifact','application/octet-stream',$1,1)`, digest)
	exec(`INSERT INTO artifact_signatures(id,tenant_id,artifact_id,subject_digest,algorithm,signature,payload_ref,payload_hash,verification_status,schema_version,created_at)VALUES('signature','tenant','artifact',$1,'cosign','not-a-valid-signature',repeat('x',5000000),repeat('x',5000000),'recorded','artifact-signature.v1.0.0',now())`, digest)
	commands, err := BuildArtifactSignatureVerificationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"verify:read"}}}}
	result, err := commands.VerifyArtifactSignature(ctx, actor, "signature")
	if err != nil || result.Result.String() != "limited" || result.Profile.ID != "artifact-signature-metadata.v1" || result.Profile.PayloadDigest != digest || len(result.Checks) != 2 {
		t.Fatal(result, err)
	}
	counts := func(want int) {
		t.Helper()
		var results, audits, jobs int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM verification_results),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&results, &audits, &jobs); err != nil || results != want || audits != want || jobs != want {
			t.Fatal("partial effects", results, audits, jobs, err)
		}
	}
	counts(1)
	var subject, receiptID string
	if err := pool.QueryRow(ctx, `SELECT subject_id,payload->>'result_id' FROM outbox_jobs`).Scan(&subject, &receiptID); err != nil || subject != "signature" || receiptID != result.ID {
		t.Fatal("receipt job link", subject, receiptID, err)
	}
	denied := actor
	denied.ResourceGrants = nil
	if _, err := commands.VerifyArtifactSignature(ctx, denied, "signature"); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal("no grant accepted", err)
	}
	denied.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "artifact", Scopes: []string{"verify:read"}}}
	if _, err := commands.VerifyArtifactSignature(ctx, denied, "signature"); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal("unrelated grant accepted", err)
	}
	foreign := actor
	foreign.TenantID = "other"
	if _, err := commands.VerifyArtifactSignature(ctx, foreign, "signature"); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("foreign signature read", err)
	}
	counts(1)
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('foreign-artifact','other','Foreign','application/octet-stream',$1,1)`, digest)
	exec(`UPDATE artifact_signatures SET artifact_id='foreign-artifact' WHERE id='signature'`)
	if r, err := commands.VerifyArtifactSignature(ctx, actor, "signature"); !errors.Is(err, verificationapp.ErrNotFound) || r.ID != "" {
		t.Fatal("foreign artifact reference authorized", r, err)
	}
	counts(1)
	exec(`UPDATE artifact_signatures SET artifact_id='artifact' WHERE id='signature'`)
	exec(`UPDATE artifact_signatures SET signature='' WHERE id='signature'`)
	if r, err := commands.VerifyArtifactSignature(ctx, actor, "signature"); !errors.Is(err, verificationapp.ErrVerificationFailed) || r.Result.String() != "failed" {
		t.Fatal("empty signature trusted", r, err)
	}
	counts(2)
	exec(`UPDATE artifact_signatures SET signature=repeat('x',5000000),algorithm=repeat('y',5000000) WHERE id='signature'`)
	if r, err := commands.VerifyArtifactSignature(ctx, actor, "signature"); err != nil || r.Result.String() != "limited" {
		t.Fatal("unused signature text was loaded or trusted", r, err)
	}
	counts(3)
	exec(`UPDATE artifacts SET digest=$1 WHERE id='artifact'`, "sha256:"+strings.Repeat("b", 64))
	if r, err := commands.VerifyArtifactSignature(ctx, actor, "signature"); !errors.Is(err, verificationapp.ErrVerificationFailed) || r.Result.String() != "failed" {
		t.Fatal("digest mismatch trusted", r, err)
	}
	counts(4)
	exec(`UPDATE artifacts SET digest=$1 WHERE id='artifact'`, digest)
	exec(`CREATE FUNCTION reject_signature_audit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced failure';END$$`)
	exec(`CREATE TRIGGER reject_signature_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_signature_audit()`)
	if r, err := commands.VerifyArtifactSignature(ctx, actor, "signature"); err == nil || r.ID != "" {
		t.Fatal("failed audit published receipt", r, err)
	}
	counts(4)
	exec(`DROP TRIGGER reject_signature_audit ON audit_chain_entries`)
	exec(`CREATE FUNCTION reject_signature_outbox()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced failure';END$$`)
	exec(`CREATE TRIGGER reject_signature_outbox BEFORE INSERT ON outbox_jobs FOR EACH ROW EXECUTE FUNCTION reject_signature_outbox()`)
	if r, err := commands.VerifyArtifactSignature(ctx, actor, "signature"); err == nil || r.ID != "" {
		t.Fatal("failed job published receipt", r, err)
	}
	counts(4)
	exec(`DROP TRIGGER reject_signature_outbox ON outbox_jobs`)
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		reader := repos.Verification.(verificationapp.ArtifactSignatureVerificationReader)
		s, err := reader.ResolveArtifactSignatureVerificationSubject(ctx, "tenant", "signature")
		if err != nil {
			return err
		}
		if _, err := reader.ReadArtifactSignatureVerification(ctx, s); err != nil {
			return err
		}
		for _, sql := range []string{`UPDATE tenants SET name=name WHERE id='tenant'`, `UPDATE artifacts SET digest=digest WHERE id='artifact'`, `UPDATE artifact_signatures SET artifact_id=artifact_id WHERE id='signature'`} {
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
				t.Fatalf("metadata fact not locked: %s err=%v", sql, blocked)
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
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "signature-metadata-replay", []byte(`{"subject_type":"artifact_signature","subject_id":"signature"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			r, err := commands.VerifyArtifactSignature(ctx, actor, "signature")
			return 200, verificationResultToLegacy(r), err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("replay duplicated metadata assessment")
	}
	counts(5)
	exec(`UPDATE artifact_signatures SET signature='' WHERE id='signature'`)
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "signature-metadata-failed", []byte(`{"subject_type":"artifact_signature","subject_id":"signature"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		r, err := commands.VerifyArtifactSignature(ctx, actor, "signature")
		return 200, verificationResultToLegacy(r), err
	}); !errors.Is(err, verificationapp.ErrVerificationFailed) {
		t.Fatal(err)
	}
	counts(5)
	exec(`UPDATE artifact_signatures SET subject_digest=repeat('x',1025) WHERE id='signature'`)
	if r, err := commands.VerifyArtifactSignature(ctx, actor, "signature"); !errors.Is(err, verificationapp.ErrConflict) || r.ID != "" {
		t.Fatal("oversized digest truncated", r, err)
	}
	counts(5)
}

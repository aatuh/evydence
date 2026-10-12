package wiring

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresReleaseBundleVerificationUsesCurrentDurableSigningState(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name) VALUES('tenant','Verify'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','Verify','verify'),('foreign_product','other','Other','other')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('release','tenant','product','1','draft'),('foreign_release','other','foreign_product','1','draft')`)
	now := time.Now().UTC().Add(-time.Hour)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{"version": 1, "nested": map[string]any{"safe": "test"}}
	hash, err := application.NormalizedJSONHash(manifest)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,created_at,valid_from,version,provider) VALUES('key','tenant','key','Ed25519','active',$1,$2,$3,$3,1,'local_ed25519')`, base64.RawStdEncoding.EncodeToString(public), []byte("private-material-not-read"), now)
	exec(`INSERT INTO release_bundles(id,tenant_id,release_id,state,manifest,manifest_hash,signature_refs) VALUES('bundle','tenant','release','signed',$1,$2,'["signature"]'),('foreign','other','foreign_release','signed',$1,$2,'["signature"]')`, manifest, hash)
	exec(`INSERT INTO signatures(id,tenant_id,subject_type,subject_id,key_id,algorithm,value,created_at) VALUES('signature','tenant','release_bundle','bundle','key','Ed25519',$1,$2)`, base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, []byte(hash))), now.Add(time.Minute))
	commands, err := BuildReleaseBundleVerificationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"verify:read"}}}}
	result, err := commands.VerifyReleaseBundle(ctx, actor, "bundle")
	if err != nil || result.Result.String() != "passed" || result.Profile.ID != "release-bundle-signature.v1" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	var results, audits, jobs int
	counts := func() {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM verification_results),(SELECT count(*) FROM audit_chain_entries),(SELECT count(*) FROM outbox_jobs)`).Scan(&results, &audits, &jobs); err != nil {
			t.Fatal(err)
		}
	}
	counts()
	if results != 1 || audits != 1 || jobs != 1 {
		t.Fatalf("effects=%d/%d/%d", results, audits, jobs)
	}
	denied := actor
	denied.ResourceGrants = nil
	if _, err := commands.VerifyReleaseBundle(ctx, denied, "bundle"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("missing grant", err)
	}
	denied.Scopes = []string{"bundle:read"}
	if _, err := commands.VerifyReleaseBundle(ctx, denied, "bundle"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("wrong scope", err)
	}
	if _, err := commands.VerifyReleaseBundle(ctx, actor, "foreign"); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("foreign bundle", err)
	}
	exec(`UPDATE signing_keys SET status='retiring',valid_until=now() WHERE id='key'`)
	if _, err := commands.VerifyReleaseBundle(ctx, actor, "bundle"); err != nil {
		t.Fatal("rotation lost historical validity", err)
	}
	exec(`UPDATE signing_keys SET status='revoked',revoked_at=now(),revocation_semantics='compromised',historical_validity_policy='invalidate_all',compromised_at=now() WHERE id='key'`)
	result, err = commands.VerifyReleaseBundle(ctx, actor, "bundle")
	if !errors.Is(err, verificationapp.ErrVerificationFailed) || result.Result.String() != "failed" {
		t.Fatal("stale key lifecycle passed", err)
	}
	counts()
	if results != 3 || audits != 3 || jobs != 3 {
		t.Fatal("failed verification not durably recorded")
	}
	exec(`CREATE FUNCTION reject_verify_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced audit failure';END$$`)
	exec(`CREATE TRIGGER reject_verify_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_verify_audit()`)
	if result, err := commands.VerifyReleaseBundle(ctx, actor, "bundle"); err == nil || result.ID != "" {
		t.Fatal("audit failure published receipt", err)
	}
	counts()
	if results != 3 || audits != 3 || jobs != 3 {
		t.Fatal("partial effects after audit failure")
	}
	exec(`DROP TRIGGER reject_verify_audit ON audit_chain_entries`)
	// Tampered bytes and missing/foreign signing material produce failed
	// receipts, not optimistic checks or raw database failures.
	exec(`UPDATE signing_keys SET revocation_semantics='ordinary',historical_validity_policy='preserve' WHERE id='key'`)
	for _, mutation := range []string{
		`UPDATE signatures SET subject_id='another_bundle' WHERE id='signature'`,
		`UPDATE signing_keys SET public_key='AQ' WHERE id='key'`,
		`UPDATE release_bundles SET manifest='{"version":2}' WHERE id='bundle'`,
	} {
		exec(mutation)
		if result, err := commands.VerifyReleaseBundle(ctx, actor, "bundle"); !errors.Is(err, verificationapp.ErrVerificationFailed) || result.Result.String() != "failed" {
			t.Fatal("tampering not detected", err)
		}
	}
	// Restore one valid snapshot for deterministic lock checks.
	exec(`UPDATE signatures SET subject_id='bundle' WHERE id='signature'`)
	exec(`UPDATE signing_keys SET public_key=$1 WHERE id='key'`, base64.RawStdEncoding.EncodeToString(public))
	exec(`UPDATE release_bundles SET manifest=$1 WHERE id='bundle'`, manifest)
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		reader := repos.Verification.(verificationapp.ReleaseBundleVerificationReader)
		subject, err := reader.ResolveReleaseBundleVerificationSubject(ctx, "tenant", "bundle")
		if err != nil {
			return err
		}
		if _, err := reader.ReadReleaseBundleVerification(ctx, subject); err != nil {
			return err
		}
		for _, sql := range []string{`UPDATE tenants SET name=name WHERE id='tenant'`, `UPDATE products SET name=name WHERE id='product'`, `UPDATE releases SET product_id=product_id WHERE id='release'`, `UPDATE release_bundles SET manifest_hash=manifest_hash WHERE id='bundle'`, `UPDATE signatures SET value=value WHERE id='signature'`, `UPDATE signing_keys SET status=status WHERE id='key'`} {
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
				t.Fatalf("verification row was not locked: %s err=%v", sql, blocked)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A successful idempotent POST shares the command transaction and replays
	// one safe response without adding another receipt, audit entry or job.
	calls := 0
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		calls++
		result, err := commands.VerifyReleaseBundle(ctx, actor, "bundle")
		return 200, verificationResultToLegacy(result), err
	}
	counts()
	startResults := results
	for i := 0; i < 2; i++ {
		if status, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "bundle-verify-replay", []byte(`{"subject_type":"release_bundle","subject_id":"bundle"}`), run); err != nil || status != 200 {
			t.Fatal("durable verification replay", err)
		}
	}
	counts()
	if calls != 1 || results != startResults+1 || audits != results || jobs != results {
		t.Fatal("replay duplicated durable effects")
	}
	// Existing POST error semantics roll back the enclosing idempotent command;
	// GET/direct verification commits failed receipts. Preserve that boundary.
	exec(`UPDATE signing_keys SET revocation_semantics='compromised',historical_validity_policy='invalidate_all' WHERE id='key'`)
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "bundle-verify-failed", []byte(`{}`), run); !errors.Is(err, verificationapp.ErrVerificationFailed) {
		t.Fatal("failed POST contract", err)
	}
	counts()
	if results != startResults+1 || audits != results || jobs != results {
		t.Fatal("failed POST leaked partial transaction")
	}
	counts()
	before := results
	for _, mutation := range []string{
		`UPDATE release_bundles SET signature_refs=(SELECT jsonb_agg('ref_'||n) FROM generate_series(1,4097)n) WHERE id='bundle'`,
		`UPDATE release_bundles SET signature_refs='["signature","signature"]' WHERE id='bundle'`,
		`UPDATE release_bundles SET signature_refs='null' WHERE id='bundle'`,
		`UPDATE release_bundles SET signature_refs='["signature"]',manifest=jsonb_build_object('oversized',repeat('x',8388608)) WHERE id='bundle'`,
	} {
		exec(mutation)
		if result, err := commands.VerifyReleaseBundle(ctx, actor, "bundle"); !errors.Is(err, verificationapp.ErrConflict) || result.ID != "" {
			t.Fatal("unbounded/malformed snapshot accepted", err)
		}
	}
	counts()
	if results != before || audits != before || jobs != before {
		t.Fatal("bounded projection failure wrote receipt")
	}
	exec(`UPDATE release_bundles SET signature_refs='["signature"]',manifest=$1 WHERE id='bundle'`, manifest)
	// Each value is individually within its field limit, but aggregate selected
	// text must still stop at the 8 MiB metadata budget.
	exec(`INSERT INTO signatures(id,tenant_id,subject_type,subject_id,key_id,algorithm,value,created_at) SELECT 'budget_'||n,'tenant','release_bundle','bundle','key','Ed25519',repeat('x',8192),$1 FROM generate_series(1,1100)n`, now)
	exec(`UPDATE release_bundles SET signature_refs=(SELECT jsonb_agg(id) FROM signatures WHERE id LIKE 'budget_%') WHERE id='bundle'`)
	if _, err := commands.VerifyReleaseBundle(ctx, actor, "bundle"); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("aggregate text budget", err)
	}
	counts()
	if results != before {
		t.Fatal("budget failure wrote receipt")
	}
	for _, id := range []string{"bad\x00id", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		if _, err := commands.VerifyReleaseBundle(ctx, actor, id); !errors.Is(err, verificationapp.ErrValidation) {
			t.Fatal("invalid id reached PostgreSQL", err)
		}
	}
	exec(`UPDATE releases SET product_id='foreign_product' WHERE id='release'`)
	if _, err := commands.VerifyReleaseBundle(ctx, actor, "bundle"); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("foreign parent accepted", err)
	}
}

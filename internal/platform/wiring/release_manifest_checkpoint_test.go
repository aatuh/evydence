package wiring

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresReleaseManifestCheckpointBindsDurableHeadAndAtomicReceipt(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Checkpoint'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Checkpoint','checkpoint'),('unrelated','tenant',repeat('x',9000000),'unrelated')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft')`)
	now := time.Now().UTC().Add(-time.Hour)
	const initial = 130
	var covered domain.AuditChainEntry
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		for i := 1; i <= initial; i++ {
			e, err := repos.Audit.Append(ctx, domain.AuditChainEntry{ID: fmt.Sprintf("entry_%d", i), TenantID: "tenant", EntryType: "test", SubjectType: "test", SubjectID: "test", ActorType: "api_key", ActorID: "caller", OccurredAt: now, Metadata: map[string]any{"safe": "value"}})
			if err != nil {
				return err
			}
			if i == 128 {
				covered = e
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,created_at,valid_from,version,provider)VALUES('key','tenant','key','Ed25519','active',$1,$2,$3,$3,1,'local_ed25519')`, base64.RawStdEncoding.EncodeToString(public), []byte("private-not-selected"), now)
	manifest := map[string]any{"chain_checkpoint": map[string]any{"sequence": covered.Sequence, "head_hash": covered.EntryHash}}
	hash, err := application.NormalizedJSONHash(manifest)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO release_bundles(id,tenant_id,release_id,state,manifest,manifest_hash,signature_refs)VALUES('bundle','tenant','release','signed',$1,$2,'["signature"]')`, manifest, hash)
	exec(`INSERT INTO signatures(id,tenant_id,subject_type,subject_id,key_id,algorithm,value,created_at)VALUES('signature','tenant','release_bundle','bundle','key','Ed25519',$1,$2)`, base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, []byte(hash))), now.Add(time.Minute))
	commands, err := BuildReleaseManifestCheckpointCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"verify:read"}}}}
	want, dropped := 0, 0
	counts := func() {
		t.Helper()
		var results, audits, jobs int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM verification_results),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&results, &audits, &jobs); err != nil || results != want || audits != want+initial-dropped || jobs != want {
			t.Fatal("partial checkpoint effects", results, audits, jobs, want, err)
		}
	}
	r, err := commands.VerifyReleaseManifestCheckpoint(ctx, actor, "bundle")
	if err != nil || r.Result.String() != "passed" || r.Profile.ID != "audit-chain-release-manifest-checkpoint.v1" || r.Profile.PayloadDigest != hash || len(r.Checks) != initial*7+4 || r.SubjectType != "audit_chain_release_manifest" {
		t.Fatal(r, err)
	}
	want++
	counts()
	denied := actor
	denied.ResourceGrants = nil
	if _, err := commands.VerifyReleaseManifestCheckpoint(ctx, denied, "bundle"); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	denied.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"verify:read"}}}
	if _, err := commands.VerifyReleaseManifestCheckpoint(ctx, denied, "bundle"); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal("release grant exposed tenant chain", err)
	}
	foreign := identitydomain.Actor{TenantID: "other", KeyID: "foreign", Scopes: []string{"verify:read"}}
	if _, err := commands.VerifyReleaseManifestCheckpoint(ctx, foreign, "bundle"); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal(err)
	}
	counts()
	if err := (releaseManifestCheckpointTransactions{store}).ExecuteReleaseManifestCheckpointVerification(ctx, func(ctx context.Context, tx verificationapp.ReleaseManifestCheckpointTransaction) error {
		view, err := tx.LockAuditChainVerification(ctx, "tenant")
		if err != nil {
			return err
		}
		s, err := tx.ResolveReleaseBundleVerificationSubject(ctx, "tenant", "bundle")
		if err != nil {
			return err
		}
		if _, err := tx.ReadReleaseBundleVerification(ctx, s); err != nil {
			return err
		}
		var after *int64
		budget := verificationapp.MaxAuditChainVerificationBytes
		for {
			page, err := tx.ReadAuditChainVerificationPage(ctx, view, after, budget)
			if err != nil {
				return err
			}
			budget -= page.BytesRead
			if len(page.Entries) == 0 {
				break
			}
			seq := page.Entries[len(page.Entries)-1].Sequence
			after = &seq
		}
		for _, sql := range []string{`UPDATE tenants SET name=name WHERE id='tenant'`, `UPDATE products SET name=name WHERE id='product'`, `UPDATE releases SET state=state WHERE id='release'`, `UPDATE release_bundles SET manifest=manifest WHERE id='bundle'`, `UPDATE signatures SET value=value WHERE id='signature'`, `UPDATE signing_keys SET status=status WHERE id='key'`, `UPDATE audit_chain_entries SET metadata=metadata WHERE id='entry_130'`, `SELECT pg_advisory_xact_lock(hashtext('tenant'))`} {
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
				t.Fatal("unstable checkpoint view", sql, blocked)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{
		{`UPDATE audit_chain_entries SET metadata='{"changed":true}' WHERE id='entry_1'`, `UPDATE audit_chain_entries SET metadata='{"safe":"value"}' WHERE id='entry_1'`},
		{`UPDATE audit_chain_entries SET actor_id='changed' WHERE id='entry_130'`, `UPDATE audit_chain_entries SET actor_id='caller' WHERE id='entry_130'`},
		{`UPDATE release_bundles SET manifest=manifest||'{"changed":true}' WHERE id='bundle'`, `UPDATE release_bundles SET manifest=manifest-'changed' WHERE id='bundle'`},
		{`UPDATE signatures SET subject_id='other' WHERE id='signature'`, `UPDATE signatures SET subject_id='bundle' WHERE id='signature'`},
		{`UPDATE signatures SET tenant_id='other' WHERE id='signature'`, `UPDATE signatures SET tenant_id='tenant' WHERE id='signature'`},
		{`UPDATE signing_keys SET revocation_semantics='compromised',historical_validity_policy='invalidate_all' WHERE id='key'`, `UPDATE signing_keys SET revocation_semantics='ordinary',historical_validity_policy='preserve' WHERE id='key'`},
	} {
		exec(pair[0])
		r, err := commands.VerifyReleaseManifestCheckpoint(ctx, actor, "bundle")
		if !errors.Is(err, verificationapp.ErrVerificationFailed) || r.Result.String() != "failed" {
			t.Fatal(r, err)
		}
		want++
		counts()
		exec(pair[1])
	}
	for _, table := range []string{"audit_chain_entries", "outbox_jobs"} {
		exec(`CREATE OR REPLACE FUNCTION reject_manifest_checkpoint_effect()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced failure';END$$`)
		exec(`CREATE TRIGGER reject_manifest_checkpoint_effect BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_manifest_checkpoint_effect()`)
		if r, err := commands.VerifyReleaseManifestCheckpoint(ctx, actor, "bundle"); err == nil || r.ID != "" {
			t.Fatal(r, err)
		}
		counts()
		exec(`DROP TRIGGER reject_manifest_checkpoint_effect ON ` + table)
	}
	actor.UserID, actor.KeyID = "", "caller"
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	calls := 0
	for range 2 {
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "manifest-checkpoint-replay", []byte(`{"subject_type":"audit_chain_release_manifest","subject_id":"bundle"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			r, err := commands.VerifyReleaseManifestCheckpoint(ctx, actor, "bundle")
			return 200, verificationResultToLegacy(r), err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("duplicate checkpoint receipt")
	}
	want++
	counts()
	exec(`UPDATE audit_chain_entries SET actor_id='changed' WHERE id='entry_1'`)
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "manifest-checkpoint-failed", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		r, err := commands.VerifyReleaseManifestCheckpoint(ctx, actor, "bundle")
		return 200, verificationResultToLegacy(r), err
	}); !errors.Is(err, verificationapp.ErrVerificationFailed) {
		t.Fatal(err)
	}
	counts()
	exec(`UPDATE audit_chain_entries SET actor_id='caller' WHERE id='entry_1'`)
	exec(`UPDATE release_bundles SET manifest=manifest||jsonb_build_object('large',repeat('x',8388609)) WHERE id='bundle'`)
	if r, err := commands.VerifyReleaseManifestCheckpoint(ctx, actor, "bundle"); !errors.Is(err, verificationapp.ErrConflict) || r.ID != "" {
		t.Fatal("oversize manifest truncated", r, err)
	}
	counts()
	exec(`UPDATE release_bundles SET manifest=manifest-'large' WHERE id='bundle'`)
	// Create a valid signed head at the current tip, then deliberately remove
	// the covered tail from this isolated corruption fixture.
	var tailHash string
	tail := initial + want
	if err := pool.QueryRow(ctx, `SELECT entry_hash FROM audit_chain_entries WHERE sequence=$1`, tail).Scan(&tailHash); err != nil {
		t.Fatal(err)
	}
	manifest = map[string]any{"chain_checkpoint": map[string]any{"sequence": tail, "head_hash": tailHash}}
	hash, err = application.NormalizedJSONHash(manifest)
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE release_bundles SET manifest=$1,manifest_hash=$2 WHERE id='bundle'`, manifest, hash)
	exec(`UPDATE signatures SET value=$1 WHERE id='signature'`, base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, []byte(hash))))
	rollback := errors.New("test-only rollback of pre-truncation verification")
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "manifest-checkpoint-before-truncation", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		r, err := commands.VerifyReleaseManifestCheckpoint(ctx, actor, "bundle")
		if err != nil || r.Result.String() != "passed" {
			t.Fatal(r, err)
		}
		return 200, verificationResultToLegacy(r), rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	counts()
	exec(`DELETE FROM audit_chain_entries WHERE sequence=$1`, tail)
	dropped++
	exec(`UPDATE tenant_audit_sequences SET next_sequence=$1 WHERE tenant_id='tenant'`, tail)
	r, err = commands.VerifyReleaseManifestCheckpoint(ctx, actor, "bundle")
	last := len(r.Checks) - 1
	if !errors.Is(err, verificationapp.ErrVerificationFailed) || last < 3 || r.Checks[last].Result != "failed" || r.Checks[last-1].Result != "passed" || r.Checks[last-2].Result != "passed" || r.Checks[last-3].Result != "passed" {
		t.Fatal("signed truncated head accepted", r, err)
	}
	want++
	counts()
}

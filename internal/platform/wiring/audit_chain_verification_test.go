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
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresAuditChainVerificationPagesCanonicalContentAtomically(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Audit'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('unrelated','tenant',repeat('x',9000000),'unrelated')`)
	now := time.Now().UTC().Add(-time.Hour)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,created_at,valid_from,version,provider)VALUES('key','tenant','key','Ed25519','active',$1,$2,$3,$3,1,'local_ed25519')`, base64.RawStdEncoding.EncodeToString(public), []byte("private-not-selected"), now)
	exec(`INSERT INTO signatures(id,tenant_id,subject_type,subject_id,key_id,algorithm,value,created_at)VALUES('signature','tenant','merkle_batch','batch','key','Ed25519',$1,$2)`, base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, []byte("hash"))), now.Add(time.Minute))
	exec(`INSERT INTO merkle_batches(id,tenant_id,from_sequence,to_sequence,entry_count,leaf_hashes,root_hash,signature_refs,schema_version,created_at)VALUES('batch','tenant',1,1,1,'{hash}','hash','{signature}','merkle-batch.v1',now())`)
	const initial = 130
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		for n := 1; n <= initial; n++ {
			e := domain.AuditChainEntry{ID: fmt.Sprintf("entry_%d", n), TenantID: "tenant", EntryType: "test", SubjectType: "test", SubjectID: "test", ActorType: "api_key", ActorID: "caller", OccurredAt: now.Add(time.Minute), Metadata: map[string]any{"safe": "value"}}
			if n == initial {
				e.SubjectType, e.SubjectID, e.SignatureRef = "merkle_batch", "batch", "signature"
			}
			if _, err := repos.Audit.Append(ctx, e); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildAuditChainVerificationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"verify:read"}}}}
	want := 0
	counts := func() {
		t.Helper()
		var receipts, audits, jobs int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM verification_results),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&receipts, &audits, &jobs); err != nil || receipts != want || audits != want+initial || jobs != want {
			t.Fatal("partial effects", receipts, audits, jobs, want, err)
		}
	}
	r, err := commands.VerifyAuditChain(ctx, actor)
	if err != nil || r.Result.String() != "passed" || len(r.Checks) != initial*7+1 || r.Profile.ID != "audit-chain-integrity.v1" {
		t.Fatal(r, err)
	}
	want++
	counts()
	denied := actor
	denied.ResourceGrants = nil
	if _, err := commands.VerifyAuditChain(ctx, denied); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	denied.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "unrelated", Scopes: []string{"verify:read"}}}
	if _, err := commands.VerifyAuditChain(ctx, denied); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	counts()
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		reader := repos.Verification.(verificationapp.AuditChainVerificationReader)
		view, err := reader.LockAuditChainVerification(ctx, "tenant")
		if err != nil {
			return err
		}
		var after *int64
		budget := verificationapp.MaxAuditChainVerificationBytes
		for {
			page, err := reader.ReadAuditChainVerificationPage(ctx, view, after, budget)
			if err != nil {
				return err
			}
			budget -= page.BytesRead
			if len(page.Entries) == 0 {
				break
			}
			sequence := page.Entries[len(page.Entries)-1].Sequence
			after = &sequence
		}
		for _, sql := range []string{`UPDATE tenants SET name=name WHERE id='tenant'`, `UPDATE audit_chain_entries SET actor_id=actor_id WHERE id='entry_1'`, `UPDATE merkle_batches SET root_hash=root_hash WHERE id='batch'`, `UPDATE signatures SET value=value WHERE id='signature'`, `UPDATE signing_keys SET status=status WHERE id='key'`, `SELECT pg_advisory_xact_lock(hashtext('tenant'))`} {
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
				t.Fatal("unstable audit view", sql, blocked)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{
		{`UPDATE audit_chain_entries SET metadata='{"changed":true}' WHERE id='entry_1'`, `UPDATE audit_chain_entries SET metadata='{"safe":"value"}' WHERE id='entry_1'`},
		{`UPDATE signatures SET subject_id='other' WHERE id='signature'`, `UPDATE signatures SET subject_id='batch' WHERE id='signature'`},
		{`UPDATE signatures SET tenant_id='other' WHERE id='signature'`, `UPDATE signatures SET tenant_id='tenant' WHERE id='signature'`},
		{`UPDATE signing_keys SET revocation_semantics='compromised',historical_validity_policy='invalidate_all' WHERE id='key'`, `UPDATE signing_keys SET revocation_semantics='ordinary',historical_validity_policy='preserve' WHERE id='key'`},
		{`UPDATE merkle_batches SET root_hash='other' WHERE id='batch'`, `UPDATE merkle_batches SET root_hash='hash' WHERE id='batch'`},
	} {
		exec(pair[0])
		r, err := commands.VerifyAuditChain(ctx, actor)
		if !errors.Is(err, verificationapp.ErrVerificationFailed) || r.Result.String() != "failed" {
			t.Fatal(r, err)
		}
		want++
		counts()
		exec(pair[1])
	}
	for _, table := range []string{"audit_chain_entries", "outbox_jobs"} {
		exec(`CREATE OR REPLACE FUNCTION reject_audit_verify_effect()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced failure';END$$`)
		exec(`CREATE TRIGGER reject_audit_verify_effect BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_audit_verify_effect()`)
		if r, err := commands.VerifyAuditChain(ctx, actor); err == nil || r.ID != "" {
			t.Fatal(r, err)
		}
		counts()
		exec(`DROP TRIGGER reject_audit_verify_effect ON ` + table)
	}
	actor.UserID, actor.KeyID = "", "caller"
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	calls := 0
	for range 2 {
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "audit-replay", []byte(`{"subject_type":"audit_chain"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			r, err := commands.VerifyAuditChain(ctx, actor)
			return 200, verificationResultToLegacy(r), err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("duplicate verification on replay")
	}
	want++
	counts()
	exec(`UPDATE audit_chain_entries SET actor_id='changed' WHERE id='entry_1'`)
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "audit-failed", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		r, err := commands.VerifyAuditChain(ctx, actor)
		return 200, verificationResultToLegacy(r), err
	}); !errors.Is(err, verificationapp.ErrVerificationFailed) {
		t.Fatal(err)
	}
	counts()
	exec(`UPDATE audit_chain_entries SET actor_id='caller',metadata=jsonb_build_object('large',repeat('x',8388609)) WHERE id='entry_1'`)
	if r, err := commands.VerifyAuditChain(ctx, actor); !errors.Is(err, verificationapp.ErrConflict) || r.ID != "" {
		t.Fatal("oversized audit content truncated", r, err)
	}
	counts()
	// Foreign tenant data cannot enter the same chain or its receipt.
	other := identitydomain.Actor{TenantID: "other", KeyID: "other", Scopes: []string{"verify:read"}}
	if r, err := commands.VerifyAuditChain(ctx, other); err != nil || r.Result.String() != "passed" || len(r.Checks) != 1 || r.TenantID != "other" {
		t.Fatal("foreign data reached empty tenant", r, err)
	}
	want++
	counts()
}

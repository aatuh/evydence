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
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresMerkleVerificationReadsOnlyCoveredDurableHashes(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Merkle'),('other','Other')`)
	// Unrelated audit metadata exceeds the command budget but is not read.
	exec(`INSERT INTO audit_chain_entries(id,tenant_id,sequence,entry_type,subject_type,subject_id,actor_type,actor_id,occurred_at,canonical_entry_hash,previous_entry_hash,entry_hash,metadata,schema_version) VALUES('leaf','tenant',1,'test','test','test','api_key','key',now(),'unused','','hash',jsonb_build_object('unused',repeat('x',9000000)),'audit-chain-entry.v2')`)
	exec(`INSERT INTO tenant_audit_sequences(tenant_id,next_sequence)VALUES('tenant',2)`)
	now := time.Now().UTC().Add(-time.Hour)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,created_at,valid_from,version,provider)VALUES('key','tenant','key','Ed25519','active',$1,$2,$3,$3,1,'local_ed25519')`, base64.RawStdEncoding.EncodeToString(public), []byte("private-material-not-read"), now)
	exec(`INSERT INTO signatures(id,tenant_id,subject_type,subject_id,key_id,algorithm,value,created_at)VALUES('signature','tenant','merkle_batch','batch','key','Ed25519',$1,$2)`, base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, []byte("hash"))), now.Add(time.Minute))
	exec(`INSERT INTO merkle_batches(id,tenant_id,from_sequence,to_sequence,entry_count,leaf_hashes,root_hash,signature_refs,schema_version,created_at)VALUES('batch','tenant',1,1,1,'{hash}','hash','{signature}','merkle-batch.v1',now())`)
	commands, err := BuildMerkleVerificationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"verify:read"}}}}
	want := 0
	counts := func() {
		t.Helper()
		var results, audits, jobs int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM verification_results),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&results, &audits, &jobs); err != nil || results != want || audits != want+1 || jobs != want {
			t.Fatal("partial effects", results, audits, jobs, want, err)
		}
	}
	r, err := commands.VerifyMerkleBatch(ctx, actor, "batch")
	if err != nil || r.Result.String() != "passed" || len(r.Checks) != 3 || r.Profile.TransparencyProof != "not_evaluated" {
		t.Fatal(r, err)
	}
	want++
	counts()
	denied := actor
	denied.ResourceGrants = nil
	if _, err := commands.VerifyMerkleBatch(ctx, denied, "batch"); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	denied.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "batch", Scopes: []string{"verify:read"}}}
	if _, err := commands.VerifyMerkleBatch(ctx, denied, "batch"); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	foreign := actor
	foreign.TenantID = "other"
	if _, err := commands.VerifyMerkleBatch(ctx, foreign, "batch"); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal(err)
	}
	counts()
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		reader := repos.Verification.(verificationapp.MerkleVerificationReader)
		s, err := reader.ResolveMerkleVerificationSubject(ctx, "tenant", "batch")
		if err != nil {
			return err
		}
		if _, err := reader.ReadMerkleVerification(ctx, s); err != nil {
			return err
		}
		for _, sql := range []string{`UPDATE tenants SET name=name WHERE id='tenant'`, `UPDATE merkle_batches SET root_hash=root_hash WHERE id='batch'`, `UPDATE audit_chain_entries SET entry_hash=entry_hash WHERE id='leaf'`, `UPDATE signatures SET value=value WHERE id='signature'`, `UPDATE signing_keys SET status=status WHERE id='key'`} {
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
				t.Fatal("unlocked verification fact", sql, blocked)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{
		{`UPDATE audit_chain_entries SET entry_hash='changed' WHERE id='leaf'`, `UPDATE audit_chain_entries SET entry_hash='hash' WHERE id='leaf'`},
		{`UPDATE audit_chain_entries SET sequence=100 WHERE id='leaf'`, `UPDATE audit_chain_entries SET sequence=1 WHERE id='leaf'`},
		{`UPDATE merkle_batches SET entry_count=2 WHERE id='batch'`, `UPDATE merkle_batches SET entry_count=1 WHERE id='batch'`},
		{`UPDATE signatures SET subject_id='another' WHERE id='signature'`, `UPDATE signatures SET subject_id='batch' WHERE id='signature'`},
		{`UPDATE signatures SET tenant_id='other' WHERE id='signature'`, `UPDATE signatures SET tenant_id='tenant' WHERE id='signature'`},
		{`UPDATE signing_keys SET tenant_id='other' WHERE id='key'`, `UPDATE signing_keys SET tenant_id='tenant' WHERE id='key'`},
		{`UPDATE signing_keys SET status='revoked',revoked_at=now(),revocation_semantics='compromised',historical_validity_policy='invalidate_all' WHERE id='key'`, `UPDATE signing_keys SET status='active',revoked_at=NULL,revocation_semantics='ordinary',historical_validity_policy='preserve' WHERE id='key'`},
	} {
		exec(pair[0])
		r, err := commands.VerifyMerkleBatch(ctx, actor, "batch")
		if !errors.Is(err, verificationapp.ErrVerificationFailed) || r.Result.String() != "failed" {
			t.Fatal("tampering passed", r, err)
		}
		want++
		counts()
		exec(pair[1])
	}
	for _, table := range []string{"audit_chain_entries", "outbox_jobs"} {
		exec(`CREATE OR REPLACE FUNCTION reject_merkle_effect()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced failure';END$$`)
		exec(`CREATE TRIGGER reject_merkle_effect BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_merkle_effect()`)
		if r, err := commands.VerifyMerkleBatch(ctx, actor, "batch"); err == nil || r.ID != "" {
			t.Fatal("partial receipt", r, err)
		}
		counts()
		exec(`DROP TRIGGER reject_merkle_effect ON ` + table)
	}
	actor.UserID, actor.KeyID = "", "caller"
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	calls := 0
	for range 2 {
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "merkle-replay", []byte(`{"subject_type":"merkle_batch","subject_id":"batch"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			r, err := commands.VerifyMerkleBatch(ctx, actor, "batch")
			return 200, verificationResultToLegacy(r), err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("replay duplicated receipt")
	}
	want++
	counts()
	exec(`UPDATE signatures SET value='invalid' WHERE id='signature'`)
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "merkle-failed", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		r, err := commands.VerifyMerkleBatch(ctx, actor, "batch")
		return 200, verificationResultToLegacy(r), err
	}); !errors.Is(err, verificationapp.ErrVerificationFailed) {
		t.Fatal(err)
	}
	counts()
	for _, pair := range [][2]string{
		{`UPDATE merkle_batches SET leaf_hashes=array_fill('hash'::text,ARRAY[4097]) WHERE id='batch'`, `UPDATE merkle_batches SET leaf_hashes='{hash}' WHERE id='batch'`},
		{`UPDATE merkle_batches SET to_sequence=9223372036854775807 WHERE id='batch'`, `UPDATE merkle_batches SET to_sequence=1 WHERE id='batch'`},
		{`UPDATE merkle_batches SET root_hash=repeat('x',1025) WHERE id='batch'`, `UPDATE merkle_batches SET root_hash='hash' WHERE id='batch'`},
		{`UPDATE merkle_batches SET signature_refs='{signature,signature}' WHERE id='batch'`, `UPDATE merkle_batches SET signature_refs='{signature}' WHERE id='batch'`},
		{`UPDATE audit_chain_entries SET entry_hash=repeat('x',1025) WHERE id='leaf'`, `UPDATE audit_chain_entries SET entry_hash='hash' WHERE id='leaf'`},
		{`UPDATE merkle_batches SET leaf_hashes=ARRAY[repeat('x',8388609)] WHERE id='batch'`, `UPDATE merkle_batches SET leaf_hashes='{hash}' WHERE id='batch'`},
	} {
		exec(pair[0])
		if r, err := commands.VerifyMerkleBatch(ctx, actor, "batch"); !errors.Is(err, verificationapp.ErrConflict) || r.ID != "" {
			t.Fatal("truncated projection", r, err)
		}
		counts()
		exec(pair[1])
	}
	for _, id := range []string{"bad\x00id", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		if _, err := commands.VerifyMerkleBatch(ctx, actor, id); !errors.Is(err, verificationapp.ErrValidation) {
			t.Fatal(err)
		}
	}
	// Each selected signature fits its own field limit. The shared reader must
	// nevertheless stop before the total selected metadata exceeds 8 MiB.
	exec(`INSERT INTO signatures(id,tenant_id,subject_type,subject_id,key_id,algorithm,value,created_at)SELECT 'budget_'||n,'tenant','merkle_batch','batch','key','Ed25519',repeat('x',8192),$1 FROM generate_series(1,1100)n`, now)
	exec(`UPDATE merkle_batches SET signature_refs=ARRAY(SELECT id FROM signatures WHERE id LIKE 'budget_%' ORDER BY id) WHERE id='batch'`)
	if r, err := commands.VerifyMerkleBatch(ctx, actor, "batch"); !errors.Is(err, verificationapp.ErrConflict) || r.ID != "" {
		t.Fatal("aggregate metadata budget bypassed", r, err)
	}
	counts()
}

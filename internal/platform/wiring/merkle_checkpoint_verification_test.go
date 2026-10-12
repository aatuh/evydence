package wiring

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresMerkleCheckpointVerificationUsesCanonicalChainAndAtomicReceipt(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Checkpoint'),('other','Other')`)
	now := time.Now().UTC().Add(-time.Hour)
	var entry domain.AuditChainEntry
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		var err error
		entry, err = repos.Audit.Append(ctx, domain.AuditChainEntry{ID: "entry", TenantID: "tenant", EntryType: "test", SubjectType: "test", SubjectID: "test", ActorType: "api_key", ActorID: "caller", OccurredAt: now, Metadata: map[string]any{"safe": "value"}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,created_at,valid_from,version,provider)VALUES('key','tenant','key','Ed25519','active',$1,$2,$3,$3,1,'local_ed25519')`, base64.RawStdEncoding.EncodeToString(public), []byte("private-not-selected"), now)
	exec(`INSERT INTO signatures(id,tenant_id,subject_type,subject_id,key_id,algorithm,value,created_at)VALUES('signature','tenant','merkle_batch','batch','key','Ed25519',$1,$2)`, base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, []byte(entry.EntryHash))), now.Add(time.Minute))
	exec(`INSERT INTO merkle_batches(id,tenant_id,from_sequence,to_sequence,entry_count,leaf_hashes,root_hash,signature_refs,schema_version,created_at)VALUES('batch','tenant',1,1,1,$1,$2,'{signature}','merkle-batch.v1',now())`, []string{entry.EntryHash}, entry.EntryHash)
	commands, err := BuildMerkleCheckpointVerificationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"verify:read"}}}}
	want := 0
	counts := func() {
		t.Helper()
		var results, audits, jobs int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM verification_results),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&results, &audits, &jobs); err != nil || results != want || audits != want+1 || jobs != want {
			t.Fatal("partial receipt", results, audits, jobs, want, err)
		}
	}
	r, err := commands.VerifyMerkleCheckpoint(ctx, actor, "batch")
	if err != nil || r.Result.String() != "passed" || r.Profile.ID != "audit-chain-merkle-checkpoint.v1" || r.SubjectType != "audit_chain_checkpoint" || len(r.Checks) != 11 || r.Profile.PayloadDigest != "" {
		t.Fatal(r, err)
	}
	want++
	counts()
	denied := actor
	denied.ResourceGrants = nil
	if _, err := commands.VerifyMerkleCheckpoint(ctx, denied, "batch"); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	denied.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "batch", Scopes: []string{"verify:read"}}}
	if _, err := commands.VerifyMerkleCheckpoint(ctx, denied, "batch"); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	foreign := identitydomain.Actor{TenantID: "other", KeyID: "foreign", Scopes: []string{"verify:read"}}
	if _, err := commands.VerifyMerkleCheckpoint(ctx, foreign, "batch"); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal(err)
	}
	counts()
	for _, pair := range [][2]string{
		{`UPDATE audit_chain_entries SET metadata='{"changed":true}' WHERE id='entry'`, `UPDATE audit_chain_entries SET metadata='{"safe":"value"}' WHERE id='entry'`},
		// The covered first entry is unchanged; all later entries must still verify.
		{`UPDATE audit_chain_entries SET actor_id='changed' WHERE sequence=2`, `UPDATE audit_chain_entries SET actor_id='user' WHERE sequence=2`},
		{`UPDATE merkle_batches SET root_hash='other' WHERE id='batch'`, `UPDATE merkle_batches SET root_hash=$1 WHERE id='batch'`},
		{`UPDATE signatures SET subject_id='another' WHERE id='signature'`, `UPDATE signatures SET subject_id='batch' WHERE id='signature'`},
		{`UPDATE signatures SET tenant_id='other' WHERE id='signature'`, `UPDATE signatures SET tenant_id='tenant' WHERE id='signature'`},
		{`UPDATE signing_keys SET historical_validity_policy='invalidate_all',revocation_semantics='compromised' WHERE id='key'`, `UPDATE signing_keys SET historical_validity_policy='preserve',revocation_semantics='ordinary' WHERE id='key'`},
	} {
		exec(pair[0])
		r, err := commands.VerifyMerkleCheckpoint(ctx, actor, "batch")
		if !errors.Is(err, verificationapp.ErrVerificationFailed) || r.Result.String() != "failed" {
			t.Fatal("tampering passed", r, err)
		}
		want++
		counts()
		if pair[1] == `UPDATE merkle_batches SET root_hash=$1 WHERE id='batch'` {
			exec(pair[1], entry.EntryHash)
		} else {
			exec(pair[1])
		}
	}
	for _, table := range []string{"audit_chain_entries", "outbox_jobs"} {
		exec(`CREATE OR REPLACE FUNCTION reject_checkpoint_effect()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced failure';END$$`)
		exec(`CREATE TRIGGER reject_checkpoint_effect BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_checkpoint_effect()`)
		if r, err := commands.VerifyMerkleCheckpoint(ctx, actor, "batch"); err == nil || r.ID != "" {
			t.Fatal(r, err)
		}
		counts()
		exec(`DROP TRIGGER reject_checkpoint_effect ON ` + table)
	}
	actor.UserID, actor.KeyID = "", "caller"
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	calls := 0
	for range 2 {
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "checkpoint-replay", []byte(`{"subject_type":"audit_chain_checkpoint","subject_id":"batch"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			r, err := commands.VerifyMerkleCheckpoint(ctx, actor, "batch")
			return 200, verificationResultToLegacy(r), err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("replay repeated checkpoint receipt")
	}
	want++
	counts()
	exec(`UPDATE audit_chain_entries SET actor_id='changed' WHERE id='entry'`)
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "checkpoint-failed", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		r, err := commands.VerifyMerkleCheckpoint(ctx, actor, "batch")
		return 200, verificationResultToLegacy(r), err
	}); !errors.Is(err, verificationapp.ErrVerificationFailed) {
		t.Fatal(err)
	}
	counts()
	exec(`UPDATE audit_chain_entries SET actor_id='caller' WHERE id='entry'`)
	// A canonical prefix still verifies, but cannot cover a signed deleted tail.
	// Deliberately corrupt the isolated fixture and its allocator for this case.
	var tailHash string
	if err := pool.QueryRow(ctx, `SELECT entry_hash FROM audit_chain_entries WHERE sequence=$1`, want+1).Scan(&tailHash); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE merkle_batches SET from_sequence=$1,to_sequence=$1,leaf_hashes=$2,root_hash=$3 WHERE id='batch'`, want+1, []string{tailHash}, tailHash)
	exec(`UPDATE signatures SET value=$1 WHERE id='signature'`, base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, []byte(tailHash))))
	rollback := errors.New("test-only rollback of pre-truncation verification")
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "checkpoint-before-truncation", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		r, err := commands.VerifyMerkleCheckpoint(ctx, actor, "batch")
		if err != nil || r.Result.String() != "passed" {
			t.Fatal("checkpoint was not valid before truncation", r, err)
		}
		return 200, verificationResultToLegacy(r), rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	counts()
	exec(`DELETE FROM audit_chain_entries WHERE sequence=$1`, want+1)
	exec(`UPDATE tenant_audit_sequences SET next_sequence=$1 WHERE tenant_id='tenant'`, want+1)
	r, err = commands.VerifyMerkleCheckpoint(ctx, actor, "batch")
	if !errors.Is(err, verificationapp.ErrVerificationFailed) || r.Checks[len(r.Checks)-1].Name != "checkpoint_coverage" || r.Checks[len(r.Checks)-1].Result != "failed" || r.Checks[len(r.Checks)-2].Result != "passed" {
		t.Fatal("truncation accepted", r, err)
	}
	// The verification audit replaces the deliberately deleted row.
	want++
	var results, jobs, audits int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM verification_results),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM audit_chain_entries)`).Scan(&results, &jobs, &audits); err != nil || results != want || jobs != want || audits != want {
		t.Fatal(results, jobs, audits, want, err)
	}
}

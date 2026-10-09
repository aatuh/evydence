package wiring

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresMerkleCreationUsesBoundedOwnedLeavesAndAtomicSigning(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Merkle'),('other','Other')`)
	var leaves []string
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		for i := 1; i <= 3; i++ {
			metadata := map[string]any{"safe": "value"}
			if i == 1 {
				metadata["large_unselected_body"] = strings.Repeat("x", 9000000)
			}
			entry, err := repos.Audit.Append(ctx, domain.AuditChainEntry{ID: fmt.Sprintf("entry_%d", i), TenantID: "tenant", EntryType: "test", SubjectType: "test", SubjectID: "test", ActorType: "api_key", ActorID: "caller", OccurredAt: time.Now().UTC(), Metadata: metadata})
			if err != nil {
				return err
			}
			leaves = append(leaves, entry.EntryHash)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c, err := BuildMerkleCreationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"keys:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"keys:admin"}}}}
	input := verificationapp.CreateMerkleBatchInput{FromSequence: 1, ToSequence: 3}
	want, wantKeys := 0, 0
	counts := func() {
		t.Helper()
		var batches, sigs, keys, audits, jobs int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM merkle_batches),(SELECT count(*)FROM signatures),(SELECT count(*)FROM signing_keys),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&batches, &sigs, &keys, &audits, &jobs); err != nil || batches != want || sigs != want || keys != wantKeys || audits != 3+want || jobs != 0 {
			t.Fatal("partial Merkle effects", batches, sigs, keys, audits, jobs, want, wantKeys, err)
		}
	}
	// Each fault must roll back the initial key as well as signature and batch.
	for _, table := range []string{"signing_keys", "signatures", "merkle_batches", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_merkle_creation()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced private database failure';END$$`)
		exec(`CREATE TRIGGER reject_merkle_creation BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_merkle_creation()`)
		if r, err := c.CreateMerkleBatch(ctx, a, input); err == nil || r.ID != "" {
			t.Fatal("partial result", table, r, err)
		}
		counts()
		exec(`DROP TRIGGER reject_merkle_creation ON ` + table)
	}
	r, err := c.CreateMerkleBatch(ctx, a, input)
	if err != nil || r.ID == "" || r.TenantID != "tenant" || r.FromSequence != 1 || r.ToSequence != 3 || r.EntryCount != 3 || len(r.SignatureRefs) != 1 || strings.Join(r.LeafHashes, ",") != strings.Join(leaves, ",") {
		t.Fatal(r, err)
	}
	want++
	wantKeys++
	counts()
	var keyID, public, value, subjectID, auditHash, auditRef, previous string
	var sequence int64
	if err := pool.QueryRow(ctx, `SELECT k.id,k.public_key,s.value,s.subject_id,a.payload_hash,a.signature_ref,a.previous_entry_hash,a.sequence FROM signatures s JOIN signing_keys k ON k.id=s.key_id AND k.tenant_id=s.tenant_id JOIN audit_chain_entries a ON a.tenant_id=s.tenant_id AND a.subject_id=s.subject_id WHERE s.id=$1`, r.SignatureRefs[0]).Scan(&keyID, &public, &value, &subjectID, &auditHash, &auditRef, &previous, &sequence); err != nil {
		t.Fatal(err)
	}
	pub, err := base64.RawStdEncoding.DecodeString(public)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte(r.RootHash), sig) || subjectID != r.ID || auditHash != r.RootHash || auditRef != r.SignatureRefs[0] || previous != leaves[2] || sequence != 4 {
		t.Fatal("unbound signature or audit", r)
	}
	denied := a
	denied.ResourceGrants = nil
	if _, err := c.CreateMerkleBatch(ctx, denied, input); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	denied.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"keys:admin"}}}
	if _, err := c.CreateMerkleBatch(ctx, denied, input); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tenant string
		err    error
	}{{"other", verificationapp.ErrValidation}, {"missing", verificationapp.ErrNotFound}} {
		if _, err := c.CreateMerkleBatch(ctx, identitydomain.Actor{TenantID: tc.tenant, KeyID: "caller", Scopes: []string{"keys:admin"}}, input); !errors.Is(err, tc.err) {
			t.Fatal(tc.tenant, err)
		}
	}
	counts()
	// Global sequence and nonempty-hash checks must survive bounded selection.
	for _, blank := range []string{"", " \t\n", "\u00a0", "\u2007\u202f", "\u3000"} {
		exec(`UPDATE audit_chain_entries SET entry_hash=$1 WHERE id='entry_3'`, blank)
		if r, err := c.CreateMerkleBatch(ctx, a, verificationapp.CreateMerkleBatchInput{ToSequence: 1}); !errors.Is(err, verificationapp.ErrValidation) || r.ID != "" {
			t.Fatalf("unselected blank hash %q accepted: %v %v", blank, r, err)
		}
		counts()
		exec(`UPDATE audit_chain_entries SET entry_hash=$1 WHERE id='entry_3'`, leaves[2])
	}
	exec(`UPDATE audit_chain_entries SET sequence=99 WHERE id='entry_3'`)
	if _, err := c.CreateMerkleBatch(ctx, a, verificationapp.CreateMerkleBatchInput{ToSequence: 1}); !errors.Is(err, verificationapp.ErrValidation) {
		t.Fatal("gapped chain accepted", err)
	}
	counts()
	exec(`UPDATE audit_chain_entries SET sequence=3 WHERE id='entry_3'`)
	// Invalid selected key material fails closed; it never creates a fallback key.
	var original []byte
	if err := pool.QueryRow(ctx, `SELECT encrypted_private_key FROM signing_keys WHERE id=$1`, keyID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	defer clear(original)
	badSeed := append([]byte(nil), original...)
	badSeed[0] ^= 1
	defer clear(badSeed)
	for _, bad := range [][]byte{[]byte("short"), badSeed} {
		exec(`UPDATE signing_keys SET encrypted_private_key=$1 WHERE id=$2`, bad, keyID)
		if _, err := c.CreateMerkleBatch(ctx, a, input); !errors.Is(err, verificationapp.ErrConflict) {
			t.Fatal("malformed private material accepted", err)
		}
		counts()
		exec(`UPDATE signing_keys SET encrypted_private_key=$1 WHERE id=$2`, original, keyID)
	}
	for _, sql := range []string{`valid_from=now()+interval '1 hour'`, `valid_until=now()-interval '1 hour'`, `revoked_at=now()`, `compromised_at=now()`, `public_key='invalid'`, `algorithm='invalid'`} {
		exec(`UPDATE signing_keys SET `+sql+` WHERE id=$1`, keyID)
		if _, err := c.CreateMerkleBatch(ctx, a, input); !errors.Is(err, verificationapp.ErrConflict) {
			t.Fatal(sql, err)
		}
		counts()
		exec(`UPDATE signing_keys SET valid_from=created_at,valid_until=NULL,revoked_at=NULL,compromised_at=NULL,public_key=$1,algorithm='Ed25519' WHERE id=$2`, public, keyID)
	}
	if err := (merkleCreationTransactions{store}).ExecuteMerkleCreation(ctx, func(ctx context.Context, tx verificationapp.MerkleCreationTransaction) error {
		if _, err := tx.LockMerkleCreationView(ctx, "tenant"); err != nil {
			return err
		}
		if _, err := tx.ReadMerkleCreationLeaves(ctx, "tenant", 1, 3); err != nil {
			return err
		}
		if _, err := tx.SignMerkleRoot(ctx, verificationapp.SigningRequest{TenantID: "tenant", SubjectType: "merkle_batch", SubjectID: "lock-test", Payload: []byte("root"), CreatedAt: time.Now().UTC()}); err != nil {
			return err
		}
		for _, sql := range []string{`UPDATE tenants SET name=name WHERE id='tenant'`, `UPDATE audit_chain_entries SET entry_hash=entry_hash WHERE id='entry_1'`, `UPDATE signing_keys SET status=status WHERE tenant_id='tenant'`, `SELECT pg_advisory_xact_lock(hashtext('tenant'))`} {
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
				t.Fatal("unstable Merkle view", sql, blocked)
			}
		}
		other, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := other.Exec(ctx, `SET LOCAL lock_timeout='50ms'`); err != nil {
			_ = other.Rollback(ctx)
			return err
		}
		blocked := coordination.LockWorkerProjection(ctx, other, "tenant")
		_ = other.Rollback(ctx)
		var pgErr *pgconn.PgError
		if !errors.As(blocked, &pgErr) || pgErr.Code != "55P03" {
			t.Fatal("projection fence missing", blocked)
		}
		_, err = pool.Exec(ctx, `UPDATE tenants SET name=name WHERE id='other'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The explicit range excludes the oversized hash, and never reads its body.
	exec(`UPDATE audit_chain_entries SET entry_hash=repeat('x',9000000) WHERE id='entry_3'`)
	if _, err := c.CreateMerkleBatch(ctx, a, input); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("oversized selected leaf accepted", err)
	}
	counts()
	if _, err := c.CreateMerkleBatch(ctx, a, verificationapp.CreateMerkleBatchInput{ToSequence: 1}); err != nil {
		t.Fatal("unselected material loaded", err)
	}
	want++
	counts()
	exec(`UPDATE audit_chain_entries SET entry_hash=$1 WHERE id='entry_3'`, leaves[2])
	a.UserID, a.KeyID = "", "caller"
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	calls := 0
	for range 2 {
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/merkle-batches", "merkle-replay", []byte(`{"from_sequence":1,"to_sequence":3}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			r, err := c.CreateMerkleBatch(ctx, a, input)
			return 201, r, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("replay signed again", calls)
	}
	want++
	counts()
	exec(`CREATE TRIGGER reject_merkle_creation BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_merkle_creation()`)
	if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/merkle-batches", "merkle-failed", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		r, err := c.CreateMerkleBatch(ctx, a, input)
		return 201, r, err
	}); err == nil {
		t.Fatal("failed outer transaction committed")
	}
	counts()
	exec(`DROP TRIGGER reject_merkle_creation ON audit_chain_entries`)
	// No active local key bootstraps the next version without changing history.
	exec(`UPDATE signing_keys SET status='retired' WHERE id=$1`, keyID)
	if _, err := c.CreateMerkleBatch(ctx, a, input); err != nil {
		t.Fatal(err)
	}
	want++
	wantKeys++
	counts()
	var version int
	var status string
	if err := pool.QueryRow(ctx, `SELECT (SELECT max(version)FROM signing_keys WHERE tenant_id='tenant'),(SELECT status FROM signing_keys WHERE id=$1)`, keyID).Scan(&version, &status); err != nil || version != 2 || status != "retired" {
		t.Fatal(version, status, err)
	}
	exec(`UPDATE signing_keys SET status='retired',version=2147483647 WHERE tenant_id='tenant' AND version=2`)
	if _, err := c.CreateMerkleBatch(ctx, a, input); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("local key version overflow", err)
	}
	counts()
	exec(`UPDATE signing_keys SET status='active',version=2 WHERE tenant_id='tenant' AND version=2147483647`)
	// The range cap must not silently sign a prefix. A bounded explicit range
	// still works when the global chain is longer than the synchronous limit.
	exec(`INSERT INTO audit_chain_entries(id,tenant_id,sequence,entry_type,subject_type,subject_id,actor_type,actor_id,occurred_at,payload_hash,canonical_entry_hash,previous_entry_hash,entry_hash,metadata,schema_version) SELECT 'large_'||n,'tenant',n,'test','test','test','api_key','caller',now(),'','canonical','previous','hash-'||n,'{}','audit-chain-entry.v2.0.0' FROM generate_series((SELECT max(sequence)+1 FROM audit_chain_entries WHERE tenant_id='tenant'),4097) AS n`)
	exec(`UPDATE tenant_audit_sequences SET next_sequence=4098 WHERE tenant_id='tenant'`)
	if r, err := c.CreateMerkleBatch(ctx, a, verificationapp.CreateMerkleBatchInput{}); !errors.Is(err, verificationapp.ErrConflict) || r.ID != "" {
		t.Fatal("oversized default range accepted", r, err)
	}
	if r, err := c.CreateMerkleBatch(ctx, a, verificationapp.CreateMerkleBatchInput{ToSequence: 1}); err != nil || r.EntryCount != 1 || r.RootHash != leaves[0] {
		t.Fatal("small explicit range rejected", r, err)
	}
	var batches, audits int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM merkle_batches),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant')`).Scan(&batches, &audits); err != nil || batches != want+1 || audits != 4098 {
		t.Fatal(batches, audits, err)
	}
}

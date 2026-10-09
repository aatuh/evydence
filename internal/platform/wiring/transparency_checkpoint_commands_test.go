package wiring

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresRecordedTransparencyCheckpointReadsBoundedOwnedRootAndCommitsAtomically(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Checkpoint'),('other','Other')`)
	// These unrelated material columns are intentionally too large for a full
	// batch read. Recording its assertion needs only the tenant-owned root.
	exec(`INSERT INTO merkle_batches(id,tenant_id,from_sequence,to_sequence,entry_count,leaf_hashes,root_hash,signature_refs,schema_version,created_at)VALUES('batch','tenant',1,1,1,ARRAY[repeat('x',9000000)],'sha256:one',ARRAY[repeat('x',9000000)],'merkle-batch.v1.0.0',now()),('foreign','other',1,1,1,'{}','sha256:other','{}','merkle-batch.v1.0.0',now())`)
	c, err := BuildTransparencyCheckpointCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	input := verificationapp.CreateTransparencyCheckpointInput{BatchID: "batch", Provider: "operator-provider", ExternalID: "record"}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"keys:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"keys:admin"}}}}
	want := 0
	counts := func() {
		t.Helper()
		var checkpoints, audits, jobs int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM transparency_checkpoints),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&checkpoints, &audits, &jobs); err != nil || checkpoints != want || audits != want || jobs != 0 {
			t.Fatal(checkpoints, audits, jobs, want, err)
		}
	}
	r, err := c.CreateTransparencyCheckpoint(ctx, a, input)
	hash, _ := application.NormalizedJSONHash(map[string]any{"batch_id": "batch", "root_hash": "sha256:one", "provider": "operator-provider", "external_url": "", "external_id": "record"})
	if err != nil || r.State != "recorded" || r.TimestampHash != hash || r.BatchID != "batch" || r.TenantID != "tenant" {
		t.Fatal(r, err)
	}
	want++
	counts()
	var auditHash, recordHash string
	if err := pool.QueryRow(ctx, `SELECT c.timestamp_hash,a.payload_hash FROM transparency_checkpoints c JOIN audit_chain_entries a ON a.tenant_id=c.tenant_id AND a.subject_id=c.id WHERE c.id=$1 AND c.tenant_id='tenant'`, r.ID).Scan(&recordHash, &auditHash); err != nil || recordHash != hash || auditHash != hash {
		t.Fatal(recordHash, auditHash, err)
	}
	denied := a
	denied.ResourceGrants = nil
	if _, err := c.CreateTransparencyCheckpoint(ctx, denied, input); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	denied.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"keys:admin"}}}
	if _, err := c.CreateTransparencyCheckpoint(ctx, denied, input); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	foreign := input
	foreign.BatchID = "foreign"
	if _, err := c.CreateTransparencyCheckpoint(ctx, a, foreign); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("foreign batch", err)
	}
	counts()
	if err := (transparencyCheckpointTransactions{store}).ExecuteTransparencyCheckpoint(ctx, func(ctx context.Context, tx verificationapp.TransparencyCheckpointTransaction) error {
		if _, err := tx.ReadTransparencyCheckpointSource(ctx, "tenant", "batch"); err != nil {
			return err
		}
		for _, sql := range []string{`UPDATE tenants SET name=name WHERE id='tenant'`, `UPDATE merkle_batches SET root_hash=root_hash WHERE tenant_id='tenant' AND id='batch'`} {
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
				t.Fatal("unstable checkpoint source", sql, blocked)
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
			t.Fatal("projection fence not held", blocked)
		}
		// A different tenant's root remains independently writable.
		_, err = pool.Exec(ctx, `UPDATE merkle_batches SET root_hash=root_hash WHERE tenant_id='other' AND id='foreign'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE merkle_batches SET root_hash='sha256:changed' WHERE id='batch'`)
	r, err = c.CreateTransparencyCheckpoint(ctx, a, input)
	if err != nil || r.TimestampHash == hash || r.State != "recorded" {
		t.Fatal("cached root or invented verification", r, err)
	}
	want++
	counts()
	for _, table := range []string{"transparency_checkpoints", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_recorded_checkpoint()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced failure';END$$`)
		exec(`CREATE TRIGGER reject_recorded_checkpoint BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_recorded_checkpoint()`)
		if r, err := c.CreateTransparencyCheckpoint(ctx, a, input); err == nil || r.ID != "" {
			t.Fatal("partial checkpoint returned", r, err)
		}
		counts()
		exec(`DROP TRIGGER reject_recorded_checkpoint ON ` + table)
	}
	a.UserID, a.KeyID = "", "caller"
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	calls := 0
	for range 2 {
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/transparency-checkpoints", "checkpoint-replay", []byte(`{"batch_id":"batch","provider":"operator-provider","external_id":"record"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			r, err := c.CreateTransparencyCheckpoint(ctx, a, input)
			return 201, r, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("replayed checkpoint was recreated", calls)
	}
	want++
	counts()
	for _, root := range []string{"", "oversized"} {
		if root == "" {
			exec(`UPDATE merkle_batches SET root_hash='' WHERE id='batch'`)
		} else {
			exec(`UPDATE merkle_batches SET root_hash=repeat('x',9000000) WHERE id='batch'`)
		}
		wantErr := verificationapp.ErrNotFound
		if root != "" {
			wantErr = verificationapp.ErrConflict
		}
		if r, err := c.CreateTransparencyCheckpoint(ctx, a, input); !errors.Is(err, wantErr) || r.ID != "" {
			t.Fatal(root, r, err)
		}
		counts()
	}
	if r, err := c.CreateTransparencyCheckpoint(ctx, identitydomain.Actor{TenantID: "other", KeyID: "other", Scopes: []string{"keys:admin"}}, foreign); err != nil || r.TenantID != "other" || r.State != "recorded" {
		t.Fatal("foreign oversized root was loaded", r, err)
	}
	want++
	counts()
}

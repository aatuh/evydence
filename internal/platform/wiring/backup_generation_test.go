package wiring

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresBackupStateCommitmentIsCompleteTenantScopedAndSecretFree(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Backup'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product'),('foreign','other','Foreign','foreign')`)
	exec(`INSERT INTO api_keys(id,tenant_id,name,prefix,hash,scopes)VALUES('key','tenant','Key','prefix','credential-original','["admin"]')`)
	read := func() verificationapp.BackupStateCommitment {
		t.Helper()
		var c verificationapp.BackupStateCommitment
		if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
			r, ok := repos.Integrity.(verificationapp.BackupStateCommitmentReader)
			if !ok {
				t.Fatal("focused backup commitment reader missing")
			}
			var err error
			c, err = r.ReadBackupStateCommitment(ctx, "tenant")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	a := read()
	if a.TenantID != "tenant" || a.Profile != verificationapp.BackupStateCommitmentProfile || !strings.HasPrefix(a.StateHash, "sha256:") || a.RowsRead < 3 || a.ResourceCounts["evidence"] != 0 {
		t.Fatal(a)
	}
	exec(`UPDATE api_keys SET hash='credential-changed' WHERE id='key'`)
	exec(`UPDATE products SET name='Foreign changed' WHERE id='foreign'`)
	if b := read(); b.StateHash != a.StateHash {
		t.Fatal("foreign or credential input affects commitment", a, b)
	}
	exec(`UPDATE products SET name='Product changed' WHERE id='product'`)
	b := read()
	if b.StateHash == a.StateHash {
		t.Fatal("durable product omitted from state commitment")
	}
	exec(`UPDATE api_keys SET scopes='["evidence:read"]' WHERE id='key'`)
	if c := read(); c.StateHash == b.StateHash {
		t.Fatal("credential authorization metadata omitted")
	}
	baseline := read()
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	if _, _, err := executor.WithBody(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "POST", "/v1/backup-manifests", "pending-backup", []byte(`{}`), func(ctx context.Context, repos app.Repositories) (int, any, error) {
		point, err := repos.Integrity.(verificationapp.BackupStateCommitmentReader).ReadBackupStateCommitment(ctx, "tenant")
		if err == nil && point.StateHash != baseline.StateHash {
			t.Fatal("uncommitted replay bookkeeping affects backup commitment")
		}
		return 201, map[string]any{"ok": true}, err
	}); err != nil {
		t.Fatal(err)
	}
	if point := read(); point.StateHash != baseline.StateHash {
		t.Fatal("completed replay bookkeeping affects backup commitment")
	}
	exec(`UPDATE products SET name=repeat('x',9000000) WHERE id='product'`)
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		_, err := repos.Integrity.(verificationapp.BackupStateCommitmentReader).ReadBackupStateCommitment(ctx, "tenant")
		return err
	}); !errors.Is(err, app.ErrConflict) {
		t.Fatal("oversized commitment silently truncated", err)
	}
	exec(`UPDATE products SET name='Product' WHERE id='product'`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)SELECT 'cap_'||n,'tenant','Product','cap_'||n FROM generate_series(1,32769)n`)
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		c, err := repos.Integrity.(verificationapp.BackupStateCommitmentReader).ReadBackupStateCommitment(ctx, "tenant")
		if err == nil && c.StateHash != "" {
			t.Fatal("oversized prefix digest published")
		}
		return err
	}); !errors.Is(err, app.ErrConflict) {
		t.Fatal("row-bounded snapshot truncated", err)
	}
}

type backupTenantBarrierTx struct {
	pgx.Tx
	locked chan struct{}
}

func (t backupTenantBarrierTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	row := t.Tx.QueryRow(ctx, sql, args...)
	if strings.Contains(sql, "SELECT 1 FROM tenants") {
		return backupTenantBarrierRow{row, t.locked}
	}
	return row
}

type backupTenantBarrierRow struct {
	pgx.Row
	locked chan struct{}
}

func (r backupTenantBarrierRow) Scan(dest ...any) error {
	err := r.Row.Scan(dest...)
	if err == nil {
		close(r.locked)
	}
	return err
}

func TestPostgresBackupAndMerkleViewsDoNotDeadlockProjectionOwnerAuditAppend(t *testing.T) {
	for _, kind := range []string{"backup", "merkle"} {
		t.Run(kind, func(t *testing.T) {
			_, pool := openHTMLReportWiringStore(t)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Worker')`); err != nil {
				t.Fatal(err)
			}
			worker, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = worker.Rollback(context.WithoutCancel(ctx)) }()
			if err := coordination.LockWorkerProjection(ctx, worker, "tenant"); err != nil {
				t.Fatal(err)
			}
			if _, err := worker.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
				t.Fatal(err)
			}
			view, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = view.Rollback(context.WithoutCancel(ctx)) }()
			locked, done := make(chan struct{}), make(chan error, 1)
			repos := repositories.New(backupTenantBarrierTx{view, locked})
			go func() {
				if kind == "backup" {
					_, err := repos.Integrity.(verificationapp.BackupStateCommitmentReader).ReadBackupStateCommitment(ctx, "tenant")
					done <- err
				} else {
					_, err := repos.Integrity.(verificationapp.MerkleCreationReader).LockMerkleCreationView(ctx, "tenant")
					done <- err
				}
			}()
			select {
			case <-locked:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			_, appendErr := repositories.New(worker).Audit.Append(ctx, domain.AuditChainEntry{ID: "entry", TenantID: "tenant", EntryType: "worker", SubjectType: "test", SubjectID: "test", ActorType: "collector", ActorID: "worker", OccurredAt: time.Now().UTC()})
			if appendErr == nil {
				err = worker.Commit(ctx)
			} else {
				err = worker.Rollback(context.WithoutCancel(ctx))
			}
			select {
			case readErr := <-done:
				if readErr != nil {
					t.Fatal(readErr)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if appendErr != nil || err != nil {
				t.Fatal("projection owner blocked by a waiting view's tenant lock", appendErr, err)
			}
		})
	}
}

func TestPostgresMerkleSignerDoesNotBlockTenantForeignKeyReaders(t *testing.T) {
	_, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Signer')`); err != nil {
		t.Fatal(err)
	}
	reader, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := reader.Exec(ctx, `SELECT 1 FROM tenants WHERE id='tenant' FOR KEY SHARE`); err != nil {
		t.Fatal(err)
	}
	signer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = signer.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := signer.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	r, err := repositories.New(signer).Signatures.(merkleRootSigner).SignMerkleRoot(ctx, verificationapp.SigningRequest{TenantID: "tenant", SubjectType: "merkle_batch", SubjectID: "batch", Payload: []byte("root"), CreatedAt: time.Now().UTC()})
	if r.NewKey != nil {
		defer clear(r.NewKey.PrivateMaterial)
	}
	if err != nil || r.Signature.KeyID == "" {
		t.Fatal("signing-key serialization blocks ordinary foreign keys", err)
	}
}

func TestPostgresBackupCommitmentProfileClassifiesEveryMigrationTableAndColumn(t *testing.T) {
	_, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	fields := map[string]map[string]bool{}
	for _, r := range repositories.BackupCommitmentProfileResources() {
		fields[r.Name] = map[string]bool{}
		for _, c := range r.Columns {
			fields[r.Name][c] = true
		}
	}
	excludedTables := map[string]bool{"ledger_state": true, "resource_index": true, "schema_migrations": true, "idempotency_records": true}
	excludedColumns := map[string]bool{"api_keys.hash": true, "customer_portal_access.hash": true, "sso_sessions.hash": true, "signing_keys.encrypted_private_key": true, "outbox_jobs.payload": true, "outbox_jobs.last_error": true, "outbox_jobs.lease_token": true, "vex_import_reports.failure_detail": true}
	rows, err := pool.Query(ctx, `SELECT table_name,column_name FROM information_schema.columns WHERE table_schema=current_schema() ORDER BY table_name,column_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		if excludedTables[table] {
			continue
		}
		seen[table] = true
		declared := fields[table][column]
		excluded := excludedColumns[table+"."+column]
		if declared == excluded {
			t.Fatal("unclassified or credential-selected profile field", table, column)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(fields) {
		t.Fatal("missing declared resource", len(seen), len(fields))
	}
}

func TestPostgresBackupGenerationCommitsVersionedManifestAuditAndReplayAtomically(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Backup'),('other','Other')`)
	c, err := BuildBackupGenerationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"admin"}}}}
	want := 0
	counts := func() {
		t.Helper()
		var manifests, audits, jobs int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM backup_manifests),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&manifests, &audits, &jobs); err != nil || manifests != want || audits != want || jobs != 0 {
			t.Fatal(manifests, audits, jobs, want, err)
		}
	}
	r, err := c.GenerateBackupManifest(ctx, a)
	if err != nil || r.TenantID != "tenant" || r.SchemaVersion != "backup-manifest.v2.0.0" || len(r.ConsistencyChecks) != 1 || r.ConsistencyChecks[0].Result != "passed" || r.ResourceCounts["audit_chain_entries"] != 0 {
		t.Fatal(r, err)
	}
	want++
	counts()
	var stored, audit string
	if err := pool.QueryRow(ctx, `SELECT b.state_hash,a.payload_hash FROM backup_manifests b JOIN audit_chain_entries a ON a.tenant_id=b.tenant_id AND a.subject_id=b.id WHERE b.id=$1`, r.ID).Scan(&stored, &audit); err != nil || stored != r.StateHash || audit != r.StateHash {
		t.Fatal(stored, audit, err)
	}
	denied := a
	denied.ResourceGrants = nil
	if _, err := c.GenerateBackupManifest(ctx, denied); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	denied.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"admin"}}}
	if _, err := c.GenerateBackupManifest(ctx, denied); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	counts()
	for _, table := range []string{"backup_manifests", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_backup_generation()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced private SQL failure';END$$`)
		exec(`CREATE TRIGGER reject_backup_generation BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_backup_generation()`)
		if r, err := c.GenerateBackupManifest(ctx, a); err == nil || r.ID != "" {
			t.Fatal("partial manifest returned", r, err)
		}
		counts()
		exec(`DROP TRIGGER reject_backup_generation ON ` + table)
	}
	a.UserID, a.KeyID = "", "caller"
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	calls := 0
	for range 2 {
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/backup-manifests", "backup-replay", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			r, err := c.GenerateBackupManifest(ctx, a)
			return 201, r, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("backup replay rehashed state", calls)
	}
	want++
	counts()
	exec(`UPDATE audit_chain_entries SET actor_id='tampered' WHERE sequence=1 AND tenant_id='tenant'`)
	r, err = c.GenerateBackupManifest(ctx, a)
	if err != nil || r.ConsistencyChecks[len(r.ConsistencyChecks)-1].Result != "failed" {
		t.Fatal("failed audit facts hidden", r, err)
	}
	want++
	counts()
}

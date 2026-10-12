package wiring

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresBackupVerificationReadsOnlyRecordedFactsAtomically(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Backup'),('other','Other')`)
	// Neither the recorded resource-count map nor limitations are needed for
	// this existing profile; enormous unused fields must not be loaded.
	exec(`INSERT INTO backup_manifests(id,tenant_id,state_hash,resource_counts,consistency_checks,limitations,schema_version,created_at)VALUES('backup','tenant','sha256:backup',jsonb_build_object(repeat('x',9000000),1),'[{"name":"audit_chain","result":"passed"}]',ARRAY[repeat('x',9000000)],'backup-manifest.v1.0.0',now()),('foreign','other','sha256:foreign','{}','[]','{}','backup-manifest.v1.0.0',now())`)
	commands, err := BuildBackupVerificationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"verify:read"}}}}
	want := 0
	counts := func() {
		t.Helper()
		var results, audits, jobs int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM verification_results),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&results, &audits, &jobs); err != nil || results != want || audits != want || jobs != want {
			t.Fatal("partial backup effects", results, audits, jobs, want, err)
		}
	}
	r, err := commands.VerifyBackupManifest(ctx, actor, "backup")
	if err != nil || r.Result.String() != "passed" || r.Profile.ID != "backup-manifest-consistency.v1" || r.Profile.PayloadDigest != "sha256:backup" || len(r.Checks) != 2 || r.Checks[1].Name != "backup_manifest_present" {
		t.Fatal(r, err)
	}
	want++
	counts()
	denied := actor
	denied.ResourceGrants = nil
	if _, err := commands.VerifyBackupManifest(ctx, denied, "backup"); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	denied.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"verify:read"}}}
	if _, err := commands.VerifyBackupManifest(ctx, denied, "backup"); !errors.Is(err, verificationapp.ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := commands.VerifyBackupManifest(ctx, actor, "foreign"); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("foreign manifest", err)
	}
	counts()
	if err := (backupVerificationTransactions{store}).ExecuteBackupVerification(ctx, func(ctx context.Context, tx verificationapp.BackupVerificationTransaction) error {
		if _, err := tx.ReadBackupVerification(ctx, verificationapp.SubjectReference{TenantID: "tenant", Type: "backup_manifest", ID: "backup"}); err != nil {
			return err
		}
		for _, sql := range []string{`UPDATE tenants SET name=name WHERE id='tenant'`, `UPDATE backup_manifests SET state_hash=state_hash WHERE id='backup'`} {
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
				t.Fatal("unstable recorded backup facts", sql, blocked)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE backup_manifests SET state_hash='sha256:updated' WHERE id='backup'`)
	r, err = commands.VerifyBackupManifest(ctx, actor, "backup")
	if err != nil || r.Profile.PayloadDigest != "sha256:updated" || r.Result.String() != "passed" {
		t.Fatal("cached state or invented live comparison", r, err)
	}
	want++
	counts()
	exec(`UPDATE backup_manifests SET consistency_checks='[{"name":"audit_chain","result":"failed"}]' WHERE id='backup'`)
	r, err = commands.VerifyBackupManifest(ctx, actor, "backup")
	if !errors.Is(err, verificationapp.ErrVerificationFailed) || r.Result.String() != "failed" || r.Checks[0].Result != "failed" {
		t.Fatal(r, err)
	}
	want++
	counts()
	exec(`UPDATE backup_manifests SET consistency_checks='[{"name":"audit_chain","result":"passed"}]' WHERE id='backup'`)
	for _, table := range []string{"audit_chain_entries", "outbox_jobs"} {
		exec(`CREATE OR REPLACE FUNCTION reject_backup_verify_effect()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced failure';END$$`)
		exec(`CREATE TRIGGER reject_backup_verify_effect BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_backup_verify_effect()`)
		if r, err := commands.VerifyBackupManifest(ctx, actor, "backup"); err == nil || r.ID != "" {
			t.Fatal(r, err)
		}
		counts()
		exec(`DROP TRIGGER reject_backup_verify_effect ON ` + table)
	}
	actor.UserID, actor.KeyID = "", "caller"
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	calls := 0
	for range 2 {
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "backup-replay", []byte(`{"subject_type":"backup_manifest","subject_id":"backup"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			r, err := commands.VerifyBackupManifest(ctx, actor, "backup")
			return 200, verificationResultToLegacy(r), err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("duplicate backup assessment")
	}
	want++
	counts()
	exec(`UPDATE backup_manifests SET consistency_checks='[{"name":"audit_chain","result":"failed"}]' WHERE id='backup'`)
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "backup-failed", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		r, err := commands.VerifyBackupManifest(ctx, actor, "backup")
		return 200, verificationResultToLegacy(r), err
	}); !errors.Is(err, verificationapp.ErrVerificationFailed) {
		t.Fatal(err)
	}
	counts()
	for _, sql := range []string{`UPDATE backup_manifests SET consistency_checks=jsonb_build_array(jsonb_build_object('name','audit_chain','result','passed','detail',repeat('x',8388609))) WHERE id='backup'`, `UPDATE backup_manifests SET consistency_checks=(SELECT jsonb_agg(jsonb_build_object('name','test','result','passed'))FROM generate_series(1,4097)) WHERE id='backup'`, `UPDATE backup_manifests SET consistency_checks='{}' WHERE id='backup'`, `UPDATE backup_manifests SET consistency_checks='null' WHERE id='backup'`, `UPDATE backup_manifests SET consistency_checks='[{"name":null,"result":"passed"}]' WHERE id='backup'`} {
		exec(sql)
		if r, err := commands.VerifyBackupManifest(ctx, actor, "backup"); !errors.Is(err, verificationapp.ErrConflict) || r.ID != "" {
			t.Fatal("malformed or unbounded backup projection", r, err)
		}
		counts()
	}
	other := identitydomain.Actor{TenantID: "other", KeyID: "other", Scopes: []string{"verify:read"}}
	if r, err := commands.VerifyBackupManifest(ctx, other, "foreign"); err != nil || r.TenantID != "other" || r.Profile.PayloadDigest != "sha256:foreign" || len(r.Checks) != 1 {
		t.Fatal("foreign data leaked into presence-only record", r, err)
	}
	want++
	counts()
}

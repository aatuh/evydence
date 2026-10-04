package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func seedBackupGenerationHTTP(t *testing.T, p *pgxpool.Pool, store *postgres.Store) {
	t.Helper()
	seedProviderReceiptHTTP(t, p)
	// Excluded credential columns and foreign tenant data exceed the view
	// budget. Neither may be selected by the native commitment or replay guard.
	if _, err := p.Exec(t.Context(), `INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product'),('foreign-product','other',repeat('private-foreign',700000),'foreign');INSERT INTO api_keys(id,tenant_id,name,prefix,hash,scopes)VALUES('unused-key','tenant','Key','unused',repeat('private-credential',600000),'[]');INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,created_at,valid_from)VALUES('unused-signing-key','tenant','unused','Ed25519','active','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',decode(repeat('ab',9*1024*1024),'hex'),now(),now())`); err != nil {
		t.Fatal(err)
	}
	if err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, r app.Repositories) error {
		_, err := r.Audit.Append(ctx, domain.AuditChainEntry{ID: "backup-seed", TenantID: "tenant", EntryType: "fixture", SubjectType: "product", SubjectID: "product", ActorType: "api_key", ActorID: "operator", OccurredAt: time.Now().UTC(), Metadata: map[string]any{"fixture": "private-audit-metadata"}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func backupGenerationHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.BackupGenerationCommands == nil || opts.DurableCommandExecutor == nil {
		t.Fatal("native backup composition missing", err)
	}
	noReload := &decisionHTTPNoReloadStore{}
	l, err := app.NewLedgerWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/backup-manifests", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("unsafe/legacy backup route status=%d want=%d loads=%d body=%s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("missing replay key")
	}
	return w.Body.String()
}

func backupGenerationHTTPCounts(t *testing.T, p *pgxpool.Pool) [5]int {
	t.Helper()
	var v [5]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM backup_manifests WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed'),(SELECT count(*)FROM outbox_jobs)`).Scan(&v[0], &v[1], &v[2], &v[3], &v[4]); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPostgresBackupGenerationHTTPRestartReplayAndCurrentAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBackupGenerationHTTP(t, p, store)
	var before verificationapp.BackupStateCommitment
	if err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, r app.Repositories) error {
		var err error
		before, err = r.Integrity.(verificationapp.BackupStateCommitmentReader).ReadBackupStateCommitment(ctx, "tenant")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	one := backupGenerationHTTP(t, store, "generate", `{}`, 201)
	var envelope struct {
		Data domain.BackupManifest `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &envelope); err != nil {
		t.Fatal(err)
	}
	m := envelope.Data
	if m.TenantID != "tenant" || m.StateHash != before.StateHash || m.SchemaVersion != "backup-manifest.v2.0.0" || m.ResourceCounts["audit_chain_entries"] != 1 || len(m.ResourceCounts) != 8 || len(m.ConsistencyChecks) != 8 || m.ConsistencyChecks[7].Result != "passed" || len(m.Limitations) != 3 || backupGenerationHTTPCounts(t, p) != [5]int{1, 2, 1, 0, 0} {
		t.Fatal("backup commitment/effects changed", one, before)
	}
	var hash, actor, kind, saved string
	if err := p.QueryRow(t.Context(), `SELECT a.payload_hash,a.actor_id,a.entry_type,i.response::text FROM audit_chain_entries a JOIN idempotency_records i ON i.tenant_id=a.tenant_id AND i.idempotency_key='generate'WHERE a.tenant_id='tenant'AND a.subject_id=$1`, m.ID).Scan(&hash, &actor, &kind, &saved); err != nil || hash != m.StateHash || actor != "user" || kind != "backup_manifest.generated" || strings.Contains(saved, "private-") {
		t.Fatal("backup audit/replay mismatch", err)
	}
	assertRetentionHTTPReplay(t, one, backupGenerationHTTP(t, store, "generate", `{}`, 201))
	exec := func(sql string) {
		t.Helper()
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	// Completed replay must not stream or verify current state, even when that
	// state is now too large and its audit-chain root is corrupt.
	exec(`UPDATE products SET name=repeat('private-new-state',600000)WHERE id='product';UPDATE audit_chain_entries SET entry_hash=''WHERE id='backup-seed'`)
	assertRetentionHTTPReplay(t, one, backupGenerationHTTP(t, store, "generate", `{}`, 201))
	backupGenerationHTTP(t, store, "generate", `{} `, 409)
	for _, sql := range []string{`UPDATE role_bindings SET resource_type='product',resource_id='product'WHERE id='grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='other'WHERE id='grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='viewer'WHERE id='grant'`} {
		exec(sql)
		backupGenerationHTTP(t, store, "generate", `{}`, 403)
		backupGenerationHTTP(t, store, "fresh-denied", `{}`, 403)
	}
	exec(`UPDATE role_bindings SET role='tenant_admin'WHERE id='grant';UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`)
	backupGenerationHTTP(t, store, "generate", `{}`, 401)
	if backupGenerationHTTPCounts(t, p) != [5]int{1, 2, 1, 0, 0} {
		t.Fatal("denied/conflicting replay changed effects")
	}
}

func TestPostgresBackupGenerationHTTPFailuresRollbackManifestAuditAndReplay(t *testing.T) {
	for _, stage := range []string{"manifest", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedBackupGenerationHTTP(t, p, store)
			table := map[string]string{"manifest": "backup_manifests", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_backup BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_backup()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_backup BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_backup()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_backup AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_backup()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_backup()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-backup SQL password=secret';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			backupGenerationHTTP(t, store, "failed", `{}`, 500)
			want := [5]int{0, 1, 0, 1, 0}
			if stage == "replay" || stage == "commit" {
				want[3] = 0
			}
			if backupGenerationHTTPCounts(t, p) != want {
				t.Fatal("partial backup/audit/replay survived", stage, backupGenerationHTTPCounts(t, p))
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_backup ON "+table); err != nil {
				t.Fatal(err)
			}
			if stage == "replay" || stage == "commit" {
				backupGenerationHTTP(t, store, "failed", `{}`, 201)
				if backupGenerationHTTPCounts(t, p) != [5]int{1, 2, 1, 0, 0} {
					t.Fatal("rolled-back reservation prevented retry")
				}
			}
		})
	}
}

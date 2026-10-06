package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
)

func seedRecordedCheckpointHTTP(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	seedProviderReceiptHTTP(t, p)
	// An ownership guard cannot deserialize these unrelated leaf/signature
	// columns. Creation selects only a bounded root from the owned batch.
	if _, err := p.Exec(t.Context(), `INSERT INTO merkle_batches(id,tenant_id,from_sequence,to_sequence,entry_count,leaf_hashes,root_hash,signature_refs,schema_version,created_at)VALUES('batch','tenant',1,1,1,ARRAY[repeat('private-leaf',900000)],'sha256:root',ARRAY[repeat('private-signature',600000)],'future-batch.v5000',now()),('foreign','other',1,1,1,'{}','sha256:foreign','{}','merkle-batch.v1.0.0',now())`); err != nil {
		t.Fatal(err)
	}
}

func recordedCheckpointHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.TransparencyCheckpointCommands == nil || opts.DurableCommandExecutor == nil {
		t.Fatal("native checkpoint composition missing", err)
	}
	noReload := &decisionHTTPNoReloadStore{}
	l, err := newLegacyLedgerFixtureWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/transparency-checkpoints", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("unsafe/legacy checkpoint route status=%d want=%d loads=%d body=%s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("missing replay key")
	}
	return w.Body.String()
}

func recordedCheckpointHTTPCounts(t *testing.T, p *pgxpool.Pool) [5]int {
	t.Helper()
	var v [5]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM transparency_checkpoints WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed'),(SELECT count(*)FROM outbox_jobs)`).Scan(&v[0], &v[1], &v[2], &v[3], &v[4]); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPostgresRecordedCheckpointHTTPRestartReplayOwnershipAndCurrentAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedRecordedCheckpointHTTP(t, p)
	body := `{"batch_id":" batch ","provider":" operator-provider ","external_url":" https://example.test/assertion ","external_id":" record "}`
	one := recordedCheckpointHTTP(t, store, "create", body, 201)
	var envelope struct {
		Data domain.TransparencyCheckpoint `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &envelope); err != nil {
		t.Fatal(err)
	}
	c := envelope.Data
	hash, err := application.NormalizedJSONHash(map[string]any{"batch_id": "batch", "root_hash": "sha256:root", "provider": "operator-provider", "external_url": "https://example.test/assertion", "external_id": "record"})
	if err != nil || c.TenantID != "tenant" || c.BatchID != "batch" || c.TimestampHash != hash || c.State != "recorded" || c.SchemaVersion != "transparency-checkpoint.v1.0.0" || recordedCheckpointHTTPCounts(t, p) != [5]int{1, 1, 1, 0, 0} {
		t.Fatal("checkpoint assertion/effects changed", one, err)
	}
	var auditHash, actor, kind, saved string
	if err := p.QueryRow(t.Context(), `SELECT a.payload_hash,a.actor_id,a.entry_type,i.response::text FROM audit_chain_entries a JOIN idempotency_records i ON i.tenant_id=a.tenant_id AND i.idempotency_key='create'WHERE a.tenant_id='tenant'AND a.subject_id=$1`, c.ID).Scan(&auditHash, &actor, &kind, &saved); err != nil || auditHash != hash || actor != "user" || kind != "transparency_checkpoint.recorded" || strings.Contains(saved, "private-") {
		t.Fatal("checkpoint audit/replay mismatch", err)
	}
	assertRetentionHTTPReplay(t, one, recordedCheckpointHTTP(t, store, "create", body, 201))
	exec := func(sql string) {
		t.Helper()
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	// Replay requires only current ownership, not present root integrity or
	// mutable source payloads. It never rehashes a completed assertion.
	exec(`UPDATE merkle_batches SET root_hash=repeat('private-corrupt-root',500000),leaf_hashes=ARRAY[repeat('private-new-leaf',700000)]WHERE tenant_id='tenant'AND id='batch'`)
	assertRetentionHTTPReplay(t, one, recordedCheckpointHTTP(t, store, "create", body, 201))
	recordedCheckpointHTTP(t, store, "create", body+" ", 409)
	recordedCheckpointHTTP(t, store, "foreign", `{"batch_id":"foreign","provider":"provider","external_id":"record"}`, 404)
	recordedCheckpointHTTP(t, store, "missing", `{"batch_id":"missing","provider":"provider","external_id":"record"}`, 404)
	for _, sql := range []string{`UPDATE role_bindings SET resource_type='product',resource_id='missing'WHERE id='grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='other'WHERE id='grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='viewer'WHERE id='grant'`} {
		exec(sql)
		recordedCheckpointHTTP(t, store, "create", body, 403)
		recordedCheckpointHTTP(t, store, "denied-fresh", body, 403)
	}
	exec(`UPDATE role_bindings SET role='tenant_admin'WHERE id='grant';UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`)
	recordedCheckpointHTTP(t, store, "create", body, 401)
	if recordedCheckpointHTTPCounts(t, p) != [5]int{1, 1, 1, 0, 0} {
		t.Fatal("denied/conflicting replay changed effects")
	}
}

func TestPostgresRecordedCheckpointHTTPFailuresRollbackCheckpointAuditAndReplay(t *testing.T) {
	for _, stage := range []string{"checkpoint", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedRecordedCheckpointHTTP(t, p)
			table := map[string]string{"checkpoint": "transparency_checkpoints", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_checkpoint BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_checkpoint()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_checkpoint BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_checkpoint()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_checkpoint AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_checkpoint()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_checkpoint()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-checkpoint SQL password=secret';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			body := `{"batch_id":"batch","provider":"provider","external_id":"record"}`
			recordedCheckpointHTTP(t, store, "failed", body, 500)
			want := [5]int{0, 0, 0, 1, 0}
			if stage == "replay" || stage == "commit" {
				want[3] = 0
			}
			if recordedCheckpointHTTPCounts(t, p) != want {
				t.Fatal("partial checkpoint/audit/replay survived", stage, recordedCheckpointHTTPCounts(t, p))
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_checkpoint ON "+table); err != nil {
				t.Fatal(err)
			}
			if stage == "replay" || stage == "commit" {
				recordedCheckpointHTTP(t, store, "failed", body, 201)
				if recordedCheckpointHTTPCounts(t, p) != [5]int{1, 1, 1, 0, 0} {
					t.Fatal("rolled-back reservation prevented safe retry")
				}
			}
		})
	}
}

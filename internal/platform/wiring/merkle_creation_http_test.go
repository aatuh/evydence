package wiring

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func seedMerkleCreationHTTP(t *testing.T, p *pgxpool.Pool, store *postgres.Store) []string {
	t.Helper()
	seedProviderReceiptHTTP(t, p)
	var leaves []string
	if err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, r app.Repositories) error {
		for i := 1; i <= 3; i++ {
			metadata := map[string]any{"public": "fixture"}
			if i == 1 {
				metadata["unselected_body"] = strings.Repeat("private-unselected-payload", 400000)
			}
			e, err := r.Audit.Append(ctx, domain.AuditChainEntry{ID: fmt.Sprintf("entry_%d", i), TenantID: "tenant", EntryType: "fixture", SubjectType: "fixture", SubjectID: "fixture", ActorType: "api_key", ActorID: "operator", OccurredAt: time.Now().UTC(), Metadata: metadata})
			if err != nil {
				return err
			}
			leaves = append(leaves, e.EntryHash)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Foreign rows and unrelated bodies must never enter the tenant's view.
	if err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, r app.Repositories) error {
		_, err := r.Audit.Append(ctx, domain.AuditChainEntry{ID: "foreign", TenantID: "other", EntryType: "fixture", SubjectType: "fixture", SubjectID: "fixture", ActorType: "api_key", ActorID: "foreign", OccurredAt: time.Now().UTC()})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return leaves
}

func merkleCreationHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.MerkleCreationCommands == nil || opts.DurableCommandExecutor == nil {
		t.Fatal("native Merkle composition missing", err)
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
	r := httptest.NewRequest("POST", "/v1/merkle-batches", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("unsafe/legacy Merkle route status=%d want=%d loads=%d body=%s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("missing replay key")
	}
	return w.Body.String()
}

func merkleCreationHTTPCounts(t *testing.T, p *pgxpool.Pool) [6]int {
	t.Helper()
	var v [6]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM signing_keys WHERE tenant_id='tenant'),(SELECT count(*)FROM signatures WHERE tenant_id='tenant'),(SELECT count(*)FROM merkle_batches WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&v[0], &v[1], &v[2], &v[3], &v[4], &v[5]); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPostgresMerkleCreationHTTPRestartReplayAndCurrentAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	leaves := seedMerkleCreationHTTP(t, p, store)
	one := merkleCreationHTTP(t, store, "create", `{}`, 201)
	var envelope struct {
		Data domain.MerkleBatch `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &envelope); err != nil {
		t.Fatal(err)
	}
	b := envelope.Data
	if b.TenantID != "tenant" || b.FromSequence != 1 || b.ToSequence != 3 || b.EntryCount != 3 || !reflect.DeepEqual(b.LeafHashes, leaves) || len(b.SignatureRefs) != 1 || merkleCreationHTTPCounts(t, p) != [6]int{1, 1, 1, 4, 1, 0} {
		t.Fatal("Merkle snapshot/effects differ", one)
	}
	var public, value, actor, kind, subject, hash, sigRef, saved string
	if err := p.QueryRow(t.Context(), `SELECT k.public_key,s.value,a.actor_id,a.entry_type,a.subject_id,a.payload_hash,a.signature_ref,i.response::text FROM signatures s JOIN signing_keys k ON k.id=s.key_id AND k.tenant_id=s.tenant_id JOIN audit_chain_entries a ON a.tenant_id=s.tenant_id AND a.subject_id=s.subject_id JOIN idempotency_records i ON i.tenant_id=s.tenant_id AND i.idempotency_key='create'WHERE s.id=$1`, b.SignatureRefs[0]).Scan(&public, &value, &actor, &kind, &subject, &hash, &sigRef, &saved); err != nil {
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
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(b.RootHash), sig) || actor != "user" || kind != "merkle_batch.created" || subject != b.ID || hash != b.RootHash || sigRef != b.SignatureRefs[0] || strings.Contains(saved, "private-") || strings.Contains(saved, "encrypted_private_key") {
		t.Fatal("Merkle signature/audit/replay contract changed")
	}
	assertRetentionHTTPReplay(t, one, merkleCreationHTTP(t, store, "create", `{}`, 201))
	// A fresh audit append changes the default upper bound. Later source/key
	// corruption must not cause a completed retry to recalculate or sign.
	if err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, r app.Repositories) error {
		_, err := r.Audit.Append(ctx, domain.AuditChainEntry{ID: "later", TenantID: "tenant", EntryType: "fixture", SubjectType: "fixture", SubjectID: "later", ActorType: "api_key", ActorID: "operator", OccurredAt: time.Now().UTC()})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE audit_chain_entries SET entry_hash=''WHERE id='entry_1';UPDATE signing_keys SET status='revoked',revoked_at=now(),encrypted_private_key=decode(repeat('ab',9*1024*1024),'hex')WHERE tenant_id='tenant'`)
	assertRetentionHTTPReplay(t, one, merkleCreationHTTP(t, store, "create", `{}`, 201))
	merkleCreationHTTP(t, store, "create", `{"from_sequence":1}`, 409)
	for _, sql := range []string{`UPDATE role_bindings SET resource_type='product',resource_id='missing'WHERE id='grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='other'WHERE id='grant'`, `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='viewer'WHERE id='grant'`} {
		exec(sql)
		merkleCreationHTTP(t, store, "create", `{}`, 403)
		merkleCreationHTTP(t, store, "fresh-denied", `{}`, 403)
	}
	exec(`UPDATE role_bindings SET role='tenant_admin'WHERE id='grant';UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`)
	merkleCreationHTTP(t, store, "create", `{}`, 401)
	if merkleCreationHTTPCounts(t, p) != [6]int{1, 1, 1, 5, 1, 0} {
		t.Fatal("denied/conflicting replay generated effects")
	}
}

func TestPostgresMerkleCreationHTTPFailuresRollbackKeySignatureBatchAuditAndReplay(t *testing.T) {
	for _, stage := range []string{"key", "signature", "batch", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedMerkleCreationHTTP(t, p, store)
			table := map[string]string{"key": "signing_keys", "signature": "signatures", "batch": "merkle_batches", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_merkle BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_merkle()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_merkle BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_merkle()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_merkle AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_merkle()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_merkle()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-merkle SQL password=secret';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			merkleCreationHTTP(t, store, "failed", `{}`, 500)
			want := [6]int{0, 0, 0, 3, 0, 1}
			if stage == "replay" || stage == "commit" {
				want[5] = 0
			}
			if got := merkleCreationHTTPCounts(t, p); got != want {
				t.Fatal("failed Merkle transaction published effects", got, want)
			}
			var unsafe int
			if err := p.QueryRow(t.Context(), `SELECT count(*)FROM idempotency_records WHERE response IS NOT NULL AND response<>'null'::jsonb`).Scan(&unsafe); err != nil || unsafe != 0 {
				t.Fatal("failure saved a partial result", err)
			}
			if stage == "replay" || stage == "commit" {
				if _, err := p.Exec(t.Context(), fmt.Sprintf("DROP TRIGGER reject_merkle ON %s", table)); err != nil {
					t.Fatal(err)
				}
				merkleCreationHTTP(t, store, "failed", `{}`, 201)
				if merkleCreationHTTPCounts(t, p) != [6]int{1, 1, 1, 4, 1, 0} {
					t.Fatal("failed commit retry did not create one batch")
				}
			}
		})
	}
}

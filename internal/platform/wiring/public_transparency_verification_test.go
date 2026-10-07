package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func seedPublicProofEntry(t *testing.T, store app.UnitOfWorkFactory, p *pgxpool.Pool) d.PublicTransparencyLogEntry {
	t.Helper()
	seedPublicTransparencyMetadata(t, p)
	c, err := BuildPublicTransparencyMetadataCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.PublishPublicTransparencyLogEntry(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}, e.PublicTransparencyPublicationInput{LogID: "log", CheckpointID: "checkpoint", ExternalID: "external"})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestPostgresPublicTransparencyVerificationBoundedRootsAtomicityAndStaleProof(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	v := seedPublicProofEntry(t, store, p)
	c, err := BuildPublicTransparencyVerificationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPublicTransparencyVerificationCommands(nil); err == nil {
		t.Fatal("nil transactions accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
	in := e.PublicTransparencyProofInput{RootHash: v.EntryHash, TreeSize: 1}
	before := publicTransparencyMetadataCounts(t, p)
	if err := c.AuthorizeVerifyPublicTransparencyLogEntry(t.Context(), a, v.ID, in); err != nil || publicTransparencyMetadataCounts(t, p) != before {
		t.Fatal("guard loaded oversized metadata or wrote", err)
	}
	first, err := c.VerifyPublicTransparencyLogEntry(t.Context(), a, v.ID, in)
	if err != nil || first.State != "inclusion_verified" || first.InclusionProofHash == "" {
		t.Fatal("verification failed", first, err)
	}
	// Previously stored checks/limitations are deliberately not read by this command.
	if _, err := p.Exec(t.Context(), `UPDATE public_transparency_log_entries SET verification_checks=jsonb_build_array(jsonb_build_object('detail',repeat('x',9437184))),verification_limitations=ARRAY[repeat('x',9437184)] WHERE id=$1`, v.ID); err != nil {
		t.Fatal(err)
	}
	second, err := c.VerifyPublicTransparencyLogEntry(t.Context(), a, v.ID, in)
	if err != nil || second.State != "inclusion_verified" || second.InclusionProofHash != first.InclusionProofHash {
		t.Fatal("prior diagnostic payload gained authority", second, err)
	}
	stale := second
	in.RootHash = "sha256:" + strings.Repeat("b", 64)
	changed, err := c.VerifyPublicTransparencyLogEntry(t.Context(), a, v.ID, in)
	if err != nil || changed.State != "inclusion_not_verified" {
		t.Fatal(changed, err)
	}
	in.RootHash = "sha256:" + strings.Repeat("c", 64)
	latest, err := c.VerifyPublicTransparencyLogEntry(t.Context(), a, v.ID, in)
	if err != nil || latest.State != changed.State || latest.InclusionProofHash == changed.InclusionProofHash {
		t.Fatal("same-state proof replacement not recorded", latest, err)
	}
	stale = changed
	err = app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, repos app.Repositories) error {
		r := repos.Future.(interface {
			UpdateFocusedPublicTransparencyVerification(context.Context, d.PublicTransparencyLogEntry, d.PublicTransparencyLogEntry) error
		})
		return r.UpdateFocusedPublicTransparencyVerification(ctx, second, stale)
	})
	if !errors.Is(err, app.ErrConflict) {
		t.Fatal("same-state stale assessment overwrote current proof", err)
	}
	before = publicTransparencyMetadataCounts(t, p)
	for _, tc := range []struct {
		change, restore string
		want            error
	}{
		{`UPDATE public_transparency_logs SET tenant_id='other' WHERE id='log'`, `UPDATE public_transparency_logs SET tenant_id='tenant' WHERE id='log'`, e.ErrNotFound},
		{`UPDATE transparency_checkpoints SET tenant_id='other' WHERE id='checkpoint'`, `UPDATE transparency_checkpoints SET tenant_id='tenant' WHERE id='checkpoint'`, e.ErrNotFound},
		{`UPDATE merkle_batches SET tenant_id='other' WHERE id='batch'`, `UPDATE merkle_batches SET tenant_id='tenant' WHERE id='batch'`, e.ErrNotFound},
		{`UPDATE transparency_checkpoints SET batch_id='different' WHERE id='checkpoint'`, `UPDATE transparency_checkpoints SET batch_id='batch' WHERE id='checkpoint'`, e.ErrNotFound},
		{`UPDATE public_transparency_log_entries SET external_id=repeat('x',9437184)`, `UPDATE public_transparency_log_entries SET external_id='external'`, e.ErrValidation},
	} {
		if _, err := p.Exec(t.Context(), tc.change); err != nil {
			t.Fatal(err)
		}
		out, err := c.VerifyPublicTransparencyLogEntry(t.Context(), a, v.ID, in)
		if !errors.Is(err, tc.want) || out.ID != "" || publicTransparencyMetadataCounts(t, p) != before {
			t.Fatal("invalid source assessed", out, err)
		}
		if _, err := p.Exec(t.Context(), tc.restore); err != nil {
			t.Fatal(err)
		}
	}
	for _, phase := range []string{"update", "audit", "commit"} {
		target := "public_transparency_log_entries"
		trigger := `CREATE TRIGGER reject_public_proof BEFORE UPDATE ON `
		if phase == "audit" {
			target = "audit_chain_entries"
			trigger = `CREATE TRIGGER reject_public_proof BEFORE INSERT ON `
		}
		if phase == "commit" {
			trigger = `CREATE CONSTRAINT TRIGGER reject_public_proof AFTER UPDATE ON `
		}
		sql := `CREATE OR REPLACE FUNCTION reject_public_proof()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private proof storage';END$$;` + trigger + target
		if phase == "commit" {
			sql += ` DEFERRABLE INITIALLY DEFERRED`
		}
		sql += ` FOR EACH ROW EXECUTE FUNCTION reject_public_proof()`
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
		out, err := c.VerifyPublicTransparencyLogEntry(t.Context(), a, v.ID, in)
		if err == nil || out.ID != "" || publicTransparencyMetadataCounts(t, p) != before {
			t.Fatal("failed proof published", phase, out, err)
		}
		var hash string
		if err := p.QueryRow(t.Context(), `SELECT inclusion_proof_hash FROM public_transparency_log_entries WHERE id=$1`, v.ID).Scan(&hash); err != nil || hash != latest.InclusionProofHash {
			t.Fatal("failed proof replaced prior assessment", err)
		}
		if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_public_proof ON `+target); err != nil {
			t.Fatal(err)
		}
	}
}
func TestPostgresPublicTransparencyVerificationHTTPRestartAndCurrentReplayAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	v := seedPublicProofEntry(t, store, p)
	path := "/v1/public-transparency-log-entries/" + v.ID + "/verify"
	body := fmt.Sprintf(`{"root_hash":%q,"leaf_index":0,"tree_size":1,"inclusion_proof":[]}`, v.EntryHash)
	request := func(key, body string, want int) []byte {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.PublicTransparencyProofCommands == nil {
			t.Fatal("verification remains Ledger-backed", err)
		}
		noReload := newAggregateLoadCanary(t, t.Context(), store)
		s, err := newNativeHTTPFixture(t.Context(), opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(t.Context())
		r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "evysso_receipt_fixture") {
			t.Fatal("legacy/private proof response", want, w.Code, noReload.Intact(t.Context()), w.Body.String())
		}
		return w.Body.Bytes()
	}
	first := request("proof", body, 200)
	before := publicTransparencyMetadataCounts(t, p)
	var left, right any
	if json.Unmarshal(first, &left) != nil || json.Unmarshal(request("proof", body, 200), &right) != nil || !reflect.DeepEqual(left, right) || publicTransparencyMetadataCounts(t, p) != before {
		t.Fatal("restart replay reassessed proof")
	}
	request("proof", body+" ", 409)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request("proof", body, 403)
	request("new", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `CREATE OR REPLACE FUNCTION reject_public_proof_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private proof commit';END$$;CREATE CONSTRAINT TRIGGER reject_public_proof_http AFTER UPDATE ON public_transparency_log_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_public_proof_http()`); err != nil {
		t.Fatal(err)
	}
	failed := request("commit", body, 500)
	if strings.Contains(string(failed), "private proof commit") || strings.Contains(string(failed), `"inclusion_proof_hash":`) || publicTransparencyMetadataCounts(t, p) != before {
		t.Fatal("outer commit failure exposed assessment", string(failed))
	}
	if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_public_proof_http ON public_transparency_log_entries;DELETE FROM transparency_checkpoints WHERE id='checkpoint'`); err != nil {
		t.Fatal(err)
	}
	request("proof", body, 404)
	if publicTransparencyMetadataCounts(t, p) != before {
		t.Fatal("deleted reference replay changed state")
	}
}
func TestPostgresPublicTransparencyVerificationLocksRootsUntilReplayCommit(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	v := seedPublicProofEntry(t, store, p)
	c, err := BuildPublicTransparencyVerificationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
	uow := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = uow.WithBody(ctx, a, "POST", "/v1/public-transparency-log-entries/"+v.ID+"/verify", "locks", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		out, err := c.VerifyPublicTransparencyLogEntry(ctx, a, v.ID, e.PublicTransparencyProofInput{RootHash: v.EntryHash, TreeSize: 1})
		if err != nil {
			return 0, nil, err
		}
		for _, tc := range []struct{ table, id string }{{"tenants", "tenant"}, {"public_transparency_logs", "log"}, {"transparency_checkpoints", "checkpoint"}, {"merkle_batches", "batch"}, {"public_transparency_log_entries", v.ID}} {
			tx, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, lockErr := tx.Exec(ctx, fmt.Sprintf("SELECT 1 FROM %s WHERE id=$1 FOR UPDATE NOWAIT", tc.table), tc.id)
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
				return 0, nil, fmt.Errorf("proof root lock missing: %s", tc.table)
			}
		}
		tx, err := p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='200ms'`); err != nil {
			return 0, nil, err
		}
		lockErr := coordination.LockWorkerProjection(ctx, tx, "tenant")
		var pgErr *pgconn.PgError
		if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
			return 0, nil, errors.New("worker fence released before proof replay commit")
		}
		return 200, out, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

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

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	e "github.com/aatuh/evydence/internal/experimental/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type publicFetchWiringClient struct {
	calls       int
	result      app.TransparencyProofResult
	err         error
	request     app.TransparencyProofRequest
	duringFetch func(context.Context)
}

func (f *publicFetchWiringClient) FetchTransparencyProof(ctx context.Context, r app.TransparencyProofRequest) (app.TransparencyProofResult, error) {
	f.calls++
	f.request = r
	if f.duringFetch != nil {
		f.duringFetch(ctx)
	}
	return f.result, f.err
}
func TestPostgresPublicTransparencyFetchHTTPRestartReplayLocksAndPrivateProviderFailures(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	v := seedPublicProofEntry(t, store, p)
	if _, err := p.Exec(t.Context(), `UPDATE public_transparency_logs SET endpoint='https://log.example.test' WHERE id='log'`); err != nil {
		t.Fatal(err)
	}
	f := &publicFetchWiringClient{result: app.TransparencyProofResult{RootHash: v.EntryHash, TreeSize: 1, Checks: []domain.VerifyCheck{{Name: "provider-private-canary", Result: "passed", Detail: "provider secret"}}, Limitations: []string{"provider-private-canary"}}}
	path := "/v1/public-transparency-log-entries/" + v.ID + "/fetch-proof"
	request := func(key, body string, want int) []byte {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, TransparencyProofs: f}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.PublicTransparencyFetchCommands == nil {
			t.Fatal("fetch remains Ledger-backed", err)
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
		r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(t.Context())
		r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "evysso_receipt_fixture") || strings.Contains(w.Body.String(), "provider-private-canary") {
			t.Fatal("legacy/private fetch response", want, w.Code, noReload.loads, w.Body.String())
		}
		return w.Body.Bytes()
	}
	f.duringFetch = func(ctx context.Context) {
		// A provider cannot change the same root chain while the ambient replay
		// transaction owns it. Prove all roots remain fenced with NOWAIT.
		for _, tc := range []struct{ table, id string }{{"tenants", "tenant"}, {"public_transparency_logs", "log"}, {"transparency_checkpoints", "checkpoint"}, {"merkle_batches", "batch"}, {"public_transparency_log_entries", v.ID}} {
			tx, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, lockErr := tx.Exec(ctx, fmt.Sprintf("SELECT 1 FROM %s WHERE id=$1 FOR UPDATE NOWAIT", tc.table), tc.id)
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
				t.Fatal("fetch source not locked", tc.table)
			}
		}
		tx, err := p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='200ms'`); err != nil {
			t.Fatal(err)
		}
		lockErr := coordination.LockWorkerProjection(ctx, tx, "tenant")
		_ = tx.Rollback(ctx)
		var pgErr *pgconn.PgError
		if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
			t.Fatal("worker projection fence not retained during fetch", lockErr)
		}
	}
	first := request("fetch", "", 200)
	if f.calls != 1 || f.request.Endpoint != "https://log.example.test" || f.request.EntryHash != v.EntryHash || f.request.ExternalID != v.ExternalID {
		t.Fatal("provider coordinates changed", f.calls, f.request)
	}
	before := publicTransparencyMetadataCounts(t, p)
	var left, right any
	if json.Unmarshal(first, &left) != nil || json.Unmarshal(request("fetch", "", 200), &right) != nil || !reflect.DeepEqual(left, right) || f.calls != 1 || publicTransparencyMetadataCounts(t, p) != before {
		t.Fatal("restart replay refetched")
	}
	request("fetch", "{}", 409)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request("fetch", "", 403)
	request("new", "", 403)
	if f.calls != 1 {
		t.Fatal("revoked grant reached provider")
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	f.err = errors.New("provider-private-canary")
	request("unavailable", "", 422)
	f.err = nil
	f.result.ExternalID = "foreign"
	request("mismatch", "", 422)
	f.result.ExternalID = ""
	if publicTransparencyMetadataCounts(t, p) != before {
		t.Fatal("provider failure wrote partial assessment")
	}
	if _, err := p.Exec(t.Context(), `CREATE OR REPLACE FUNCTION reject_public_fetch()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private fetch commit';END$$;CREATE CONSTRAINT TRIGGER reject_public_fetch AFTER UPDATE ON public_transparency_log_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_public_fetch()`); err != nil {
		t.Fatal(err)
	}
	failed := request("commit", "", 500)
	if strings.Contains(string(failed), "private fetch commit") || strings.Contains(string(failed), `"inclusion_proof_hash":`) || publicTransparencyMetadataCounts(t, p) != before {
		t.Fatal("failed outer fetch commit published", string(failed))
	}
	if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_public_fetch ON public_transparency_log_entries;DELETE FROM transparency_checkpoints WHERE id='checkpoint'`); err != nil {
		t.Fatal(err)
	}
	calls := f.calls
	request("fetch", "", 404)
	request("missing", "", 404)
	if f.calls != calls {
		t.Fatal("missing source/replay reached provider")
	}
}
func TestPostgresPublicTransparencyFetchBoundedSourcesAndRollback(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	v := seedPublicProofEntry(t, store, p)
	f := &publicFetchWiringClient{result: app.TransparencyProofResult{RootHash: v.EntryHash, TreeSize: 1}}
	c, err := BuildPublicTransparencyFetchCommands(store, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPublicTransparencyFetchCommands(nil, f); err == nil {
		t.Fatal("missing transactions accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
	before := publicTransparencyMetadataCounts(t, p)
	if out, err := c.FetchAndVerifyPublicTransparencyLogEntry(t.Context(), a, v.ID); !errors.Is(err, e.ErrValidation) || out.ID != "" || f.calls != 0 {
		t.Fatal("oversized endpoint transferred/fetched", err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE public_transparency_logs SET endpoint='https://log.example.test' WHERE id='log'`); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"update", "audit"} {
		target, event := "public_transparency_log_entries", "UPDATE"
		if phase == "audit" {
			target, event = "audit_chain_entries", "INSERT"
		}
		if _, err := p.Exec(t.Context(), `CREATE OR REPLACE FUNCTION reject_public_fetch_write()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private fetch write';END$$;CREATE TRIGGER reject_public_fetch_write BEFORE `+event+` ON `+target+` FOR EACH ROW EXECUTE FUNCTION reject_public_fetch_write()`); err != nil {
			t.Fatal(err)
		}
		out, err := c.FetchAndVerifyPublicTransparencyLogEntry(t.Context(), a, v.ID)
		if err == nil || out.ID != "" || publicTransparencyMetadataCounts(t, p) != before {
			t.Fatal("partial fetched assessment", phase, out, err)
		}
		var state, hash string
		if err := p.QueryRow(t.Context(), `SELECT state,coalesce(inclusion_proof_hash,'') FROM public_transparency_log_entries WHERE id=$1`, v.ID).Scan(&state, &hash); err != nil || state != "published" || hash != "" {
			t.Fatal("failed fetch mutated entry", err)
		}
		if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_public_fetch_write ON `+target); err != nil {
			t.Fatal(err)
		}
	}
	config, err := OpenRuntime(t.Context(), RuntimeConfig{Process: API, Profile: LocalMemory, TransparencyProofs: f})
	if err != nil || config.TransparencyProofs != f {
		t.Fatal("runtime lost configured fetcher", err)
	}
	config.Close()
}

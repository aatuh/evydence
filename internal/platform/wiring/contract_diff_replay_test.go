package wiring

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresContractDiffReadsPendingInputsInItsCommandTransaction(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	commands, err := BuildContractDiffCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("outer rollback")
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:read"}}
	_, _, err = (app.IdempotencyUnitOfWork{Transactions: store}).WithBody(ctx, a, "POST", "/v1/openapi-diffs", "compound-rollback", []byte(`{}`), func(ctx context.Context, repos app.Repositories) (int, any, error) {
		at := time.Now().UTC().Truncate(time.Microsecond)
		digest := "sha256:" + strings.Repeat("b", 64)
		e := domain.EvidenceItem{ID: "pending-evidence", TenantID: "tenant", ProductID: "product", ReleaseID: "release", Type: "openapi_contract", Title: "Pending", SourceSystem: "manual", PayloadHash: digest, CanonicalHash: digest, Canonicalization: "evydence-json-v1", TrustLevel: "unverified", SchemaVersion: "evydence.evidence.v1", ObservedAt: at, CreatedAt: at, VerificationStatus: "pending"}
		if err := repos.Evidence.InsertEvidence(ctx, e); err != nil {
			return 0, nil, err
		}
		if err := repos.Evidence.InsertOpenAPIContract(ctx, domain.OpenAPIContract{ID: "pending", TenantID: "tenant", EvidenceID: e.ID, ProductID: "product", ReleaseID: "release", Version: "1", Hash: digest, PathCount: 2, Operations: []domain.OpenAPIOperation{}, CreatedAt: at}); err != nil {
			return 0, nil, err
		}
		v, err := commands.CreateContractDiff(ctx, a, evidenceapp.CreateContractDiffInput{BaseContractID: "contract", TargetContractID: "pending"})
		if err != nil {
			return 0, nil, err
		}
		if v.Result != "changed" || !reflect.DeepEqual(v.NonBreakingChanges, []string{"target contract has additional paths"}) {
			t.Fatal("pending projection invisible", v)
		}
		return 0, nil, rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal("command opened independent snapshot", err)
	}
	var effects int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM contract_diffs)+(SELECT count(*)FROM evidence_items WHERE id='pending-evidence')+(SELECT count(*)FROM openapi_contracts WHERE id='pending')+(SELECT count(*)FROM audit_chain_entries WHERE entry_type='openapi_contract.diffed')+(SELECT count(*)FROM idempotency_records WHERE state<>'failed')`).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("outer rollback leaked effects", effects, err)
	}
	// The executor deliberately persists a safe failure receipt separately.
	var safeFailures int
	if err := pool.QueryRow(ctx, `SELECT count(*)FROM idempotency_records WHERE state='failed' AND status=0 AND response='null'::jsonb AND owner_token_hash='' AND failed_at IS NOT NULL`).Scan(&safeFailures); err != nil || safeFailures != 1 {
		t.Fatal("unsafe failure receipt", safeFailures, err)
	}
}
func TestPostgresContractDiffReplayCannotRewriteHistory(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO evidence_items SELECT(jsonb_populate_record(NULL::evidence_items,to_jsonb(e)||'{"id":"ev-target"}'::jsonb)).* FROM evidence_items e WHERE id='ev-contract';INSERT INTO openapi_contracts SELECT(jsonb_populate_record(NULL::openapi_contracts,to_jsonb(c)||jsonb_build_object('id','target','evidence_id','ev-target','hash','sha256:'||repeat('b',64),'path_count',2))).* FROM openapi_contracts c WHERE id='contract'`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildContractDiffCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	v, err := commands.CreateContractDiff(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:read"}}, evidenceapp.CreateContractDiffInput{BaseContractID: "contract", TargetContractID: "target", ReleaseID: "release"})
	if err != nil {
		t.Fatal(v, err)
	}
	state, exists, err := store.LoadState(ctx)
	if err != nil || !exists {
		t.Fatal(err)
	}
	var originalRow string
	if err := pool.QueryRow(ctx, `SELECT to_jsonb(d)::text FROM contract_diffs d WHERE id=$1`, v.ID).Scan(&originalRow); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveState(ctx, state); err != nil {
		t.Fatal("matching replay", err)
	}
	original := state.ContractDiffs[v.ID]
	legacy := original
	legacy.CreatedAt = time.Time{}
	state.ContractDiffs[v.ID] = legacy
	if err := store.SaveState(ctx, state); err != nil {
		t.Fatal("legacy absent timestamp replay", err)
	}
	state.ContractDiffs[v.ID] = original
	for _, change := range []func(*domain.ContractDiff){func(v *domain.ContractDiff) { v.Result = "breaking" }, func(v *domain.ContractDiff) { v.BreakingChanges = []string{"rewrite"} }, func(v *domain.ContractDiff) { v.NonBreakingChanges = []string{"rewrite"} }, func(v *domain.ContractDiff) { v.BaseContractID = "target" }, func(v *domain.ContractDiff) { v.TargetContractID = "contract" }, func(v *domain.ContractDiff) { v.ProductID = "other-product" }, func(v *domain.ContractDiff) { v.ReleaseID = "" }, func(v *domain.ContractDiff) { v.SchemaVersion = "rewritten" }, func(v *domain.ContractDiff) { v.CreatedAt = v.CreatedAt.Add(time.Second) }, func(v *domain.ContractDiff) { v.TenantID = "other" }} {
		updated := original
		change(&updated)
		state.ContractDiffs[v.ID] = updated
		want := app.ErrConflict
		if updated.TenantID == "other" {
			want = app.ErrNotFound
		}
		if err := store.SaveState(ctx, state); !errors.Is(err, want) {
			t.Fatal("historical diff rewrite accepted", updated, err)
		}
		state.ContractDiffs[v.ID] = original
	}
	// The compatibility store prefers its snapshot, including legacy zero
	// timestamps. Compare the authoritative relational row, not that cache.
	var currentRow string
	if err := pool.QueryRow(ctx, `SELECT to_jsonb(d)::text FROM contract_diffs d WHERE id=$1`, v.ID).Scan(&currentRow); err != nil || currentRow != originalRow {
		t.Fatal("failed replay changed persisted history", err)
	}
}

func TestPostgresContractDiffReaderBoundsOperationTransfer(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	read := func(want error) {
		t.Helper()
		err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
			reader := repos.Evidence.(evidenceapp.ContractDiffReader)
			if _, err := reader.ReadContractDiffSubject(ctx, "tenant", "contract"); err != nil {
				t.Fatal("metadata unexpectedly reads operations", err)
			}
			v, err := reader.ReadContractDiffProjection(ctx, "tenant", "contract")
			if len(v.Operations) != 0 {
				t.Fatal("invalid operation projection transferred", len(v.Operations))
			}
			return err
		})
		if !errors.Is(err, want) {
			t.Fatal("projection bound changed", err, want)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE openapi_contracts SET operations=(SELECT jsonb_agg(NULL::jsonb)FROM generate_series(1,524289)) WHERE id='contract'`); err != nil {
		t.Fatal(err)
	}
	read(app.ErrValidation)
	if _, err := pool.Exec(ctx, `UPDATE openapi_contracts SET operations=jsonb_build_array(jsonb_build_object('path',repeat('x',33554433),'method','GET')) WHERE id='contract'`); err != nil {
		t.Fatal(err)
	}
	read(app.ErrValidation)
	if _, err := pool.Exec(ctx, `UPDATE openapi_contracts SET operations='[]',hash=repeat('x',33554433) WHERE id='contract'`); err != nil {
		t.Fatal(err)
	}
	read(app.ErrValidation)
	if _, err := pool.Exec(ctx, `UPDATE openapi_contracts SET operations='null',hash='sha256:'||repeat('a',64) WHERE id='contract'`); err != nil {
		t.Fatal(err)
	}
	read(nil)
}

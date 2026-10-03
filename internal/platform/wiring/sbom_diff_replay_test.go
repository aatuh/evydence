package wiring

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresSBOMDiffReadsPendingInputsInItsCommandTransaction(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	commands, err := BuildSBOMDiffCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("outer rollback")
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:read"}}
	_, _, err = (app.IdempotencyUnitOfWork{Transactions: store}).WithBody(ctx, a, "POST", "/v1/sbom-diffs", "compound-rollback", []byte(`{}`), func(ctx context.Context, repos app.Repositories) (int, any, error) {
		at := time.Now().UTC().Truncate(time.Microsecond)
		digest := "sha256:" + strings.Repeat("a", 64)
		e := domain.EvidenceItem{ID: "pending-evidence", TenantID: "tenant", ProductID: "product", ReleaseID: "release", Type: "sbom", Title: "Pending", SourceSystem: "manual", PayloadHash: digest, CanonicalHash: digest, Canonicalization: "evydence-json-v1", TrustLevel: "unverified", SchemaVersion: "evydence.evidence.v1", ObservedAt: at, CreatedAt: at, VerificationStatus: "pending"}
		if err := repos.Evidence.InsertEvidence(ctx, e); err != nil {
			return 0, nil, err
		}
		if err := repos.Evidence.InsertSBOM(ctx, domain.SBOM{ID: "pending", TenantID: "tenant", EvidenceID: e.ID, ReleaseID: "release", Format: "cyclonedx", SpecVersion: "1.6", ComponentCount: 1, Components: []domain.SBOMComponent{{Name: "pending"}}, CreatedAt: at}); err != nil {
			return 0, nil, err
		}
		v, err := commands.CreateSBOMDiff(ctx, a, evidenceapp.CreateSBOMDiffInput{BaseSBOMID: "sbom", TargetSBOMID: "pending"})
		if err != nil {
			return 0, nil, err
		}
		if len(v.AddedComponents) != 1 || v.AddedComponents[0].Name != "pending" {
			t.Fatal("pending input invisible", v)
		}
		return 0, nil, rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal("command opened an independent snapshot", err)
	}
	var effects int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*)FROM sbom_diffs)+(SELECT count(*)FROM dependency_changes)+(SELECT count(*)FROM evidence_items WHERE id='pending-evidence')+(SELECT count(*)FROM sboms WHERE id='pending')+(SELECT count(*)FROM audit_chain_entries WHERE entry_type='sbom.diffed')`).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("outer rollback leaked effects", effects, err)
	}
	// The dedicated reader is required; a broad ingestion adapter is not used.
	if err := app.ExecuteUnitOfWork(ctx, store, func(_ context.Context, repos app.Repositories) error {
		if _, ok := repos.Evidence.(evidenceapp.SBOMDiffReader); !ok {
			t.Fatal("focused reader missing")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresSBOMDiffRejectsReleaseInferredOnlyFromSourceBuild(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	if _, err := pool.Exec(ctx, `UPDATE sboms SET release_id=NULL WHERE id='sbom';UPDATE evidence_items SET release_id=NULL,build_id='build' WHERE id='ev-sbom';INSERT INTO evidence_items SELECT(jsonb_populate_record(NULL::evidence_items,to_jsonb(e)||'{"id":"ev-target"}'::jsonb)).* FROM evidence_items e WHERE id='ev-sbom';INSERT INTO sboms SELECT(jsonb_populate_record(NULL::sboms,to_jsonb(s)||'{"id":"target","evidence_id":"ev-target"}'::jsonb)).* FROM sboms s WHERE id='sbom'`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildSBOMDiffCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:read"}}
	in := evidenceapp.CreateSBOMDiffInput{BaseSBOMID: "sbom", TargetSBOMID: "target", ReleaseID: "release"}
	if err := commands.AuthorizeCreateSBOMDiff(ctx, a, in); !errors.Is(err, evidenceapp.ErrValidation) {
		t.Fatal("inferred build release allowed as parsed SBOM release", err)
	}
	in.ReleaseID = ""
	if err := commands.AuthorizeCreateSBOMDiff(ctx, a, in); err != nil {
		t.Fatal("valid detached SBOM diff denied", err)
	}
}

func TestPostgresSBOMDiffReaderRejectsOversizedProjectionBeforeTransfer(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	read := func(want error) {
		t.Helper()
		err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
			reader := repos.Evidence.(evidenceapp.SBOMDiffReader)
			components, err := reader.ReadSBOMDiffComponents(ctx, "tenant", "sbom")
			if err == nil && len(components) != 0 {
				t.Fatal("invalid projection transferred", len(components))
			}
			return err
		})
		if !errors.Is(err, want) {
			t.Fatal("reader bound changed", err, want)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE sboms SET component_count=100001,components=(SELECT jsonb_agg(jsonb_build_object('name','x'))FROM generate_series(1,100001)) WHERE id='sbom'`); err != nil {
		t.Fatal(err)
	}
	read(app.ErrValidation)
	if _, err := pool.Exec(ctx, `UPDATE sboms SET component_count=65,components=(SELECT jsonb_agg(jsonb_build_object('name',repeat('x',1048576)))FROM generate_series(1,65)) WHERE id='sbom'`); err != nil {
		t.Fatal(err)
	}
	read(app.ErrValidation)
	if _, err := pool.Exec(ctx, `UPDATE sboms SET component_count=0,components='null'::jsonb WHERE id='sbom'`); err != nil {
		t.Fatal(err)
	}
	read(nil)
}

func TestPostgresSBOMDiffReplayCannotRewriteHistory(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	if _, err := pool.Exec(ctx, `UPDATE sboms SET components='[{"name":"removed"}]',component_count=1 WHERE id='sbom';INSERT INTO evidence_items SELECT(jsonb_populate_record(NULL::evidence_items,to_jsonb(e)||'{"id":"ev-target"}'::jsonb)).* FROM evidence_items e WHERE id='ev-sbom';INSERT INTO sboms SELECT(jsonb_populate_record(NULL::sboms,to_jsonb(s)||'{"id":"target","evidence_id":"ev-target","components":[],"component_count":0}'::jsonb)).* FROM sboms s WHERE id='sbom'`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildSBOMDiffCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	v, err := commands.CreateSBOMDiff(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:read"}}, evidenceapp.CreateSBOMDiffInput{BaseSBOMID: "sbom", TargetSBOMID: "target"})
	if err != nil || len(v.DependencyChanges) != 1 {
		t.Fatal(v, err)
	}
	state, exists, err := store.LoadState(ctx)
	if err != nil || !exists {
		t.Fatal(err)
	}
	if err := store.SaveState(ctx, state); err != nil {
		t.Fatal("matching replay", err)
	}
	original := state.SBOMDiffs[v.ID]
	for _, change := range []func(*domain.SBOMDiff){func(v *domain.SBOMDiff) { v.UnchangedCount = 999 }, func(v *domain.SBOMDiff) { v.AddedComponents = []domain.SBOMComponent{{Name: "rewrite"}} }, func(v *domain.SBOMDiff) { v.BaseSBOMID = "target" }, func(v *domain.SBOMDiff) { v.TenantID = "other" }} {
		updated := original
		change(&updated)
		state.SBOMDiffs[v.ID] = updated
		want := app.ErrConflict
		if updated.TenantID == "other" {
			want = app.ErrNotFound
		}
		if err := store.SaveState(ctx, state); !errors.Is(err, want) {
			t.Fatal("historical diff rewrite accepted", updated, err)
		}
		state.SBOMDiffs[v.ID] = original
	}
	id := v.DependencyChanges[0].ID
	c := state.DependencyChanges[id]
	for _, change := range []func(*domain.DependencyChange){func(v *domain.DependencyChange) { v.Component.Name = "rewrite" }, func(v *domain.DependencyChange) { v.ChangeType = "added" }, func(v *domain.DependencyChange) { v.SBOMDiffID = "wrong" }, func(v *domain.DependencyChange) { v.TenantID = "other" }} {
		updated := c
		change(&updated)
		state.DependencyChanges[id] = updated
		want := app.ErrConflict
		if updated.TenantID == "other" {
			want = app.ErrNotFound
		}
		if err := store.SaveState(ctx, state); !errors.Is(err, want) {
			t.Fatal("historical dependency rewrite accepted", updated, err)
		}
		state.DependencyChanges[id] = c
	}
}

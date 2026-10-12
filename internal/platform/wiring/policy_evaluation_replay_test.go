package wiring

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresPolicyEvaluationStateReplayCannotRewriteHistoricalChecks(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	if _, err := pool.Exec(ctx, `UPDATE vulnerability_scans SET findings='[]'::jsonb`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildPolicyEvaluationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"verify:read"}}
	evaluation, err := commands.EvaluateRelease(ctx, actor, "release")
	if err != nil {
		t.Fatal(err)
	}
	state, exists, err := store.LoadState(ctx)
	if err != nil || !exists {
		t.Fatal(err)
	}
	if err := store.SaveState(ctx, state); err != nil {
		t.Fatal("matching historical replay", err)
	}
	original := state.Policies[evaluation.ID]
	for _, change := range []func(*domain.PolicyEvaluation){func(v *domain.PolicyEvaluation) { v.Result = "rewritten" }, func(v *domain.PolicyEvaluation) {
		v.Checks = []domain.PolicyCheck{{Name: "rewritten", Result: "passed"}}
	}, func(v *domain.PolicyEvaluation) { v.PolicySet = "rewritten" }, func(v *domain.PolicyEvaluation) { v.ReleaseID = "other" }, func(v *domain.PolicyEvaluation) { v.TenantID = "other" }} {
		v := original
		change(&v)
		state.Policies[evaluation.ID] = v
		want := app.ErrConflict
		if v.TenantID == "other" {
			want = app.ErrNotFound
		}
		if err := store.SaveState(ctx, state); !errors.Is(err, want) {
			t.Fatal("policy history rewrite accepted", v, err)
		}
		state.Policies[evaluation.ID] = original
	}
}

func TestPostgresPolicyEvaluationRequiresMatchingDecisionScanAndRelease(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	if _, err := pool.Exec(ctx, `UPDATE vulnerability_scans SET findings='[{"id":"finding","severity":"high","state":"open","vulnerability":"CVE-TEST"}]';UPDATE vulnerability_decisions SET scan_id='wrong-scan' WHERE id='decision'`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildPolicyEvaluationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"verify:read"}}
	assertUnhandled := func() {
		t.Helper()
		v, err := commands.EvaluateRelease(ctx, a, "release")
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range v.Checks {
			if c.Name == "high_findings_require_triage" {
				if c.Result != "failed" {
					t.Fatal("unrelated decision handled release finding", v)
				}
				return
			}
		}
		t.Fatal("missing high triage check")
	}
	assertUnhandled()
	if _, err := pool.Exec(ctx, `UPDATE vulnerability_decisions SET scan_id='scan',release_id='wrong-release' WHERE id='decision'`); err != nil {
		t.Fatal(err)
	}
	assertUnhandled()
}

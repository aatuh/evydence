package wiring

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestPostgresCustomPolicyStateReplayCannotRewriteHistoricalInputsOrResults(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	commands, err := BuildCustomPolicyCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"policy:read", "policy:write"}}
	policy, err := commands.CreateCustomPolicy(ctx, actor, riskapp.CreateCustomPolicyInput{Name: "Policy", Version: "1", Rules: []riskdomain.PolicyRule{{Name: "SBOM", EvidenceType: "sbom", Severity: "high", Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := commands.EvaluateCustomPolicy(ctx, actor, policy.ID, "release")
	if err != nil {
		t.Fatal(err)
	}
	state, exists, err := store.LoadState(ctx)
	if err != nil || !exists {
		t.Fatal(err)
	}
	if err := store.SaveState(ctx, state); err != nil {
		t.Fatal("unchanged historical replay", err)
	}
	originalPolicy, originalEval := state.CustomPolicies[policy.ID], state.CustomPolicyEvaluations[evaluation.ID]
	for _, change := range []func(*domain.CustomPolicy){func(v *domain.CustomPolicy) { v.Description = "rewritten" }, func(v *domain.CustomPolicy) { v.Rules = []domain.PolicyRule{{Name: "different", Severity: "low"}} }, func(v *domain.CustomPolicy) { v.Name = "different" }, func(v *domain.CustomPolicy) { v.SchemaVersion = "different" }, func(v *domain.CustomPolicy) { v.TenantID = "other" }} {
		p := originalPolicy
		change(&p)
		state.CustomPolicies[policy.ID] = p
		want := app.ErrConflict
		if p.TenantID == "other" {
			want = app.ErrNotFound
		}
		if err := store.SaveState(ctx, state); !errors.Is(err, want) {
			t.Fatal("historical policy rewritten", p, err)
		}
		state.CustomPolicies[policy.ID] = originalPolicy
	}
	for _, change := range []func(*domain.CustomPolicyEvaluation){func(v *domain.CustomPolicyEvaluation) { v.Result = "failed" }, func(v *domain.CustomPolicyEvaluation) {
		v.Checks = []domain.PolicyCheck{{Name: "rewritten", Result: "failed"}}
	}, func(v *domain.CustomPolicyEvaluation) { v.InputHash = "sha256:changed" }, func(v *domain.CustomPolicyEvaluation) { v.ReleaseID = "other" }, func(v *domain.CustomPolicyEvaluation) { v.TenantID = "other" }} {
		e := originalEval
		change(&e)
		state.CustomPolicyEvaluations[e.ID] = e
		want := app.ErrConflict
		if e.TenantID == "other" {
			want = app.ErrNotFound
		}
		if err := store.SaveState(ctx, state); !errors.Is(err, want) {
			t.Fatal("historical evaluation rewritten", e, err)
		}
		state.CustomPolicyEvaluations[e.ID] = originalEval
	}
	var unchanged bool
	err = pool.QueryRow(ctx, `SELECT p.name='Policy' AND p.description IS NULL AND e.result='passed' AND e.input_hash=$3 FROM custom_policies p JOIN custom_policy_evaluations e ON e.policy_id=p.id WHERE p.id=$1 AND e.id=$2`, policy.ID, evaluation.ID, evaluation.InputHash).Scan(&unchanged)
	if err != nil || !unchanged {
		t.Fatal("failed replay damaged history", err)
	}
}

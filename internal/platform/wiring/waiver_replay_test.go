package wiring

import (
	"context"
	"testing"
	"time"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestPostgresWaiverStateReplayCannotUndoFocusedTransitions(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	commands, err := BuildWaiverCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"policy:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"policy:write"}}}}
	in := riskapp.CreateWaiverInput{ScopeType: "release", ScopeID: "release", Owner: "Owner", Risk: "low", Reason: "Reviewed", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	prior, err := commands.CreateWaiver(ctx, actor, in)
	if err != nil {
		t.Fatal(err)
	}
	stale, exists, err := store.LoadState(ctx)
	if err != nil || !exists {
		t.Fatal("snapshot unavailable", err)
	}
	approved, err := commands.ApproveWaiver(ctx, actor, prior.ID)
	if err != nil {
		t.Fatal(err)
	}
	in.Supersedes = prior.ID
	next, err := commands.CreateWaiver(ctx, actor, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveState(ctx, stale); err != nil {
		t.Fatal("unchanged historical snapshot cannot be replayed", err)
	}
	var approvalPreserved, supersessionPreserved bool
	if err := pool.QueryRow(ctx, `SELECT approved AND approved_by=$2 AND approved_at=$3,COALESCE(superseded_by=$4,false) FROM waivers WHERE id=$1`, prior.ID, approved.ApprovedBy, approved.ApprovedAt, next.ID).Scan(&approvalPreserved, &supersessionPreserved); err != nil || !approvalPreserved || !supersessionPreserved {
		t.Fatal("stale replay undid durable waiver transitions", approvalPreserved, supersessionPreserved, err)
	}
}

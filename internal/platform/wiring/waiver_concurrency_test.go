package wiring

import (
	"context"
	"errors"
	"testing"
	"time"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestPostgresWaiverCommandsSerializeCompetingTransitions(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedApprovalSubjects(t, ctx, store, pool)
	commands, err := BuildWaiverCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"policy:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"policy:write"}}}}
	in := riskapp.CreateWaiverInput{ScopeType: "release", ScopeID: "release", Owner: "Owner", Risk: "low", Reason: "Reviewed", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	v, err := commands.CreateWaiver(ctx, actor, in)
	if err != nil {
		t.Fatal(err)
	}
	race := func(run func() error) {
		t.Helper()
		results := make(chan error, 2)
		for range 2 {
			go func() { results <- run() }()
		}
		success, conflict := 0, 0
		for range 2 {
			err := <-results
			if err == nil {
				success++
			} else if errors.Is(err, riskapp.ErrConflict) {
				conflict++
			} else {
				t.Fatal("unexpected concurrent transition failure", err)
			}
		}
		if success != 1 || conflict != 1 {
			t.Fatal("competing transitions did not select one winner", success, conflict)
		}
	}
	race(func() error { _, err := commands.ApproveWaiver(ctx, actor, v.ID); return err })
	in.Supersedes = "waiver"
	race(func() error { _, err := commands.CreateWaiver(ctx, actor, in); return err })
	var records, created, approved int
	var approvedOnce, historicalCorePreserved bool
	if err := pool.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM waivers),
 (SELECT count(*) FROM audit_chain_entries WHERE entry_type='waiver.created'),
 (SELECT count(*) FROM audit_chain_entries WHERE entry_type='waiver.approved'),
 (SELECT approved AND approved_by='human' AND approved_at IS NOT NULL FROM waivers WHERE id=$1),
 (SELECT reason=repeat('x',9000000) AND NOT approved AND superseded_by IS NOT NULL FROM waivers WHERE id='waiver')`, v.ID).Scan(&records, &created, &approved, &approvedOnce, &historicalCorePreserved); err != nil || records != 3 || created != 2 || approved != 1 || !approvedOnce || !historicalCorePreserved {
		t.Fatal("concurrent loser left effects or rewrote historical content", records, created, approved, err)
	}
}

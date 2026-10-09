package wiring

import (
	"context"
	"reflect"
	"testing"
	"time"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestPostgresExceptionStateReplayCannotUndoFocusedApproval(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	commands, err := BuildExceptionCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"release:write"}}}}
	prior, err := commands.CreateException(ctx, actor, riskapp.CreateExceptionInput{ReleaseID: "release", Owner: "Owner", Reason: "Reviewed", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	stale, exists, err := store.LoadState(ctx)
	if err != nil || !exists {
		t.Fatal("snapshot unavailable", err)
	}
	approved, err := commands.ApproveException(ctx, actor, prior.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveState(ctx, stale); err != nil {
		t.Fatal("safe historical snapshot replay rejected", err)
	}
	var preserved bool
	if err := pool.QueryRow(ctx, `SELECT approved AND approved_by=$2 AND approved_at=$3 FROM exceptions WHERE id=$1`, prior.ID, approved.ApprovedBy, approved.ApprovedAt).Scan(&preserved); err != nil || !preserved {
		t.Fatal("stale replay undid durable exception approval", preserved, err)
	}
}

func TestPostgresExceptionConcurrentApprovalsReturnOneDurableResult(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	commands, err := BuildExceptionCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"release:write"}}}}
	v, err := commands.CreateException(ctx, actor, riskapp.CreateExceptionInput{ReleaseID: "release", Owner: "Owner", Reason: "Reviewed", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		value riskdomain.Exception
		err   error
	}
	results := make(chan outcome, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			value, err := commands.ApproveException(ctx, actor, v.ID)
			results <- outcome{value, err}
		}()
	}
	close(start)
	a, b := <-results, <-results
	if a.err != nil || b.err != nil || !a.value.Approved || !reflect.DeepEqual(a.value, b.value) {
		t.Fatal("concurrent exception approval changed original result", a, b)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries WHERE entry_type='exception.approved' AND subject_id=$1`, v.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("duplicate exception approval audit", audits, err)
	}
}

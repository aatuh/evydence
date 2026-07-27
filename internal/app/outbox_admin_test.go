package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type recordingOutboxAdmin struct {
	replayJobID string
	actorID     string
	replay      OutboxReplay
	diagnostics OutboxDiagnostics
}

func (r *recordingOutboxAdmin) ReplayTerminalJob(_ context.Context, jobID, actorID string) (OutboxReplay, error) {
	r.replayJobID, r.actorID = jobID, actorID
	return r.replay, nil
}

func (r *recordingOutboxAdmin) OutboxDiagnostics(context.Context) (OutboxDiagnostics, error) {
	return r.diagnostics, nil
}

func TestOutboxOperatorControlsRequireExplicitInstanceAdmin(t *testing.T) {
	admin := &recordingOutboxAdmin{
		replay:      OutboxReplay{JobID: "job_terminal", Status: "queued", ReplayedAt: fixedNow()},
		diagnostics: OutboxDiagnostics{PendingJobs: 2, RunningJobs: 1, TerminalJobs: 3, OldestPendingCreatedAt: fixedNow()},
	}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, OutboxAdmin: admin})
	ctx := context.Background()
	instance := domain.Actor{TenantID: "ten_instance", KeyID: "key_instance", Scopes: []string{ScopeInstanceAdmin}}
	if _, err := ledger.ReplayTerminalOutboxJob(ctx, domain.Actor{TenantID: "ten_tenant", KeyID: "key_tenant", Scopes: []string{"*"}}, "job_terminal"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant replay err=%v, want forbidden", err)
	}
	if replay, err := ledger.ReplayTerminalOutboxJob(ctx, instance, " job_terminal "); err != nil || replay.Status != "queued" || admin.replayJobID != "job_terminal" || admin.actorID != instance.KeyID {
		t.Fatalf("instance replay=%#v err=%v admin=%#v", replay, err, admin)
	}
	diagnostics, err := ledger.OutboxOperatorDiagnostics(ctx, instance)
	if err != nil || diagnostics.PendingJobs != 2 || diagnostics.OldestPendingCreatedAt.IsZero() {
		t.Fatalf("diagnostics=%#v err=%v", diagnostics, err)
	}
	metrics, err := ledger.Metrics(ctx, instance)
	if err != nil || metrics["outbox_pending_jobs"] != 2 || metrics["outbox_running_jobs"] != 1 || metrics["outbox_terminal_jobs"] != 3 {
		t.Fatalf("instance outbox metrics=%#v err=%v", metrics, err)
	}
	if _, err := ledger.Metrics(ctx, domain.Actor{Scopes: []string{ScopeInstanceAdmin}}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unauthenticated instance metrics err=%v, want unauthorized", err)
	}
	if _, err := ledger.OutboxOperatorDiagnostics(ctx, domain.Actor{TenantID: "ten_tenant", KeyID: "key_tenant", Scopes: []string{"*"}}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant diagnostics err=%v, want forbidden", err)
	}
}

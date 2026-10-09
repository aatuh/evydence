package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type replayRepositoryFake struct {
	jobID   string
	actorID string
	calls   int
	result  OutboxReplay
	err     error
}

func (f *replayRepositoryFake) ReplayTerminalJob(_ context.Context, jobID, actorID string) (OutboxReplay, error) {
	f.calls++
	f.jobID, f.actorID = jobID, actorID
	return f.result, f.err
}

type replayTransactionFake struct {
	repository *replayRepositoryFake
	calls      int
}

func (f *replayTransactionFake) ExecuteReplay(ctx context.Context, command func(context.Context, ReplayRepository) error) error {
	f.calls++
	return command(ctx, f.repository)
}

func TestReplayTerminalJobRequiresExplicitInstanceAdminBeforeTransaction(t *testing.T) {
	transactions := &replayTransactionFake{repository: &replayRepositoryFake{}}
	service, err := NewOutboxReplayCommands(transactions)
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []identitydomain.Actor{
		{TenantID: "ten_other", KeyID: "key_other", Scopes: []string{"*"}},
		{TenantID: "ten_other", KeyID: "key_other", Scopes: []string{"tenant:admin"}},
	} {
		if _, err := service.ReplayTerminalJob(t.Context(), actor, "job_terminal"); !errors.Is(err, application.ErrForbidden) {
			t.Fatalf("actor=%#v err=%v, want forbidden", actor, err)
		}
	}
	if transactions.calls != 0 {
		t.Fatalf("unauthorized replay opened %d transactions", transactions.calls)
	}
}

func TestReplayTerminalJobUsesScopedTransactionAndReturnsSafeResult(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	repository := &replayRepositoryFake{result: OutboxReplay{JobID: "job_terminal", Status: "queued", ReplayedAt: now}}
	transactions := &replayTransactionFake{repository: repository}
	service, err := NewOutboxReplayCommands(transactions)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_operator", KeyID: "key_operator", Scopes: []string{"instance:admin"}}
	result, err := service.ReplayTerminalJob(t.Context(), actor, " job_terminal ")
	if err != nil || result != repository.result || repository.jobID != "job_terminal" || repository.actorID != actor.KeyID || transactions.calls != 1 {
		t.Fatalf("result=%#v err=%v repository=%#v transactions=%d", result, err, repository, transactions.calls)
	}
	if _, err := service.ReplayTerminalJob(t.Context(), actor, "  "); !errors.Is(err, ErrValidation) {
		t.Fatalf("blank job err=%v, want validation", err)
	}
	if transactions.calls != 1 {
		t.Fatal("invalid replay opened a transaction")
	}
}

func TestReplayTerminalJobRejectsInvalidRepositoryResultBeforeCommit(t *testing.T) {
	repository := &replayRepositoryFake{result: OutboxReplay{JobID: "other_job", Status: "queued", ReplayedAt: time.Now().UTC()}}
	transactions := &replayTransactionFake{repository: repository}
	service, err := NewOutboxReplayCommands(transactions)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_operator", KeyID: "key_operator", Scopes: []string{"instance:admin"}}
	if _, err := service.ReplayTerminalJob(t.Context(), actor, "job_terminal"); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid replay result err=%v, want validation rollback", err)
	}
}

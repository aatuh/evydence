package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var ErrValidation = errors.New("invalid operations command")

// OutboxReplay contains only the operator-safe result of requeuing a job.
type OutboxReplay struct {
	JobID      string
	Status     string
	ReplayedAt time.Time
}

// ReplayRepository is bound to the caller's transaction. It must requeue the
// job and append its audit entry before returning.
type ReplayRepository interface {
	ReplayTerminalJob(context.Context, string, string) (OutboxReplay, error)
}

type ReplayTransactions interface {
	ExecuteReplay(context.Context, func(context.Context, ReplayRepository) error) error
}

type OutboxReplayCommands struct {
	transactions ReplayTransactions
}

func NewOutboxReplayCommands(transactions ReplayTransactions) (*OutboxReplayCommands, error) {
	if transactions == nil {
		return nil, ErrValidation
	}
	return &OutboxReplayCommands{transactions: transactions}, nil
}

// ReplayTerminalJob authorizes before opening a transaction. Only an explicit
// instance administrator can mutate the global queue, regardless of the job's
// tenant. The repository owns the row lock and append-only audit write.
func (s *OutboxReplayCommands) ReplayTerminalJob(ctx context.Context, actor identitydomain.Actor, jobID string) (OutboxReplay, error) {
	var empty OutboxReplay
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := application.AuthorizeInstanceScope(ctx, actor, "instance:admin"); err != nil {
		return empty, err
	}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" || strings.TrimSpace(actor.KeyID) == "" {
		return empty, ErrValidation
	}
	var replay OutboxReplay
	err := s.transactions.ExecuteReplay(ctx, func(ctx context.Context, repository ReplayRepository) error {
		if repository == nil {
			return ErrValidation
		}
		var err error
		replay, err = repository.ReplayTerminalJob(ctx, jobID, actor.KeyID)
		if err != nil {
			return err
		}
		if replay.JobID != jobID || replay.Status != "queued" || replay.ReplayedAt.IsZero() {
			return ErrValidation
		}
		return nil
	})
	if err != nil {
		return empty, err
	}
	return replay, nil
}

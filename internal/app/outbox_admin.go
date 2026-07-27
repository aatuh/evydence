package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// ReplayTerminalOutboxJob requeues one dead-letter job through the configured
// operator adapter. Only an explicit instance administrator can invoke it;
// ordinary tenant administrators and wildcard tenant keys are insufficient.
func (l *Ledger) ReplayTerminalOutboxJob(ctx context.Context, actor domain.Actor, jobID string) (OutboxReplay, error) {
	if err := ctx.Err(); err != nil {
		return OutboxReplay{}, err
	}
	if err := require(actor, ScopeInstanceAdmin); err != nil {
		return OutboxReplay{}, err
	}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" || strings.TrimSpace(actor.KeyID) == "" {
		return OutboxReplay{}, ErrValidation
	}
	l.mu.Lock()
	operator := l.outboxAdmin
	l.mu.Unlock()
	if operator == nil {
		return OutboxReplay{}, ErrConflict
	}
	return operator.ReplayTerminalJob(ctx, jobID, actor.KeyID)
}

// OutboxOperatorDiagnostics exposes aggregate, payload-free queue health to
// explicit instance administrators.
func (l *Ledger) OutboxOperatorDiagnostics(ctx context.Context, actor domain.Actor) (OutboxDiagnostics, error) {
	if err := ctx.Err(); err != nil {
		return OutboxDiagnostics{}, err
	}
	if err := require(actor, ScopeInstanceAdmin); err != nil {
		return OutboxDiagnostics{}, err
	}
	l.mu.Lock()
	operator := l.outboxAdmin
	l.mu.Unlock()
	if operator == nil {
		return OutboxDiagnostics{}, ErrConflict
	}
	return operator.OutboxDiagnostics(ctx)
}

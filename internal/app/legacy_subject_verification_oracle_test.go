package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// Historical aggregate verification characterization only. HTTP fixtures and
// recovery tests compose focused commands over current repository facts.
func (l *Ledger) VerifySubject(ctx context.Context, actor domain.Actor, subjectType, subjectID string) (domain.VerificationResult, error) {
	value, err := l.legacyVerificationCommands().VerifySubject(ctx, actor, subjectType, subjectID)
	return domain.VerificationResultFromContextModel(value), fromVerificationContextError(err)
}

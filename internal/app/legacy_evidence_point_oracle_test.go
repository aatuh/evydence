package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// Historical aggregate behavior remains only as an unchanged test oracle.
// Focused point fixtures use current repository rows instead.
func (l *Ledger) GetEvidence(ctx context.Context, actor domain.Actor, id string) (domain.EvidenceItem, error) {
	value, err := l.evidenceCommands.GetEvidence(ctx, actor, id)
	return evidenceFromContext(value), fromEvidenceContextError(err)
}

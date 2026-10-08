package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// Historical aggregate behavior remains only as an unchanged test oracle.
// Focused lifecycle fixtures read current repository rows instead.
func (l *Ledger) ListEvidenceLifecycleEvents(ctx context.Context, actor domain.Actor, evidenceID string) ([]domain.EvidenceLifecycleEvent, error) {
	events, err := l.evidenceCommands.ListLifecycleEvents(ctx, actor, evidenceID)
	if err != nil {
		return nil, fromEvidenceContextError(err)
	}
	result := make([]domain.EvidenceLifecycleEvent, 0, len(events))
	for _, event := range events {
		result = append(result, lifecycleFromEvidenceContext(event))
	}
	return result, nil
}

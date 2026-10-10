package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) ExportEvidenceBundle(ctx context.Context, actor domain.Actor, releaseID string, evidenceIDs []string) (domain.EvidenceBundle, error) {
	value, err := l.packageCommands.ExportEvidenceBundle(ctx, actor, releaseID, evidenceIDs)
	return evidenceBundleFromPackageContext(value), fromPackageContextError(err)
}

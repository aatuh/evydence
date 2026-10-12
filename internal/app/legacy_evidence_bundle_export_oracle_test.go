package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged aggregate behavior is retained only as a characterization oracle.
func (l *Ledger) ExportEvidenceBundle(ctx context.Context, actor domain.Actor, releaseID string, evidenceIDs []string) (domain.EvidenceBundle, error) {
	value, err := l.legacyPackageCommands().ExportEvidenceBundle(ctx, actor, releaseID, evidenceIDs)
	return evidenceBundleFromPackageContext(value), fromPackageContextError(err)
}

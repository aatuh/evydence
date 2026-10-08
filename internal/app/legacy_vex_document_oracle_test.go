package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// Historical point behavior remains only for package-local characterizations.
// Runtime and repository-backed HTTP fixtures use focused VEX points.
func (l *Ledger) GetVEXDocument(ctx context.Context, actor domain.Actor, id string) (domain.VEXDocument, error) {
	if err := ctx.Err(); err != nil {
		return domain.VEXDocument{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.VEXDocument{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.VEXDocument{}, err
	}
	vex, ok := l.vexDocuments[strings.TrimSpace(id)]
	if !ok || vex.TenantID != actor.TenantID {
		return domain.VEXDocument{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: vex.ReleaseID}); err != nil {
		return domain.VEXDocument{}, err
	}
	return vex, nil
}

package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// Historical report reads remain only for package-local characterizations.
func (l *Ledger) GetVEXImportReport(ctx context.Context, actor domain.Actor, vexID string) (domain.VEXImportReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.VEXImportReport{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.VEXImportReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.VEXImportReport{}, err
	}
	vex, ok := l.vexDocuments[strings.TrimSpace(vexID)]
	if !ok || vex.TenantID != actor.TenantID {
		return domain.VEXImportReport{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: vex.ReleaseID}); err != nil {
		return domain.VEXImportReport{}, err
	}
	for _, report := range l.vexImportReports {
		if report.TenantID == actor.TenantID && report.VEXDocumentID == vex.ID {
			return report, nil
		}
	}
	return domain.VEXImportReport{}, ErrNotFound
}

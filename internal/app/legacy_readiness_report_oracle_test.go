package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// The unchanged historical readiness report facade is a test-only oracle.
func (l *Ledger) ReleaseReadinessReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseReadinessReport, error) {
	value, err := l.packageCommands.ReleaseReadinessReport(ctx, actor, releaseID)
	return releaseReadinessReportFromPackageContext(value), fromPackageContextError(err)
}

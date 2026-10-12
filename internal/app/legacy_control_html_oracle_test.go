package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged historical HTML facade; never production wiring.
func (l *Ledger) CRAReadinessHTMLPackage(ctx context.Context, actor domain.Actor, productID, releaseID string) (domain.HTMLReportPackage, error) {
	value, err := l.legacyPackageCommands().CRAReadinessHTMLPackage(ctx, actor, productID, releaseID)
	return htmlReportPackageFromPackageContext(value), fromPackageContextError(err)
}

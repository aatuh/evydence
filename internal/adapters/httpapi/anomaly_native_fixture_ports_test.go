package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type anomalyNativeRepository interface {
	experimentalapp.AnomalyScopeReader
	experimentalapp.AnomalyReleaseFactsReader
	InsertFocusedAnomalyReport(context.Context, experimentaldomain.AnomalyReport) error
}
type anomalyNativeTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type anomalyNativeTransaction struct {
	anomalyNativeRepository
	repos    app.Repositories
	readOnly bool
}

func (f anomalyNativeTransactions) ExecuteAnomalyReport(ctx context.Context, tenant string, fn func(context.Context, experimentalapp.AnomalyTransaction) error) error {
	return anomalyFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(anomalyNativeRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, anomalyNativeTransaction{r, repos, f.readOnly})
	}))
}
func (tx anomalyNativeTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewEvidenceSummaryAuthorizer().Authorize(ctx, a, r)
}
func (tx anomalyNativeTransaction) ReadAnomalyReleaseFacts(ctx context.Context, tenant, release string, at time.Time) (experimentalapp.AnomalyReleaseFacts, error) {
	if tx.readOnly {
		panic("anomaly preflight read private release facts")
	}
	return tx.anomalyNativeRepository.ReadAnomalyReleaseFacts(ctx, tenant, release, at)
}
func (tx anomalyNativeTransaction) InsertAnomalyReport(ctx context.Context, v experimentaldomain.AnomalyReport) error {
	if tx.readOnly {
		panic("anomaly preflight wrote a report")
	}
	return tx.InsertFocusedAnomalyReport(ctx, v)
}
func (tx anomalyNativeTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if tx.readOnly {
		panic("anomaly preflight appended audit")
	}
	return (portalFixtureTransaction{repos: tx.repos}).AppendAudit(ctx, e)
}
func (f reportSigningFixtureCommands) nativeAnomaly(readOnly bool) (*experimentalapp.AnomalyCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	return experimentalapp.NewAnomalyCommands(experimentalapp.AnomalyCommandConfig{Transactions: anomalyNativeTransactions{f.catalogFixtureCommands, readOnly}, Authorizer: packagequery.NewEvidenceSummaryAuthorizer(), Clock: clock, IDs: ids})
}
func anomalyFixtureError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return experimentalapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return experimentalapp.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return experimentalapp.ErrConflict
	default:
		return err
	}
}

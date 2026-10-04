package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func BuildAnomalyReportCommands(factory app.UnitOfWorkFactory) (*experimentalapp.AnomalyCommands, error) {
	if factory == nil {
		return nil, errors.New("anomaly report transactions are required")
	}
	// The composition root supplies the existing resolved report-grant policy.
	// Experimental core code depends only on the transport-neutral authorizer.
	return experimentalapp.NewAnomalyCommands(experimentalapp.AnomalyCommandConfig{Transactions: anomalyTransactions{factory}, Authorizer: packagequery.NewEvidenceSummaryAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type anomalyRepository interface {
	experimentalapp.AnomalyScopeReader
	InsertFocusedAnomalyReport(context.Context, experimentaldomain.AnomalyReport) error
}
type anomalyTransactions struct{ factory app.UnitOfWorkFactory }

func (t anomalyTransactions) ExecuteAnomalyReport(ctx context.Context, tenant string, fn func(context.Context, experimentalapp.AnomalyTransaction) error) error {
	return mapAnomalyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(anomalyRepository)
		f, hasFacts := repos.PolicyEvaluationReader.(experimentalapp.AnomalyReleaseFactsReader)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !hasFacts || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, anomalyTransaction{r, f, repos.Audit})
	}))
}

type anomalyTransaction struct {
	anomalyRepository
	facts experimentalapp.AnomalyReleaseFactsReader
	audit app.AuditRepository
}

func (t anomalyTransaction) ReadAnomalyScope(ctx context.Context, tenant, kind, id string) (experimentalapp.AnomalyScope, error) {
	v, err := t.anomalyRepository.ReadAnomalyScope(ctx, tenant, kind, id)
	return v, mapAnomalyWriteError(err)
}
func (t anomalyTransaction) ReadAnomalyReleaseFacts(ctx context.Context, tenant, id string, at time.Time) (experimentalapp.AnomalyReleaseFacts, error) {
	v, err := t.facts.ReadAnomalyReleaseFacts(ctx, tenant, id, at)
	return v, mapAnomalyWriteError(err)
}
func (t anomalyTransaction) InsertAnomalyReport(ctx context.Context, v experimentaldomain.AnomalyReport) error {
	return mapAnomalyWriteError(t.InsertFocusedAnomalyReport(ctx, v))
}
func (t anomalyTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewEvidenceSummaryAuthorizer().Authorize(ctx, a, r)
}
func (t anomalyTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := appendAuditEvent(ctx, t.audit, e)
	return v, mapAnomalyWriteError(err)
}
func mapAnomalyWriteError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation) || errors.Is(err, riskapp.ErrValidation):
		return experimentalapp.ErrValidation
	case errors.Is(err, app.ErrNotFound) || errors.Is(err, riskapp.ErrNotFound):
		return experimentalapp.ErrNotFound
	case errors.Is(err, app.ErrConflict) || errors.Is(err, riskapp.ErrConflict):
		return experimentalapp.ErrConflict
	default:
		return err
	}
}

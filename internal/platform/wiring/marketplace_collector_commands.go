package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
)

func BuildMarketplaceCollectorCommands(factory app.UnitOfWorkFactory) (*experimentalapp.MarketplaceCollectorCommands, error) {
	if factory == nil {
		return nil, errors.New("marketplace collector transactions are required")
	}
	return experimentalapp.NewMarketplaceCollectorCommands(experimentalapp.MarketplaceCollectorConfig{Transactions: marketplaceCollectorTransactions{factory}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type marketplaceCollectorRepository interface {
	experimentalapp.MarketplaceReferenceReader
	InsertFocusedMarketplaceCollector(context.Context, experimentaldomain.MarketplaceCollector) error
}
type marketplaceCollectorTransactions struct{ factory app.UnitOfWorkFactory }

func (t marketplaceCollectorTransactions) ExecuteMarketplaceCollector(ctx context.Context, tenant string, fn func(context.Context, experimentalapp.MarketplaceCollectorTransaction) error) error {
	return mapAnomalyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(marketplaceCollectorRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, marketplaceCollectorTransaction{r, repos.Audit})
	}))
}

type marketplaceCollectorTransaction struct {
	marketplaceCollectorRepository
	audit app.AuditRepository
}

func (t marketplaceCollectorTransaction) ReadMarketplaceReferences(ctx context.Context, tenant string, ids experimentalapp.MarketplaceReferenceIDs) (experimentalapp.MarketplaceReferences, error) {
	v, err := t.marketplaceCollectorRepository.ReadMarketplaceReferences(ctx, tenant, ids)
	return v, mapAnomalyWriteError(err)
}
func (t marketplaceCollectorTransaction) InsertMarketplaceCollector(ctx context.Context, v experimentaldomain.MarketplaceCollector) error {
	return mapAnomalyWriteError(t.InsertFocusedMarketplaceCollector(ctx, v))
}
func (t marketplaceCollectorTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := appendAuditEvent(ctx, t.audit, e)
	return v, mapAnomalyWriteError(err)
}

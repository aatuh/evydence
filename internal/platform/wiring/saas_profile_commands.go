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

func BuildSaaSProfileCommands(factory app.UnitOfWorkFactory) (*experimentalapp.SaaSProfileCommands, error) {
	if factory == nil {
		return nil, errors.New("SaaS profile transactions are required")
	}
	return experimentalapp.NewSaaSProfileCommands(experimentalapp.SaaSProfileConfig{Transactions: saasProfileTransactions{factory}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type saasProfileRepository interface {
	experimentalapp.SaaSProfileTenantReader
	InsertFocusedSaaSProfile(context.Context, experimentaldomain.SaaSEditionProfile) error
}
type saasProfileTransactions struct{ factory app.UnitOfWorkFactory }

func (t saasProfileTransactions) ExecuteSaaSProfile(ctx context.Context, tenant string, fn func(context.Context, experimentalapp.SaaSProfileTransaction) error) error {
	return mapAnomalyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(saasProfileRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, saasProfileTransaction{r, repos.Audit})
	}))
}

type saasProfileTransaction struct {
	saasProfileRepository
	audit app.AuditRepository
}

func (t saasProfileTransaction) ReadSaaSProfileTenants(ctx context.Context, tenant, admin string) (experimentalapp.SaaSProfileTenants, error) {
	v, err := t.saasProfileRepository.ReadSaaSProfileTenants(ctx, tenant, admin)
	return v, mapAnomalyWriteError(err)
}
func (t saasProfileTransaction) InsertSaaSProfile(ctx context.Context, v experimentaldomain.SaaSEditionProfile) error {
	return mapAnomalyWriteError(t.InsertFocusedSaaSProfile(ctx, v))
}
func (t saasProfileTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := appendAuditEvent(ctx, t.audit, e)
	return v, mapAnomalyWriteError(err)
}

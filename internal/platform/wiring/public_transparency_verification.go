package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
)

func BuildPublicTransparencyVerificationCommands(factory app.UnitOfWorkFactory) (*e.PublicTransparencyVerificationCommands, error) {
	if factory == nil {
		return nil, errors.New("public transparency verification transactions are required")
	}
	return e.NewPublicTransparencyVerificationCommands(e.PublicTransparencyVerificationConfig{Transactions: publicTransparencyVerificationTransactions{factory}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type publicTransparencyVerificationRepository interface {
	e.PublicTransparencyVerificationReader
	UpdateFocusedPublicTransparencyVerification(context.Context, d.PublicTransparencyLogEntry, d.PublicTransparencyLogEntry) error
}
type publicTransparencyVerificationTransactions struct{ factory app.UnitOfWorkFactory }

func (t publicTransparencyVerificationTransactions) ExecutePublicTransparencyVerification(ctx context.Context, tenant string, fn func(context.Context, e.PublicTransparencyVerificationTransaction) error) error {
	return mapAnomalyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(publicTransparencyVerificationRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, publicTransparencyVerificationTransaction{r, repos.Audit})
	}))
}

type publicTransparencyVerificationTransaction struct {
	publicTransparencyVerificationRepository
	audit app.AuditRepository
}

func (t publicTransparencyVerificationTransaction) ReadPublicTransparencyVerification(ctx context.Context, tenant, id string) (d.PublicTransparencyLogEntry, error) {
	v, err := t.publicTransparencyVerificationRepository.ReadPublicTransparencyVerification(ctx, tenant, id)
	return v, mapAnomalyWriteError(err)
}
func (t publicTransparencyVerificationTransaction) UpdatePublicTransparencyVerification(ctx context.Context, v, expected d.PublicTransparencyLogEntry) error {
	return mapAnomalyWriteError(t.UpdateFocusedPublicTransparencyVerification(ctx, v, expected))
}
func (t publicTransparencyVerificationTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	a, err := appendAuditEvent(ctx, t.audit, v)
	return a, mapAnomalyWriteError(err)
}

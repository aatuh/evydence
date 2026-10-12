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

func BuildPublicTransparencyMetadataCommands(factory app.UnitOfWorkFactory) (*e.PublicTransparencyMetadataCommands, error) {
	if factory == nil {
		return nil, errors.New("public transparency metadata transactions are required")
	}
	return e.NewPublicTransparencyMetadataCommands(e.PublicTransparencyMetadataConfig{Transactions: publicTransparencyMetadataTransactions{factory}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type publicTransparencyMetadataRepository interface {
	e.PublicTransparencyMetadataReader
	InsertFocusedPublicTransparencyLog(context.Context, d.PublicTransparencyLog) error
	InsertFocusedPublicTransparencyEntry(context.Context, d.PublicTransparencyLogEntry) error
}
type publicTransparencyMetadataTransactions struct{ factory app.UnitOfWorkFactory }

func (t publicTransparencyMetadataTransactions) ExecutePublicTransparencyMetadata(ctx context.Context, tenant string, fn func(context.Context, e.PublicTransparencyMetadataTransaction) error) error {
	return mapAnomalyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(publicTransparencyMetadataRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, publicTransparencyMetadataTransaction{r, repos.Audit})
	}))
}

type publicTransparencyMetadataTransaction struct {
	publicTransparencyMetadataRepository
	audit app.AuditRepository
}

func (t publicTransparencyMetadataTransaction) ReadPublicTransparencyTenant(ctx context.Context, tenant string) error {
	return mapAnomalyWriteError(t.publicTransparencyMetadataRepository.ReadPublicTransparencyTenant(ctx, tenant))
}
func (t publicTransparencyMetadataTransaction) ReadPublicTransparencyPublication(ctx context.Context, tenant, log, checkpoint string) (e.PublicTransparencyPublicationSource, error) {
	v, err := t.publicTransparencyMetadataRepository.ReadPublicTransparencyPublication(ctx, tenant, log, checkpoint)
	return v, mapAnomalyWriteError(err)
}
func (t publicTransparencyMetadataTransaction) InsertPublicTransparencyLog(ctx context.Context, v d.PublicTransparencyLog) error {
	return mapAnomalyWriteError(t.InsertFocusedPublicTransparencyLog(ctx, v))
}
func (t publicTransparencyMetadataTransaction) InsertPublicTransparencyEntry(ctx context.Context, v d.PublicTransparencyLogEntry) error {
	return mapAnomalyWriteError(t.InsertFocusedPublicTransparencyEntry(ctx, v))
}
func (t publicTransparencyMetadataTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	a, err := appendAuditEvent(ctx, t.audit, v)
	return a, mapAnomalyWriteError(err)
}

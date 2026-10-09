package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

func BuildRetentionMarkerCommands(factory app.UnitOfWorkFactory) (*operationsapp.RetentionMarkerCommands, error) {
	if factory == nil {
		return nil, errors.New("retention marker transactions are required")
	}
	return operationsapp.NewRetentionMarkerCommands(operationsapp.RetentionMarkerConfig{Transactions: retentionMarkerTransactions{factory}, Authorizer: operationsapp.NewRetentionMarkerAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type retentionMarkerRepository interface {
	InsertLegalHold(context.Context, domain.LegalHold) error
	InsertRetentionOverride(context.Context, domain.RetentionOverride) error
}
type retentionMarkerTransactions struct{ factory app.UnitOfWorkFactory }

func (t retentionMarkerTransactions) ExecuteRetentionMarker(ctx context.Context, fn func(context.Context, operationsapp.RetentionMarkerTransaction) error) error {
	return mapEnvironmentWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		locker, ok := repos.Governance.(operationsapp.RetentionMarkerScopeLocker)
		fence, canFence := repos.Identity.(retentionTenantGuard)
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, retentionMarkerTransaction{locker, fence, repos.Governance, repos.Audit})
	}))
}

type retentionMarkerTransaction struct {
	locker  operationsapp.RetentionMarkerScopeLocker
	fence   retentionTenantGuard
	records retentionMarkerRepository
	audit   app.AuditRepository
}

func (t retentionMarkerTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if err := operationsapp.NewRetentionMarkerAuthorizer().Authorize(ctx, a, r); err != nil {
		return err
	}
	return mapEnvironmentWriteError(t.fence.LockAPIKeyCreation(ctx, a.TenantID))
}
func (t retentionMarkerTransaction) LockRetentionMarkerScope(ctx context.Context, tenant, kind, id string) error {
	return mapEnvironmentWriteError(t.locker.LockRetentionMarkerScope(ctx, tenant, kind, id))
}
func (t retentionMarkerTransaction) InsertLegalHold(ctx context.Context, v operationsdomain.LegalHold) error {
	return mapEnvironmentWriteError(t.records.InsertLegalHold(ctx, domain.LegalHold(v)))
}
func (t retentionMarkerTransaction) InsertRetentionOverride(ctx context.Context, v operationsdomain.RetentionOverride) error {
	return mapEnvironmentWriteError(t.records.InsertRetentionOverride(ctx, domain.RetentionOverride(v)))
}
func (t retentionMarkerTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	out, err := appendAuditEvent(ctx, t.audit, v)
	return out, mapEnvironmentWriteError(err)
}

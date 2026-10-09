package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type markerFixtureTenantGuard interface {
	LockAPIKeyCreation(context.Context, string) error
}
type retentionMarkerFixtureTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type retentionMarkerFixtureTransaction struct {
	locker   operationsapp.RetentionMarkerScopeLocker
	tenant   markerFixtureTenantGuard
	repos    app.Repositories
	readOnly bool
}

func (f retentionMarkerFixtureTransactions) ExecuteRetentionMarker(ctx context.Context, run func(context.Context, operationsapp.RetentionMarkerTransaction) error) error {
	if ctx == nil || run == nil {
		return operationsapp.ErrValidation
	}
	return deploymentFixtureCoreError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		locker, ok := r.Governance.(operationsapp.RetentionMarkerScopeLocker)
		tenant, hasTenant := r.Identity.(markerFixtureTenantGuard)
		if !ok || !hasTenant || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, retentionMarkerFixtureTransaction{locker, tenant, r, f.readOnly})
	}))
}
func (t retentionMarkerFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	if err := operationsapp.NewRetentionMarkerAuthorizer().Authorize(ctx, a, r); err != nil {
		return err
	}
	return deploymentFixtureCoreError(t.tenant.LockAPIKeyCreation(ctx, a.TenantID))
}
func (t retentionMarkerFixtureTransaction) LockRetentionMarkerScope(ctx context.Context, tenant, kind, id string) error {
	return deploymentFixtureCoreError(t.locker.LockRetentionMarkerScope(ctx, tenant, kind, id))
}
func (t retentionMarkerFixtureTransaction) InsertLegalHold(ctx context.Context, v operationsdomain.LegalHold) error {
	if t.readOnly {
		panic("retention preflight inserted legal hold")
	}
	return deploymentFixtureCoreError(t.repos.Governance.InsertLegalHold(ctx, domain.LegalHold(v)))
}
func (t retentionMarkerFixtureTransaction) InsertRetentionOverride(ctx context.Context, v operationsdomain.RetentionOverride) error {
	if t.readOnly {
		panic("retention preflight inserted override")
	}
	return deploymentFixtureCoreError(t.repos.Governance.InsertRetentionOverride(ctx, domain.RetentionOverride(v)))
}
func (t retentionMarkerFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if t.readOnly {
		panic("retention preflight appended audit")
	}
	v, err := (governanceFixtureTransaction{audit: t.repos.Audit}).AppendAudit(ctx, e)
	return v, deploymentFixtureCoreError(err)
}
func (f operationsFixtureCommands) nativeRetention(readOnly bool) (*operationsapp.RetentionMarkerCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return operationsapp.NewRetentionMarkerCommands(operationsapp.RetentionMarkerConfig{Transactions: retentionMarkerFixtureTransactions{f.catalogFixtureCommands, readOnly}, Authorizer: operationsapp.NewRetentionMarkerAuthorizer(), Clock: clock, IDs: ids})
}

var _ operationsapp.RetentionMarkerTransaction = retentionMarkerFixtureTransaction{}

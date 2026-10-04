package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func BuildTrustConfigurationCommands(factory app.UnitOfWorkFactory) (*verificationapp.TrustConfigurationCommands, error) {
	if factory == nil {
		return nil, errors.New("trust configuration transactions are required")
	}
	return verificationapp.NewTrustConfigurationCommands(verificationapp.TrustConfigurationConfig{Transactions: trustConfigurationTransactions{factory}, Authorizer: verificationquery.NewSigningKeyAdminAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type trustConfigurationTransactions struct{ factory app.UnitOfWorkFactory }

func (t trustConfigurationTransactions) ExecuteTrustConfigurationCommand(ctx context.Context, command func(context.Context, verificationapp.TrustConfigurationTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		guard, ok := repos.Identity.(trustConfigurationTenantGuard)
		if !ok || repos.Integrity == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, trustConfigurationTransaction{integrity: repos.Integrity, audit: repos.Audit, guard: guard})
	}))
}

type trustConfigurationTenantGuard interface {
	LockAPIKeyCreation(context.Context, string) error
}

type trustConfigurationTransaction struct {
	integrity app.IntegrityRepository
	audit     app.AuditRepository
	guard     trustConfigurationTenantGuard
}

func (t trustConfigurationTransaction) InsertSigningProvider(ctx context.Context, provider verificationdomain.SigningProvider) error {
	return mapSigningKeyWriteError(t.integrity.InsertSigningProvider(ctx, domain.SigningProviderFromContextModel(provider)))
}
func (t trustConfigurationTransaction) InsertDSSETrustRoot(ctx context.Context, root verificationdomain.DSSETrustRoot) error {
	return mapSigningKeyWriteError(t.integrity.InsertDSSETrustRoot(ctx, domain.DSSETrustRootFromContextModel(root)))
}
func (t trustConfigurationTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if err := verificationquery.NewSigningKeyAdminAuthorizer().Authorize(ctx, actor, request); err != nil {
		return err
	}
	// Reuse only Identity's tenant-existence/mutation guard, not credential
	// inventories. The common writer fence precedes tenant and audit locks;
	// the enclosing durable unit of work holds it through replay/commit.
	return mapSigningKeyWriteError(t.guard.LockAPIKeyCreation(ctx, actor.TenantID))
}
func (t trustConfigurationTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	receipt, err := appendAuditEvent(ctx, t.audit, event)
	return receipt, mapSigningKeyWriteError(err)
}

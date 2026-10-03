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
		if repos.Integrity == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, trustConfigurationTransaction{repos.Integrity, repos.Audit})
	}))
}

type trustConfigurationTransaction struct {
	integrity app.IntegrityRepository
	audit     app.AuditRepository
}

func (t trustConfigurationTransaction) InsertSigningProvider(ctx context.Context, provider verificationdomain.SigningProvider) error {
	return mapSigningKeyWriteError(t.integrity.InsertSigningProvider(ctx, domain.SigningProviderFromContextModel(provider)))
}
func (t trustConfigurationTransaction) InsertDSSETrustRoot(ctx context.Context, root verificationdomain.DSSETrustRoot) error {
	return mapSigningKeyWriteError(t.integrity.InsertDSSETrustRoot(ctx, domain.DSSETrustRootFromContextModel(root)))
}
func (t trustConfigurationTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return verificationquery.NewSigningKeyAdminAuthorizer().Authorize(ctx, actor, request)
}
func (t trustConfigurationTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	receipt, err := appendAuditEvent(ctx, t.audit, event)
	return receipt, mapSigningKeyWriteError(err)
}

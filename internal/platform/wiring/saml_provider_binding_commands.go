package wiring

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func BuildSAMLProviderBindingCommands(factory app.UnitOfWorkFactory) (*identityapp.SAMLProviderBindingCommands, error) {
	if factory == nil {
		return nil, identityapp.ErrValidation
	}
	return identityapp.NewSAMLProviderBindingCommands(identityapp.SAMLProviderBindingCommandConfig{Transactions: samlBindingTransactions{factory}, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Hasher: verificationCanonicalHasher{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type samlBindingRepository interface {
	identityapp.SSOProviderWriteReader
	ReadOwnedSAMLProviderBinding(context.Context, string, string) (identitydomain.SAMLProviderBinding, error)
	UpsertSAMLProviderBinding(context.Context, identitydomain.SAMLProviderBinding) error
}
type samlBindingTransactions struct{ factory app.UnitOfWorkFactory }
type samlBindingTransaction struct {
	samlBindingRepository
	audit app.AuditRepository
}

func (t samlBindingTransactions) ExecuteSAMLProviderBinding(ctx context.Context, fn func(context.Context, identityapp.SAMLProviderBindingTransaction) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		writer, ok := repos.Identity.(samlBindingRepository)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, samlBindingTransaction{writer, repos.Audit})
	}))
}
func (t samlBindingTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return identityapp.NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (t samlBindingTransaction) ReadOwnedSSOProvider(ctx context.Context, tenant, id string) (identitydomain.SSOProvider, error) {
	p, err := t.samlBindingRepository.ReadOwnedSSOProvider(ctx, tenant, id)
	return p, mapAPIKeyWriteError(err)
}
func (t samlBindingTransaction) ReadOwnedSAMLProviderBinding(ctx context.Context, tenant, id string) (identitydomain.SAMLProviderBinding, error) {
	b, err := t.samlBindingRepository.ReadOwnedSAMLProviderBinding(ctx, tenant, id)
	return b, mapAPIKeyWriteError(err)
}
func (t samlBindingTransaction) LockSSOProviderCreation(ctx context.Context, tenant string) error {
	return mapAPIKeyWriteError(t.samlBindingRepository.LockSSOProviderCreation(ctx, tenant))
}
func (t samlBindingTransaction) UpsertSAMLProviderBinding(ctx context.Context, b identitydomain.SAMLProviderBinding) error {
	return mapAPIKeyWriteError(t.samlBindingRepository.UpsertSAMLProviderBinding(ctx, b))
}
func (t samlBindingTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, v)
	return r, mapAPIKeyWriteError(err)
}

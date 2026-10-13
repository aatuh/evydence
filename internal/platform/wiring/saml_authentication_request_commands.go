package wiring

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func BuildSAMLAuthenticationRequestCommands(factory app.UnitOfWorkFactory, pepper string, production bool) (*identityapp.SAMLAuthenticationRequestCommands, error) {
	if factory == nil {
		return nil, identityapp.ErrValidation
	}
	credentials, err := buildAuthenticationCredentials(pepper, production)
	if err != nil {
		return nil, err
	}
	return identityapp.NewSAMLAuthenticationRequestCommands(identityapp.SAMLAuthenticationRequestCommandConfig{Reader: ssoExchangeReader{factory: factory}, Transactions: samlRequestTransactions{factory}, Credentials: credentials, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

func (r ssoExchangeReader) SAMLProviderBindingByID(ctx context.Context, id string) (identitydomain.SAMLProviderBinding, error) {
	var out identitydomain.SAMLProviderBinding
	err := mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.SAMLRequestProviderReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.SAMLProviderBindingByID(ctx, id)
		return err
	}))
	return out, err
}
func (r ssoExchangeReader) ReadSAMLAuthenticationRequest(ctx context.Context, tenant, provider, id string) (identitydomain.SAMLAuthenticationRequest, error) {
	var out identitydomain.SAMLAuthenticationRequest
	err := mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.SAMLAuthenticationRequestReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadSAMLAuthenticationRequest(ctx, tenant, provider, id)
		return err
	}))
	return out, err
}

type samlRequestRepository interface {
	ValidateSAMLProviderBinding(context.Context, identitydomain.SAMLProviderBinding) error
	InsertSAMLAuthenticationRequest(context.Context, identitydomain.SAMLAuthenticationRequest, time.Time) error
}
type samlRequestTransactions struct{ factory app.UnitOfWorkFactory }
type samlRequestTransaction struct {
	identity samlRequestRepository
	audit    app.AuditRepository
}

func (t samlRequestTransactions) ExecuteSAMLAuthenticationRequest(ctx context.Context, fn func(context.Context, identityapp.SAMLAuthenticationRequestTransaction) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		writer, ok := repos.Identity.(samlRequestRepository)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, samlRequestTransaction{writer, repos.Audit})
	}))
}
func (t samlRequestTransaction) ValidateSAMLProviderBinding(ctx context.Context, b identitydomain.SAMLProviderBinding) error {
	return mapAPIKeyWriteError(t.identity.ValidateSAMLProviderBinding(ctx, b))
}
func (t samlRequestTransaction) InsertSAMLAuthenticationRequest(ctx context.Context, r identitydomain.SAMLAuthenticationRequest, at time.Time) error {
	return mapAPIKeyWriteError(t.identity.InsertSAMLAuthenticationRequest(ctx, r, at))
}
func (t samlRequestTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, v)
	return r, mapAPIKeyWriteError(err)
}

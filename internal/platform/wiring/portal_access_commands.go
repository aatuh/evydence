package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func BuildPortalAccessCommands(factory app.UnitOfWorkFactory, pepper string, production bool) (*packageapp.PortalAccessCommands, error) {
	if factory == nil {
		return nil, errors.New("portal access transactions are required")
	}
	c, err := buildAuthenticationCredentials(pepper, production)
	if err != nil {
		return nil, err
	}
	return packageapp.NewPortalAccessCommands(packageapp.PortalAccessCommandConfig{Transactions: portalAccessTransactions{factory}, Credentials: portalCredentials{c}, Authorizer: packagequery.NewPortalAccessWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type portalCredentials struct {
	credentials *identityapp.HMACAuthenticationCredentials
}

func (c portalCredentials) GeneratePortalCredential() (packageapp.PortalCredential, error) {
	v, err := c.credentials.GeneratePortalAccess()
	return packageapp.PortalCredential{Secret: v.Secret, Prefix: v.Prefix, Hash: v.Hash}, err
}

type portalAccessRepository interface {
	packageapp.PortalAccessWriteReader
	LockAPIKeyCreation(context.Context, string) error
	InsertFocusedPortalAccess(context.Context, packagedomain.CustomerPortalAccess) error
	RevokeFocusedPortalAccess(context.Context, string, string, time.Time) error
}
type portalAccessTransactions struct{ factory app.UnitOfWorkFactory }

func (t portalAccessTransactions) ExecutePortalAccess(ctx context.Context, tenant string, fn func(context.Context, packageapp.PortalAccessTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Identity.(portalAccessRepository)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := r.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, portalAccessTransaction{r, repos.Audit})
	}))
}

type portalAccessTransaction struct {
	portalAccessRepository
	audit app.AuditRepository
}

func (t portalAccessTransaction) InsertPortalAccess(ctx context.Context, v packagedomain.CustomerPortalAccess) error {
	return mapPackageAccessWriteError(t.InsertFocusedPortalAccess(ctx, v))
}
func (t portalAccessTransaction) RevokePortalAccess(ctx context.Context, tenant, id string, at time.Time) error {
	return mapPackageAccessWriteError(t.RevokeFocusedPortalAccess(ctx, tenant, id, at))
}
func (t portalAccessTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewPortalAccessWriteAuthorizer().Authorize(ctx, a, r)
}
func (t portalAccessTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, e)
}

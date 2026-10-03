package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func BuildPortalTokenCommands(factory app.UnitOfWorkFactory, lookup packageapp.PortalAccessLookup, pepper string, production bool) (*packageapp.PortalTokenCommands, error) {
	if factory == nil || lookup == nil {
		return nil, errors.New("portal token transactions and lookup are required")
	}
	c, err := buildAuthenticationCredentials(pepper, production)
	if err != nil {
		return nil, err
	}
	return packageapp.NewPortalTokenCommands(packageapp.PortalTokenCommandConfig{Lookup: lookup, Transactions: portalTokenTransactions{factory}, Credentials: portalCredentials{c}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}
func (c portalCredentials) HashPortalToken(token string) string { return c.credentials.Hash(token) }
func (c portalCredentials) EqualPortalHashes(a, b string) bool  { return c.credentials.Equal(a, b) }

type portalTokenRepository interface {
	packageapp.PortalAccessWriteReader
	LockAPIKeyCreation(context.Context, string) error
	ReadPortalAccessForToken(context.Context, string, string) (packagedomain.CustomerPortalAccess, error)
	UpdateFocusedPortalTokenAccess(context.Context, packagedomain.CustomerPortalAccess, packagedomain.CustomerPortalAccess) error
}
type portalTokenTransactions struct{ factory app.UnitOfWorkFactory }

func (t portalTokenTransactions) ExecutePortalToken(ctx context.Context, tenant string, fn func(context.Context, packageapp.PortalTokenTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Identity.(portalTokenRepository)
		if !ok || repos.Packages == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := r.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, portalTokenTransaction{r, repos.Packages, repos.Audit})
	}))
}

type portalTokenTransaction struct {
	portalTokenRepository
	packages app.PackageRepository
	audit    app.AuditRepository
}

func (t portalTokenTransaction) ReadPortalAccessForToken(ctx context.Context, tenant, id string) (packagedomain.CustomerPortalAccess, error) {
	v, err := t.portalTokenRepository.ReadPortalAccessForToken(ctx, tenant, id)
	return v, mapPackageAccessWriteError(err)
}
func (t portalTokenTransaction) ReadPortalPackageScope(ctx context.Context, tenant, id string) (packageapp.PortalPackageScope, error) {
	v, err := t.portalTokenRepository.ReadPortalPackageScope(ctx, tenant, id)
	return v, mapPackageAccessWriteError(err)
}
func (t portalTokenTransaction) GetPortalPackageForUpdate(ctx context.Context, tenant, id string) (packagedomain.CustomerSecurityPackage, error) {
	v, err := t.packages.GetCustomerSecurityPackageForUpdate(ctx, tenant, id)
	return packagedomain.CustomerSecurityPackage(v), mapPackageAccessWriteError(err)
}
func (t portalTokenTransaction) UpdatePortalTokenAccess(ctx context.Context, old, v packagedomain.CustomerPortalAccess) error {
	return mapPackageAccessWriteError(t.UpdateFocusedPortalTokenAccess(ctx, old, v))
}
func (t portalTokenTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, e)
}

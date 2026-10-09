package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type customerPackageFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
}
type customerPackageFixtureGuard interface {
	LockCustomerPackageCreationScope(context.Context, string, string, string) error
	GetCustomerPackageRedactionProfile(context.Context, string, string) (packagedomain.RedactionProfile, error)
}
type customerPackageFixtureTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type customerPackageFixtureTransaction struct {
	packages app.PackageRepository
	guard    customerPackageFixtureGuard
	audit    app.AuditRepository
	readOnly bool
}
type customerPackageFixtureSnapshot struct {
	catalogFixtureCommands
	readOnly bool
}
type customerPackageFixtureHasher struct{ readOnly bool }

func (f customerPackageFixtureSnapshot) ReadCustomerPackageCreationSnapshot(ctx context.Context, tenant, product, release, profile string, at time.Time) (packageapp.CustomerPackageCreationSnapshot, error) {
	if f.readOnly {
		panic("customer preflight read a manifest snapshot")
	}
	var out packageapp.CustomerPackageCreationSnapshot
	if ctx == nil {
		return out, packageapp.ErrValidation
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Packages.(packageapp.CustomerPackageSnapshotReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadCustomerPackageCreationSnapshot(ctx, tenant, product, release, profile, at)
		return err
	})
	if err != nil {
		return packageapp.CustomerPackageCreationSnapshot{}, portalFixtureError(err)
	}
	return out, nil
}
func (f customerPackageFixtureTransactions) ExecuteCustomerPackageCreation(ctx context.Context, run func(context.Context, packageapp.CustomerPackageCreationTransaction) error) error {
	if ctx == nil || run == nil {
		return packageapp.ErrValidation
	}
	return portalFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		guard, ok := r.Packages.(customerPackageFixtureGuard)
		if !ok || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, customerPackageFixtureTransaction{r.Packages, guard, r.Audit, f.readOnly})
	}))
}
func (t customerPackageFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	if err := packagequery.NewCustomerPackageCreationAuthorizer().Authorize(ctx, a, r); err != nil {
		return err
	}
	return portalFixtureError(t.guard.LockCustomerPackageCreationScope(ctx, a.TenantID, r.Resources.ProductID, r.Resources.ReleaseID))
}
func (t customerPackageFixtureTransaction) GetRedactionProfile(ctx context.Context, tenant, id string) (packagedomain.RedactionProfile, error) {
	v, err := t.guard.GetCustomerPackageRedactionProfile(ctx, tenant, id)
	return v, portalFixtureError(err)
}
func (t customerPackageFixtureTransaction) InsertCustomerSecurityPackage(ctx context.Context, v packagedomain.CustomerSecurityPackage) error {
	if t.readOnly {
		panic("customer preflight inserted package")
	}
	return portalFixtureError(t.packages.InsertCustomerSecurityPackage(ctx, domain.CustomerSecurityPackage(v)))
}
func (t customerPackageFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if t.readOnly {
		panic("customer preflight appended audit")
	}
	v, err := (governanceFixtureTransaction{audit: t.audit}).AppendAudit(ctx, e)
	return v, portalFixtureError(err)
}
func (f customerPackageFixtureHasher) HashPackageManifest(ctx context.Context, manifest map[string]any) (string, error) {
	if f.readOnly {
		panic("customer preflight hashed manifest")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return application.NormalizedJSONHash(manifest)
}
func (f customerPackageFixtureCommands) commands(readOnly bool) (*packageapp.CustomerPackageCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return packageapp.NewCustomerPackageCommands(packageapp.CustomerPackageCommandConfig{Reader: customerPackageFixtureSnapshot{f.catalogFixtureCommands, readOnly}, Transactions: customerPackageFixtureTransactions{f.catalogFixtureCommands, readOnly}, Authorizer: packagequery.NewCustomerPackageCreationAuthorizer(), Hasher: customerPackageFixtureHasher{readOnly}, Clock: clock, IDs: ids})
}
func (f customerPackageFixtureCommands) AuthorizeCreateCustomerSecurityPackage(ctx context.Context, a domain.Actor, in packageapp.CreateCustomerPackageInput) error {
	c, err := f.commands(true)
	if err != nil {
		return err
	}
	return portalFixtureError(c.AuthorizeCreateCustomerSecurityPackage(ctx, a, in))
}
func (f customerPackageFixtureCommands) CreateCustomerSecurityPackage(ctx context.Context, a domain.Actor, in packageapp.CreateCustomerPackageInput) (packagedomain.CustomerSecurityPackage, error) {
	c, err := f.commands(false)
	if err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	v, err := c.CreateCustomerSecurityPackage(ctx, a, in)
	return v, mapCustomerPackageAccessError(portalFixtureError(err))
}

var _ CustomerPackageCreationCommands = customerPackageFixtureCommands{}

func createCustomerPackageFixture(ctx context.Context, ledger *app.Ledger, a domain.Actor, in packageapp.CreateCustomerPackageInput) (domain.CustomerSecurityPackage, error) {
	v, err := (customerPackageFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}).CreateCustomerSecurityPackage(ctx, a, in)
	return domain.CustomerSecurityPackage(v), err
}

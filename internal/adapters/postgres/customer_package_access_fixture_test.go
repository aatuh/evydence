package postgres

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

// Recovery tests exercise the focused access service over restored repositories,
// not an aggregate reconstruction or a compatibility package cache.
func newCustomerPackageAccessFixture(store *Store) (*packageapp.AccessCommands, error) {
	return packageapp.NewAccessCommands(packageapp.AccessCommandConfig{Transactions: postgresCustomerFixture{store}, Authorizer: packagequery.NewPackageAccessAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

func (f postgresCustomerFixture) ExecutePackageAccess(ctx context.Context, run func(context.Context, packageapp.AccessTransaction) error) error {
	return app.ExecuteUnitOfWork(ctx, f.store, func(ctx context.Context, r app.Repositories) error {
		if r.Packages == nil || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, postgresCustomerAccessFixtureTransaction{r.Packages, r.Audit})
	})
}

type postgresCustomerAccessFixtureTransaction struct {
	packages app.PackageRepository
	audit    app.AuditRepository
}

func (t postgresCustomerAccessFixtureTransaction) GetCustomerSecurityPackageForUpdate(ctx context.Context, tenant, id string) (packagedomain.CustomerSecurityPackage, error) {
	p, err := t.packages.GetCustomerSecurityPackageForUpdate(ctx, tenant, id)
	return packagedomain.CustomerSecurityPackage(p), err
}
func (t postgresCustomerAccessFixtureTransaction) UpdateCustomerSecurityPackageAccess(ctx context.Context, previous, current packagedomain.CustomerSecurityPackage) error {
	return t.packages.UpdateCustomerSecurityPackageAccess(ctx, domain.CustomerSecurityPackage(previous), domain.CustomerSecurityPackage(current))
}
func (t postgresCustomerAccessFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewPackageAccessAuthorizer().Authorize(ctx, a, r)
}
func (t postgresCustomerAccessFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return (postgresCustomerFixtureTransaction{audit: t.audit}).AppendAudit(ctx, e)
}

package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// Test-only composition over the current transaction repositories. Ledger
// supplies the existing fixture unit-of-work context, never package caches.
type customerAccessFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
}
type customerAccessFixtureTransactions struct{ catalogFixtureCommands }
type customerAccessFixtureTransaction struct {
	packages app.PackageRepository
	audit    app.AuditRepository
}

func (f customerAccessFixtureTransactions) ExecutePackageAccess(ctx context.Context, run func(context.Context, packageapp.AccessTransaction) error) error {
	if ctx == nil || run == nil {
		return packageapp.ErrValidation
	}
	ledger := f.commandLedger(ctx)
	if ledger == nil {
		return packageapp.ErrValidation
	}
	return portalFixtureError(ledger.ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		if r.Packages == nil || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, customerAccessFixtureTransaction{r.Packages, r.Audit})
	}))
}
func (t customerAccessFixtureTransaction) GetCustomerSecurityPackageForUpdate(ctx context.Context, tenant, id string) (packagedomain.CustomerSecurityPackage, error) {
	p, err := t.packages.GetCustomerSecurityPackageForUpdate(ctx, tenant, id)
	return packagedomain.CustomerSecurityPackage(p), portalFixtureError(err)
}
func (t customerAccessFixtureTransaction) UpdateCustomerSecurityPackageAccess(ctx context.Context, previous, current packagedomain.CustomerSecurityPackage) error {
	return portalFixtureError(t.packages.UpdateCustomerSecurityPackageAccess(ctx, domain.CustomerSecurityPackage(previous), domain.CustomerSecurityPackage(current)))
}
func (t customerAccessFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewPackageAccessAuthorizer().Authorize(ctx, a, r)
}
func (t customerAccessFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := (governanceFixtureTransaction{audit: t.audit}).AppendAudit(ctx, e)
	return v, portalFixtureError(err)
}
func (f customerAccessFixtureCommands) commands() (*packageapp.AccessCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	if f.clock != nil {
		clock = f.clock
	}
	return packageapp.NewAccessCommands(packageapp.AccessCommandConfig{Transactions: customerAccessFixtureTransactions{f.catalogFixtureCommands}, Authorizer: packagequery.NewPackageAccessAuthorizer(), Clock: clock, IDs: ids})
}
func (f customerAccessFixtureCommands) AccessCustomerSecurityPackage(ctx context.Context, a domain.Actor, id string) (packagedomain.CustomerSecurityPackage, error) {
	c, err := f.commands()
	if err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	v, err := c.AccessCustomerSecurityPackage(ctx, a, id)
	return v, mapCustomerPackageAccessError(portalFixtureError(err))
}
func (f customerAccessFixtureCommands) SecurityReviewPackageReport(ctx context.Context, a domain.Actor, id string) (packagedomain.SecurityReviewPackageReport, error) {
	c, err := f.commands()
	if err != nil {
		return packagedomain.SecurityReviewPackageReport{}, err
	}
	v, err := c.SecurityReviewPackageReport(ctx, a, id)
	return v, mapCustomerPackageAccessError(portalFixtureError(err))
}

var _ CustomerPackageAccessCommands = customerAccessFixtureCommands{}

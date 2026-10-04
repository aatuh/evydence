package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// The reader must supply a bounded, committed snapshot. This builder does not
// install a Ledger fallback; production route binding waits for its database
// snapshot reader. Write effects already use the native unit of work.
func BuildCustomerPackageCreationCommands(reader packageapp.CustomerPackageSnapshotReader, factory app.UnitOfWorkFactory) (*packageapp.CustomerPackageCommands, error) {
	if reader == nil || factory == nil {
		return nil, errors.New("customer-package snapshot reader and transactions are required")
	}
	return packageapp.NewCustomerPackageCommands(packageapp.CustomerPackageCommandConfig{Reader: reader, Transactions: customerPackageCreationTransactions{factory}, Authorizer: packagequery.NewCustomerPackageCreationAuthorizer(), Hasher: packageCanonicalizer{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type customerPackageCreationRepository interface {
	LockCustomerPackageCreationScope(context.Context, string, string, string) error
	GetCustomerPackageRedactionProfile(context.Context, string, string) (packagedomain.RedactionProfile, error)
}
type customerPackageCreationTransactions struct{ factory app.UnitOfWorkFactory }

func (t customerPackageCreationTransactions) ExecuteCustomerPackageCreation(ctx context.Context, fn func(context.Context, packageapp.CustomerPackageCreationTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		guard, ok := repos.Packages.(customerPackageCreationRepository)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, customerPackageCreationTransaction{repos.Packages, guard, repos.Audit})
	}))
}

type customerPackageCreationTransaction struct {
	packages app.PackageRepository
	guard    customerPackageCreationRepository
	audit    app.AuditRepository
}

func (t customerPackageCreationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if err := packagequery.NewCustomerPackageCreationAuthorizer().Authorize(ctx, a, r); err != nil {
		return err
	}
	return mapPackageAccessWriteError(t.guard.LockCustomerPackageCreationScope(ctx, a.TenantID, r.Resources.ProductID, r.Resources.ReleaseID))
}
func (t customerPackageCreationTransaction) GetRedactionProfile(ctx context.Context, tenant, id string) (packagedomain.RedactionProfile, error) {
	v, err := t.guard.GetCustomerPackageRedactionProfile(ctx, tenant, id)
	return v, mapPackageAccessWriteError(err)
}
func (t customerPackageCreationTransaction) InsertCustomerSecurityPackage(ctx context.Context, v packagedomain.CustomerSecurityPackage) error {
	return mapPackageAccessWriteError(t.packages.InsertCustomerSecurityPackage(ctx, packageAccessToLegacy(v)))
}
func (t customerPackageCreationTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, v)
}

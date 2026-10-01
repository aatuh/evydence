package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// BuildCustomerPackageAccessCommands binds single-package access and reporting
// directly to transaction-scoped repositories, without constructing a Ledger.
func BuildCustomerPackageAccessCommands(factory app.UnitOfWorkFactory) (*packageapp.AccessCommands, error) {
	if factory == nil {
		return nil, errors.New("package access transactions are required")
	}
	return packageapp.NewAccessCommands(packageapp.AccessCommandConfig{Transactions: packageAccessTransactions{factory: factory}, Authorizer: packagequery.NewPackageAccessAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type packageAccessTransactions struct{ factory app.UnitOfWorkFactory }

func (t packageAccessTransactions) ExecutePackageAccess(ctx context.Context, command func(context.Context, packageapp.AccessTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repositories app.Repositories) error {
		if repositories.Packages == nil || repositories.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, packageAccessTransaction{packages: repositories.Packages, audit: repositories.Audit})
	}))
}

type packageAccessTransaction struct {
	packages app.PackageRepository
	audit    app.AuditRepository
}

func (t packageAccessTransaction) GetCustomerSecurityPackageForUpdate(ctx context.Context, tenantID, id string) (packagedomain.CustomerSecurityPackage, error) {
	pkg, err := t.packages.GetCustomerSecurityPackageForUpdate(ctx, tenantID, id)
	if err != nil {
		return packagedomain.CustomerSecurityPackage{}, mapPackageAccessWriteError(err)
	}
	return packagedomain.CustomerSecurityPackage{ID: pkg.ID, TenantID: pkg.TenantID, ProductID: pkg.ProductID, ReleaseID: pkg.ReleaseID, RedactionProfileID: pkg.RedactionProfileID, Title: pkg.Title, State: pkg.State, Manifest: pkg.Manifest, ManifestHash: pkg.ManifestHash, DistributionWatermark: pkg.DistributionWatermark, ExpiresAt: pkg.ExpiresAt, AccessCount: pkg.AccessCount, SchemaVersion: pkg.SchemaVersion, CreatedAt: pkg.CreatedAt}, nil
}

func (t packageAccessTransaction) UpdateCustomerSecurityPackageAccess(ctx context.Context, previous, current packagedomain.CustomerSecurityPackage) error {
	return mapPackageAccessWriteError(t.packages.UpdateCustomerSecurityPackageAccess(ctx, packageAccessToLegacy(previous), packageAccessToLegacy(current)))
}

func packageAccessToLegacy(pkg packagedomain.CustomerSecurityPackage) domain.CustomerSecurityPackage {
	return domain.CustomerSecurityPackage{ID: pkg.ID, TenantID: pkg.TenantID, ProductID: pkg.ProductID, ReleaseID: pkg.ReleaseID, RedactionProfileID: pkg.RedactionProfileID, Title: pkg.Title, State: pkg.State, Manifest: pkg.Manifest, ManifestHash: pkg.ManifestHash, DistributionWatermark: pkg.DistributionWatermark, ExpiresAt: pkg.ExpiresAt, AccessCount: pkg.AccessCount, SchemaVersion: pkg.SchemaVersion, CreatedAt: pkg.CreatedAt}
}

func (t packageAccessTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return packagequery.NewPackageAccessAuthorizer().Authorize(ctx, actor, request)
}
func (t packageAccessTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, event)
}

func appendPackageAudit(ctx context.Context, audit app.AuditRepository, event application.AuditEvent) (application.AuditReceipt, error) {
	entry, err := audit.Append(ctx, domain.AuditChainEntry{ID: event.ID, TenantID: event.TenantID, EntryType: event.EntryType, SubjectType: event.SubjectType, SubjectID: event.SubjectID, ActorType: event.ActorType, ActorID: event.ActorID, OccurredAt: event.OccurredAt, PayloadHash: event.PayloadHash, SchemaVersion: domain.AuditChainEntrySchemaVersion})
	if err != nil {
		return application.AuditReceipt{}, mapPackageAccessWriteError(err)
	}
	return application.AuditReceipt{ID: entry.ID}, nil
}

func mapPackageAccessWriteError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return packageapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return packageapp.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return packageapp.ErrConflict
	default:
		return err
	}
}

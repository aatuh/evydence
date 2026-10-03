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

// BuildBundleImportCommand records validated manifest receipts without a
// Ledger, signing provider, evidence reader, or package projection cache.
func BuildBundleImportCommand(factory app.UnitOfWorkFactory) (*packageapp.ImportCommands, error) {
	if factory == nil {
		return nil, errors.New("bundle import transactions are required")
	}
	return packageapp.NewImportCommands(packageapp.ImportCommandConfig{Transactions: bundleImportTransactions{factory}, Authorizer: packagequery.NewBundleImportAuthorizer(), Hasher: packageCanonicalizer{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type bundleImportTransactions struct{ factory app.UnitOfWorkFactory }

func (t bundleImportTransactions) ExecuteBundleImport(ctx context.Context, command func(context.Context, packageapp.ImportTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		if repos.Packages == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, bundleImportTransaction{repos.Packages, repos.Audit})
	}))
}

type bundleImportTransaction struct {
	packages app.PackageRepository
	audit    app.AuditRepository
}

func (t bundleImportTransaction) InsertEvidenceBundleImport(ctx context.Context, record packagedomain.EvidenceBundleImport) error {
	return mapPackageAccessWriteError(t.packages.InsertEvidenceBundleImport(ctx, domain.EvidenceBundleImport{ID: record.ID, TenantID: record.TenantID, BundleHash: record.BundleHash, Result: record.Result, ImportedCount: record.ImportedCount, SchemaVersion: record.SchemaVersion, CreatedAt: record.CreatedAt}))
}
func (t bundleImportTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return packagequery.NewBundleImportAuthorizer().Authorize(ctx, actor, request)
}
func (t bundleImportTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, event)
}

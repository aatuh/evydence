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

// Test-only adapters over current repositories. The ambient fixture context
// retains isolated HTTP replay; no template/tenant Ledger cache is consulted.
type reportTemplateFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
}
type bundleImportFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
}
type reportImportFixtureTransactions struct{ catalogFixtureCommands }
type reportTemplateFixtureTransaction struct {
	packages app.PackageRepository
	audit    app.AuditRepository
	guard    packageapp.ReportTemplateScopeLocker
}
type bundleImportFixtureTransaction struct {
	packages app.PackageRepository
	audit    app.AuditRepository
	guard    packageapp.BundleImportScopeLocker
}

func (f reportImportFixtureTransactions) ExecuteReportTemplate(ctx context.Context, run func(context.Context, packageapp.TemplateTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return packageapp.ErrValidation
	}
	return portalFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		guard, ok := r.Packages.(packageapp.ReportTemplateScopeLocker)
		if !ok || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, reportTemplateFixtureTransaction{r.Packages, r.Audit, guard})
	}))
}
func (f reportImportFixtureTransactions) ExecuteBundleImport(ctx context.Context, run func(context.Context, packageapp.ImportTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return packageapp.ErrValidation
	}
	return portalFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		guard, ok := r.Packages.(packageapp.BundleImportScopeLocker)
		if !ok || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, bundleImportFixtureTransaction{r.Packages, r.Audit, guard})
	}))
}
func (t reportTemplateFixtureTransaction) LockReportTemplateTenant(ctx context.Context, tenant string) error {
	return portalFixtureError(t.guard.LockReportTemplateTenant(ctx, tenant))
}
func (t reportTemplateFixtureTransaction) LockReportTemplateIdentity(ctx context.Context, tenant, id string) error {
	return portalFixtureError(t.guard.LockReportTemplateIdentity(ctx, tenant, id))
}
func (t reportTemplateFixtureTransaction) GetCustomReportTemplate(ctx context.Context, tenant, id string) (packagedomain.CustomReportTemplate, error) {
	v, err := t.packages.GetCustomReportTemplate(ctx, tenant, id)
	return packagedomain.CustomReportTemplate(v), portalFixtureError(err)
}
func (t reportTemplateFixtureTransaction) InsertCustomReportTemplate(ctx context.Context, v packagedomain.CustomReportTemplate) error {
	return portalFixtureError(t.packages.InsertCustomReportTemplate(ctx, domain.CustomReportTemplate(v)))
}
func (t reportTemplateFixtureTransaction) InsertRenderedCustomReport(ctx context.Context, v packagedomain.RenderedCustomReport) error {
	return portalFixtureError(t.packages.InsertRenderedCustomReport(ctx, domain.RenderedCustomReport(v)))
}
func (t reportTemplateFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewTemplateAuthorizer().Authorize(ctx, a, r)
}
func (t reportTemplateFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := (governanceFixtureTransaction{audit: t.audit}).AppendAudit(ctx, e)
	return v, portalFixtureError(err)
}
func (t bundleImportFixtureTransaction) LockBundleImportTenant(ctx context.Context, tenant string) error {
	return portalFixtureError(t.guard.LockBundleImportTenant(ctx, tenant))
}
func (t bundleImportFixtureTransaction) InsertEvidenceBundleImport(ctx context.Context, v packagedomain.EvidenceBundleImport) error {
	return portalFixtureError(t.packages.InsertEvidenceBundleImport(ctx, domain.EvidenceBundleImport(v)))
}
func (t bundleImportFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewBundleImportAuthorizer().Authorize(ctx, a, r)
}
func (t bundleImportFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := (governanceFixtureTransaction{audit: t.audit}).AppendAudit(ctx, e)
	return v, portalFixtureError(err)
}

type reportImportFixtureHasher struct{}

func (reportImportFixtureHasher) HashReportOutput(ctx context.Context, output map[string]any) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	for _, v := range output {
		if _, ok := v.(string); !ok {
			return "", packageapp.ErrValidation
		}
	}
	return application.NormalizedJSONHash(output)
}
func (reportImportFixtureHasher) HashPackageManifest(ctx context.Context, manifest map[string]any) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return application.NormalizedJSONHash(manifest)
}

func (f reportTemplateFixtureCommands) commands() (*packageapp.TemplateCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	if f.clock != nil {
		clock = f.clock
	}
	return packageapp.NewTemplateCommands(packageapp.TemplateCommandConfig{Transactions: reportImportFixtureTransactions{f.catalogFixtureCommands}, Authorizer: packagequery.NewTemplateAuthorizer(), Hasher: reportImportFixtureHasher{}, Clock: clock, IDs: ids})
}
func (f reportTemplateFixtureCommands) AuthorizeReportTemplateCreation(ctx context.Context, a domain.Actor, in packageapp.CreateReportTemplateInput) error {
	c, err := f.commands()
	if err != nil {
		return err
	}
	return mapCustomerPackageAccessError(portalFixtureError(c.AuthorizeReportTemplateCreation(ctx, a, in)))
}
func (f reportTemplateFixtureCommands) AuthorizeReportRendering(ctx context.Context, a domain.Actor, in packageapp.RenderReportInput) error {
	c, err := f.commands()
	if err != nil {
		return err
	}
	return mapCustomerPackageAccessError(portalFixtureError(c.AuthorizeReportRendering(ctx, a, in)))
}
func (f reportTemplateFixtureCommands) CreateCustomReportTemplate(ctx context.Context, a domain.Actor, in packageapp.CreateReportTemplateInput) (packagedomain.CustomReportTemplate, error) {
	c, err := f.commands()
	if err != nil {
		return packagedomain.CustomReportTemplate{}, err
	}
	v, err := c.CreateCustomReportTemplate(ctx, a, in)
	return v, mapCustomerPackageAccessError(portalFixtureError(err))
}
func (f reportTemplateFixtureCommands) RenderCustomReport(ctx context.Context, a domain.Actor, in packageapp.RenderReportInput) (packagedomain.RenderedCustomReport, error) {
	c, err := f.commands()
	if err != nil {
		return packagedomain.RenderedCustomReport{}, err
	}
	v, err := c.RenderCustomReport(ctx, a, in)
	return v, mapCustomerPackageAccessError(portalFixtureError(err))
}
func (f bundleImportFixtureCommands) commands() (*packageapp.ImportCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	if f.clock != nil {
		clock = f.clock
	}
	return packageapp.NewImportCommands(packageapp.ImportCommandConfig{Transactions: reportImportFixtureTransactions{f.catalogFixtureCommands}, Authorizer: packagequery.NewBundleImportAuthorizer(), Hasher: reportImportFixtureHasher{}, Clock: clock, IDs: ids})
}
func (f bundleImportFixtureCommands) AuthorizeBundleImport(ctx context.Context, a domain.Actor, b packagedomain.EvidenceBundle) error {
	c, err := f.commands()
	if err != nil {
		return err
	}
	return mapCustomerPackageAccessError(portalFixtureError(c.AuthorizeBundleImport(ctx, a, b)))
}
func (f bundleImportFixtureCommands) ImportEvidenceBundle(ctx context.Context, a domain.Actor, b packagedomain.EvidenceBundle) (packagedomain.EvidenceBundleImport, error) {
	c, err := f.commands()
	if err != nil {
		return packagedomain.EvidenceBundleImport{}, err
	}
	v, err := c.ImportEvidenceBundle(ctx, a, b)
	return v, mapCustomerPackageAccessError(portalFixtureError(err))
}

var (
	_ ReportTemplateCommands = reportTemplateFixtureCommands{}
	_ BundleImportCommand    = bundleImportFixtureCommands{}
)

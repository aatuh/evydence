package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func (l *Ledger) CreateReleaseBundle(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseBundle, error) {
	value, err := l.packageCommands.CreateReleaseBundle(ctx, actor, releaseID)
	return domain.ReleaseBundleFromContextModel(value), fromPackageContextError(err)
}

// Explicit local-memory replay uses current scoped access without generating
// a manifest, signature, audit entry or worker job. The PostgreSQL runtime
// binds the native Package command guard instead of this compatibility helper.
func (l *Ledger) AuthorizeReleaseBundleCreation(ctx context.Context, a domain.Actor, raw string) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeBundleWrite); err != nil {
		return err
	}
	id, err := packageapp.NormalizeReleaseBundleID(raw)
	if err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.authorizeProductReleaseLocked(a, ScopeBundleWrite, "", id)
	return err
}

func (l *Ledger) CreateRedactionProfile(ctx context.Context, actor domain.Actor, in CreateRedactionProfileInput) (domain.RedactionProfile, error) {
	value, err := l.packageCommands.CreateRedactionProfile(ctx, actor, packageapp.CreateRedactionProfileInput{
		Name: in.Name, Description: in.Description, Preset: in.Preset,
		AllowedTypes: append([]string(nil), in.AllowedTypes...), ExcludedFields: append([]string(nil), in.ExcludedFields...),
	})
	return redactionProfileFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) CreateCustomerSecurityPackage(ctx context.Context, actor domain.Actor, in CreateCustomerPackageInput) (domain.CustomerSecurityPackage, error) {
	value, err := l.packageCommands.CreateCustomerSecurityPackage(ctx, actor, packageapp.CreateCustomerPackageInput{
		ProductID: in.ProductID, ReleaseID: in.ReleaseID, RedactionProfileID: in.RedactionProfileID,
		Title: in.Title, ExpiresAt: in.ExpiresAt,
	})
	return customerSecurityPackageFromContext(value), fromPackageContextError(err)
}

func (l *Ledger) AccessCustomerSecurityPackage(ctx context.Context, actor domain.Actor, id string) (domain.CustomerSecurityPackage, error) {
	value, err := l.packageCommands.AccessCustomerSecurityPackage(ctx, actor, id)
	return customerSecurityPackageFromContext(value), fromPackageContextError(err)
}

func (l *Ledger) CRAReadinessHTMLPackage(ctx context.Context, actor domain.Actor, productID, releaseID string) (domain.HTMLReportPackage, error) {
	value, err := l.packageCommands.CRAReadinessHTMLPackage(ctx, actor, productID, releaseID)
	return htmlReportPackageFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) CreateCustomReportTemplate(ctx context.Context, actor domain.Actor, in CreateReportTemplateInput) (domain.CustomReportTemplate, error) {
	value, err := l.packageCommands.CreateCustomReportTemplate(ctx, actor, packageapp.CreateReportTemplateInput{
		Name: in.Name, Version: in.Version, ReportType: in.ReportType,
		AllowedFields: append([]string(nil), in.AllowedFields...), Template: in.Template,
	})
	return customReportTemplateFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) RenderCustomReport(ctx context.Context, actor domain.Actor, in RenderReportInput) (domain.RenderedCustomReport, error) {
	value, err := l.packageCommands.RenderCustomReport(ctx, actor, packageapp.RenderReportInput{
		TemplateID: in.TemplateID, SubjectType: in.SubjectType, SubjectID: in.SubjectID,
	})
	return renderedCustomReportFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) ExportEvidenceBundle(ctx context.Context, actor domain.Actor, releaseID string, evidenceIDs []string) (domain.EvidenceBundle, error) {
	value, err := l.packageCommands.ExportEvidenceBundle(ctx, actor, releaseID, evidenceIDs)
	return evidenceBundleFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) ImportEvidenceBundle(ctx context.Context, actor domain.Actor, bundle domain.EvidenceBundle) (domain.EvidenceBundleImport, error) {
	value, err := l.packageCommands.ImportEvidenceBundle(ctx, actor, evidenceBundleToPackageContext(bundle))
	return evidenceBundleImportFromPackageContext(value), fromPackageContextError(err)
}

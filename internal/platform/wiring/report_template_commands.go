package wiring

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func BuildReportTemplateCommands(factory app.UnitOfWorkFactory) (*packageapp.TemplateCommands, error) {
	if factory == nil {
		return nil, errors.New("report template transactions are required")
	}
	return packageapp.NewTemplateCommands(packageapp.TemplateCommandConfig{Transactions: reportTemplateTransactions{factory}, Authorizer: packagequery.NewTemplateAuthorizer(), Hasher: reportOutputHasher{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type reportTemplateTransactions struct{ factory app.UnitOfWorkFactory }

func (t reportTemplateTransactions) ExecuteReportTemplate(ctx context.Context, command func(context.Context, packageapp.TemplateTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		if repos.Packages == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, reportTemplateTransaction{repos.Packages, repos.Audit})
	}))
}

type reportTemplateTransaction struct {
	packages app.PackageRepository
	audit    app.AuditRepository
}

func (t reportTemplateTransaction) GetCustomReportTemplate(ctx context.Context, tenantID, id string) (packagedomain.CustomReportTemplate, error) {
	value, err := t.packages.GetCustomReportTemplate(ctx, tenantID, id)
	return packagedomain.CustomReportTemplate{ID: value.ID, TenantID: value.TenantID, Name: value.Name, Version: value.Version, ReportType: value.ReportType, AllowedFields: value.AllowedFields, Template: value.Template, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}, mapPackageAccessWriteError(err)
}
func (t reportTemplateTransaction) InsertCustomReportTemplate(ctx context.Context, value packagedomain.CustomReportTemplate) error {
	return mapPackageAccessWriteError(t.packages.InsertCustomReportTemplate(ctx, domain.CustomReportTemplate{ID: value.ID, TenantID: value.TenantID, Name: value.Name, Version: value.Version, ReportType: value.ReportType, AllowedFields: value.AllowedFields, Template: value.Template, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}))
}
func (t reportTemplateTransaction) InsertRenderedCustomReport(ctx context.Context, value packagedomain.RenderedCustomReport) error {
	return mapPackageAccessWriteError(t.packages.InsertRenderedCustomReport(ctx, domain.RenderedCustomReport{ID: value.ID, TenantID: value.TenantID, TemplateID: value.TemplateID, SubjectType: value.SubjectType, SubjectID: value.SubjectID, Output: value.Output, Hash: value.Hash, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}))
}
func (t reportTemplateTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return packagequery.NewTemplateAuthorizer().Authorize(ctx, actor, request)
}
func (t reportTemplateTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, event)
}

type reportOutputHasher struct{}

func (reportOutputHasher) HashReportOutput(ctx context.Context, output map[string]any) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// This version's output is string metadata only. Go's sorted JSON map
	// keys and escaping match the legacy normalized-JSON byte representation.
	for _, value := range output {
		if _, ok := value.(string); !ok {
			return "", packageapp.ErrValidation
		}
	}
	body, err := json.Marshal(output)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(body)), nil
}

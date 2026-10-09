package wiring

import (
	"context"
	"crypto/sha256"
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

type craReadinessQuery interface {
	CRAReadiness(context.Context, identitydomain.Actor, string, string) (packagedomain.CRAReadinessReport, error)
}

// BuildHTMLReportCommands reuses the canonical durable CRA query and writes
// only the generated report and audit entry through one unit of work.
func BuildHTMLReportCommands(query craReadinessQuery, factory app.UnitOfWorkFactory) (*packageapp.HTMLReportCommands, error) {
	if query == nil || factory == nil {
		return nil, errors.New("HTML report query and transactions are required")
	}
	return packageapp.NewHTMLReportCommands(packageapp.HTMLReportCommandConfig{Reader: craHTMLReportReader{query}, Transactions: htmlReportTransactions{factory}, Authorizer: packagequery.NewReportAuthorizer(), Hasher: htmlReportBytesHasher{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type craHTMLReportReader struct{ query craReadinessQuery }

func (r craHTMLReportReader) ReadCRAReadinessHTMLSnapshot(ctx context.Context, actor identitydomain.Actor, productID, releaseID string) (packageapp.CRAReadinessHTMLSnapshot, error) {
	report, err := r.query.CRAReadiness(ctx, actor, productID, releaseID)
	if err != nil {
		return packageapp.CRAReadinessHTMLSnapshot{}, err
	}
	return packageapp.CRAReadinessHTMLSnapshot{SnapshotVersion: packageapp.CRAReadinessHTMLSnapshotVersion, TenantID: actor.TenantID, ProductID: report.ProductID, ReleaseID: report.ReleaseID, Result: report.Result, Limitations: report.Limitations}, nil
}

type htmlReportTransactions struct{ factory app.UnitOfWorkFactory }

func (t htmlReportTransactions) ExecuteHTMLReport(ctx context.Context, command func(context.Context, packageapp.HTMLReportTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		if repos.Packages == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, htmlReportTransaction{repos.Packages, repos.Audit})
	}))
}

type htmlReportTransaction struct {
	packages app.PackageRepository
	audit    app.AuditRepository
}

func (t htmlReportTransaction) InsertHTMLReportPackage(ctx context.Context, report packagedomain.HTMLReportPackage) error {
	return mapPackageAccessWriteError(t.packages.InsertHTMLReportPackage(ctx, domain.HTMLReportPackage{ID: report.ID, TenantID: report.TenantID, ReportType: report.ReportType, ProductID: report.ProductID, ReleaseID: report.ReleaseID, HTML: report.HTML, Hash: report.Hash, SchemaVersion: report.SchemaVersion, CreatedAt: report.CreatedAt}))
}
func (t htmlReportTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return packagequery.NewReportAuthorizer().Authorize(ctx, actor, request)
}
func (t htmlReportTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, event)
}

type htmlReportBytesHasher struct{}

func (htmlReportBytesHasher) HashPackageBytes(ctx context.Context, body []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(body)), nil
}

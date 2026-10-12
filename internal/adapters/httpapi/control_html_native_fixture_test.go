package httpapi

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// HTML consumes the focused CRA snapshot, not the retired control inventories.
// This mirrors native composition: one committed read, then report/audit writes.
type controlHTMLFixture struct{ catalogFixtureCommands }
type controlHTMLFixtureTransaction struct{ repos app.Repositories }

func (f controlHTMLFixture) ReadCRAReadinessHTMLSnapshot(ctx context.Context, a domain.Actor, product, release string) (packageapp.CRAReadinessHTMLSnapshot, error) {
	report, err := (packageCoverageFixture{catalogFixtureCommands: f.catalogFixtureCommands}).CRAReadiness(ctx, a, product, release)
	if err != nil {
		return packageapp.CRAReadinessHTMLSnapshot{}, err
	}
	return packageapp.CRAReadinessHTMLSnapshot{SnapshotVersion: packageapp.CRAReadinessHTMLSnapshotVersion, TenantID: a.TenantID, ProductID: report.ProductID, ReleaseID: report.ReleaseID, Result: report.Result, Limitations: report.Limitations}, nil
}
func (f controlHTMLFixture) ExecuteHTMLReport(ctx context.Context, run func(context.Context, packageapp.HTMLReportTransaction) error) error {
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		if r.Packages == nil || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, controlHTMLFixtureTransaction{r})
	})
}
func (tx controlHTMLFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewReportAuthorizer().Authorize(ctx, a, r)
}
func (tx controlHTMLFixtureTransaction) InsertHTMLReportPackage(ctx context.Context, v packagedomain.HTMLReportPackage) error {
	return tx.repos.Packages.InsertHTMLReportPackage(ctx, domain.HTMLReportPackage(v))
}
func (tx controlHTMLFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return (governanceFixtureTransaction{audit: tx.repos.Audit}).AppendAudit(ctx, e)
}
func (f packageFixtureCommands) nativeHTML() (*packageapp.HTMLReportCommands, error) {
	ports := controlHTMLFixture(f)
	return packageapp.NewHTMLReportCommands(packageapp.HTMLReportCommandConfig{Reader: ports, Transactions: ports, Authorizer: packagequery.NewReportAuthorizer(), Hasher: pdfFixtureNativeHasher{}, Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID)})
}

type controlHTMLFailureFactory struct {
	base app.UnitOfWorkFactory
	fail bool
}
type controlHTMLFailureUnit struct{ app.UnitOfWork }
type controlHTMLFailureRecords struct {
	app.PackageRepository
	packagequery.ControlCoverageReader
}

func (f *controlHTMLFailureFactory) BeginUnitOfWork(ctx context.Context) (app.UnitOfWork, error) {
	u, err := f.base.BeginUnitOfWork(ctx)
	if err != nil || !f.fail {
		return u, err
	}
	return controlHTMLFailureUnit{u}, nil
}
func (u controlHTMLFailureUnit) Repositories() app.Repositories {
	r := u.UnitOfWork.Repositories()
	coverage, ok := r.Packages.(packagequery.ControlCoverageReader)
	if !ok {
		panic("HTML failure fixture lost current coverage reader")
	}
	r.Packages = controlHTMLFailureRecords{r.Packages, coverage}
	return r
}
func (r controlHTMLFailureRecords) InsertHTMLReportPackage(ctx context.Context, v domain.HTMLReportPackage) error {
	if err := r.PackageRepository.InsertHTMLReportPackage(ctx, v); err != nil {
		return err
	}
	return errors.New("private HTML failure after report insert")
}
func TestControlHTMLNativeFixtureConsumesCurrentControlsAndRollsBackReportInsertFailure(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedControlFixtureScope(t, ledger, "Owner")
	foreign := seedControlFixtureScope(t, ledger, "Foreign")
	factory := &controlHTMLFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("HTML used cached aggregate report") }})
	f := packageFixtureCommands{catalogFixtureCommands{ledger: rebound}}
	a := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"report:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"report:read"}}}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.CRAReadinessHTMLPackage(t.Context(), a, owner.product.ID, owner.release.ID)
	if err != nil || v.ID == "" || v.TenantID != a.TenantID || v.ProductID != owner.product.ID || v.ReleaseID != owner.release.ID || v.ReportType != "cra_readiness" || v.SchemaVersion != "html-report-package.v1.0.0" || v.CreatedAt.IsZero() || !strings.HasPrefix(v.HTML, "<!doctype html>") || !strings.Contains(v.HTML, "does not prove") || v.Hash != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(v.HTML))) {
		t.Fatal("HTML lost current report/complete DTO/exact-byte hash", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.HTMLReports) != len(before.HTMLReports)+1 || len(after.AuditEntries[a.TenantID]) != len(before.AuditEntries[a.TenantID])+1 || after.HTMLReports[v.ID].HTML != v.HTML {
		t.Fatal("HTML report/audit did not commit together", err)
	}
	entry := after.AuditEntries[a.TenantID][len(after.AuditEntries[a.TenantID])-1]
	if entry.ActorType != "human_user" || entry.ActorID != a.UserID || entry.SubjectID != v.ID || entry.PayloadHash != v.Hash {
		t.Fatal("HTML caller/hash audit lost")
	}
	if _, err := f.CRAReadinessHTMLPackage(t.Context(), owner.actor, foreign.product.ID, foreign.release.ID); err == nil {
		t.Fatal("foreign HTML report accepted")
	}
	a.ResourceGrants = nil
	if _, err := f.CRAReadinessHTMLPackage(t.Context(), a, owner.product.ID, owner.release.ID); err == nil {
		t.Fatal("revoked HTML grant accepted")
	}
	factory.fail = true
	if v, err := f.CRAReadinessHTMLPackage(t.Context(), owner.actor, owner.product.ID, owner.release.ID); err == nil || !reflect.DeepEqual(v, packagedomain.HTMLReportPackage{}) {
		t.Fatal("failed insert exposed generated HTML", err)
	}
	factory.fail = false
	failed, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("failed/denied HTML changed report or audit state", err)
	}
}

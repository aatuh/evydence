package httpapi

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

type releaseBundleFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
}
type releaseBundleFixtureSnapshots struct{ catalogFixtureCommands }
type releaseBundleFixtureSigner struct{ catalogFixtureCommands }
type releaseBundleFixtureTransactions struct{ catalogFixtureCommands }
type releaseBundleFixtureParent interface {
	LockReleaseBundleParent(context.Context, string, string) (string, error)
}
type releaseBundleFixtureKeyValidator interface {
	ValidatePackageSignature(context.Context, domain.Signature, string) error
}
type releaseBundleFixtureFence interface {
	LockAPIKeyCreation(context.Context, string) error
}
type releaseBundleFixtureTransaction struct {
	packages   app.PackageRepository
	parent     releaseBundleFixtureParent
	fence      releaseBundleFixtureFence
	signatures app.SignatureRepository
	validator  releaseBundleFixtureKeyValidator
	audit      app.AuditRepository
	outbox     app.OutboxRepository
}

func (f releaseBundleFixtureSnapshots) ReadReleaseBundleSnapshot(ctx context.Context, tenant, release string, at time.Time) (packageapp.ReleaseBundleSnapshot, error) {
	if ctx == nil || f.commandLedger(ctx) == nil {
		return packageapp.ReleaseBundleSnapshot{}, packageapp.ErrValidation
	}
	var out packageapp.ReleaseBundleSnapshot
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Packages.(packageapp.ReleaseBundleSnapshotReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadReleaseBundleSnapshot(ctx, tenant, release, at)
		return err
	})
	if err != nil {
		return packageapp.ReleaseBundleSnapshot{}, portalFixtureError(err)
	}
	return out, nil
}
func (f releaseBundleFixtureSigner) SignPackage(ctx context.Context, request packageapp.PackageSigningRequest) (packageapp.PackageSignature, error) {
	if ctx == nil || f.commandLedger(ctx) == nil {
		return packageapp.PackageSignature{}, packageapp.ErrValidation
	}
	var out packageapp.PackageSignature
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		signer, ok := r.Signatures.(packageapp.PackageSigner)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = signer.SignPackage(ctx, request)
		return err
	})
	if err != nil {
		return packageapp.PackageSignature{}, portalFixtureError(err)
	}
	return out, nil
}
func (f releaseBundleFixtureTransactions) ExecuteReleaseBundle(ctx context.Context, run func(context.Context, packageapp.ReleaseBundleTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return packageapp.ErrValidation
	}
	return portalFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		parent, owned := r.Packages.(releaseBundleFixtureParent)
		validator, signed := r.Signatures.(releaseBundleFixtureKeyValidator)
		fence, fenced := r.Identity.(releaseBundleFixtureFence)
		if !owned || !signed || !fenced || r.Audit == nil || r.Outbox == nil {
			return app.ErrValidation
		}
		return run(ctx, releaseBundleFixtureTransaction{r.Packages, parent, fence, r.Signatures, validator, r.Audit, r.Outbox})
	}))
}
func (t releaseBundleFixtureTransaction) LockReleaseBundleCreationScope(ctx context.Context, tenant, release string) (string, error) {
	if err := t.fence.LockAPIKeyCreation(ctx, tenant); err != nil {
		return "", portalFixtureError(err)
	}
	product, err := t.parent.LockReleaseBundleParent(ctx, tenant, release)
	return product, portalFixtureError(err)
}
func (t releaseBundleFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	if err := packagequery.NewReleaseBundleAuthorizer().Authorize(ctx, a, r); err != nil {
		return err
	}
	product, err := t.LockReleaseBundleCreationScope(ctx, a.TenantID, r.Resources.ReleaseID)
	if err != nil {
		return err
	}
	if product != r.Resources.ProductID {
		return packageapp.ErrConflict
	}
	return nil
}
func (t releaseBundleFixtureTransaction) InsertReleaseBundleSignature(ctx context.Context, v packageapp.PackageSignature, hash string) error {
	sig := domain.Signature{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, KeyID: v.KeyID, Algorithm: v.Algorithm, Value: v.Value, CreatedAt: v.CreatedAt}
	if err := t.validator.ValidatePackageSignature(ctx, sig, hash); err != nil {
		return portalFixtureError(err)
	}
	return portalFixtureError(t.signatures.InsertSignature(ctx, sig))
}
func (t releaseBundleFixtureTransaction) InsertReleaseBundle(ctx context.Context, v packagedomain.ReleaseBundle) error {
	return portalFixtureError(t.packages.InsertReleaseBundle(ctx, domain.ReleaseBundleFromContextModel(v)))
}
func (t releaseBundleFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := (governanceFixtureTransaction{audit: t.audit}).AppendAudit(ctx, e)
	return v, portalFixtureError(err)
}
func (t releaseBundleFixtureTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	job := app.OutboxJob{ID: e.ID, TenantID: e.TenantID, Kind: e.Kind, SubjectType: e.SubjectType, SubjectID: e.SubjectID, Payload: e.Payload, CreatedAt: e.CreatedAt}
	if err := app.EnsureOutboxDeduplicationKey(&job); err != nil {
		return portalFixtureError(err)
	}
	return portalFixtureError(t.outbox.Enqueue(ctx, job))
}
func (f releaseBundleFixtureCommands) commands() (*packageapp.ReleaseBundleCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	if f.clock != nil {
		clock = f.clock
	}
	return packageapp.NewReleaseBundleCommands(packageapp.ReleaseBundleCommandConfig{Reader: releaseBundleFixtureSnapshots{f.catalogFixtureCommands}, Transactions: releaseBundleFixtureTransactions{f.catalogFixtureCommands}, Signer: releaseBundleFixtureSigner{f.catalogFixtureCommands}, Hasher: reportImportFixtureHasher{}, Authorizer: packagequery.NewReleaseBundleAuthorizer(), Clock: clock, IDs: ids})
}
func (f releaseBundleFixtureCommands) AuthorizeReleaseBundleCreation(ctx context.Context, a domain.Actor, id string) error {
	c, err := f.commands()
	if err != nil {
		return err
	}
	return mapCustomerPackageAccessError(portalFixtureError(c.AuthorizeReleaseBundleCreation(ctx, a, id)))
}
func (f releaseBundleFixtureCommands) CreateReleaseBundle(ctx context.Context, a domain.Actor, id string) (packagedomain.ReleaseBundle, error) {
	c, err := f.commands()
	if err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	v, err := c.CreateReleaseBundle(ctx, a, id)
	return v, mapCustomerPackageAccessError(portalFixtureError(err))
}

var _ ReleaseBundleCommands = releaseBundleFixtureCommands{}

func createReleaseBundleFixture(ctx context.Context, ledger *app.Ledger, a domain.Actor, id string, at time.Time) (domain.ReleaseBundle, error) {
	v, err := (releaseBundleFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: application.ClockFunc(func() time.Time { return at })}).CreateReleaseBundle(ctx, a, id)
	return domain.ReleaseBundleFromContextModel(v), err
}

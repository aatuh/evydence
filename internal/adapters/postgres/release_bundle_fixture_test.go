package postgres

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

// PostgreSQL recovery/concurrency fixtures use the existing focused command,
// native snapshot and local signer. No bundle is published to a Ledger cache.
func createReleaseBundleFixture(ctx context.Context, store *Store, actor domain.Actor, release string) (domain.ReleaseBundle, error) {
	commands, err := packageapp.NewReleaseBundleCommands(packageapp.ReleaseBundleCommandConfig{Reader: store, Signer: store, Transactions: postgresReleaseBundleFixture{store}, Hasher: postgresCustomerFixtureHasher{}, Authorizer: packagequery.NewReleaseBundleAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
	if err != nil {
		return domain.ReleaseBundle{}, err
	}
	v, err := commands.CreateReleaseBundle(ctx, actor, release)
	return domain.ReleaseBundleFromContextModel(v), err
}

type postgresReleaseBundleFixture struct{ store *Store }
type postgresBundleParent interface {
	LockReleaseBundleParent(context.Context, string, string) (string, error)
}
type postgresBundleSignatureValidator interface {
	ValidatePackageSignature(context.Context, domain.Signature, string) error
}
type postgresBundleFence interface {
	LockAPIKeyCreation(context.Context, string) error
}
type postgresBundleTransaction struct {
	packages   app.PackageRepository
	parent     postgresBundleParent
	fence      postgresBundleFence
	signatures app.SignatureRepository
	validator  postgresBundleSignatureValidator
	audit      app.AuditRepository
	outbox     app.OutboxRepository
}

func (f postgresReleaseBundleFixture) ExecuteReleaseBundle(ctx context.Context, run func(context.Context, packageapp.ReleaseBundleTransaction) error) error {
	return app.ExecuteUnitOfWork(ctx, f.store, func(ctx context.Context, r app.Repositories) error {
		parent, owned := r.Packages.(postgresBundleParent)
		validator, signed := r.Signatures.(postgresBundleSignatureValidator)
		fence, fenced := r.Identity.(postgresBundleFence)
		if !owned || !signed || !fenced || r.Audit == nil || r.Outbox == nil {
			return app.ErrValidation
		}
		return run(ctx, postgresBundleTransaction{r.Packages, parent, fence, r.Signatures, validator, r.Audit, r.Outbox})
	})
}
func (t postgresBundleTransaction) LockReleaseBundleCreationScope(ctx context.Context, tenant, release string) (string, error) {
	if err := t.fence.LockAPIKeyCreation(ctx, tenant); err != nil {
		return "", err
	}
	return t.parent.LockReleaseBundleParent(ctx, tenant, release)
}
func (t postgresBundleTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
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
func (t postgresBundleTransaction) InsertReleaseBundleSignature(ctx context.Context, v packageapp.PackageSignature, hash string) error {
	sig := domain.Signature{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, KeyID: v.KeyID, Algorithm: v.Algorithm, Value: v.Value, CreatedAt: v.CreatedAt}
	if err := t.validator.ValidatePackageSignature(ctx, sig, hash); err != nil {
		return err
	}
	return t.signatures.InsertSignature(ctx, sig)
}
func (t postgresBundleTransaction) InsertReleaseBundle(ctx context.Context, v packagedomain.ReleaseBundle) error {
	return t.packages.InsertReleaseBundle(ctx, domain.ReleaseBundleFromContextModel(v))
}
func (t postgresBundleTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return (postgresCustomerFixtureTransaction{audit: t.audit}).AppendAudit(ctx, e)
}
func (t postgresBundleTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	job := app.OutboxJob{ID: e.ID, TenantID: e.TenantID, Kind: e.Kind, SubjectType: e.SubjectType, SubjectID: e.SubjectID, Payload: e.Payload, CreatedAt: e.CreatedAt}
	if err := app.EnsureOutboxDeduplicationKey(&job); err != nil {
		return err
	}
	return t.outbox.Enqueue(ctx, job)
}

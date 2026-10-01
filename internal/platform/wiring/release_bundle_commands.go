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

func BuildReleaseBundleCommands(reader packageapp.ReleaseBundleSnapshotReader, signer packageapp.PackageSigner, factory app.UnitOfWorkFactory) (*packageapp.ReleaseBundleCommands, error) {
	if reader == nil || signer == nil || factory == nil {
		return nil, errors.New("release bundle reader, signer and transactions are required")
	}
	return packageapp.NewReleaseBundleCommands(packageapp.ReleaseBundleCommandConfig{Reader: reader, Signer: signer, Transactions: releaseBundleTransactions{factory}, Authorizer: packagequery.NewReleaseBundleAuthorizer(), Hasher: packageCanonicalizer{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type releaseBundleParentLocker interface {
	LockReleaseBundleParent(context.Context, string, string) (string, error)
}
type packageSignatureValidator interface {
	ValidatePackageSignature(context.Context, domain.Signature, string) error
}
type releaseBundleTransactions struct{ factory app.UnitOfWorkFactory }

func (t releaseBundleTransactions) ExecuteReleaseBundle(ctx context.Context, command func(context.Context, packageapp.ReleaseBundleTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		locker, ok := repos.Packages.(releaseBundleParentLocker)
		validator, valid := repos.Signatures.(packageSignatureValidator)
		if !ok || !valid || repos.Audit == nil || repos.Outbox == nil {
			return app.ErrValidation
		}
		return command(ctx, releaseBundleTransaction{repos.Packages, locker, repos.Signatures, validator, repos.Audit, repos.Outbox})
	}))
}

type releaseBundleTransaction struct {
	packages   app.PackageRepository
	parent     releaseBundleParentLocker
	signatures app.SignatureRepository
	validator  packageSignatureValidator
	audit      app.AuditRepository
	outbox     app.OutboxRepository
}

func (t releaseBundleTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	productID, err := t.parent.LockReleaseBundleParent(ctx, actor.TenantID, request.Resources.ReleaseID)
	if err != nil {
		return mapPackageAccessWriteError(err)
	}
	if productID != request.Resources.ProductID {
		return packageapp.ErrConflict
	}
	return packagequery.NewReleaseBundleAuthorizer().Authorize(ctx, actor, request)
}
func (t releaseBundleTransaction) InsertReleaseBundleSignature(ctx context.Context, signature packageapp.PackageSignature, hash string) error {
	legacy := domain.Signature{ID: signature.ID, TenantID: signature.TenantID, SubjectType: signature.SubjectType, SubjectID: signature.SubjectID, KeyID: signature.KeyID, Algorithm: signature.Algorithm, Value: signature.Value, CreatedAt: signature.CreatedAt}
	if err := t.validator.ValidatePackageSignature(ctx, legacy, hash); err != nil {
		return mapPackageAccessWriteError(err)
	}
	return mapPackageAccessWriteError(t.signatures.InsertSignature(ctx, legacy))
}
func (t releaseBundleTransaction) InsertReleaseBundle(ctx context.Context, bundle packagedomain.ReleaseBundle) error {
	return mapPackageAccessWriteError(t.packages.InsertReleaseBundle(ctx, domain.ReleaseBundle{ID: bundle.ID, TenantID: bundle.TenantID, ReleaseID: bundle.ReleaseID, State: bundle.State.String(), Manifest: bundle.Manifest, ManifestHash: bundle.ManifestHash, SignatureRefs: bundle.SignatureRefs, CreatedAt: bundle.CreatedAt, PublishedAt: bundle.PublishedAt, RevokedAt: bundle.RevokedAt}))
}
func (t releaseBundleTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, event)
}
func (t releaseBundleTransaction) EnqueueOutbox(ctx context.Context, event application.OutboxEvent) error {
	return mapPackageAccessWriteError(t.outbox.Enqueue(ctx, app.OutboxJob{ID: event.ID, TenantID: event.TenantID, Kind: event.Kind, SubjectType: event.SubjectType, SubjectID: event.SubjectID, Payload: event.Payload, CreatedAt: event.CreatedAt}))
}

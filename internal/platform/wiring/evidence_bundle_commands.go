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

func BuildEvidenceBundleCommands(reader packageapp.EvidenceBundleSnapshotReader, signer packageapp.PackageSigner, factory app.UnitOfWorkFactory) (*packageapp.ExportCommands, error) {
	if reader == nil || signer == nil || factory == nil {
		return nil, errors.New("evidence bundle reader, signer and transactions are required")
	}
	return packageapp.NewExportCommands(packageapp.ExportCommandConfig{Reader: reader, Signer: signer, Transactions: exportTransactions{factory}, Authorizer: packagequery.NewEvidenceBundleAuthorizer(), Hasher: packageCanonicalizer{}, Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID)})
}

type exportEvidenceLocker interface {
	LockEvidenceBundleEvidence(context.Context, string, string) (application.ResourceReferences, error)
}
type exportTenantLocker interface {
	LockEvidenceBundleTenant(context.Context, string) error
}
type exportTransactions struct{ factory app.UnitOfWorkFactory }

func (t exportTransactions) ExecuteEvidenceBundleExport(ctx context.Context, command func(context.Context, packageapp.ExportTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		parent, ok := repos.Packages.(releaseBundleParentLocker)
		tenant, owned := repos.Packages.(exportTenantLocker)
		evidence, valid := repos.Evidence.(exportEvidenceLocker)
		validator, signed := repos.Signatures.(packageSignatureValidator)
		if !ok || !owned || !valid || !signed || repos.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, exportTransaction{repos.Packages, tenant, parent, evidence, repos.Signatures, validator, repos.Audit})
	}))
}

type exportTransaction struct {
	packages   app.PackageRepository
	tenant     exportTenantLocker
	parent     releaseBundleParentLocker
	evidence   exportEvidenceLocker
	signatures app.SignatureRepository
	validator  packageSignatureValidator
	audit      app.AuditRepository
}

func (t exportTransaction) LockEvidenceBundleTenant(ctx context.Context, tenant string) error {
	return mapPackageAccessWriteError(t.tenant.LockEvidenceBundleTenant(ctx, tenant))
}
func (t exportTransaction) LockEvidenceBundleRelease(ctx context.Context, tenant, release string) (string, error) {
	v, err := t.parent.LockReleaseBundleParent(ctx, tenant, release)
	return v, mapPackageAccessWriteError(err)
}
func (t exportTransaction) LockEvidenceBundleEvidence(ctx context.Context, tenant, id string) (application.ResourceReferences, error) {
	v, err := t.evidence.LockEvidenceBundleEvidence(ctx, tenant, id)
	return v, mapPackageAccessWriteError(err)
}

func (t exportTransaction) AuthorizeEvidenceBundleSelection(ctx context.Context, actor identitydomain.Actor, root application.ResourceReferences, selected []packageapp.EvidenceBundleEvidence) error {
	policy := packagequery.NewEvidenceBundleAuthorizer()
	if err := t.LockEvidenceBundleTenant(ctx, actor.TenantID); err != nil {
		return err
	}
	if root.ReleaseID != "" {
		product, err := t.parent.LockReleaseBundleParent(ctx, actor.TenantID, root.ReleaseID)
		if err != nil {
			return mapPackageAccessWriteError(err)
		}
		if product != root.ProductID {
			return packageapp.ErrConflict
		}
		if err := policy.Authorize(ctx, actor, application.AuthorizationRequest{Scope: "bundle:read", Resources: root}); err != nil {
			return err
		}
	}
	for _, item := range selected {
		refs, err := t.evidence.LockEvidenceBundleEvidence(ctx, actor.TenantID, item.ID)
		if err != nil {
			return mapPackageAccessWriteError(err)
		}
		if refs != item.Resources {
			return packageapp.ErrConflict
		}
		if err := policy.Authorize(ctx, actor, application.AuthorizationRequest{Scope: "bundle:read", Resources: refs}); err != nil {
			return err
		}
	}
	return nil
}
func (t exportTransaction) InsertEvidenceBundleSignature(ctx context.Context, signature packageapp.PackageSignature, hash string) error {
	return insertValidatedPackageSignature(ctx, t.signatures, t.validator, signature, hash)
}
func (t exportTransaction) InsertEvidenceBundle(ctx context.Context, bundle packagedomain.EvidenceBundle) error {
	return mapPackageAccessWriteError(t.packages.InsertEvidenceBundle(ctx, domain.EvidenceBundle{ID: bundle.ID, TenantID: bundle.TenantID, ReleaseID: bundle.ReleaseID, EvidenceIDs: bundle.EvidenceIDs, Manifest: bundle.Manifest, ManifestHash: bundle.ManifestHash, SignatureRefs: bundle.SignatureRefs, VerificationText: bundle.VerificationText, SchemaVersion: bundle.SchemaVersion, CreatedAt: bundle.CreatedAt}))
}
func (t exportTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, event)
}

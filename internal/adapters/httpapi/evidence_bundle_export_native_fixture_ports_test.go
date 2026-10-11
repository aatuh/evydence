package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// Test-only composition: selection, current guards and signature validation
// come from repositories, never aggregate evidence/tenant/key caches.
type evidenceBundleFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
}
type evidenceBundleFixtureSnapshots struct{ catalogFixtureCommands }
type evidenceBundleFixtureTransactions struct{ catalogFixtureCommands }
type evidenceBundleFixtureTenant interface {
	LockEvidenceBundleTenant(context.Context, string) error
}
type evidenceBundleFixtureEvidence interface {
	LockEvidenceBundleEvidence(context.Context, string, string) (application.ResourceReferences, error)
}
type evidenceBundleFixtureTransaction struct {
	packages   app.PackageRepository
	tenant     evidenceBundleFixtureTenant
	parent     releaseBundleFixtureParent
	evidence   evidenceBundleFixtureEvidence
	signatures app.SignatureRepository
	validator  releaseBundleFixtureKeyValidator
	audit      app.AuditRepository
}

func (f evidenceBundleFixtureSnapshots) ReadEvidenceBundleSnapshot(ctx context.Context, tenant, release string, at time.Time) (packageapp.EvidenceBundleSnapshot, error) {
	if ctx == nil || f.commandLedger(ctx) == nil {
		return packageapp.EvidenceBundleSnapshot{}, packageapp.ErrValidation
	}
	var out packageapp.EvidenceBundleSnapshot
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Packages.(packageapp.EvidenceBundleSnapshotReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadEvidenceBundleSnapshot(ctx, tenant, release, at)
		return err
	})
	if err != nil {
		return packageapp.EvidenceBundleSnapshot{}, portalFixtureError(err)
	}
	return out, nil
}
func (f evidenceBundleFixtureTransactions) ExecuteEvidenceBundleExport(ctx context.Context, run func(context.Context, packageapp.ExportTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return packageapp.ErrValidation
	}
	return portalFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		tenant, owned := r.Packages.(evidenceBundleFixtureTenant)
		parent, root := r.Packages.(releaseBundleFixtureParent)
		evidence, selected := r.Evidence.(evidenceBundleFixtureEvidence)
		validator, signed := r.Signatures.(releaseBundleFixtureKeyValidator)
		if !owned || !root || !selected || !signed || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, evidenceBundleFixtureTransaction{r.Packages, tenant, parent, evidence, r.Signatures, validator, r.Audit})
	}))
}
func (t evidenceBundleFixtureTransaction) LockEvidenceBundleTenant(ctx context.Context, tenant string) error {
	return portalFixtureError(t.tenant.LockEvidenceBundleTenant(ctx, tenant))
}
func (t evidenceBundleFixtureTransaction) LockEvidenceBundleRelease(ctx context.Context, tenant, release string) (string, error) {
	v, err := t.parent.LockReleaseBundleParent(ctx, tenant, release)
	return v, portalFixtureError(err)
}
func (t evidenceBundleFixtureTransaction) LockEvidenceBundleEvidence(ctx context.Context, tenant, id string) (application.ResourceReferences, error) {
	v, err := t.evidence.LockEvidenceBundleEvidence(ctx, tenant, id)
	return v, portalFixtureError(err)
}
func (t evidenceBundleFixtureTransaction) AuthorizeEvidenceBundleSelection(ctx context.Context, a domain.Actor, root application.ResourceReferences, selected []packageapp.EvidenceBundleEvidence) error {
	if err := t.LockEvidenceBundleTenant(ctx, a.TenantID); err != nil {
		return err
	}
	policy := packagequery.NewEvidenceBundleAuthorizer()
	if root.ReleaseID != "" {
		product, err := t.LockEvidenceBundleRelease(ctx, a.TenantID, root.ReleaseID)
		if err != nil {
			return err
		}
		if product != root.ProductID {
			return packageapp.ErrConflict
		}
		if err := policy.Authorize(ctx, a, application.AuthorizationRequest{Action: authz.ActionEvidenceBundlesExport, Resources: root}); err != nil {
			return err
		}
	}
	for _, item := range selected {
		refs, err := t.LockEvidenceBundleEvidence(ctx, a.TenantID, item.ID)
		if err != nil {
			return err
		}
		if refs != item.Resources {
			return packageapp.ErrConflict
		}
		if err := policy.Authorize(ctx, a, application.AuthorizationRequest{Action: authz.ActionEvidenceBundlesExport, Resources: refs}); err != nil {
			return err
		}
	}
	return nil
}
func (t evidenceBundleFixtureTransaction) InsertEvidenceBundleSignature(ctx context.Context, v packageapp.PackageSignature, hash string) error {
	sig := domain.Signature{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, KeyID: v.KeyID, Algorithm: v.Algorithm, Value: v.Value, CreatedAt: v.CreatedAt}
	if err := t.validator.ValidatePackageSignature(ctx, sig, hash); err != nil {
		return portalFixtureError(err)
	}
	return portalFixtureError(t.signatures.InsertSignature(ctx, sig))
}
func (t evidenceBundleFixtureTransaction) InsertEvidenceBundle(ctx context.Context, v packagedomain.EvidenceBundle) error {
	return portalFixtureError(t.packages.InsertEvidenceBundle(ctx, evidenceBundleFromCommands(v)))
}
func (t evidenceBundleFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := (governanceFixtureTransaction{audit: t.audit}).AppendAudit(ctx, e)
	return v, portalFixtureError(err)
}
func (f evidenceBundleFixtureCommands) commands() (*packageapp.ExportCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	if f.clock != nil {
		clock = f.clock
	}
	return packageapp.NewExportCommands(packageapp.ExportCommandConfig{Reader: evidenceBundleFixtureSnapshots{f.catalogFixtureCommands}, Transactions: evidenceBundleFixtureTransactions{f.catalogFixtureCommands}, Signer: releaseBundleFixtureSigner{f.catalogFixtureCommands}, Hasher: reportImportFixtureHasher{}, Authorizer: packagequery.NewEvidenceBundleAuthorizer(), Clock: clock, IDs: ids})
}
func (f evidenceBundleFixtureCommands) AuthorizeEvidenceBundleExport(ctx context.Context, a domain.Actor, release string, ids []string) error {
	c, err := f.commands()
	if err != nil {
		return err
	}
	return mapCustomerPackageAccessError(portalFixtureError(c.AuthorizeEvidenceBundleExport(ctx, a, release, ids)))
}
func (f evidenceBundleFixtureCommands) AuthorizeEvidenceBundleReplay(ctx context.Context, a domain.Actor, release string, ids []string) error {
	c, err := f.commands()
	if err != nil {
		return err
	}
	return mapCustomerPackageAccessError(portalFixtureError(c.AuthorizeEvidenceBundleReplay(ctx, a, release, ids)))
}
func (f evidenceBundleFixtureCommands) ExportEvidenceBundle(ctx context.Context, a domain.Actor, release string, ids []string) (packagedomain.EvidenceBundle, error) {
	c, err := f.commands()
	if err != nil {
		return packagedomain.EvidenceBundle{}, err
	}
	v, err := c.ExportEvidenceBundle(ctx, a, release, ids)
	return v, mapCustomerPackageAccessError(portalFixtureError(err))
}

var _ EvidenceBundleCommands = evidenceBundleFixtureCommands{}

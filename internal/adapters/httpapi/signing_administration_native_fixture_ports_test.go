package httpapi

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type signingAdminFixtureReader interface {
	ListLocalSigningKeysForUpdate(context.Context, string) ([]verificationdomain.SigningKey, error)
	GetSigningKeyForUpdate(context.Context, string, string) (verificationdomain.SigningKey, error)
}
type signingAdminFixtureTransactions struct{ catalogFixtureCommands }
type signingAdminFixtureTransaction struct {
	reader     signingAdminFixtureReader
	signatures app.SignatureRepository
	guard      releaseBundleFixtureFence
	locker     verificationapp.SigningKeyScopeLocker
	audit      app.AuditRepository
}
type trustAdminFixtureTransaction struct {
	integrity app.IntegrityRepository
	guard     releaseBundleFixtureFence
	audit     app.AuditRepository
}

func (f signingAdminFixtureTransactions) ExecuteSigningKeyCommand(ctx context.Context, run func(context.Context, verificationapp.SigningKeyTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return verificationapp.ErrValidation
	}
	return signingAdminFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Signatures.(signingAdminFixtureReader)
		guard, guarded := r.Identity.(releaseBundleFixtureFence)
		locker, scoped := r.Signatures.(verificationapp.SigningKeyScopeLocker)
		if !ok || !guarded || !scoped || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, signingAdminFixtureTransaction{reader, r.Signatures, guard, locker, r.Audit})
	}))
}
func (f signingAdminFixtureTransactions) ExecuteTrustConfigurationCommand(ctx context.Context, run func(context.Context, verificationapp.TrustConfigurationTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return verificationapp.ErrValidation
	}
	return signingAdminFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		guard, ok := r.Identity.(releaseBundleFixtureFence)
		if !ok || r.Integrity == nil || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, trustAdminFixtureTransaction{r.Integrity, guard, r.Audit})
	}))
}
func signingAdminFixtureAuthorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest, guard releaseBundleFixtureFence) error {
	if err := verificationquery.NewSigningKeyAdminAuthorizer().Authorize(ctx, a, r); err != nil {
		return err
	}
	return signingAdminFixtureError(guard.LockAPIKeyCreation(ctx, a.TenantID))
}
func (t signingAdminFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return signingAdminFixtureAuthorize(ctx, a, r, t.guard)
}
func (t trustAdminFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return signingAdminFixtureAuthorize(ctx, a, r, t.guard)
}
func (t signingAdminFixtureTransaction) LockSigningKeyScope(ctx context.Context, tenant, id string) error {
	return signingAdminFixtureError(t.locker.LockSigningKeyScope(ctx, tenant, id))
}
func (t signingAdminFixtureTransaction) ListLocalSigningKeysForUpdate(ctx context.Context, tenant string) ([]verificationdomain.SigningKey, error) {
	v, err := t.reader.ListLocalSigningKeysForUpdate(ctx, tenant)
	return v, signingAdminFixtureError(err)
}
func (t signingAdminFixtureTransaction) GetSigningKeyForUpdate(ctx context.Context, tenant, id string) (verificationdomain.SigningKey, error) {
	v, err := t.reader.GetSigningKeyForUpdate(ctx, tenant, id)
	return v, signingAdminFixtureError(err)
}
func (t signingAdminFixtureTransaction) UpdateSigningKey(ctx context.Context, v verificationdomain.SigningKey, expected string) error {
	return signingAdminFixtureError(t.signatures.UpdateSigningKey(ctx, signingKeyFromQuery(v), expected))
}
func (t signingAdminFixtureTransaction) InsertSigningKey(ctx context.Context, v verificationapp.PreparedSigningKey) error {
	key := signingKeyFromQuery(v.Key)
	key.Private = v.PrivateMaterial
	return signingAdminFixtureError(t.signatures.InsertSigningKey(ctx, key))
}
func (t trustAdminFixtureTransaction) InsertSigningProvider(ctx context.Context, v verificationdomain.SigningProvider) error {
	return signingAdminFixtureError(t.integrity.InsertSigningProvider(ctx, domain.SigningProviderFromContextModel(v)))
}
func (t trustAdminFixtureTransaction) InsertDSSETrustRoot(ctx context.Context, v verificationdomain.DSSETrustRoot) error {
	return signingAdminFixtureError(t.integrity.InsertDSSETrustRoot(ctx, domain.DSSETrustRootFromContextModel(v)))
}
func signingAdminFixtureAudit(ctx context.Context, r app.AuditRepository, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := (governanceFixtureTransaction{audit: r}).AppendAudit(ctx, e)
	return v, signingAdminFixtureError(err)
}
func (t signingAdminFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return signingAdminFixtureAudit(ctx, t.audit, e)
}
func (t trustAdminFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return signingAdminFixtureAudit(ctx, t.audit, e)
}
func (f signingAdministrationFixtureCommands) signingCommands() (*verificationapp.SigningKeyCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	if f.clock != nil {
		clock = f.clock
	}
	return verificationapp.NewSigningKeyCommands(verificationapp.SigningKeyCommandConfig{Transactions: signingAdminFixtureTransactions{f.catalogFixtureCommands}, KeyFactory: localed25519.KeyFactory{}, Authorizer: verificationquery.NewSigningKeyAdminAuthorizer(), Clock: clock, IDs: ids})
}
func (f signingAdministrationFixtureCommands) trustCommands() (*verificationapp.TrustConfigurationCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	if f.clock != nil {
		clock = f.clock
	}
	return verificationapp.NewTrustConfigurationCommands(verificationapp.TrustConfigurationConfig{Transactions: signingAdminFixtureTransactions{f.catalogFixtureCommands}, Authorizer: verificationquery.NewSigningKeyAdminAuthorizer(), Clock: clock, IDs: ids})
}
func signingAdminFixtureError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return verificationapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return verificationapp.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return verificationapp.ErrConflict
	default:
		return err
	}
}

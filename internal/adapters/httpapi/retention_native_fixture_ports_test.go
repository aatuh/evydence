package httpapi

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// Fixture-only composition uses current repositories, not aggregate policy
// caches or provider configuration. Explicit injected observations remain test
// evidence, not verification of a real operator's storage provider.
type retentionFixtureCommands struct {
	catalogFixtureCommands
	clock    application.Clock
	verifier app.ObjectRetentionVerifier
}

type retentionFixtureReader interface {
	verificationapp.RetentionPolicyReader
	GetObjectRetentionPolicyForUpdate(context.Context, string, string) (verificationdomain.ObjectRetentionPolicy, error)
	LockObjectRetentionPolicy(context.Context, string, string) error
}
type retentionFixtureTransactions struct{ catalogFixtureCommands }
type retentionFixtureTransaction struct {
	reader    retentionFixtureReader
	integrity app.IntegrityRepository
	guard     releaseBundleFixtureFence
	audit     app.AuditRepository
}

func (f retentionFixtureTransactions) ExecuteRetentionCommand(ctx context.Context, run func(context.Context, verificationapp.RetentionTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return verificationapp.ErrValidation
	}
	return signingAdminFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Integrity.(retentionFixtureReader)
		guard, guarded := r.Identity.(releaseBundleFixtureFence)
		if !ok || !guarded || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, retentionFixtureTransaction{reader, r.Integrity, guard, r.Audit})
	}))
}

func (f retentionFixtureTransactions) ReadObjectRetentionPolicy(ctx context.Context, tenant, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	var out verificationdomain.ObjectRetentionPolicy
	err := f.ExecuteRetentionCommand(ctx, func(ctx context.Context, tx verificationapp.RetentionTransaction) error {
		var err error
		out, err = tx.GetObjectRetentionPolicyForUpdate(ctx, tenant, id)
		return err
	})
	if err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	return out, nil
}

func (t retentionFixtureTransaction) LockObjectRetentionPolicy(ctx context.Context, tenant, id string) error {
	return signingAdminFixtureError(t.reader.LockObjectRetentionPolicy(ctx, tenant, id))
}
func (t retentionFixtureTransaction) GetObjectRetentionPolicyForUpdate(ctx context.Context, tenant, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	v, err := t.reader.GetObjectRetentionPolicyForUpdate(ctx, tenant, id)
	return v, signingAdminFixtureError(err)
}
func (t retentionFixtureTransaction) InsertObjectRetentionPolicy(ctx context.Context, p verificationdomain.ObjectRetentionPolicy) error {
	return signingAdminFixtureError(t.integrity.InsertObjectRetentionPolicy(ctx, domain.ObjectRetentionPolicyFromContextModel(p)))
}
func (t retentionFixtureTransaction) UpdateObjectRetentionPolicy(ctx context.Context, p verificationdomain.ObjectRetentionPolicy, expected string) error {
	return signingAdminFixtureError(t.integrity.UpdateObjectRetentionPolicy(ctx, domain.ObjectRetentionPolicyFromContextModel(p), expected))
}
func (t retentionFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	if err := verificationquery.NewRetentionAuthorizer().Authorize(ctx, a, r); err != nil {
		return err
	}
	return signingAdminFixtureError(t.guard.LockAPIKeyCreation(ctx, a.TenantID))
}
func (t retentionFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return signingAdminFixtureAudit(ctx, t.audit, e)
}

type retentionFixtureProvider struct{ verifier app.ObjectRetentionVerifier }

func (p retentionFixtureProvider) VerifyRetention(ctx context.Context, r verificationapp.RetentionRequest) (verificationapp.RetentionObservation, bool, error) {
	if ctx == nil {
		return verificationapp.RetentionObservation{}, false, verificationapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return verificationapp.RetentionObservation{}, false, err
	}
	if p.verifier == nil {
		return verificationapp.RetentionObservation{}, false, nil
	}
	v, err := p.verifier.VerifyObjectRetention(ctx, app.ObjectRetentionRequest{TenantID: r.TenantID, ObjectPrefix: r.ObjectPrefix, ObjectKey: r.ObjectKey, Mode: r.Mode, RetentionDays: r.RetentionDays, RequireLegalHold: r.RequireLegalHold})
	if err != nil {
		return verificationapp.RetentionObservation{}, true, err
	}
	checks := make([]verificationdomain.VerifyCheck, 0, len(v.Checks))
	for _, c := range v.Checks {
		checks = append(checks, verificationdomain.VerifyCheck(c))
	}
	var hold *bool
	if v.LegalHold != nil {
		copied := *v.LegalHold
		hold = &copied
	}
	return verificationapp.RetentionObservation{Provider: v.Provider, Bucket: v.Bucket, ObjectKey: v.ObjectKey, Mode: v.Mode, RetentionDays: v.RetentionDays, Enforced: v.Enforced, LegalHold: hold, ObservedAt: v.ObservedAt, Checks: checks, Limitations: append([]string(nil), v.Limitations...)}, true, nil
}

func (f retentionFixtureCommands) commands() (*verificationapp.RetentionCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	if f.clock != nil {
		clock = f.clock
	}
	tx := retentionFixtureTransactions{f.catalogFixtureCommands}
	return verificationapp.NewRetentionCommands(verificationapp.RetentionCommandConfig{Reader: tx, Transactions: tx, Verifier: retentionFixtureProvider{f.verifier}, Hasher: releaseBundleVerificationFixtureHasher{}, Authorizer: verificationquery.NewRetentionAuthorizer(), Clock: clock, IDs: ids})
}
func retentionFixtureGuardError(err error) error {
	if errors.Is(err, application.ErrForbidden) || errors.Is(err, application.ErrUnauthorized) {
		return err
	}
	return mapVerificationCommandError(err)
}
func (f retentionFixtureCommands) AuthorizeCreateObjectRetentionPolicy(ctx context.Context, a domain.Actor, in verificationapp.CreateObjectRetentionPolicyInput) error {
	c, err := f.commands()
	if err != nil {
		return err
	}
	return retentionFixtureGuardError(c.AuthorizeCreateObjectRetentionPolicy(ctx, a, in))
}
func (f retentionFixtureCommands) AuthorizeVerifyObjectRetentionPolicy(ctx context.Context, a domain.Actor, id string) error {
	c, err := f.commands()
	if err != nil {
		return err
	}
	return retentionFixtureGuardError(c.AuthorizeVerifyObjectRetentionPolicy(ctx, a, id))
}
func (f retentionFixtureCommands) CreateObjectRetentionPolicy(ctx context.Context, a domain.Actor, in verificationapp.CreateObjectRetentionPolicyInput) (verificationdomain.ObjectRetentionPolicy, error) {
	c, err := f.commands()
	if err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	v, err := c.CreateObjectRetentionPolicy(ctx, a, in)
	return v, mapVerificationCommandError(err)
}
func (f retentionFixtureCommands) VerifyObjectRetentionPolicy(ctx context.Context, a domain.Actor, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	c, err := f.commands()
	if err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	v, err := c.VerifyObjectRetentionPolicy(ctx, a, id)
	return v, mapVerificationCommandError(err)
}

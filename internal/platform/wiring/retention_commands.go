package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func BuildRetentionCommands(reader verificationapp.RetentionPolicyReader, factory app.UnitOfWorkFactory, verifier app.ObjectRetentionVerifier) (*verificationapp.RetentionCommands, error) {
	if reader == nil || factory == nil {
		return nil, errors.New("retention policy reader and transactions are required")
	}
	return verificationapp.NewRetentionCommands(verificationapp.RetentionCommandConfig{
		Reader: reader, Transactions: retentionTransactions{factory}, Verifier: retentionProvider{verifier}, Hasher: verificationCanonicalHasher{},
		Authorizer: verificationquery.NewRetentionAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID),
	})
}

type retentionPolicyLocker interface {
	GetObjectRetentionPolicyForUpdate(context.Context, string, string) (verificationdomain.ObjectRetentionPolicy, error)
	LockObjectRetentionPolicy(context.Context, string, string) error
}
type retentionTenantGuard interface {
	LockAPIKeyCreation(context.Context, string) error
}
type retentionTransactions struct{ factory app.UnitOfWorkFactory }

func (t retentionTransactions) ExecuteRetentionCommand(ctx context.Context, command func(context.Context, verificationapp.RetentionTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Integrity.(retentionPolicyLocker)
		guard, canGuard := repos.Identity.(retentionTenantGuard)
		if !ok || !canGuard || repos.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, retentionTransaction{reader: reader, integrity: repos.Integrity, audit: repos.Audit, guard: guard})
	}))
}

type retentionTransaction struct {
	reader    retentionPolicyLocker
	integrity app.IntegrityRepository
	audit     app.AuditRepository
	guard     retentionTenantGuard
}

func (t retentionTransaction) LockObjectRetentionPolicy(ctx context.Context, tenant, id string) error {
	return mapSigningKeyWriteError(t.reader.LockObjectRetentionPolicy(ctx, tenant, id))
}

func (t retentionTransaction) GetObjectRetentionPolicyForUpdate(ctx context.Context, tenantID, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	policy, err := t.reader.GetObjectRetentionPolicyForUpdate(ctx, tenantID, id)
	return policy, mapSigningKeyWriteError(err)
}
func (t retentionTransaction) InsertObjectRetentionPolicy(ctx context.Context, policy verificationdomain.ObjectRetentionPolicy) error {
	return mapSigningKeyWriteError(t.integrity.InsertObjectRetentionPolicy(ctx, domain.ObjectRetentionPolicyFromContextModel(policy)))
}
func (t retentionTransaction) UpdateObjectRetentionPolicy(ctx context.Context, policy verificationdomain.ObjectRetentionPolicy, expected string) error {
	return mapSigningKeyWriteError(t.integrity.UpdateObjectRetentionPolicy(ctx, domain.ObjectRetentionPolicyFromContextModel(policy), expected))
}
func (t retentionTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if err := verificationquery.NewRetentionAuthorizer().Authorize(ctx, actor, request); err != nil {
		return err
	}
	// Fence before tenant/policy/audit locks; a native HTTP request joins its
	// enclosing replay transaction and holds the guard until outer commit.
	return mapSigningKeyWriteError(t.guard.LockAPIKeyCreation(ctx, actor.TenantID))
}
func (t retentionTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	receipt, err := appendAuditEvent(ctx, t.audit, event)
	return receipt, mapSigningKeyWriteError(err)
}

type retentionProvider struct{ verifier app.ObjectRetentionVerifier }

func (p retentionProvider) VerifyRetention(ctx context.Context, request verificationapp.RetentionRequest) (verificationapp.RetentionObservation, bool, error) {
	if err := ctx.Err(); err != nil {
		return verificationapp.RetentionObservation{}, false, err
	}
	if p.verifier == nil {
		return verificationapp.RetentionObservation{}, false, nil
	}
	result, err := p.verifier.VerifyObjectRetention(ctx, app.ObjectRetentionRequest{TenantID: request.TenantID, ObjectPrefix: request.ObjectPrefix, ObjectKey: request.ObjectKey, Mode: request.Mode, RetentionDays: request.RetentionDays, RequireLegalHold: request.RequireLegalHold})
	if err != nil {
		return verificationapp.RetentionObservation{}, true, err
	}
	checks := make([]verificationdomain.VerifyCheck, 0, len(result.Checks))
	for _, check := range result.Checks {
		checks = append(checks, verificationdomain.VerifyCheck(check))
	}
	var hold *bool
	if result.LegalHold != nil {
		value := *result.LegalHold
		hold = &value
	}
	return verificationapp.RetentionObservation{Provider: result.Provider, Bucket: result.Bucket, ObjectKey: result.ObjectKey, Mode: result.Mode, RetentionDays: result.RetentionDays, Enforced: result.Enforced, LegalHold: hold, ObservedAt: result.ObservedAt, Checks: checks, Limitations: append([]string(nil), result.Limitations...)}, true, nil
}

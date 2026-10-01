package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func BuildReleaseBundleVerificationCommands(factory app.UnitOfWorkFactory) (*verificationapp.ReleaseBundleVerificationCommands, error) {
	if factory == nil {
		return nil, errors.New("release bundle verification transactions are required")
	}
	return verificationapp.NewReleaseBundleVerificationCommands(verificationapp.ReleaseBundleVerificationConfig{Transactions: releaseBundleVerificationTransactions{factory}, Authorizer: verificationquery.NewReleaseBundleVerificationAuthorizer(), Hasher: verificationCanonicalHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type verificationCanonicalHasher struct{}

func (verificationCanonicalHasher) Hash(value any) (string, error) {
	return application.NormalizedJSONHash(value)
}

type releaseBundleVerificationTransactions struct{ factory app.UnitOfWorkFactory }

func (t releaseBundleVerificationTransactions) ExecuteReleaseBundleVerification(ctx context.Context, command func(context.Context, verificationapp.ReleaseBundleVerificationTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Verification.(verificationapp.ReleaseBundleVerificationReader)
		if !ok || repos.Audit == nil || repos.Outbox == nil {
			return app.ErrValidation
		}
		return command(ctx, releaseBundleVerificationTransaction{reader, repos.Verification, repos.Audit, repos.Outbox})
	}))
}

type releaseBundleVerificationTransaction struct {
	reader       verificationapp.ReleaseBundleVerificationReader
	verification app.VerificationRepository
	audit        app.AuditRepository
	outbox       app.OutboxRepository
}

func (t releaseBundleVerificationTransaction) ResolveReleaseBundleVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	subject, err := t.reader.ResolveReleaseBundleVerificationSubject(ctx, tenant, id)
	return subject, mapSigningKeyWriteError(err)
}
func (t releaseBundleVerificationTransaction) ReadReleaseBundleVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.ReleaseBundleVerificationSnapshot, error) {
	snapshot, err := t.reader.ReadReleaseBundleVerification(ctx, subject)
	return snapshot, mapSigningKeyWriteError(err)
}
func (t releaseBundleVerificationTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return verificationquery.NewReleaseBundleVerificationAuthorizer().Authorize(ctx, actor, request)
}
func (t releaseBundleVerificationTransaction) InsertVerificationResult(ctx context.Context, result verificationdomain.VerificationResult) error {
	return mapSigningKeyWriteError(t.verification.InsertVerificationResult(ctx, verificationResultToLegacy(result)))
}
func (t releaseBundleVerificationTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	receipt, err := appendAuditEvent(ctx, t.audit, event)
	return receipt, mapSigningKeyWriteError(err)
}
func (t releaseBundleVerificationTransaction) EnqueueOutbox(ctx context.Context, event application.OutboxEvent) error {
	return mapSigningKeyWriteError(t.outbox.Enqueue(ctx, app.OutboxJob{ID: event.ID, TenantID: event.TenantID, Kind: event.Kind, SubjectType: event.SubjectType, SubjectID: event.SubjectID, Payload: event.Payload, CreatedAt: event.CreatedAt}))
}
func verificationResultToLegacy(result verificationdomain.VerificationResult) domain.VerificationResult {
	checks := make([]domain.VerifyCheck, 0, len(result.Checks))
	for _, check := range result.Checks {
		checks = append(checks, domain.VerifyCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
	}
	p := result.Profile
	return domain.VerificationResult{ID: result.ID, TenantID: result.TenantID, SubjectType: result.SubjectType, SubjectID: result.SubjectID, Result: result.Result.String(), Checks: checks, Profile: domain.VerificationProfile{ID: p.ID, Version: p.Version, RequiredChecks: p.RequiredChecks, TrustMaterial: p.TrustMaterial, IdentityPolicy: p.IdentityPolicy, TransparencyProof: p.TransparencyProof, PayloadScope: p.PayloadScope, PayloadDigest: p.PayloadDigest, Limitations: p.Limitations}, Limitations: result.Limitations, SchemaVersion: result.SchemaVersion, VerifiedAt: result.VerifiedAt}
}

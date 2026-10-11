package httpapi

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/authz"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// Test-only focused verification against current public rows, not a Ledger
// bundle/key cache. Receipt, audit and job remain in one fixture transaction.
type releaseBundleVerificationFixtureTransactions struct{ catalogFixtureCommands }
type releaseBundleVerificationFixtureTransaction struct {
	reader       verificationapp.ReleaseBundleVerificationReader
	verification app.VerificationRepository
	audit        app.AuditRepository
	outbox       app.OutboxRepository
}
type releaseBundleVerificationFixtureHasher struct{}

func (releaseBundleVerificationFixtureHasher) Hash(v any) (string, error) {
	return application.NormalizedJSONHash(v)
}
func (f releaseBundleVerificationFixtureTransactions) ExecuteReleaseBundleVerification(ctx context.Context, run func(context.Context, verificationapp.ReleaseBundleVerificationTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return verificationapp.ErrValidation
	}
	return signingFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Verification.(verificationapp.ReleaseBundleVerificationReader)
		if !ok || r.Audit == nil || r.Outbox == nil {
			return app.ErrValidation
		}
		return run(ctx, releaseBundleVerificationFixtureTransaction{reader, r.Verification, r.Audit, r.Outbox})
	}))
}
func (t releaseBundleVerificationFixtureTransaction) ResolveReleaseBundleVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	v, err := t.reader.ResolveReleaseBundleVerificationSubject(ctx, tenant, id)
	return v, signingFixtureError(err)
}
func (t releaseBundleVerificationFixtureTransaction) ReadReleaseBundleVerification(ctx context.Context, s verificationapp.SubjectReference) (verificationapp.ReleaseBundleVerificationSnapshot, error) {
	v, err := t.reader.ReadReleaseBundleVerification(ctx, s)
	return v, signingFixtureError(err)
}
func (t releaseBundleVerificationFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewReleaseBundleVerificationAuthorizer().Authorize(ctx, a, r)
}
func (t releaseBundleVerificationFixtureTransaction) InsertVerificationResult(ctx context.Context, v verificationdomain.VerificationResult) error {
	return signingFixtureError(t.verification.InsertVerificationResult(ctx, domain.VerificationResultFromContextModel(v)))
}
func (t releaseBundleVerificationFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := (governanceFixtureTransaction{audit: t.audit}).AppendAudit(ctx, e)
	return v, signingFixtureError(err)
}
func (t releaseBundleVerificationFixtureTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	job := app.OutboxJob{ID: e.ID, TenantID: e.TenantID, Kind: e.Kind, SubjectType: e.SubjectType, SubjectID: e.SubjectID, Payload: e.Payload, CreatedAt: e.CreatedAt}
	if err := app.EnsureOutboxDeduplicationKey(&job); err != nil {
		return signingFixtureError(err)
	}
	return signingFixtureError(t.outbox.Enqueue(ctx, job))
}
func (f verificationCommandFixture) verifyCurrentReleaseBundle(ctx context.Context, a domain.Actor, id string) (verificationdomain.VerificationResult, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	c, err := verificationapp.NewReleaseBundleVerificationCommands(verificationapp.ReleaseBundleVerificationConfig{Transactions: (releaseBundleVerificationFixtureTransactions{f.catalogFixtureCommands}), Authorizer: verificationquery.NewReleaseBundleVerificationAuthorizer(), Hasher: releaseBundleVerificationFixtureHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: clock, IDs: ids})
	if err != nil {
		return verificationdomain.VerificationResult{}, mapVerificationCommandError(err)
	}
	v, err := c.VerifyReleaseBundle(ctx, a, id)
	return v, mapVerificationCommandError(err)
}

func (f verificationCommandFixture) authorizeCurrentReleaseBundle(ctx context.Context, a domain.Actor, id string) error {
	policy := verificationquery.NewReleaseBundleVerificationAuthorizer()
	if err := policy.Authorize(ctx, a, application.AuthorizationRequest{Action: authz.ActionReleaseBundleVerify, ScopeOnly: true}); err != nil {
		return mapVerificationCommandError(err)
	}
	return mapVerificationCommandError((releaseBundleVerificationFixtureTransactions{f.catalogFixtureCommands}).ExecuteReleaseBundleVerification(ctx, func(ctx context.Context, tx verificationapp.ReleaseBundleVerificationTransaction) error {
		subject, err := tx.ResolveReleaseBundleVerificationSubject(ctx, a.TenantID, strings.TrimSpace(id))
		if err != nil {
			return err
		}
		return tx.Authorize(ctx, a, application.AuthorizationRequest{Action: authz.ActionReleaseBundleVerify, Resources: subject.Resources})
	}))
}

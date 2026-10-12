package postgres

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// Restored records are verified through native readers and atomic effects,
// never reconstructed aggregate caches. Live recovery tests remain required.
func verifyRestoredSubjectFixture(ctx context.Context, store *Store, actor domain.Actor, kind, id string) (domain.VerificationResult, error) {
	tx := postgresSubjectVerificationFixture{store}
	var v verificationdomain.VerificationResult
	var err error
	switch kind {
	case "audit_chain":
		c, buildErr := verificationapp.NewAuditChainVerificationCommands(verificationapp.AuditChainVerificationConfig{Transactions: tx, Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Hasher: postgresCustomerFixtureHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
		if buildErr != nil {
			return domain.VerificationResult{}, buildErr
		}
		v, err = c.VerifyAuditChain(ctx, actor)
	case "release_bundle":
		c, buildErr := verificationapp.NewReleaseBundleVerificationCommands(verificationapp.ReleaseBundleVerificationConfig{Transactions: tx, Authorizer: verificationquery.NewReleaseBundleVerificationAuthorizer(), Hasher: postgresCustomerFixtureHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
		if buildErr != nil {
			return domain.VerificationResult{}, buildErr
		}
		v, err = c.VerifyReleaseBundle(ctx, actor, id)
	default:
		return domain.VerificationResult{}, app.ErrValidation
	}
	return domain.VerificationResultFromContextModel(v), err
}

type postgresSubjectVerificationFixture struct{ store *Store }
type postgresVerificationFixtureReceipt struct{ repos app.Repositories }
type postgresAuditSubjectFixtureTransaction struct {
	postgresVerificationFixtureReceipt
	reader verificationapp.AuditChainVerificationReader
}
type postgresReleaseSubjectFixtureTransaction struct {
	postgresVerificationFixtureReceipt
	reader verificationapp.ReleaseBundleVerificationReader
}

func (f postgresSubjectVerificationFixture) ExecuteAuditChainVerification(ctx context.Context, run func(context.Context, verificationapp.AuditChainVerificationTransaction) error) error {
	return app.ExecuteUnitOfWork(ctx, f.store, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Verification.(verificationapp.AuditChainVerificationReader)
		if !ok || r.Audit == nil || r.Outbox == nil {
			return app.ErrValidation
		}
		return run(ctx, postgresAuditSubjectFixtureTransaction{postgresVerificationFixtureReceipt{r}, reader})
	})
}
func (f postgresSubjectVerificationFixture) ExecuteReleaseBundleVerification(ctx context.Context, run func(context.Context, verificationapp.ReleaseBundleVerificationTransaction) error) error {
	return app.ExecuteUnitOfWork(ctx, f.store, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Verification.(verificationapp.ReleaseBundleVerificationReader)
		if !ok || r.Audit == nil || r.Outbox == nil {
			return app.ErrValidation
		}
		return run(ctx, postgresReleaseSubjectFixtureTransaction{postgresVerificationFixtureReceipt{r}, reader})
	})
}
func (t postgresVerificationFixtureReceipt) InsertVerificationResult(ctx context.Context, v verificationdomain.VerificationResult) error {
	return t.repos.Verification.InsertVerificationResult(ctx, domain.VerificationResultFromContextModel(v))
}
func (t postgresVerificationFixtureReceipt) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return (postgresCustomerFixtureTransaction{audit: t.repos.Audit}).AppendAudit(ctx, e)
}
func (t postgresVerificationFixtureReceipt) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	return (postgresBundleTransaction{outbox: t.repos.Outbox}).EnqueueOutbox(ctx, e)
}
func (t postgresAuditSubjectFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewEvidenceVerificationAuthorizer().Authorize(ctx, a, r)
}
func (t postgresAuditSubjectFixtureTransaction) LockAuditChainVerification(ctx context.Context, tenant string) (verificationapp.AuditChainVerificationView, error) {
	return t.reader.LockAuditChainVerification(ctx, tenant)
}
func (t postgresAuditSubjectFixtureTransaction) ReadAuditChainVerificationPage(ctx context.Context, v verificationapp.AuditChainVerificationView, after *int64, budget int) (verificationapp.AuditChainVerificationPage, error) {
	return t.reader.ReadAuditChainVerificationPage(ctx, v, after, budget)
}
func (t postgresReleaseSubjectFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewReleaseBundleVerificationAuthorizer().Authorize(ctx, a, r)
}
func (t postgresReleaseSubjectFixtureTransaction) ResolveReleaseBundleVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	return t.reader.ResolveReleaseBundleVerificationSubject(ctx, tenant, id)
}
func (t postgresReleaseSubjectFixtureTransaction) ReadReleaseBundleVerification(ctx context.Context, v verificationapp.SubjectReference) (verificationapp.ReleaseBundleVerificationSnapshot, error) {
	return t.reader.ReadReleaseBundleVerification(ctx, v)
}

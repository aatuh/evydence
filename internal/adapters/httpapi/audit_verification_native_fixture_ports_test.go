package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type auditVerificationFixtureTransactions struct{ catalogFixtureCommands }
type auditVerificationFixtureTransaction struct {
	reader  verificationapp.AuditChainVerificationReader
	receipt releaseBundleVerificationFixtureTransaction
}
type auditMerkleCheckpointFixtureTransaction struct {
	auditVerificationFixtureTransaction
	merkle verificationapp.MerkleVerificationReader
}
type auditManifestCheckpointFixtureTransaction struct {
	auditVerificationFixtureTransaction
	bundle verificationapp.ReleaseBundleVerificationReader
}

func (f auditVerificationFixtureTransactions) execute(ctx context.Context, run func(context.Context, app.Repositories, auditVerificationFixtureTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return verificationapp.ErrValidation
	}
	return signingFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Verification.(verificationapp.AuditChainVerificationReader)
		if !ok || r.Audit == nil || r.Outbox == nil {
			return app.ErrValidation
		}
		return run(ctx, r, auditVerificationFixtureTransaction{reader, releaseBundleVerificationFixtureTransaction{verification: r.Verification, audit: r.Audit, outbox: r.Outbox}})
	}))
}
func (f auditVerificationFixtureTransactions) ExecuteAuditChainVerification(ctx context.Context, run func(context.Context, verificationapp.AuditChainVerificationTransaction) error) error {
	if run == nil {
		return verificationapp.ErrValidation
	}
	return f.execute(ctx, func(ctx context.Context, _ app.Repositories, tx auditVerificationFixtureTransaction) error {
		return run(ctx, tx)
	})
}
func (f auditVerificationFixtureTransactions) ExecuteMerkleCheckpointVerification(ctx context.Context, run func(context.Context, verificationapp.MerkleCheckpointVerificationTransaction) error) error {
	if run == nil {
		return verificationapp.ErrValidation
	}
	return f.execute(ctx, func(ctx context.Context, r app.Repositories, tx auditVerificationFixtureTransaction) error {
		reader, ok := r.Verification.(verificationapp.MerkleVerificationReader)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, auditMerkleCheckpointFixtureTransaction{tx, reader})
	})
}
func (f auditVerificationFixtureTransactions) ExecuteReleaseManifestCheckpointVerification(ctx context.Context, run func(context.Context, verificationapp.ReleaseManifestCheckpointTransaction) error) error {
	if run == nil {
		return verificationapp.ErrValidation
	}
	return f.execute(ctx, func(ctx context.Context, r app.Repositories, tx auditVerificationFixtureTransaction) error {
		reader, ok := r.Verification.(verificationapp.ReleaseBundleVerificationReader)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, auditManifestCheckpointFixtureTransaction{tx, reader})
	})
}
func (t auditVerificationFixtureTransaction) LockAuditChainVerification(ctx context.Context, tenant string) (verificationapp.AuditChainVerificationView, error) {
	v, err := t.reader.LockAuditChainVerification(ctx, tenant)
	return v, signingFixtureError(err)
}
func (t auditVerificationFixtureTransaction) ReadAuditChainVerificationPage(ctx context.Context, v verificationapp.AuditChainVerificationView, after *int64, budget int) (verificationapp.AuditChainVerificationPage, error) {
	p, err := t.reader.ReadAuditChainVerificationPage(ctx, v, after, budget)
	return p, signingFixtureError(err)
}
func (t auditVerificationFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewEvidenceVerificationAuthorizer().Authorize(ctx, a, r)
}
func (t auditVerificationFixtureTransaction) InsertVerificationResult(ctx context.Context, v verificationdomain.VerificationResult) error {
	return t.receipt.InsertVerificationResult(ctx, v)
}
func (t auditVerificationFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return t.receipt.AppendAudit(ctx, e)
}
func (t auditVerificationFixtureTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	return t.receipt.EnqueueOutbox(ctx, e)
}
func (t auditMerkleCheckpointFixtureTransaction) ResolveMerkleVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	v, err := t.merkle.ResolveMerkleVerificationSubject(ctx, tenant, id)
	return v, signingFixtureError(err)
}
func (t auditMerkleCheckpointFixtureTransaction) ReadMerkleVerification(ctx context.Context, v verificationapp.SubjectReference) (verificationapp.MerkleVerificationSnapshot, error) {
	s, err := t.merkle.ReadMerkleVerification(ctx, v)
	return s, signingFixtureError(err)
}
func (t auditManifestCheckpointFixtureTransaction) ResolveReleaseBundleVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	v, err := t.bundle.ResolveReleaseBundleVerificationSubject(ctx, tenant, id)
	return v, signingFixtureError(err)
}
func (t auditManifestCheckpointFixtureTransaction) ReadReleaseBundleVerification(ctx context.Context, v verificationapp.SubjectReference) (verificationapp.ReleaseBundleVerificationSnapshot, error) {
	s, err := t.bundle.ReadReleaseBundleVerification(ctx, v)
	return s, signingFixtureError(err)
}
func (f verificationCommandFixture) verifyCurrentAuditChain(ctx context.Context, a domain.Actor) (verificationdomain.VerificationResult, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	c, err := verificationapp.NewAuditChainVerificationCommands(verificationapp.AuditChainVerificationConfig{Transactions: auditVerificationFixtureTransactions{f.catalogFixtureCommands}, Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Hasher: releaseBundleVerificationFixtureHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: clock, IDs: ids})
	if err != nil {
		return verificationdomain.VerificationResult{}, mapVerificationCommandError(err)
	}
	v, err := c.VerifyAuditChain(ctx, a)
	return v, mapVerificationCommandError(err)
}
func (f verificationCommandFixture) verifyCurrentAuditMerkleCheckpoint(ctx context.Context, a domain.Actor, id string) (verificationdomain.VerificationResult, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	c, err := verificationapp.NewMerkleCheckpointVerificationCommands(verificationapp.MerkleCheckpointVerificationConfig{Transactions: auditVerificationFixtureTransactions{f.catalogFixtureCommands}, Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Hasher: releaseBundleVerificationFixtureHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: clock, IDs: ids})
	if err != nil {
		return verificationdomain.VerificationResult{}, mapVerificationCommandError(err)
	}
	v, err := c.VerifyMerkleCheckpoint(ctx, a, id)
	return v, mapVerificationCommandError(err)
}
func (f verificationCommandFixture) verifyCurrentAuditManifestCheckpoint(ctx context.Context, a domain.Actor, id string) (verificationdomain.VerificationResult, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	c, err := verificationapp.NewReleaseManifestCheckpointCommands(verificationapp.ReleaseManifestCheckpointConfig{Transactions: auditVerificationFixtureTransactions{f.catalogFixtureCommands}, Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Hasher: releaseBundleVerificationFixtureHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: clock, IDs: ids})
	if err != nil {
		return verificationdomain.VerificationResult{}, mapVerificationCommandError(err)
	}
	v, err := c.VerifyReleaseManifestCheckpoint(ctx, a, id)
	return v, mapVerificationCommandError(err)
}

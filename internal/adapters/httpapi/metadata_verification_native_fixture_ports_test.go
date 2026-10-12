package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/authz"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type metadataVerificationFixtureTransactions struct{ catalogFixtureCommands }
type evidenceVerificationFixtureTransaction struct {
	reader  verificationapp.EvidenceVerificationReader
	receipt releaseBundleVerificationFixtureTransaction
}
type artifactMetadataVerificationFixtureTransaction struct {
	reader  verificationapp.ArtifactSignatureVerificationReader
	locker  verificationapp.CosignVerificationScopeLocker
	receipt releaseBundleVerificationFixtureTransaction
}

func (f metadataVerificationFixtureTransactions) ExecuteEvidenceVerification(ctx context.Context, run func(context.Context, verificationapp.EvidenceVerificationTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return verificationapp.ErrValidation
	}
	return signingFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Verification.(verificationapp.EvidenceVerificationReader)
		if !ok || r.Audit == nil || r.Outbox == nil {
			return app.ErrValidation
		}
		return run(ctx, evidenceVerificationFixtureTransaction{reader, releaseBundleVerificationFixtureTransaction{verification: r.Verification, audit: r.Audit, outbox: r.Outbox}})
	}))
}
func (f metadataVerificationFixtureTransactions) ExecuteArtifactSignatureVerification(ctx context.Context, run func(context.Context, verificationapp.ArtifactSignatureVerificationTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return verificationapp.ErrValidation
	}
	return signingFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Verification.(verificationapp.ArtifactSignatureVerificationReader)
		locker, scoped := r.Verification.(verificationapp.CosignVerificationScopeLocker)
		if !ok || !scoped || r.Audit == nil || r.Outbox == nil {
			return app.ErrValidation
		}
		return run(ctx, artifactMetadataVerificationFixtureTransaction{reader, locker, releaseBundleVerificationFixtureTransaction{verification: r.Verification, audit: r.Audit, outbox: r.Outbox}})
	}))
}
func (t evidenceVerificationFixtureTransaction) ResolveEvidenceVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	v, err := t.reader.ResolveEvidenceVerificationSubject(ctx, tenant, id)
	return v, signingFixtureError(err)
}
func (t evidenceVerificationFixtureTransaction) ReadEvidenceVerification(ctx context.Context, s verificationapp.SubjectReference) (verificationapp.EvidenceVerificationSnapshot, error) {
	v, err := t.reader.ReadEvidenceVerification(ctx, s)
	return v, signingFixtureError(err)
}
func (t evidenceVerificationFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewEvidenceVerificationAuthorizer().Authorize(ctx, a, r)
}
func (t evidenceVerificationFixtureTransaction) InsertVerificationResult(ctx context.Context, v verificationdomain.VerificationResult) error {
	return t.receipt.InsertVerificationResult(ctx, v)
}
func (t evidenceVerificationFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return t.receipt.AppendAudit(ctx, e)
}
func (t evidenceVerificationFixtureTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	return t.receipt.EnqueueOutbox(ctx, e)
}
func (t artifactMetadataVerificationFixtureTransaction) ResolveArtifactSignatureVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	v, err := t.reader.ResolveArtifactSignatureVerificationSubject(ctx, tenant, id)
	return v, signingFixtureError(err)
}
func (t artifactMetadataVerificationFixtureTransaction) LockCosignVerificationScope(ctx context.Context, tenant, id string) (application.ResourceReferences, error) {
	v, err := t.locker.LockCosignVerificationScope(ctx, tenant, id)
	return v, signingFixtureError(err)
}
func (t artifactMetadataVerificationFixtureTransaction) ReadArtifactSignatureVerification(ctx context.Context, s verificationapp.SubjectReference) (verificationapp.ArtifactSignatureVerificationSnapshot, error) {
	v, err := t.reader.ReadArtifactSignatureVerification(ctx, s)
	return v, signingFixtureError(err)
}
func (t artifactMetadataVerificationFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewCosignVerificationAuthorizer().Authorize(ctx, a, r)
}
func (t artifactMetadataVerificationFixtureTransaction) InsertVerificationResult(ctx context.Context, v verificationdomain.VerificationResult) error {
	return t.receipt.InsertVerificationResult(ctx, v)
}
func (t artifactMetadataVerificationFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return t.receipt.AppendAudit(ctx, e)
}
func (t artifactMetadataVerificationFixtureTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	return t.receipt.EnqueueOutbox(ctx, e)
}
func (f verificationCommandFixture) verifyCurrentEvidence(ctx context.Context, a domain.Actor, id string) (verificationdomain.VerificationResult, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	c, err := verificationapp.NewEvidenceVerificationCommands(verificationapp.EvidenceVerificationConfig{Transactions: (metadataVerificationFixtureTransactions{f.catalogFixtureCommands}), Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Hasher: evidenceCreationNativeFixture{}, Clock: clock, IDs: ids})
	if err != nil {
		return verificationdomain.VerificationResult{}, mapVerificationCommandError(err)
	}
	v, err := c.VerifyEvidence(ctx, a, id)
	return v, mapVerificationCommandError(err)
}
func (f verificationCommandFixture) verifyCurrentArtifactMetadata(ctx context.Context, a domain.Actor, id string) (verificationdomain.VerificationResult, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	c, err := verificationapp.NewArtifactSignatureVerificationCommands(verificationapp.ArtifactSignatureVerificationConfig{Transactions: (metadataVerificationFixtureTransactions{f.catalogFixtureCommands}), Authorizer: verificationquery.NewCosignVerificationAuthorizer(), Clock: clock, IDs: ids})
	if err != nil {
		return verificationdomain.VerificationResult{}, mapVerificationCommandError(err)
	}
	v, err := c.VerifyArtifactSignature(ctx, a, id)
	return v, mapVerificationCommandError(err)
}
func (f verificationCommandFixture) authorizeCurrentEvidenceVerification(ctx context.Context, a domain.Actor, id string) error {
	policy := verificationquery.NewEvidenceVerificationAuthorizer()
	if err := policy.Authorize(ctx, a, application.AuthorizationRequest{Action: authz.ActionEvidenceVerify, ScopeOnly: true}); err != nil {
		return mapVerificationCommandError(err)
	}
	_, id, err := verificationapp.NormalizeSubjectVerificationInput("evidence_item", id)
	if err != nil {
		return mapVerificationCommandError(err)
	}
	return mapVerificationCommandError((metadataVerificationFixtureTransactions{f.catalogFixtureCommands}).ExecuteEvidenceVerification(ctx, func(ctx context.Context, tx verificationapp.EvidenceVerificationTransaction) error {
		s, err := tx.ResolveEvidenceVerificationSubject(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		return tx.Authorize(ctx, a, application.AuthorizationRequest{Action: authz.ActionEvidenceVerify, Resources: s.Resources, TenantWide: s.Resources == (application.ResourceReferences{})})
	}))
}
func (f verificationCommandFixture) authorizeCurrentArtifactMetadata(ctx context.Context, a domain.Actor, id string) error {
	policy := verificationquery.NewCosignVerificationAuthorizer()
	if err := policy.Authorize(ctx, a, application.AuthorizationRequest{Action: authz.ActionArtifactSignatureVerify, ScopeOnly: true}); err != nil {
		return mapVerificationCommandError(err)
	}
	_, id, err := verificationapp.NormalizeSubjectVerificationInput("artifact_signature", id)
	if err != nil {
		return mapVerificationCommandError(err)
	}
	return mapVerificationCommandError((metadataVerificationFixtureTransactions{f.catalogFixtureCommands}).ExecuteArtifactSignatureVerification(ctx, func(ctx context.Context, tx verificationapp.ArtifactSignatureVerificationTransaction) error {
		locker, ok := tx.(verificationapp.CosignVerificationScopeLocker)
		if !ok {
			return verificationapp.ErrValidation
		}
		refs, err := locker.LockCosignVerificationScope(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		return tx.Authorize(ctx, a, application.AuthorizationRequest{Action: authz.ActionArtifactSignatureVerify, Resources: refs})
	}))
}

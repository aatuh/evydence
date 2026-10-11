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

type merkleVerificationFixtureTransactions struct{ catalogFixtureCommands }
type merkleVerificationFixtureTransaction struct {
	reader  verificationapp.MerkleVerificationReader
	receipt releaseBundleVerificationFixtureTransaction
}

func (f merkleVerificationFixtureTransactions) ExecuteMerkleVerification(ctx context.Context, run func(context.Context, verificationapp.MerkleVerificationTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return verificationapp.ErrValidation
	}
	return signingFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Verification.(verificationapp.MerkleVerificationReader)
		if !ok || r.Audit == nil || r.Outbox == nil {
			return app.ErrValidation
		}
		return run(ctx, merkleVerificationFixtureTransaction{reader, releaseBundleVerificationFixtureTransaction{verification: r.Verification, audit: r.Audit, outbox: r.Outbox}})
	}))
}
func (t merkleVerificationFixtureTransaction) ResolveMerkleVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	v, err := t.reader.ResolveMerkleVerificationSubject(ctx, tenant, id)
	return v, signingFixtureError(err)
}
func (t merkleVerificationFixtureTransaction) ReadMerkleVerification(ctx context.Context, s verificationapp.SubjectReference) (verificationapp.MerkleVerificationSnapshot, error) {
	v, err := t.reader.ReadMerkleVerification(ctx, s)
	return v, signingFixtureError(err)
}
func (t merkleVerificationFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewEvidenceVerificationAuthorizer().Authorize(ctx, a, r)
}
func (t merkleVerificationFixtureTransaction) InsertVerificationResult(ctx context.Context, v verificationdomain.VerificationResult) error {
	return t.receipt.InsertVerificationResult(ctx, v)
}
func (t merkleVerificationFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return t.receipt.AppendAudit(ctx, e)
}
func (t merkleVerificationFixtureTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	return t.receipt.EnqueueOutbox(ctx, e)
}
func (f verificationCommandFixture) verifyCurrentMerkle(ctx context.Context, a domain.Actor, id string) (verificationdomain.VerificationResult, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	c, err := verificationapp.NewMerkleVerificationCommands(verificationapp.MerkleVerificationConfig{Transactions: (merkleVerificationFixtureTransactions{f.catalogFixtureCommands}), Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Verifier: localed25519.PayloadVerifier{}, Clock: clock, IDs: ids})
	if err != nil {
		return verificationdomain.VerificationResult{}, mapVerificationCommandError(err)
	}
	v, err := c.VerifyMerkleBatch(ctx, a, id)
	return v, mapVerificationCommandError(err)
}
func (f verificationCommandFixture) authorizeCurrentMerkle(ctx context.Context, a domain.Actor, id string) error {
	policy := verificationquery.NewEvidenceVerificationAuthorizer()
	if err := policy.Authorize(ctx, a, application.AuthorizationRequest{Action: authz.ActionMerkleBatchVerify, ScopeOnly: true}); err != nil {
		return mapVerificationCommandError(err)
	}
	return mapVerificationCommandError((merkleVerificationFixtureTransactions{f.catalogFixtureCommands}).ExecuteMerkleVerification(ctx, func(ctx context.Context, tx verificationapp.MerkleVerificationTransaction) error {
		if _, err := tx.ResolveMerkleVerificationSubject(ctx, a.TenantID, strings.TrimSpace(id)); err != nil {
			return err
		}
		return tx.Authorize(ctx, a, application.AuthorizationRequest{Action: authz.ActionMerkleBatchVerify, TenantWide: true})
	}))
}

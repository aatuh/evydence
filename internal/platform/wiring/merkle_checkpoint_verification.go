package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func BuildMerkleCheckpointVerificationCommands(factory app.UnitOfWorkFactory) (*verificationapp.MerkleCheckpointVerificationCommands, error) {
	if factory == nil {
		return nil, errors.New("merkle audit chain checkpoint verification transactions are required")
	}
	return verificationapp.NewMerkleCheckpointVerificationCommands(verificationapp.MerkleCheckpointVerificationConfig{Transactions: merkleCheckpointVerificationTransactions{factory}, Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Hasher: verificationCanonicalHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type merkleCheckpointVerificationTransactions struct{ factory app.UnitOfWorkFactory }

func (t merkleCheckpointVerificationTransactions) ExecuteMerkleCheckpointVerification(ctx context.Context, fn func(context.Context, verificationapp.MerkleCheckpointVerificationTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		auditReader, auditOK := repos.Verification.(verificationapp.AuditChainVerificationReader)
		merkleReader, merkleOK := repos.Verification.(verificationapp.MerkleVerificationReader)
		if !auditOK || !merkleOK || repos.Audit == nil || repos.Outbox == nil {
			return app.ErrValidation
		}
		return fn(ctx, merkleCheckpointVerificationTransaction{auditChainVerificationTransaction{auditReader, verificationReceiptWriter{repos.Verification, repos.Audit, repos.Outbox}}, merkleReader})
	}))
}

type merkleCheckpointVerificationTransaction struct {
	auditChainVerificationTransaction
	merkleReader verificationapp.MerkleVerificationReader
}

func (t merkleCheckpointVerificationTransaction) ResolveMerkleVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	s, err := t.merkleReader.ResolveMerkleVerificationSubject(ctx, tenant, id)
	return s, mapSigningKeyWriteError(err)
}
func (t merkleCheckpointVerificationTransaction) ReadMerkleVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.MerkleVerificationSnapshot, error) {
	s, err := t.merkleReader.ReadMerkleVerification(ctx, subject)
	return s, mapSigningKeyWriteError(err)
}

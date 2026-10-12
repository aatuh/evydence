package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func BuildMerkleVerificationCommands(factory app.UnitOfWorkFactory) (*verificationapp.MerkleVerificationCommands, error) {
	if factory == nil {
		return nil, errors.New("merkle verification transactions are required")
	}
	return verificationapp.NewMerkleVerificationCommands(verificationapp.MerkleVerificationConfig{Transactions: merkleVerificationTransactions{factory}, Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Verifier: localed25519.PayloadVerifier{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type merkleVerificationTransactions struct{ factory app.UnitOfWorkFactory }

func (t merkleVerificationTransactions) ExecuteMerkleVerification(ctx context.Context, fn func(context.Context, verificationapp.MerkleVerificationTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Verification.(verificationapp.MerkleVerificationReader)
		if !ok || repos.Audit == nil || repos.Outbox == nil {
			return app.ErrValidation
		}
		return fn(ctx, merkleVerificationTransaction{reader, verificationReceiptWriter{repos.Verification, repos.Audit, repos.Outbox}})
	}))
}

type merkleVerificationTransaction struct {
	reader verificationapp.MerkleVerificationReader
	verificationReceiptWriter
}

func (t merkleVerificationTransaction) ResolveMerkleVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	s, e := t.reader.ResolveMerkleVerificationSubject(ctx, tenant, id)
	return s, mapSigningKeyWriteError(e)
}
func (t merkleVerificationTransaction) ReadMerkleVerification(ctx context.Context, s verificationapp.SubjectReference) (verificationapp.MerkleVerificationSnapshot, error) {
	v, e := t.reader.ReadMerkleVerification(ctx, s)
	return v, mapSigningKeyWriteError(e)
}
func (t merkleVerificationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewEvidenceVerificationAuthorizer().Authorize(ctx, a, r)
}

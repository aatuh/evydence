package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func BuildArtifactSignatureVerificationCommands(factory app.UnitOfWorkFactory) (*verificationapp.ArtifactSignatureVerificationCommands, error) {
	if factory == nil {
		return nil, errors.New("artifact signature verification transactions are required")
	}
	return verificationapp.NewArtifactSignatureVerificationCommands(verificationapp.ArtifactSignatureVerificationConfig{Transactions: artifactSignatureVerificationTransactions{factory}, Authorizer: verificationquery.NewCosignVerificationAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type artifactSignatureVerificationTransactions struct{ factory app.UnitOfWorkFactory }

func (t artifactSignatureVerificationTransactions) ExecuteArtifactSignatureVerification(ctx context.Context, fn func(context.Context, verificationapp.ArtifactSignatureVerificationTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Verification.(verificationapp.ArtifactSignatureVerificationReader)
		if !ok || repos.Audit == nil || repos.Outbox == nil {
			return app.ErrValidation
		}
		return fn(ctx, artifactSignatureVerificationTransaction{reader, verificationReceiptWriter{repos.Verification, repos.Audit, repos.Outbox}})
	}))
}

type artifactSignatureVerificationTransaction struct {
	reader verificationapp.ArtifactSignatureVerificationReader
	verificationReceiptWriter
}

func (t artifactSignatureVerificationTransaction) ResolveArtifactSignatureVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	s, e := t.reader.ResolveArtifactSignatureVerificationSubject(ctx, tenant, id)
	return s, mapSigningKeyWriteError(e)
}
func (t artifactSignatureVerificationTransaction) ReadArtifactSignatureVerification(ctx context.Context, s verificationapp.SubjectReference) (verificationapp.ArtifactSignatureVerificationSnapshot, error) {
	v, e := t.reader.ReadArtifactSignatureVerification(ctx, s)
	return v, mapSigningKeyWriteError(e)
}
func (t artifactSignatureVerificationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewCosignVerificationAuthorizer().Authorize(ctx, a, r)
}

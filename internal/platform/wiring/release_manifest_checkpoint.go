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

func BuildReleaseManifestCheckpointCommands(factory app.UnitOfWorkFactory) (*verificationapp.ReleaseManifestCheckpointCommands, error) {
	if factory == nil {
		return nil, errors.New("release manifest checkpoint transactions are required")
	}
	return verificationapp.NewReleaseManifestCheckpointCommands(verificationapp.ReleaseManifestCheckpointConfig{Transactions: releaseManifestCheckpointTransactions{factory}, Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Hasher: verificationCanonicalHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type releaseManifestCheckpointTransactions struct{ factory app.UnitOfWorkFactory }

func (t releaseManifestCheckpointTransactions) ExecuteReleaseManifestCheckpointVerification(ctx context.Context, fn func(context.Context, verificationapp.ReleaseManifestCheckpointTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		auditReader, auditOK := repos.Verification.(verificationapp.AuditChainVerificationReader)
		bundleReader, bundleOK := repos.Verification.(verificationapp.ReleaseBundleVerificationReader)
		if !auditOK || !bundleOK || repos.Audit == nil || repos.Outbox == nil {
			return app.ErrValidation
		}
		return fn(ctx, releaseManifestCheckpointTransaction{auditChainVerificationTransaction{auditReader, verificationReceiptWriter{repos.Verification, repos.Audit, repos.Outbox}}, bundleReader})
	}))
}

type releaseManifestCheckpointTransaction struct {
	auditChainVerificationTransaction
	bundleReader verificationapp.ReleaseBundleVerificationReader
}

func (t releaseManifestCheckpointTransaction) ResolveReleaseBundleVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	s, err := t.bundleReader.ResolveReleaseBundleVerificationSubject(ctx, tenant, id)
	return s, mapSigningKeyWriteError(err)
}
func (t releaseManifestCheckpointTransaction) ReadReleaseBundleVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.ReleaseBundleVerificationSnapshot, error) {
	s, err := t.bundleReader.ReadReleaseBundleVerification(ctx, subject)
	return s, mapSigningKeyWriteError(err)
}

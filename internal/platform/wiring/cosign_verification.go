package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/adapters/verification/cosignobjects"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func BuildCosignVerificationCommands(factory app.UnitOfWorkFactory, objects app.ObjectStore, verifier app.CosignPolicyVerifier) (*verificationapp.CosignVerificationCommands, error) {
	if factory == nil {
		return nil, errors.New("cosign verification transactions are required")
	}
	var bounded app.BoundedObjectReader
	if objects != nil {
		var ok bool
		bounded, ok = objects.(app.BoundedObjectReader)
		if !ok {
			return nil, errors.New("cosign verification requires bounded object reads")
		}
	}
	return verificationapp.NewCosignVerificationCommands(verificationapp.CosignVerificationConfig{Transactions: cosignVerificationTransactions{factory}, Authorizer: verificationquery.NewCosignVerificationAuthorizer(), Inspector: cosignobjects.Inspector{Objects: bounded, Verifier: verifier}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type cosignVerificationTransactions struct{ factory app.UnitOfWorkFactory }

func (t cosignVerificationTransactions) ExecuteCosignVerification(ctx context.Context, fn func(context.Context, verificationapp.CosignVerificationTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Verification.(verificationapp.CosignSnapshotReader)
		if !ok || repos.Integrity == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, cosignVerificationTransaction{reader: reader, integrity: repos.Integrity, verificationReceiptWriter: verificationReceiptWriter{verification: repos.Verification, audit: repos.Audit}})
	}))
}

type cosignVerificationTransaction struct {
	reader    verificationapp.CosignSnapshotReader
	integrity app.IntegrityRepository
	verificationReceiptWriter
}

func (t cosignVerificationTransaction) ResolveCosignSubject(ctx context.Context, tenant, id string) (verificationapp.CosignSubject, error) {
	s, e := t.reader.ResolveCosignSubject(ctx, tenant, id)
	return s, mapSigningKeyWriteError(e)
}
func (t cosignVerificationTransaction) ReadCosignSnapshot(ctx context.Context, s verificationapp.CosignSubject) (verificationapp.CosignSnapshot, error) {
	v, e := t.reader.ReadCosignSnapshot(ctx, s)
	return v, mapSigningKeyWriteError(e)
}
func (t cosignVerificationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewCosignVerificationAuthorizer().Authorize(ctx, a, r)
}
func (t cosignVerificationTransaction) InsertCosignVerification(ctx context.Context, r verificationdomain.CosignVerification) error {
	return mapSigningKeyWriteError(t.integrity.InsertCosignVerification(ctx, cosignVerificationToLegacy(r)))
}
func cosignVerificationToLegacy(r verificationdomain.CosignVerification) domain.CosignVerification {
	return domain.CosignVerificationFromContextModel(r)
}

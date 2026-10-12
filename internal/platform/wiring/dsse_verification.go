package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/adapters/verification/dsseobjects"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func BuildDSSEVerificationCommands(factory app.UnitOfWorkFactory, objects app.ObjectStore) (*verificationapp.DSSEVerificationCommands, error) {
	if factory == nil {
		return nil, errors.New("DSSE verification transactions are required")
	}
	var bounded app.BoundedObjectReader
	if objects != nil {
		var ok bool
		bounded, ok = objects.(app.BoundedObjectReader)
		if !ok {
			return nil, errors.New("DSSE verification requires bounded object reads")
		}
	}
	return verificationapp.NewDSSEVerificationCommands(verificationapp.DSSEVerificationConfig{Transactions: dsseVerificationTransactions{factory}, Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Verifier: dsseobjects.Inspector{Objects: bounded}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type dsseVerificationTransactions struct{ factory app.UnitOfWorkFactory }

func (t dsseVerificationTransactions) ExecuteDSSEVerification(ctx context.Context, command func(context.Context, verificationapp.DSSEVerificationTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Verification.(verificationapp.DSSEVerificationReader)
		if !ok || repos.Audit == nil || repos.Outbox == nil {
			return app.ErrValidation
		}
		return command(ctx, dsseVerificationTransaction{reader, verificationReceiptWriter{repos.Verification, repos.Audit, repos.Outbox}})
	}))
}

type dsseVerificationTransaction struct {
	reader verificationapp.DSSEVerificationReader
	verificationReceiptWriter
}

func (t dsseVerificationTransaction) ResolveDSSEVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	subject, err := t.reader.ResolveDSSEVerificationSubject(ctx, tenant, id)
	return subject, mapSigningKeyWriteError(err)
}
func (t dsseVerificationTransaction) ReadDSSEVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.DSSEVerificationSnapshot, error) {
	snapshot, err := t.reader.ReadDSSEVerification(ctx, subject)
	return snapshot, mapSigningKeyWriteError(err)
}
func (t dsseVerificationTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return verificationquery.NewEvidenceVerificationAuthorizer().Authorize(ctx, actor, request)
}

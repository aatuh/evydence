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

func BuildBackupVerificationCommands(factory app.UnitOfWorkFactory) (*verificationapp.BackupVerificationCommands, error) {
	if factory == nil {
		return nil, errors.New("backup verification transactions are required")
	}
	return verificationapp.NewBackupVerificationCommands(verificationapp.BackupVerificationConfig{Transactions: backupVerificationTransactions{factory}, Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type backupVerificationTransactions struct{ factory app.UnitOfWorkFactory }

func (t backupVerificationTransactions) ExecuteBackupVerification(ctx context.Context, fn func(context.Context, verificationapp.BackupVerificationTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Verification.(verificationapp.BackupVerificationReader)
		if !ok || repos.Audit == nil || repos.Outbox == nil {
			return app.ErrValidation
		}
		return fn(ctx, backupVerificationTransaction{reader, verificationReceiptWriter{repos.Verification, repos.Audit, repos.Outbox}})
	}))
}

type backupVerificationTransaction struct {
	reader verificationapp.BackupVerificationReader
	verificationReceiptWriter
}

func (t backupVerificationTransaction) ReadBackupVerification(ctx context.Context, s verificationapp.SubjectReference) (verificationapp.BackupVerificationSnapshot, error) {
	v, err := t.reader.ReadBackupVerification(ctx, s)
	return v, mapSigningKeyWriteError(err)
}
func (t backupVerificationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewEvidenceVerificationAuthorizer().Authorize(ctx, a, r)
}

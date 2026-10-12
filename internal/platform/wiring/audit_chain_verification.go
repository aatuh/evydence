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

func BuildAuditChainVerificationCommands(factory app.UnitOfWorkFactory) (*verificationapp.AuditChainVerificationCommands, error) {
	if factory == nil {
		return nil, errors.New("audit chain verification transactions are required")
	}
	return verificationapp.NewAuditChainVerificationCommands(verificationapp.AuditChainVerificationConfig{Transactions: auditChainVerificationTransactions{factory}, Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Hasher: verificationCanonicalHasher{}, Verifier: localed25519.PayloadVerifier{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type auditChainVerificationTransactions struct{ factory app.UnitOfWorkFactory }

func (t auditChainVerificationTransactions) ExecuteAuditChainVerification(ctx context.Context, fn func(context.Context, verificationapp.AuditChainVerificationTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Verification.(verificationapp.AuditChainVerificationReader)
		if !ok || repos.Audit == nil || repos.Outbox == nil {
			return app.ErrValidation
		}
		return fn(ctx, auditChainVerificationTransaction{reader, verificationReceiptWriter{repos.Verification, repos.Audit, repos.Outbox}})
	}))
}

type auditChainVerificationTransaction struct {
	reader verificationapp.AuditChainVerificationReader
	verificationReceiptWriter
}

func (t auditChainVerificationTransaction) LockAuditChainVerification(ctx context.Context, tenant string) (verificationapp.AuditChainVerificationView, error) {
	v, e := t.reader.LockAuditChainVerification(ctx, tenant)
	return v, mapSigningKeyWriteError(e)
}
func (t auditChainVerificationTransaction) ReadAuditChainVerificationPage(ctx context.Context, v verificationapp.AuditChainVerificationView, after *int64, budget int) (verificationapp.AuditChainVerificationPage, error) {
	p, e := t.reader.ReadAuditChainVerificationPage(ctx, v, after, budget)
	return p, mapSigningKeyWriteError(e)
}
func (t auditChainVerificationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewEvidenceVerificationAuthorizer().Authorize(ctx, a, r)
}

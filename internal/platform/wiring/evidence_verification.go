package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func BuildEvidenceVerificationCommands(factory app.UnitOfWorkFactory) (*verificationapp.EvidenceVerificationCommands, error) {
	if factory == nil {
		return nil, errors.New("evidence verification transactions are required")
	}
	return verificationapp.NewEvidenceVerificationCommands(verificationapp.EvidenceVerificationConfig{Transactions: evidenceVerificationTransactions{factory}, Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Hasher: evidenceCanonicalHasher{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

// Preserve the versioned wire representation while the core owns field rules.
type evidenceCanonicalHasher struct{}

func (evidenceCanonicalHasher) HashEvidence(ctx context.Context, item evidencedomain.EvidenceItem) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return application.NormalizedJSONHash(domain.EvidenceFromContextModel(evidencedomain.CanonicalEvidenceFields(item)))
}

type evidenceVerificationTransactions struct{ factory app.UnitOfWorkFactory }

func (t evidenceVerificationTransactions) ExecuteEvidenceVerification(ctx context.Context, command func(context.Context, verificationapp.EvidenceVerificationTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Verification.(verificationapp.EvidenceVerificationReader)
		if !ok || repos.Audit == nil || repos.Outbox == nil {
			return app.ErrValidation
		}
		return command(ctx, evidenceVerificationTransaction{reader: reader, verificationReceiptWriter: verificationReceiptWriter{verification: repos.Verification, audit: repos.Audit, outbox: repos.Outbox}})
	}))
}

type evidenceVerificationTransaction struct {
	reader verificationapp.EvidenceVerificationReader
	verificationReceiptWriter
}

func (t evidenceVerificationTransaction) ResolveEvidenceVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	subject, err := t.reader.ResolveEvidenceVerificationSubject(ctx, tenant, id)
	return subject, mapSigningKeyWriteError(err)
}
func (t evidenceVerificationTransaction) ReadEvidenceVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.EvidenceVerificationSnapshot, error) {
	snapshot, err := t.reader.ReadEvidenceVerification(ctx, subject)
	return snapshot, mapSigningKeyWriteError(err)
}
func (t evidenceVerificationTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return verificationquery.NewEvidenceVerificationAuthorizer().Authorize(ctx, actor, request)
}

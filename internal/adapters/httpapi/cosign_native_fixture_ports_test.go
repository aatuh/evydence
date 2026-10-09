package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/verification/cosignobjects"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type cosignFixtureRepository interface {
	verificationapp.CosignSnapshotReader
	verificationapp.CosignVerificationScopeLocker
}
type cosignFixtureTransactions struct{ catalogFixtureCommands }
type cosignFixtureTransaction struct {
	cosignFixtureRepository
	repos app.Repositories
}

func (f cosignFixtureTransactions) ExecuteCosignVerification(ctx context.Context, run func(context.Context, verificationapp.CosignVerificationTransaction) error) error {
	if ctx == nil || run == nil {
		return verificationapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return signingFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Verification.(cosignFixtureRepository)
		if !ok || r.Integrity == nil || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, cosignFixtureTransaction{reader, r})
	}))
}
func (t cosignFixtureTransaction) Authorize(ctx context.Context, actor domain.Actor, request application.AuthorizationRequest) error {
	return verificationquery.NewCosignVerificationAuthorizer().Authorize(ctx, actor, request)
}
func (t cosignFixtureTransaction) InsertVerificationResult(ctx context.Context, v verificationdomain.VerificationResult) error {
	return signingFixtureError(t.repos.Verification.InsertVerificationResult(ctx, domain.VerificationResultFromContextModel(v)))
}
func (t cosignFixtureTransaction) InsertCosignVerification(ctx context.Context, v verificationdomain.CosignVerification) error {
	return signingFixtureError(t.repos.Integrity.InsertCosignVerification(ctx, domain.CosignVerificationFromContextModel(v)))
}
func (t cosignFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := (governanceFixtureTransaction{audit: t.repos.Audit}).AppendAudit(ctx, e)
	return v, signingFixtureError(err)
}
func (f verificationCommandFixture) nativeCosign() (*verificationapp.CosignVerificationCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	// Ordinary fixtures have no configured trust policy. Use the actual offline
	// inspector's unavailable path, not a synthetic successful verification.
	return verificationapp.NewCosignVerificationCommands(verificationapp.CosignVerificationConfig{Transactions: cosignFixtureTransactions(f), Authorizer: verificationquery.NewCosignVerificationAuthorizer(), Inspector: cosignobjects.Inspector{}, Clock: clock, IDs: ids})
}

var _ verificationapp.CosignVerificationTransaction = cosignFixtureTransaction{}

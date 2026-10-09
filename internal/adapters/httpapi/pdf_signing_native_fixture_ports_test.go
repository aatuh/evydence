package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type pdfSigningNativeRepository interface {
	packageapp.PDFReportReader
	verificationapp.SigningOperationReader
	InsertFocusedPDFReportPackage(context.Context, packagedomain.PDFReportPackage) error
	InsertFocusedSigningOperation(context.Context, verificationdomain.Signature, verificationdomain.SigningOperation) error
}
type pdfSigningNativeTransactions struct {
	reportSigningFixtureCommands
	readOnly   bool
	authorizer application.Authorizer
}
type pdfSigningNativeTransaction struct {
	pdfSigningNativeRepository
	repos      app.Repositories
	objects    app.PayloadObjectStore
	readOnly   bool
	authorizer application.Authorizer
}

func (f pdfSigningNativeTransactions) execute(ctx context.Context, tenant string, fn func(context.Context, pdfSigningNativeTransaction) error) error {
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(pdfSigningNativeRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil || repos.Payloads == nil || repos.Outbox == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, pdfSigningNativeTransaction{r, repos, f.objects, f.readOnly, f.authorizer})
	})
}
func (f pdfSigningNativeTransactions) ExecutePDFReport(ctx context.Context, tenant string, fn func(context.Context, packageapp.PDFReportTransaction) error) error {
	return portalFixtureError(f.execute(ctx, tenant, func(ctx context.Context, tx pdfSigningNativeTransaction) error { return fn(ctx, tx) }))
}
func (f pdfSigningNativeTransactions) ExecuteSigningOperation(ctx context.Context, tenant string, fn func(context.Context, verificationapp.SigningOperationTransaction) error) error {
	return signingFixtureError(f.execute(ctx, tenant, func(ctx context.Context, tx pdfSigningNativeTransaction) error { return fn(ctx, tx) }))
}
func (tx pdfSigningNativeTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return tx.authorizer.Authorize(ctx, a, r)
}
func (tx pdfSigningNativeTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if tx.readOnly {
		panic("PDF/signing preflight appended audit")
	}
	return (portalFixtureTransaction{repos: tx.repos}).AppendAudit(ctx, e)
}
func (tx pdfSigningNativeTransaction) InsertPDFReportPackage(ctx context.Context, v packagedomain.PDFReportPackage) error {
	if tx.readOnly {
		panic("PDF preflight inserted report")
	}
	return portalFixtureError(tx.InsertFocusedPDFReportPackage(ctx, v))
}
func (tx pdfSigningNativeTransaction) InsertFocusedSigningOperation(ctx context.Context, s verificationdomain.Signature, v verificationdomain.SigningOperation) error {
	if tx.readOnly {
		panic("signing preflight inserted signature or receipt")
	}
	return tx.pdfSigningNativeRepository.InsertFocusedSigningOperation(ctx, s, v)
}
func (tx pdfSigningNativeTransaction) StagePDFReportPayload(ctx context.Context, tenant, digest string, raw []byte, at time.Time) (string, error) {
	if tx.readOnly {
		panic("PDF preflight staged payload")
	}
	if tx.objects == nil {
		return "", nil
	}
	source := app.BytesPayloadSource(raw)
	if source.Digest != digest {
		return "", app.ErrValidation
	}
	p, err := app.StageObjectPayload(ctx, tx.objects, tenant, "application/pdf", source, at)
	if err != nil {
		return "", err
	}
	if err := tx.repos.Payloads.RecordStagedObjectPayload(ctx, p); err != nil {
		return "", err
	}
	if err := tx.repos.Outbox.Enqueue(ctx, app.OutboxJob{ID: application.NewID("job"), TenantID: tenant, Kind: "finalize_payload", SubjectType: "object_payload", SubjectID: digest, Payload: map[string]any{"payload_digest": digest, "payload_lifecycle": app.PayloadLifecycleVersion}, CreatedAt: at}); err != nil {
		return "", err
	}
	return p.Reference(), nil
}

type pdfFixtureNativeHasher struct{ readOnly bool }

func (h pdfFixtureNativeHasher) HashPackageBytes(ctx context.Context, raw []byte) (string, error) {
	if h.readOnly {
		panic("PDF preflight hashed bytes")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return app.BytesPayloadSource(raw).Digest, nil
}

type signingFixtureNativeExecutor struct {
	client   app.SigningExecutor
	readOnly bool
}

func (f signingFixtureNativeExecutor) SignOperation(ctx context.Context, r verificationapp.ProviderSigningRequest) (verificationapp.ProviderSigningResult, error) {
	if f.readOnly {
		panic("signing preflight called provider")
	}
	v, err := f.client.Sign(ctx, app.SigningRequestFromVerification(r))
	if err != nil {
		return verificationapp.ProviderSigningResult{}, err
	}
	if err := verificationapp.ValidateProviderSigningResult(r, app.SigningResultToVerification(v)); err != nil {
		return verificationapp.ProviderSigningResult{}, err
	}
	return app.SigningResultToVerification(app.SanitizeSigningResultMetadata(v)), nil
}
func (f reportSigningFixtureCommands) nativePDF(readOnly bool) (*packageapp.PDFReportCommands, error) {
	a := packagequery.NewPDFReportAuthorizer()
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	return packageapp.NewPDFReportCommands(packageapp.PDFReportCommandConfig{Transactions: pdfSigningNativeTransactions{f, readOnly, a}, Authorizer: a, Hasher: pdfFixtureNativeHasher{readOnly}, Clock: clock, IDs: ids})
}
func (f reportSigningFixtureCommands) nativeSigning(readOnly bool) (*verificationapp.SigningOperationCommands, error) {
	a := verificationquery.NewSigningKeyAdminAuthorizer()
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	var signer verificationapp.ProviderSigningExecutor
	if f.signer != nil {
		signer = signingFixtureNativeExecutor{f.signer, readOnly}
	}
	return verificationapp.NewSigningOperationCommands(verificationapp.SigningOperationConfig{Transactions: pdfSigningNativeTransactions{f, readOnly, a}, Authorizer: a, Signer: signer, Clock: clock, IDs: ids})
}

// Dependencies live in the existing test-only ports, not a Server/Ledger field
// or global registry. Explicit non-fixture command implementations are retained.
func (s *Server) bindReportSigningFixtureResources(objects app.PayloadObjectStore, signer app.SigningExecutor) {
	if f, ok := s.pdfReportCommands.(reportSigningFixtureCommands); ok {
		f.objects, f.signer = objects, signer
		s.pdfReportCommands = f
	}
	if f, ok := s.signingOperationCommands.(reportSigningFixtureCommands); ok {
		f.objects, f.signer = objects, signer
		s.signingOperationCommands = f
	}
}

func signingFixtureError(err error) error {
	switch {
	case errors.Is(err, app.ErrNotFound):
		return verificationapp.ErrNotFound
	case errors.Is(err, app.ErrValidation):
		return verificationapp.ErrValidation
	case errors.Is(err, app.ErrConflict):
		return verificationapp.ErrConflict
	case errors.Is(err, app.ErrVerificationFailed):
		return verificationapp.ErrVerificationFailed
	default:
		return err
	}
}

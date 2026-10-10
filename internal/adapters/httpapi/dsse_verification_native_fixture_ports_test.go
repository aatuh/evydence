package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/verification/dsseobjects"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type dsseVerificationFixtureTransactions struct{ catalogFixtureCommands }
type dsseVerificationFixtureTransaction struct {
	reader  verificationapp.DSSEVerificationReader
	receipt releaseBundleVerificationFixtureTransaction
}

func (f dsseVerificationFixtureTransactions) ExecuteDSSEVerification(ctx context.Context, run func(context.Context, verificationapp.DSSEVerificationTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return verificationapp.ErrValidation
	}
	return signingFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Verification.(verificationapp.DSSEVerificationReader)
		if !ok || r.Audit == nil || r.Outbox == nil {
			return app.ErrValidation
		}
		return run(ctx, dsseVerificationFixtureTransaction{reader, releaseBundleVerificationFixtureTransaction{verification: r.Verification, audit: r.Audit, outbox: r.Outbox}})
	}))
}
func (t dsseVerificationFixtureTransaction) ResolveDSSEVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	v, err := t.reader.ResolveDSSEVerificationSubject(ctx, tenant, id)
	return v, signingFixtureError(err)
}
func (t dsseVerificationFixtureTransaction) ReadDSSEVerification(ctx context.Context, s verificationapp.SubjectReference) (verificationapp.DSSEVerificationSnapshot, error) {
	v, err := t.reader.ReadDSSEVerification(ctx, s)
	return v, signingFixtureError(err)
}
func (t dsseVerificationFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewEvidenceVerificationAuthorizer().Authorize(ctx, a, r)
}
func (t dsseVerificationFixtureTransaction) InsertVerificationResult(ctx context.Context, v verificationdomain.VerificationResult) error {
	return t.receipt.InsertVerificationResult(ctx, v)
}
func (t dsseVerificationFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return t.receipt.AppendAudit(ctx, e)
}
func (t dsseVerificationFixtureTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	return t.receipt.EnqueueOutbox(ctx, e)
}
func (f verificationCommandFixture) nativeDSSE(guard bool) (*verificationapp.DSSEVerificationCommands, error) {
	if !guard && f.dsseObjects == nil {
		return nil, verificationapp.ErrValidation
	}
	clock, ids := questionnaireNativeFixtureClockIDs(guard)
	return verificationapp.NewDSSEVerificationCommands(verificationapp.DSSEVerificationConfig{Transactions: dsseVerificationFixtureTransactions{f.catalogFixtureCommands}, Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(), Verifier: dsseobjects.Inspector{Objects: f.dsseObjects}, Clock: clock, IDs: ids})
}

func (f verificationCommandFixture) authorizeCurrentSubjectScope(ctx context.Context, a domain.Actor, kind, id string) error {
	policy := verificationquery.NewEvidenceVerificationAuthorizer()
	if err := policy.Authorize(ctx, a, application.AuthorizationRequest{Scope: app.ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return mapVerificationCommandError(err)
	}
	kind, id, err := verificationapp.NormalizeSubjectVerificationInput(kind, id)
	if err != nil {
		return mapVerificationCommandError(err)
	}
	if ctx == nil || f.commandLedger(ctx) == nil {
		return app.ErrValidation
	}
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Verification.(verificationapp.SubjectVerificationScopeReader)
		if !ok {
			return app.ErrValidation
		}
		subject, err := reader.ResolveSubjectVerificationScope(ctx, a.TenantID, kind, id)
		if err != nil {
			return err
		}
		return mapVerificationCommandError(policy.Authorize(ctx, a, application.AuthorizationRequest{Scope: app.ScopeVerifyRead, Resources: subject.Resources, TenantWide: subject.Resources == (application.ResourceReferences{})}))
	})
}

// Payload storage is an explicit fixture resource, never read from Ledger
// configuration. Rebinding preserves it and does not replace custom ports.
func (s *Server) bindDSSEVerificationFixtureResources(objects app.BoundedObjectReader) {
	if f, ok := s.dsseVerification.(verificationCommandFixture); ok {
		f.dsseObjects = objects
		s.dsseVerification = f
	}
	if f, ok := s.subjectVerification.(verificationCommandFixture); ok {
		f.dsseObjects = objects
		s.subjectVerification = f
	}
}

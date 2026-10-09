package wiring

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type subjectVerificationScopeTransactions struct{ factory app.UnitOfWorkFactory }

func (t subjectVerificationScopeTransactions) ExecuteSubjectVerificationScope(ctx context.Context, command func(context.Context, verificationapp.SubjectVerificationScopeTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Verification.(verificationapp.SubjectVerificationScopeReader)
		if !ok {
			return app.ErrValidation
		}
		return command(ctx, subjectVerificationScopeTransaction{reader})
	}))
}

type subjectVerificationScopeTransaction struct {
	reader verificationapp.SubjectVerificationScopeReader
}

func (t subjectVerificationScopeTransaction) ResolveSubjectVerificationScope(ctx context.Context, tenant, kind, id string) (verificationapp.SubjectReference, error) {
	subject, err := t.reader.ResolveSubjectVerificationScope(ctx, tenant, kind, id)
	return subject, mapSigningKeyWriteError(err)
}
func (t subjectVerificationScopeTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if request.Resources.ArtifactID != "" {
		return verificationquery.NewCosignVerificationAuthorizer().Authorize(ctx, actor, request)
	}
	return verificationquery.NewEvidenceVerificationAuthorizer().Authorize(ctx, actor, request)
}

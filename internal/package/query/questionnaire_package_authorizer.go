package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewQuestionnairePackageAuthorizer() application.Authorizer {
	return questionnairePackageAuthorizer{}
}

type questionnairePackageAuthorizer struct{}

func (questionnairePackageAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Resources.CustomerPackageID != "" {
		return (packageAccessAuthorizer{scope: "package:write"}).Authorize(ctx, a, r)
	}
	return (questionnaireScopeAuthorizer{scope: "package:write"}).Authorize(ctx, a, r)
}

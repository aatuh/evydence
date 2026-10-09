package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewArtifactReadAuthorizer(reader ArtifactPointReader) (application.Authorizer, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return artifactReadAuthorizer{reader}, nil
}

type artifactReadAuthorizer struct{ reader ArtifactPointReader }

func (a artifactReadAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, r application.AuthorizationRequest) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if r.Scope != "evidence:read" || !actor.HasScope(r.Scope) && !actor.HasScope("admin") {
		return application.ErrForbidden
	}
	if r.ScopeOnly || r.TenantWide || r.Resources.ArtifactID == "" || r.Resources != (application.ResourceReferences{ArtifactID: r.Resources.ArtifactID}) {
		return application.ErrForbidden
	}
	return authorizeArtifactGrant(ctx, actor, r.Scope, r.Resources.ArtifactID, a.reader)
}

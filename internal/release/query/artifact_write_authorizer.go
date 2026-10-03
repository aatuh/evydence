package query

import (
	"context"
	"errors"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewArtifactWriteAuthorizer permits creation with evidence:write scope, but
// requires a current artifact association before a human can reuse a digest.
func NewArtifactWriteAuthorizer(artifacts ArtifactPointReader) (application.Authorizer, error) {
	if artifacts == nil {
		return nil, ErrValidation
	}
	return artifactWriteAuthorizer{artifacts: artifacts}, nil
}

type artifactWriteAuthorizer struct{ artifacts ArtifactPointReader }

func (a artifactWriteAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if request.Scope != "evidence:write" || !actor.HasScope(request.Scope) && !actor.HasScope("admin") {
		return application.ErrForbidden
	}
	if request.ScopeOnly && !request.TenantWide && request.Resources == (application.ResourceReferences{}) {
		return nil
	}
	refs := request.Resources
	if request.TenantWide || request.ScopeOnly || refs.ArtifactID == "" || refs != (application.ResourceReferences{ArtifactID: refs.ArtifactID}) {
		return application.ErrForbidden
	}
	return authorizeArtifactGrant(ctx, actor, request.Scope, refs.ArtifactID, a.artifacts)
}

func authorizeArtifactGrant(ctx context.Context, actor identitydomain.Actor, scope, artifactID string, reader ArtifactPointReader) error {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return nil
	}
	tenantWide, products, projects, releases := artifactVisibilityForScope(actor, scope)
	if !tenantWide && len(products) == 0 && len(projects) == 0 && len(releases) == 0 {
		return application.ErrForbidden
	}
	point, err := reader.GetArtifactPoint(ctx, ArtifactReadRequest{
		TenantID: actor.TenantID, ID: artifactID, TenantWide: tenantWide,
		AllowedProductIDs: products, AllowedProjectIDs: projects, AllowedReleaseIDs: releases,
	})
	if errors.Is(err, ErrNotFound) {
		return application.ErrForbidden
	}
	if err != nil {
		return err
	}
	if point.Artifact.ID != artifactID || point.Artifact.TenantID != actor.TenantID || !point.Visible {
		return application.ErrForbidden
	}
	return nil
}

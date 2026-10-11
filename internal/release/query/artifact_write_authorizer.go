package query

import (
	"context"
	"errors"

	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewArtifactWriteAuthorizer permits creation with evidence:write scope, but
// requires a current artifact association before a human can reuse a digest.
func NewArtifactWriteAuthorizer(artifacts ArtifactPointReader) (application.Authorizer, error) {
	return newArtifactWriteAuthorizer(artifacts, false)
}

// Security scan uploads reuse the association policy with security:write.
func NewArtifactSecurityWriteAuthorizer(artifacts ArtifactPointReader) (application.Authorizer, error) {
	return newArtifactWriteAuthorizer(artifacts, true)
}

func newArtifactWriteAuthorizer(artifacts ArtifactPointReader, security bool) (application.Authorizer, error) {
	if artifacts == nil {
		return nil, ErrValidation
	}
	return artifactWriteAuthorizer{artifacts: artifacts, security: security}, nil
}

type artifactWriteAuthorizer struct {
	artifacts ArtifactPointReader
	security  bool
}

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
	if request.Scope != "" || a.security && request.Action != authz.ActionSecurityEvidenceWrite ||
		!a.security && request.Action != authz.ActionArtifactsWrite && request.Action != authz.ActionEvidenceWrite {
		return application.ErrForbidden
	}
	if request.ScopeOnly && !request.TenantWide && request.Resources == (application.ResourceReferences{}) {
		return authz.Authorize(ctx, actor, authz.Request{Action: request.Action, Evaluation: authz.ScopeEvaluation})
	}
	refs := request.Resources
	if request.TenantWide || request.ScopeOnly || refs.ArtifactID == "" || refs != (application.ResourceReferences{ArtifactID: refs.ArtifactID}) {
		return application.ErrForbidden
	}
	return authorizeArtifactGrant(ctx, actor, request.Action, refs.ArtifactID, a.artifacts)
}

func authorizeArtifactGrant(ctx context.Context, actor identitydomain.Actor, action authz.Action, artifactID string, reader ArtifactPointReader) error {
	visibility := authz.ArtifactVisibilityFunc(func(ctx context.Context, r authz.ArtifactVisibilityRequest) (bool, error) {
		point, err := reader.GetArtifactPoint(ctx, ArtifactReadRequest{
			TenantID: r.TenantID, ID: r.ArtifactID, TenantWide: r.TenantWide,
			AllowedProductIDs: r.AllowedProductIDs, AllowedProjectIDs: r.AllowedProjectIDs, AllowedReleaseIDs: r.AllowedReleaseIDs,
		})
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return point.Artifact.ID == r.ArtifactID && point.Artifact.TenantID == r.TenantID && point.Visible, nil
	})
	return authz.AuthorizeWithArtifactVisibility(ctx, actor, authz.Request{Action: action, Resources: authz.ResourceReferences{ArtifactID: artifactID}}, visibility)
}

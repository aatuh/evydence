package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewCandidateAuthorizer enforces release-write parent grants and current
// artifact associations through a transaction-bound identifier-only reader.
func NewCandidateAuthorizer(artifacts ArtifactPointReader) (application.Authorizer, error) {
	if artifacts == nil {
		return nil, ErrValidation
	}
	return candidateAuthorizer{catalog: NewCatalogAuthorizer(), artifacts: artifacts}, nil
}

type candidateAuthorizer struct {
	catalog   application.Authorizer
	artifacts ArtifactPointReader
}

func (a candidateAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if request.Scope != "release:write" {
		return application.ErrForbidden
	}
	refs := request.Resources
	if request.ScopeOnly || request.TenantWide || refs.ArtifactID == "" || refs != (application.ResourceReferences{ArtifactID: refs.ArtifactID}) {
		return a.catalog.Authorize(ctx, actor, request)
	}
	if err := a.catalog.Authorize(ctx, actor, application.AuthorizationRequest{Scope: request.Scope, ScopeOnly: true}); err != nil {
		return err
	}
	return authorizeArtifactGrant(ctx, actor, request.Scope, refs.ArtifactID, a.artifacts)
}

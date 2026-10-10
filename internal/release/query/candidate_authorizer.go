package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
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
	if request.Scope != "" || request.Action != authz.ActionReleaseCandidatesCreate {
		return application.ErrForbidden
	}
	refs := request.Resources
	if request.ScopeOnly || request.TenantWide || refs.ArtifactID == "" || refs != (application.ResourceReferences{ArtifactID: refs.ArtifactID}) {
		return a.catalog.Authorize(ctx, actor, request)
	}
	if err := a.catalog.Authorize(ctx, actor, application.AuthorizationRequest{Action: request.Action, ScopeOnly: true}); err != nil {
		return err
	}
	definition, ok := authz.DefinitionFor(request.Action)
	if !ok {
		return application.ErrForbidden
	}
	return authorizeArtifactGrant(ctx, actor, definition.Scope, refs.ArtifactID, a.artifacts)
}

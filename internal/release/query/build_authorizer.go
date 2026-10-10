package query

import (
	"context"

	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewBuildAuthorizer checks build parents through catalog grants and linked
// output artifacts through a current tenant-bound association query.
func NewBuildAuthorizer(artifacts ArtifactPointReader) (application.Authorizer, error) {
	if artifacts == nil {
		return nil, ErrValidation
	}
	return buildAuthorizer{artifacts: artifacts, action: authz.ActionBuildsCreate}, nil
}

type buildAuthorizer struct {
	artifacts ArtifactPointReader
	action    authz.Action
}

// NewBuildAttestationAuthorizer accepts the build identity resolved and checked
// by the attestation command, while retaining parent and current artifact-grant
// policy. A build ID alone never conveys authority.
func NewBuildAttestationAuthorizer(artifacts ArtifactPointReader) (application.Authorizer, error) {
	if artifacts == nil {
		return nil, ErrValidation
	}
	return buildAuthorizer{artifacts: artifacts, action: authz.ActionBuildAttestationsCreate}, nil
}

func (a buildAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if request.Scope != "" || request.Action != a.action {
		return application.ErrForbidden
	}
	refs := request.Resources
	if request.ScopeOnly || request.TenantWide || refs.ArtifactID == "" || refs != (application.ResourceReferences{ArtifactID: refs.ArtifactID}) {
		return (catalogAuthorizer{}).Authorize(ctx, actor, request)
	}
	if err := (catalogAuthorizer{}).Authorize(ctx, actor, application.AuthorizationRequest{Action: request.Action, ScopeOnly: true}); err != nil {
		return err
	}
	definition, ok := authz.DefinitionFor(a.action)
	if !ok {
		return application.ErrForbidden
	}
	return authorizeArtifactGrant(ctx, actor, definition.Scope, refs.ArtifactID, a.artifacts)
}

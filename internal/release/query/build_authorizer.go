package query

import (
	"context"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewBuildAuthorizer checks build parents through catalog grants and linked
// output artifacts through a current tenant-bound association query.
func NewBuildAuthorizer(artifacts ArtifactPointReader) (application.Authorizer, error) {
	if artifacts == nil {
		return nil, ErrValidation
	}
	return buildAuthorizer{catalog: NewCatalogAuthorizer(), artifacts: artifacts}, nil
}

type buildAuthorizer struct {
	catalog   application.Authorizer
	artifacts ArtifactPointReader
}

// NewBuildAttestationAuthorizer accepts the build identity resolved and checked
// by the attestation command, while retaining parent and current artifact-grant
// policy. A build ID alone never conveys authority.
func NewBuildAttestationAuthorizer(artifacts ArtifactPointReader) (application.Authorizer, error) {
	base, err := NewBuildAuthorizer(artifacts)
	if err != nil {
		return nil, err
	}
	return buildAttestationAuthorizer{base}, nil
}

type buildAttestationAuthorizer struct{ base application.Authorizer }

func (a buildAttestationAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	refs := request.Resources
	if refs.BuildID != "" {
		if refs.ProductID == "" || refs.ProjectID == "" || refs.ReleaseID == "" || refs != (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID}) {
			return application.ErrForbidden
		}
		request.Resources.BuildID = ""
	}
	return a.base.Authorize(ctx, actor, request)
}

func (a buildAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if request.Scope != "build:write" {
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

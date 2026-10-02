package query

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// EvidenceCreationScopeReader resolves only coherent tenant-owned parent
// coordinates. Transaction implementations keep those parents locked through
// the evidence insert; no evidence or parent metadata is exposed here.
type EvidenceCreationScopeReader interface {
	ResolveEvidenceCreationScope(context.Context, string, application.ResourceReferences) (application.ResourceReferences, error)
}

func NewEvidenceCreationAuthorizer(reader EvidenceCreationScopeReader, artifactPolicy application.Authorizer) (application.Authorizer, error) {
	if reader == nil || artifactPolicy == nil {
		return nil, ErrValidation
	}
	return evidenceCreationAuthorizer{reader, artifactPolicy}, nil
}

type evidenceCreationAuthorizer struct {
	reader    EvidenceCreationScopeReader
	artifacts application.Authorizer
}

func (a evidenceCreationAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
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
	if request.TenantWide {
		return application.ErrForbidden
	}
	refs := request.Resources
	if request.ScopeOnly {
		if refs != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		return nil
	}
	if refs.ArtifactID != "" {
		if refs != (application.ResourceReferences{ArtifactID: refs.ArtifactID}) {
			return application.ErrForbidden
		}
		if !validCreationCoordinate(actor.TenantID) || !validCreationCoordinate(refs.ArtifactID) {
			return ErrValidation
		}
		return a.artifacts.Authorize(ctx, actor, request)
	}
	if !creationParentReferences(refs) {
		return application.ErrForbidden
	}
	if !validCreationCoordinate(actor.TenantID) || !validCreationCoordinates(refs) {
		return ErrValidation
	}
	resolved, err := a.reader.ResolveEvidenceCreationScope(ctx, actor.TenantID, refs)
	if err != nil {
		return err
	}
	if !validCreationResolution(refs, resolved) {
		return ErrConflict
	}
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return nil
	}
	for _, grant := range actor.ResourceGrants {
		allowed := false
		for _, scope := range grant.Scopes {
			if scope == request.Scope || scope == "admin" || scope == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return nil
			}
		case "product":
			if resolved.ProductID != "" && grant.ResourceID == resolved.ProductID {
				return nil
			}
		case "project":
			if resolved.ProjectID != "" && grant.ResourceID == resolved.ProjectID {
				return nil
			}
		case "release":
			if resolved.ReleaseID != "" && grant.ResourceID == resolved.ReleaseID {
				return nil
			}
		}
	}
	return application.ErrForbidden
}

func creationParentReferences(r application.ResourceReferences) bool {
	return r == (application.ResourceReferences{ProductID: r.ProductID, ProjectID: r.ProjectID, ReleaseID: r.ReleaseID, BuildID: r.BuildID, DeploymentID: r.DeploymentID})
}
func validCreationCoordinate(id string) bool {
	return validEvidenceReadID(id) && strings.TrimSpace(id) == id
}
func validCreationCoordinates(r application.ResourceReferences) bool {
	for _, id := range []string{r.ProductID, r.ProjectID, r.ReleaseID, r.BuildID, r.DeploymentID} {
		if id != "" && !validCreationCoordinate(id) {
			return false
		}
	}
	return true
}
func validCreationResolution(request, resolved application.ResourceReferences) bool {
	if !creationParentReferences(resolved) || !validCreationCoordinates(resolved) || request.BuildID != resolved.BuildID || request.DeploymentID != resolved.DeploymentID {
		return false
	}
	if request.ProductID != "" && request.ProductID != resolved.ProductID || request.ProjectID != "" && request.ProjectID != resolved.ProjectID || request.ReleaseID != "" && request.ReleaseID != resolved.ReleaseID {
		return false
	}
	if request == (application.ResourceReferences{}) {
		return resolved == request
	}
	if resolved.ProductID == "" || (request.ProjectID != "" || request.BuildID != "") && resolved.ProjectID == "" || (request.ReleaseID != "" || request.BuildID != "" || request.DeploymentID != "") && resolved.ReleaseID == "" {
		return false
	}
	if request.ProjectID == "" && request.BuildID == "" && resolved.ProjectID != "" || request.ReleaseID == "" && request.BuildID == "" && request.DeploymentID == "" && resolved.ReleaseID != "" {
		return false
	}
	return true
}

package app

import (
	"context"
	"sort"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Artifact scopes filter the association BEFORE its grant predicate. No
// artifact metadata or list of associations crosses this port.
type ControlEvidenceArtifactGrantRequest struct {
	TenantID, ArtifactID, ProductID, ReleaseID              string
	AllowedProductIDs, AllowedProjectIDs, AllowedReleaseIDs []string
}
type ControlEvidenceArtifactGrantReader interface {
	ControlEvidenceArtifactVisible(context.Context, ControlEvidenceArtifactGrantRequest) (bool, error)
}

func NewControlEvidenceWriteAuthorizer(reader ControlEvidenceArtifactGrantReader) (application.Authorizer, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return controlEvidenceWriteAuthorizer{reader}, nil
}

type controlEvidenceWriteAuthorizer struct {
	artifacts ControlEvidenceArtifactGrantReader
}

func (a controlEvidenceWriteAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, r application.AuthorizationRequest) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if r.Scope != ScopeControlsWrite || !actor.HasScope(r.Scope) && !actor.HasScope("admin") {
		return application.ErrForbidden
	}
	refs := r.Resources
	if r.ScopeOnly {
		if r.TenantWide || refs != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		return nil
	}
	if r.TenantWide && refs != (application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	if refs.ArtifactID != "" {
		if refs != (application.ResourceReferences{ArtifactID: refs.ArtifactID, ProductID: refs.ProductID, ReleaseID: refs.ReleaseID}) {
			return application.ErrForbidden
		}
	} else if refs != (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID}) || refs.ProductID == "" && (refs.ProjectID != "" || refs.ReleaseID != "") {
		return application.ErrForbidden
	}
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return nil
	}
	products, projects, releases := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, grant := range actor.ResourceGrants {
		allowed := false
		for _, scope := range grant.Scopes {
			if scope == ScopeControlsWrite || scope == "admin" || scope == "*" {
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
			if grant.ResourceID != "" {
				products[grant.ResourceID] = struct{}{}
			}
		case "project":
			if grant.ResourceID != "" {
				projects[grant.ResourceID] = struct{}{}
			}
		case "release":
			if grant.ResourceID != "" {
				releases[grant.ResourceID] = struct{}{}
			}
		}
	}
	if r.TenantWide {
		return application.ErrForbidden
	}
	if refs.ArtifactID == "" {
		if _, ok := products[refs.ProductID]; ok && refs.ProductID != "" {
			return nil
		}
		if _, ok := projects[refs.ProjectID]; ok && refs.ProjectID != "" {
			return nil
		}
		if _, ok := releases[refs.ReleaseID]; ok && refs.ReleaseID != "" {
			return nil
		}
		return application.ErrForbidden
	}
	if len(products)+len(projects)+len(releases) == 0 {
		return application.ErrForbidden
	}
	request := ControlEvidenceArtifactGrantRequest{TenantID: actor.TenantID, ArtifactID: refs.ArtifactID, ProductID: refs.ProductID, ReleaseID: refs.ReleaseID, AllowedProductIDs: sortedControlGrantIDs(products), AllowedProjectIDs: sortedControlGrantIDs(projects), AllowedReleaseIDs: sortedControlGrantIDs(releases)}
	if !ValidControlEvidenceArtifactGrantRequest(request) {
		return ErrValidation
	}
	visible, err := a.artifacts.ControlEvidenceArtifactVisible(ctx, request)
	if err != nil {
		return err
	}
	if !visible {
		return application.ErrForbidden
	}
	return nil
}

// ValidControlEvidenceArtifactGrantRequest also protects direct persistence
// port callers. Association filtering accepts at most 4096 grant identities
// and 64 KiB combined identity text, never an unbounded set of query arguments.
func ValidControlEvidenceArtifactGrantRequest(r ControlEvidenceArtifactGrantRequest) bool {
	if !validControlText(r.TenantID, 1024, true) || !validControlText(r.ArtifactID, 1024, true) || !validControlText(r.ProductID, 1024, false) || !validControlText(r.ReleaseID, 1024, false) {
		return false
	}
	count, bytes := 0, 0
	for _, ids := range [][]string{r.AllowedProductIDs, r.AllowedProjectIDs, r.AllowedReleaseIDs} {
		if len(ids) > 4096-count {
			return false
		}
		count += len(ids)
		for _, id := range ids {
			if !validControlText(id, 1024, true) || len(id) > 65536-bytes {
				return false
			}
			bytes += len(id)
		}
	}
	return count > 0
}

func sortedControlGrantIDs(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

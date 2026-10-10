package authz

import identitydomain "github.com/aatuh/evydence/internal/identity/domain"

func authorizeCatalogResource(actor identitydomain.Actor, scope string, request Request) error {
	refs := request.Resources
	if refs.TenantID != "" && refs.TenantID != actor.TenantID {
		return ErrForbidden
	}
	refs.TenantID = ""
	if !actor.HasScope(scope) && !actor.HasScope("admin") {
		return ErrForbidden
	}
	switch request.Evaluation {
	case ScopeEvaluation:
		if refs != (ResourceReferences{}) {
			return ErrForbidden
		}
		return nil
	case TenantEvaluation:
		if refs != (ResourceReferences{}) {
			return ErrForbidden
		}
		return authorizeCurrentGrant(actor, scope, ResourceReferences{}, true)
	case ResolvedEvaluation:
		if !validCatalogResources(request.Action, refs) {
			return ErrForbidden
		}
		return authorizeCurrentGrant(actor, scope, refs, false)
	default:
		return ErrForbidden
	}
}

func validCatalogResources(action Action, refs ResourceReferences) bool {
	switch action {
	case ActionProductsRead, ActionProjectsCreate:
		return refs.ProductID != "" && refs == (ResourceReferences{ProductID: refs.ProductID})
	case ActionReleasesManage:
		return refs.ProductID != "" && (refs == (ResourceReferences{ProductID: refs.ProductID}) ||
			refs.ReleaseID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID}))
	case ActionProjectsRead:
		return refs.ProductID != "" && refs.ProjectID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID})
	case ActionReleasesRead, ActionReleaseCandidatesCreate:
		return refs.ProductID != "" && refs.ReleaseID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID})
	case ActionBuildsRead, ActionBuildAttestationsCreate:
		return refs.ProductID != "" && refs.ProjectID != "" && refs.ReleaseID != "" && refs.BuildID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID})
	case ActionBuildsCreate:
		return refs.ProductID != "" && refs.ProjectID != "" && refs.ReleaseID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID})
	default:
		return false
	}
}

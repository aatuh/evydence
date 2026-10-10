package authz

import identitydomain "github.com/aatuh/evydence/internal/identity/domain"

func authorizeResource(actor identitydomain.Actor, scope string, request Request) error {
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
		if !allowsTenantResourceEvaluation(request.Action) || refs != (ResourceReferences{}) {
			return ErrForbidden
		}
		return authorizeCurrentGrant(actor, scope, ResourceReferences{}, true)
	case ResolvedEvaluation:
		if !validResourceReferences(request.Action, refs) {
			return ErrForbidden
		}
		return authorizeCurrentGrant(actor, scope, refs, false)
	default:
		return ErrForbidden
	}
}

func allowsTenantResourceEvaluation(action Action) bool {
	switch action {
	case ActionProductsRead, ActionProjectsRead, ActionProjectsCreate,
		ActionReleasesRead, ActionReleasesManage, ActionBuildsRead, ActionBuildsCreate,
		ActionBuildAttestationsCreate, ActionReleaseCandidatesCreate,
		ActionEnvironmentsRead, ActionDeploymentsRead, ActionIncidentsManage,
		ActionApprovalsRecord, ActionWaiversManage, ActionVulnerabilityWorkflowsRecord, ActionCustomPoliciesCreate:
		return true
	default:
		return false
	}
}

func validResourceReferences(action Action, refs ResourceReferences) bool {
	switch action {
	case ActionEnvironmentsCreate:
		return refs.ProductID != "" && refs == (ResourceReferences{ProductID: refs.ProductID})
	case ActionEnvironmentsRead:
		return refs.ProductID != "" && refs.EnvironmentID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, EnvironmentID: refs.EnvironmentID})
	case ActionDeploymentsRecord:
		return refs.ProductID != "" && refs.ReleaseID != "" && refs.EnvironmentID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID, EnvironmentID: refs.EnvironmentID})
	case ActionDeploymentsRead:
		return refs.ProductID != "" && refs.ReleaseID != "" && refs.EnvironmentID != "" && refs.DeploymentID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID, EnvironmentID: refs.EnvironmentID, DeploymentID: refs.DeploymentID})
	case ActionIncidentsManage:
		return refs.ProductID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID})
	case ActionVulnerabilityDecisionsRecord, ActionApprovalsRecord, ActionWaiversManage,
		ActionExceptionsManage, ActionVulnerabilityWorkflowsRecord, ActionPolicyEvaluationsCreate,
		ActionCustomPoliciesCreate, ActionCustomPoliciesEvaluate:
		return refs.ProductID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID})
	default:
		return validCatalogResources(action, refs)
	}
}

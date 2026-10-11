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
		ActionApprovalsRecord, ActionWaiversManage, ActionVulnerabilityWorkflowsRecord, ActionCustomPoliciesCreate,
		ActionVulnerabilityDecisionsRead, ActionExceptionsRead, ActionControlEvidenceRead,
		ActionVulnerabilityDecisionSummaryRead, ActionReleaseReadinessRead, ActionReleaseSecuritySummaryRead, ActionControlEvidenceLink,
		ActionEvidenceRead, ActionSBOMsRead, ActionVEXDocumentsRead, ActionOpenAPIContractsRead,
		ActionVulnerabilityScansRead, ActionEvidenceLifecycleRead, ActionSBOMComponentsRead, ActionVEXPreviewRead:
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
	case ActionVulnerabilityDecisionsRead:
		return refs.ProductID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID})
	case ActionExceptionsRead, ActionVulnerabilityDecisionSummaryRead, ActionReleaseReadinessRead, ActionReleaseSecuritySummaryRead:
		return refs.ProductID != "" && refs.ReleaseID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID})
	case ActionControlEvidenceRead:
		return refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID})
	case ActionControlEvidenceLink:
		if refs.ArtifactID != "" {
			return refs == (ResourceReferences{ArtifactID: refs.ArtifactID, ProductID: refs.ProductID, ReleaseID: refs.ReleaseID})
		}
		return refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID}) &&
			(refs.ProductID != "" || refs.ProjectID == "" && refs.ReleaseID == "")
	case ActionEvidenceWrite, ActionSecurityEvidenceWrite:
		if refs != (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID}) {
			return false
		}
		if refs == (ResourceReferences{}) {
			return true
		}
		return refs.ProductID != "" && (refs.BuildID == "" || refs.ProjectID != "" && refs.ReleaseID != "") && (refs.DeploymentID == "" || refs.ReleaseID != "")
	case ActionEvidenceRead, ActionSBOMsRead, ActionVEXDocumentsRead, ActionOpenAPIContractsRead,
		ActionVulnerabilityScansRead, ActionEvidenceLifecycleRead, ActionSBOMComponentsRead,
		ActionVEXPreviewRead, ActionEvidenceDiffsCreate:
		return refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID})
	default:
		return validCatalogResources(action, refs)
	}
}

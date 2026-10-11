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
		if err := authorizeCurrentGrant(actor, scope, refs, false); err == nil {
			return nil
		}
		return authorizePackageGrant(actor, scope, request.Action, refs)
	default:
		return ErrForbidden
	}
}

func allowsTenantResourceEvaluation(action Action) bool {
	switch action {
	case ActionAnswerLibraryEntriesRead, ActionPortalAccessRead, ActionEvidenceSummariesCreate, ActionAnomalyReportsGenerate:
		return true
	case ActionPDFReportsGenerate, ActionGraphSnapshotsCreate, ActionQuestionnaireDraftsCreate, ActionAnswerLibraryEntriesCreate, ActionQuestionnairePackagesCreate:
		return true
	case ActionControlCoverageReportRead:
		return true
	case ActionEvidenceVerify, ActionDSSEVerify, ActionAuditChainVerify, ActionMerkleBatchVerify,
		ActionMerkleCheckpointVerify, ActionReleaseManifestCheckpointVerify, ActionBackupManifestVerify, ActionArtifactSignaturesRead:
		return true
	case ActionSourceRepositoriesCreate, ActionSourceCommitsRecord, ActionSourceBranchesUpsert,
		ActionPullRequestsRecord, ActionSourceSnapshotsRecord, ActionSourceRepositoriesRead:
		return true
	case ActionProductsRead, ActionProjectsRead, ActionProjectsCreate,
		ActionReleasesRead, ActionReleasesManage, ActionBuildsRead, ActionBuildsCreate,
		ActionBuildAttestationsCreate, ActionReleaseCandidatesCreate, ActionReleaseCandidatesRead, ActionArtifactsRead,
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
	case ActionAnswerLibraryEntriesRead:
		return refs.ProductID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID})
	case ActionPortalAccessRead:
		return refs.ProductID != "" && refs.CustomerPackageID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID, CustomerPackageID: refs.CustomerPackageID})
	case ActionReleaseBundlesRead, ActionReleaseBundlesCreate:
		return refs.ProductID != "" && refs.ReleaseID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID})
	case ActionEvidenceSummariesCreate, ActionAnomalyReportsGenerate:
		return refs.ProductID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID, CustomerPackageID: refs.CustomerPackageID})
	case ActionEvidenceBundlesExport:
		return refs == (ResourceReferences{}) || refs.ProductID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID})
	case ActionCRAReadinessHTMLGenerate, ActionPDFReportsGenerate, ActionGraphSnapshotsCreate, ActionQuestionnaireDraftsCreate, ActionAnswerLibraryEntriesCreate, ActionCustomerPackagesCreate:
		return refs.ProductID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID})
	case ActionQuestionnairePackagesCreate:
		return refs.ProductID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID, CustomerPackageID: refs.CustomerPackageID})
	case ActionCustomerPackagesAccess, ActionPortalAccessManage:
		return refs.ProductID != "" && refs.CustomerPackageID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID, CustomerPackageID: refs.CustomerPackageID})
	case ActionReleaseVulnerabilityPostureRead, ActionCRAVulnerabilityHandlingRead, ActionReleaseReadinessReportRead, ActionSecurityUpdateEvidenceRead:
		return refs.ProductID != "" && refs.ReleaseID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID})
	case ActionControlCoverageReportRead:
		return refs == (ResourceReferences{}) || refs.ProductID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID})
	case ActionCRAReadinessReportRead, ActionIncidentReportRead:
		return refs.ProductID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID})
	case ActionEvidenceVerify, ActionDSSEVerify:
		return refs != (ResourceReferences{}) && refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID})
	case ActionReleaseBundleVerify:
		return refs.ProductID != "" && refs.ReleaseID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID})
	case ActionCosignVerify, ActionArtifactSignatureVerify:
		return refs.ArtifactID != "" && refs == (ResourceReferences{ArtifactID: refs.ArtifactID})
	case ActionArtifactSignaturesRead:
		return refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID})
	case ActionSourceRepositoriesCreate, ActionSourceCommitsRecord, ActionSourceBranchesUpsert,
		ActionPullRequestsRecord, ActionSourceSnapshotsRecord:
		return refs.ProductID != "" && refs.ProjectID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID})
	case ActionSourceRepositoriesRead:
		return refs == (ResourceReferences{}) || refs.ProductID != "" && refs.ProjectID != "" && refs == (ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID})
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

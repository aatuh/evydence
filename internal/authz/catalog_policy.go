package authz

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

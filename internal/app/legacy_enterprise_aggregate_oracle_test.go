package app

import (
	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) ensureRoleSubjectLocked(tenantID, subjectType, subjectID string) error {
	switch subjectType {
	case "user":
		user, ok := l.users[subjectID]
		if !ok || user.TenantID != tenantID {
			return ErrNotFound
		}
	case "collector":
		collector, ok := l.collectors[subjectID]
		if !ok || collector.TenantID != tenantID {
			return ErrNotFound
		}
	default:
		return ErrValidation
	}
	return nil
}

type resourceRefs struct {
	ProductID          string
	ProjectID          string
	ReleaseID          string
	ArtifactID         string
	BuildID            string
	DeploymentID       string
	EnvironmentID      string
	IncidentID         string
	SecurityScanID     string
	SourceRepositoryID string
	CustomerPackageID  string
	EvidenceBundleID   string
}

func refsForEvidence(item domain.EvidenceItem) resourceRefs {
	return resourceRefs{
		ProductID: item.ProductID, ProjectID: item.ProjectID, ReleaseID: item.ReleaseID,
		BuildID: item.BuildID, DeploymentID: item.DeploymentID,
	}
}

func (l *Ledger) ensureRoleResourceLocked(tenantID, resourceType, resourceID string) error {
	switch resourceType {
	case "":
		if resourceID != "" {
			return ErrValidation
		}
	case "tenant":
		if resourceID == "" {
			return nil
		}
		tenant, ok := l.tenants[resourceID]
		if !ok || tenant.ID != tenantID {
			return ErrNotFound
		}
	case "product":
		product, ok := l.products[resourceID]
		if resourceID == "" || !ok || product.TenantID != tenantID {
			return ErrNotFound
		}
	case "project":
		project, ok := l.projects[resourceID]
		if resourceID == "" || !ok || project.TenantID != tenantID {
			return ErrNotFound
		}
	case "release":
		release, ok := l.releases[resourceID]
		if resourceID == "" || !ok || release.TenantID != tenantID {
			return ErrNotFound
		}
	case "customer_security_package":
		pkg, ok := l.customerPackages[resourceID]
		if resourceID == "" || !ok || pkg.TenantID != tenantID {
			return ErrNotFound
		}
	case "evidence_bundle":
		bundle, ok := l.evidenceBundles[resourceID]
		if resourceID == "" || !ok || bundle.TenantID != tenantID {
			return ErrNotFound
		}
	default:
		return ErrValidation
	}
	return nil
}

func (l *Ledger) resourceGrantsForUserLocked(userID string) []domain.ResourceGrant {
	grants := []domain.ResourceGrant{}
	for _, binding := range l.roleBindings {
		if binding.SubjectType != "user" || binding.SubjectID != userID {
			continue
		}
		scopes := scopesForRole(binding.Role)
		if len(scopes) == 0 {
			continue
		}
		grants = append(grants, domain.ResourceGrant{
			Role:         binding.Role,
			ResourceType: binding.ResourceType,
			ResourceID:   binding.ResourceID,
			Scopes:       scopes,
		})
	}
	return grants
}

func (l *Ledger) resourceGrantsForSSOSessionLocked(session domain.SSOSession) []domain.ResourceGrant {
	provider, ok := l.ssoProviders[session.ProviderID]
	if !ok || provider.TenantID != session.TenantID {
		return nil
	}
	return resourceGrantsForProviderGroups(provider, session.Groups)
}

func (l *Ledger) authorizeResourceLocked(actor domain.Actor, scope string, refs resourceRefs) error {
	if l.resourceAllowedLocked(actor, scope, refs) {
		return nil
	}
	return ErrForbidden
}

func (l *Ledger) resourceAllowedLocked(actor domain.Actor, scope string, refs resourceRefs) bool {
	if !humanSessionActor(actor) {
		return true
	}
	for _, grant := range actor.ResourceGrants {
		if !grantHasScope(grant, scope) {
			continue
		}
		if l.grantCoversResourceLocked(actor.TenantID, grant, refs) {
			return true
		}
	}
	return false
}

func (l *Ledger) grantCoversResourceLocked(tenantID string, grant domain.ResourceGrant, refs resourceRefs) bool {
	switch grant.ResourceType {
	case "", "tenant":
		return grant.ResourceID == "" || grant.ResourceID == tenantID
	case "product":
		return grant.ResourceID != "" && l.productCoversRefsLocked(tenantID, grant.ResourceID, refs)
	case "project":
		return grant.ResourceID != "" && l.projectCoversRefsLocked(tenantID, grant.ResourceID, refs)
	case "release":
		return grant.ResourceID != "" && l.releaseCoversRefsLocked(tenantID, grant.ResourceID, refs)
	case "customer_security_package":
		return refs.CustomerPackageID != "" && refs.CustomerPackageID == grant.ResourceID
	case "evidence_bundle":
		return refs.EvidenceBundleID != "" && refs.EvidenceBundleID == grant.ResourceID
	default:
		return false
	}
}

func (l *Ledger) productCoversRefsLocked(tenantID, productID string, refs resourceRefs) bool {
	if refs == (resourceRefs{}) {
		return false
	}
	if refs.ProductID != "" && refs.ProductID != productID {
		return false
	}
	if refs.ProjectID != "" {
		project, ok := l.projects[refs.ProjectID]
		if !ok || project.TenantID != tenantID || project.ProductID != productID {
			return false
		}
	}
	if refs.SourceRepositoryID != "" {
		repo, ok := l.repositories[refs.SourceRepositoryID]
		if !ok || repo.TenantID != tenantID {
			return false
		}
		if repo.ProjectID == "" {
			return false
		}
		project, ok := l.projects[repo.ProjectID]
		if !ok || project.TenantID != tenantID || project.ProductID != productID {
			return false
		}
	}
	if refs.ReleaseID != "" {
		release, ok := l.releases[refs.ReleaseID]
		if !ok || release.TenantID != tenantID || release.ProductID != productID {
			return false
		}
	}
	if refs.BuildID != "" {
		build, ok := l.buildRuns[refs.BuildID]
		if !ok || build.TenantID != tenantID {
			return false
		}
		if build.ReleaseID != "" {
			release, ok := l.releases[build.ReleaseID]
			if !ok || release.TenantID != tenantID || release.ProductID != productID {
				return false
			}
		}
		if build.ProjectID != "" {
			project, ok := l.projects[build.ProjectID]
			if !ok || project.TenantID != tenantID || project.ProductID != productID {
				return false
			}
		}
	}
	if refs.EnvironmentID != "" {
		env, ok := l.environments[refs.EnvironmentID]
		if !ok || env.TenantID != tenantID || env.ProductID != productID {
			return false
		}
	}
	if refs.DeploymentID != "" {
		deployment, ok := l.deployments[refs.DeploymentID]
		if !ok || deployment.TenantID != tenantID {
			return false
		}
		release, ok := l.releases[deployment.ReleaseID]
		if !ok || release.TenantID != tenantID || release.ProductID != productID {
			return false
		}
	}
	if refs.IncidentID != "" {
		incident, ok := l.incidents[refs.IncidentID]
		if !ok || incident.TenantID != tenantID || incident.ProductID != productID {
			return false
		}
	}
	if refs.SecurityScanID != "" {
		scan, ok := l.securityScans[refs.SecurityScanID]
		if !ok || scan.TenantID != tenantID {
			return false
		}
		if scan.ProductID != "" && scan.ProductID != productID {
			return false
		}
		if scan.ReleaseID != "" {
			release, ok := l.releases[scan.ReleaseID]
			if !ok || release.TenantID != tenantID || release.ProductID != productID {
				return false
			}
		}
	}
	if refs.ArtifactID != "" && !l.artifactCoversProductLocked(tenantID, refs.ArtifactID, productID) {
		return false
	}
	if refs.CustomerPackageID != "" {
		pkg, ok := l.customerPackages[refs.CustomerPackageID]
		if !ok || pkg.TenantID != tenantID || pkg.ProductID != productID {
			return false
		}
	}
	if refs.EvidenceBundleID != "" {
		bundle, ok := l.evidenceBundles[refs.EvidenceBundleID]
		if !ok || bundle.TenantID != tenantID {
			return false
		}
		if bundle.ReleaseID != "" {
			release, ok := l.releases[bundle.ReleaseID]
			if !ok || release.TenantID != tenantID || release.ProductID != productID {
				return false
			}
		}
	}
	return true
}

func (l *Ledger) projectCoversRefsLocked(tenantID, projectID string, refs resourceRefs) bool {
	if refs.ProjectID != "" {
		project, ok := l.projects[refs.ProjectID]
		return ok && project.TenantID == tenantID && project.ID == projectID
	}
	if refs.SourceRepositoryID != "" {
		repo, ok := l.repositories[refs.SourceRepositoryID]
		return ok && repo.TenantID == tenantID && repo.ProjectID == projectID
	}
	if refs.BuildID != "" {
		build, ok := l.buildRuns[refs.BuildID]
		return ok && build.TenantID == tenantID && build.ProjectID == projectID
	}
	if refs.ArtifactID != "" {
		return l.artifactCoversProjectLocked(tenantID, refs.ArtifactID, projectID)
	}
	return false
}

func (l *Ledger) releaseCoversRefsLocked(tenantID, releaseID string, refs resourceRefs) bool {
	if refs.ReleaseID != "" {
		release, ok := l.releases[refs.ReleaseID]
		return ok && release.TenantID == tenantID && release.ID == releaseID
	}
	if refs.CustomerPackageID != "" {
		pkg, ok := l.customerPackages[refs.CustomerPackageID]
		return ok && pkg.TenantID == tenantID && pkg.ReleaseID == releaseID
	}
	if refs.EvidenceBundleID != "" {
		bundle, ok := l.evidenceBundles[refs.EvidenceBundleID]
		return ok && bundle.TenantID == tenantID && bundle.ReleaseID == releaseID
	}
	if refs.BuildID != "" {
		build, ok := l.buildRuns[refs.BuildID]
		return ok && build.TenantID == tenantID && build.ReleaseID == releaseID
	}
	if refs.DeploymentID != "" {
		deployment, ok := l.deployments[refs.DeploymentID]
		return ok && deployment.TenantID == tenantID && deployment.ReleaseID == releaseID
	}
	if refs.IncidentID != "" {
		incident, ok := l.incidents[refs.IncidentID]
		return ok && incident.TenantID == tenantID && incident.ReleaseID == releaseID
	}
	if refs.SecurityScanID != "" {
		scan, ok := l.securityScans[refs.SecurityScanID]
		return ok && scan.TenantID == tenantID && scan.ReleaseID == releaseID
	}
	if refs.ArtifactID != "" && l.artifactCoversReleaseLocked(tenantID, refs.ArtifactID, releaseID) {
		return true
	}
	return false
}

func (l *Ledger) artifactCoversProductLocked(tenantID, artifactID, productID string) bool {
	for _, item := range l.evidence {
		if item.TenantID == tenantID && item.ProductID == productID && evidenceReferencesArtifact(item, artifactID) {
			return true
		}
	}
	for _, build := range l.buildRuns {
		if build.TenantID != tenantID {
			continue
		}
		for _, output := range build.Outputs {
			if output.ArtifactID != artifactID {
				continue
			}
			release, ok := l.releases[build.ReleaseID]
			if ok && release.TenantID == tenantID && release.ProductID == productID {
				return true
			}
		}
	}
	return false
}

func (l *Ledger) artifactCoversProjectLocked(tenantID, artifactID, projectID string) bool {
	for _, item := range l.evidence {
		if item.TenantID == tenantID && item.ProjectID == projectID && evidenceReferencesArtifact(item, artifactID) {
			return true
		}
	}
	for _, build := range l.buildRuns {
		if build.TenantID != tenantID || build.ProjectID != projectID {
			continue
		}
		for _, output := range build.Outputs {
			if output.ArtifactID == artifactID {
				return true
			}
		}
	}
	return false
}

func (l *Ledger) artifactCoversReleaseLocked(tenantID, artifactID, releaseID string) bool {
	for _, item := range l.evidence {
		if item.TenantID == tenantID && item.ReleaseID == releaseID && evidenceReferencesArtifact(item, artifactID) {
			return true
		}
	}
	for _, build := range l.buildRuns {
		if build.TenantID != tenantID || build.ReleaseID != releaseID {
			continue
		}
		for _, output := range build.Outputs {
			if output.ArtifactID == artifactID {
				return true
			}
		}
	}
	return false
}

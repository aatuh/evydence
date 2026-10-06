package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

// AuthorizeEvidenceCreation checks explicit local-memory ownership only; native
// PostgreSQL creation uses focused transaction guards, not these maps.
func (l *Ledger) AuthorizeEvidenceCreation(ctx context.Context, a domain.Actor, in evidenceapp.CreateEvidenceInput) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeEvidenceWrite); err != nil {
		return err
	}
	if a.TenantID == "" || len(a.TenantID) > 1024 || !utf8.ValidString(a.TenantID) || strings.ContainsRune(a.TenantID, 0) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	var err error
	in, err = evidenceapp.NormalizeGenericEvidenceCreation(in)
	if err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	check := func(scope evidenceapp.EvidenceScope) error {
		if err := validateLedgerEvidenceScopeLocked(l, a.TenantID, scope); err != nil {
			return err
		}
		products := []string{scope.ProductID}
		if scope.ProjectID != "" {
			products = append(products, l.projects[scope.ProjectID].ProductID)
		}
		if scope.ReleaseID != "" {
			products = append(products, l.releases[scope.ReleaseID].ProductID)
		}
		if scope.BuildID != "" {
			products = append(products, l.projects[l.buildRuns[scope.BuildID].ProjectID].ProductID)
		}
		if scope.DeploymentID != "" {
			products = append(products, l.environments[l.deployments[scope.DeploymentID].EnvironmentID].ProductID)
		}
		for _, id := range products {
			if id == "" {
				continue
			}
			p, ok := l.products[id]
			if !ok || p.TenantID != a.TenantID {
				return ErrNotFound
			}
		}
		return l.authorizeResourceLocked(a, ScopeEvidenceWrite, resourceRefs{ProductID: scope.ProductID, ProjectID: scope.ProjectID, ReleaseID: scope.ReleaseID, BuildID: scope.BuildID, DeploymentID: scope.DeploymentID})
	}
	if err := check(evidenceapp.EvidenceScope{ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, BuildID: in.BuildID, DeploymentID: in.DeploymentID}); err != nil {
		return err
	}
	for _, ref := range in.SubjectRefs {
		if ref.ID == "" {
			continue
		}
		var scope evidenceapp.EvidenceScope
		switch ref.Type {
		case "artifact":
			v, ok := l.artifacts[ref.ID]
			if !ok || v.TenantID != a.TenantID {
				return ErrNotFound
			}
			if err := l.authorizeArtifactSignatureCreationLocked(a, v); err != nil {
				return err
			}
			continue
		case "product":
			scope.ProductID = ref.ID
		case "project":
			scope.ProjectID = ref.ID
		case "release":
			scope.ReleaseID = ref.ID
		case "build":
			scope.BuildID = ref.ID
		case "deployment":
			scope.DeploymentID = ref.ID
		default:
			continue
		}
		if err := check(scope); err != nil {
			return err
		}
	}
	return nil
}

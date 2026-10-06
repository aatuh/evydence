package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// AuthorizeEvidenceBundleExport is an explicit local-memory guard. Native
// PostgreSQL handlers use Package transaction ports instead of these maps.
func (l *Ledger) AuthorizeEvidenceBundleExport(ctx context.Context, a domain.Actor, release string, ids []string) error {
	if err := packagequery.NewEvidenceBundleAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeBundleRead, ScopeOnly: true}); err != nil {
		return fromPackageContextError(err)
	}
	if a.TenantID == "" || !validPublicMembershipText(a.TenantID, 1024) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	release, ids, err := packageapp.NormalizeEvidenceBundleSelection(release, ids)
	if err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	if release != "" {
		if _, err := l.authorizeProductReleaseLocked(a, ScopeBundleRead, "", release); err != nil {
			return err
		}
	}
	for _, id := range ids {
		v, ok := l.evidence[id]
		if !ok || v.TenantID != a.TenantID || release != "" && v.ReleaseID != release {
			return ErrNotFound
		}
		for _, coordinate := range []string{v.ProductID, v.ProjectID, v.ReleaseID, v.BuildID, v.DeploymentID} {
			if !validPublicMembershipText(coordinate, 1024) {
				return ErrConflict
			}
		}
		if err := validateLedgerEvidenceScopeLocked(l, a.TenantID, evidenceapp.EvidenceScope{ProductID: v.ProductID, ProjectID: v.ProjectID, ReleaseID: v.ReleaseID, BuildID: v.BuildID, DeploymentID: v.DeploymentID}); err != nil {
			return err
		}
		if err := l.authorizeResourceLocked(a, ScopeBundleRead, resourceRefs{ProductID: v.ProductID, ProjectID: v.ProjectID, ReleaseID: v.ReleaseID, BuildID: v.BuildID, DeploymentID: v.DeploymentID}); err != nil {
			return err
		}
	}
	return nil
}

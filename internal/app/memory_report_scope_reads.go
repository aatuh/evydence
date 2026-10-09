package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// Only root identifiers and current parent coordinates are projected. These
// test-adapter reads do not consult Ledger or transfer private report text.
func memorySummaryScope(state *MemoryUnitOfWorkSnapshot, tenant, kind, id string) (packageapp.EvidenceSummaryScope, error) {
	s := packageapp.EvidenceSummaryScope{TenantID: tenant, SubjectType: kind, SubjectID: id}
	var raw application.ResourceReferences
	switch kind {
	case "tenant":
		if id != tenant {
			return s, ErrNotFound
		}
	case "product":
		v, ok := state.Products[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return s, ErrNotFound
		}
		raw.ProductID = id
	case "release":
		v, ok := state.Releases[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return s, ErrNotFound
		}
		raw.ProductID, raw.ReleaseID = v.ProductID, id
	case "evidence":
		v, ok := state.Evidence[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return s, ErrNotFound
		}
		raw = application.ResourceReferences{ProductID: v.ProductID, ProjectID: v.ProjectID, ReleaseID: v.ReleaseID, BuildID: v.BuildID, DeploymentID: v.DeploymentID}
	case "build":
		v, ok := state.BuildRuns[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return s, ErrNotFound
		}
		raw.ProjectID, raw.ReleaseID = v.ProjectID, v.ReleaseID
	case "customer_package":
		v, ok := state.CustomerPackages[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return s, ErrNotFound
		}
		raw.ProductID, raw.ReleaseID, raw.CustomerPackageID = v.ProductID, v.ReleaseID, id
	default:
		return s, ErrValidation
	}
	// Corrupt stored coordinates conflict, never truncate or silently resolve
	// to a different tenant. The raw filter is retained before parent inference.
	s.Filter = raw
	for _, value := range []string{raw.ProductID, raw.ProjectID, raw.ReleaseID, raw.BuildID, raw.DeploymentID, raw.CustomerPackageID} {
		if value != "" && !memoryMembershipQueryText(value, 1024) {
			return s, ErrConflict
		}
	}
	refs, err := memoryOperationsCoordinates(state, tenant, raw)
	if err != nil {
		return s, ErrConflict
	}
	s.Resources = refs
	return s, nil
}
func (r memoryFutureExtensionsRepository) ReadEvidenceSummaryScope(ctx context.Context, tenant, kind, id string) (packageapp.EvidenceSummaryScope, error) {
	var out packageapp.EvidenceSummaryScope
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(state *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memorySummaryScope(state, tenant, kind, id)
		return err
	})
	if err != nil {
		return packageapp.EvidenceSummaryScope{}, err
	}
	return out, nil
}
func (r memoryFutureExtensionsRepository) ReadQuestionnaireDraftScope(ctx context.Context, tenant string, in packageapp.CreateQuestionnaireDraftInput) (packageapp.QuestionnaireDraftScope, error) {
	var out packageapp.QuestionnaireDraftScope
	for _, value := range []string{in.ProductID, in.ReleaseID} {
		if value != "" && !memoryMembershipQueryText(value, 1024) {
			return out, ErrValidation
		}
	}
	err := memoryGovernanceRead(ctx, r.uow, tenant, in.TemplateID, func(state *MemoryUnitOfWorkSnapshot) error {
		kind, id := "tenant", tenant
		if in.ReleaseID != "" {
			kind, id = "release", in.ReleaseID
		} else if in.ProductID != "" {
			kind, id = "product", in.ProductID
		}
		root, err := memorySummaryScope(state, tenant, kind, id)
		if err != nil {
			return err
		}
		if in.ProductID != "" && root.Resources.ProductID != in.ProductID {
			return ErrNotFound
		}
		v, ok := state.QuestionnaireTemplates[in.TemplateID]
		if !ok || v.ID != in.TemplateID || v.TenantID != tenant {
			return ErrNotFound
		}
		out = packageapp.QuestionnaireDraftScope{TenantID: tenant, TemplateID: in.TemplateID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Resources: application.ResourceReferences{ProductID: root.Resources.ProductID, ReleaseID: in.ReleaseID}}
		return nil
	})
	if err != nil {
		return packageapp.QuestionnaireDraftScope{}, err
	}
	return out, nil
}

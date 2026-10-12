package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

// These focused test-backend readers consult only the transaction snapshot,
// never Ledger. They provide ownership coherence, not PostgreSQL row locks.
var (
	_ operationsapp.IncidentReader             = memoryRiskRepository{}
	_ operationsapp.RetentionMarkerScopeLocker = memoryGovernanceRepository{}
)

func (r memoryRiskRepository) ReadIncidentSubject(ctx context.Context, tenant, kind, id string) (operationsapp.IncidentSubject, error) {
	var refs application.ResourceReferences
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(state *MemoryUnitOfWorkSnapshot) error {
		switch kind {
		case "product":
			refs.ProductID = id
		case "release":
			refs.ReleaseID = id
		case "incident":
			v, ok := state.Incidents[id]
			if !ok || v.ID != id || v.TenantID != tenant || v.ProductID == "" {
				return ErrNotFound
			}
			refs.ProductID, refs.ReleaseID = v.ProductID, v.ReleaseID
		case "evidence":
			v, ok := state.Evidence[id]
			if !ok || v.ID != id || v.TenantID != tenant {
				return ErrNotFound
			}
			refs = application.ResourceReferences{ProductID: v.ProductID, ProjectID: v.ProjectID, ReleaseID: v.ReleaseID, BuildID: v.BuildID, DeploymentID: v.DeploymentID}
		default:
			return ErrValidation
		}
		var err error
		refs, err = memoryOperationsCoordinates(state, tenant, refs)
		return err
	})
	if err != nil {
		return operationsapp.IncidentSubject{}, err
	}
	return operationsapp.IncidentSubject{ID: id, TenantID: tenant, Type: kind, Resources: refs}, nil
}

func memoryOperationsCoordinates(state *MemoryUnitOfWorkSnapshot, tenant string, refs application.ResourceReferences) (application.ResourceReferences, error) {
	for _, id := range []string{refs.ProductID, refs.ProjectID, refs.ReleaseID, refs.BuildID, refs.DeploymentID} {
		if !memoryGovernanceText(id, 1024) || strings.TrimSpace(id) != id {
			return application.ResourceReferences{}, ErrValidation
		}
	}
	merge := func(target *string, value string) error {
		if value == "" || !memoryGovernanceText(value, 1024) || strings.TrimSpace(value) != value {
			return ErrNotFound
		}
		if *target != "" && *target != value {
			return ErrNotFound
		}
		*target = value
		return nil
	}
	if refs.BuildID != "" {
		v, ok := state.BuildRuns[refs.BuildID]
		if !ok || v.ID != refs.BuildID || v.TenantID != tenant {
			return application.ResourceReferences{}, ErrNotFound
		}
		if err := merge(&refs.ProjectID, v.ProjectID); err != nil {
			return application.ResourceReferences{}, err
		}
		if err := merge(&refs.ReleaseID, v.ReleaseID); err != nil {
			return application.ResourceReferences{}, err
		}
	}
	if refs.DeploymentID != "" {
		v, ok := state.DeploymentEvents[refs.DeploymentID]
		if !ok || v.ID != refs.DeploymentID || v.TenantID != tenant {
			return application.ResourceReferences{}, ErrNotFound
		}
		env, ok := state.DeploymentEnvironments[v.EnvironmentID]
		if !ok || env.ID != v.EnvironmentID || env.TenantID != tenant {
			return application.ResourceReferences{}, ErrNotFound
		}
		if err := merge(&refs.ProductID, env.ProductID); err != nil {
			return application.ResourceReferences{}, err
		}
		if err := merge(&refs.ReleaseID, v.ReleaseID); err != nil {
			return application.ResourceReferences{}, err
		}
	}
	if refs.ProjectID != "" {
		v, ok := state.Projects[refs.ProjectID]
		if !ok || v.ID != refs.ProjectID || v.TenantID != tenant {
			return application.ResourceReferences{}, ErrNotFound
		}
		if err := merge(&refs.ProductID, v.ProductID); err != nil {
			return application.ResourceReferences{}, err
		}
	}
	if refs.ReleaseID != "" {
		v, ok := state.Releases[refs.ReleaseID]
		if !ok || v.ID != refs.ReleaseID || v.TenantID != tenant {
			return application.ResourceReferences{}, ErrNotFound
		}
		if err := merge(&refs.ProductID, v.ProductID); err != nil {
			return application.ResourceReferences{}, err
		}
	}
	if refs.ProductID != "" {
		if _, err := memoryGovernanceProductRelease(state, tenant, refs.ProductID, refs.ReleaseID); err != nil {
			return application.ResourceReferences{}, err
		}
	}
	return refs, nil
}

// Retention markers bind only the selected tenant-owned root. They do not
// verify its contents or require unrelated parent/projection metadata.
func (r memoryGovernanceRepository) LockRetentionMarkerScope(ctx context.Context, tenant, kind, id string) error {
	k, normalized, err := operationsapp.NormalizeRetentionMarkerScope(kind, id)
	if err != nil || k != kind || normalized != id {
		return ErrValidation
	}
	return memoryGovernanceRead(ctx, r.uow, tenant, id, func(state *MemoryUnitOfWorkSnapshot) error {
		owned := false
		switch kind {
		case "tenant":
			owned = id == tenant
		case "product":
			v, ok := state.Products[id]
			owned = ok && v.ID == id && v.TenantID == tenant
		case "project":
			v, ok := state.Projects[id]
			owned = ok && v.ID == id && v.TenantID == tenant
		case "release":
			v, ok := state.Releases[id]
			owned = ok && v.ID == id && v.TenantID == tenant
		case "evidence":
			v, ok := state.Evidence[id]
			owned = ok && v.ID == id && v.TenantID == tenant
		default:
			return ErrValidation
		}
		if !owned {
			return ErrNotFound
		}
		return nil
	})
}

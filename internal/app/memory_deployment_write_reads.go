package app

import (
	"context"
	"strings"

	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

var (
	_ operationsapp.DeploymentTenantLocker      = memoryDeploymentRepository{}
	_ operationsapp.DeploymentEnvironmentReader = memoryDeploymentRepository{}
	_ operationsapp.DeploymentReader            = memoryDeploymentRepository{}
)

// Typed snapshot guards model current identities, not SQL fences or row locks.
// Parent and artifact reads omit descriptive metadata and artifact digests.
func (r memoryDeploymentRepository) LockDeploymentTenant(ctx context.Context, tenant string) error {
	return memoryGovernanceRead(ctx, r.uow, tenant, tenant, func(*MemoryUnitOfWorkSnapshot) error { return nil })
}
func (r memoryDeploymentRepository) LockEnvironmentProduct(ctx context.Context, tenant, id string) (operationsapp.EnvironmentProduct, error) {
	var out operationsapp.EnvironmentProduct
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		p, ok := s.Products[id]
		if !ok || p.ID != id || p.TenantID != tenant {
			return ErrNotFound
		}
		out = operationsapp.EnvironmentProduct{ID: id, TenantID: tenant}
		return nil
	})
	if err != nil {
		return operationsapp.EnvironmentProduct{}, err
	}
	return out, nil
}
func (r memoryDeploymentRepository) EnvironmentByName(ctx context.Context, tenant, product, name string) (operationsdomain.DeploymentEnvironment, bool, error) {
	var out operationsdomain.DeploymentEnvironment
	found := false
	err := memoryGovernanceRead(ctx, r.uow, tenant, product, func(s *MemoryUnitOfWorkSnapshot) error {
		if name == "" || name != strings.TrimSpace(name) || !memoryGovernanceText(name, operationsapp.MaxEnvironmentTextBytes) || len(tenant)+len(product)+len(name) > operationsapp.MaxEnvironmentKeyBytes {
			return ErrValidation
		}
		p, ok := s.Products[product]
		if !ok || p.ID != product || p.TenantID != tenant {
			return ErrNotFound
		}
		for id, v := range s.DeploymentEnvironments {
			if err := ctx.Err(); err != nil {
				return err
			}
			if v.TenantID != tenant || v.ProductID != product || v.Name != name {
				continue
			}
			if found || v.ID != id || v.ID == "" {
				return ErrConflict
			}
			for _, field := range []struct {
				value string
				limit int
			}{{v.ID, 1024}, {v.TenantID, 1024}, {v.ProductID, 1024}, {v.Name, operationsapp.MaxEnvironmentTextBytes}, {v.Kind, operationsapp.MaxEnvironmentTextBytes}, {v.SchemaVersion, 1024}} {
				if !memoryGovernanceText(field.value, field.limit) {
					return ErrConflict
				}
			}
			out = operationsdomain.DeploymentEnvironment(v)
			out.CreatedAt = out.CreatedAt.UTC()
			found = true
		}
		return nil
	})
	if err != nil {
		return operationsdomain.DeploymentEnvironment{}, false, err
	}
	return out, found, nil
}
func (r memoryDeploymentRepository) LockDeploymentEnvironment(ctx context.Context, tenant, id string) (operationsapp.DeploymentEnvironmentIdentity, error) {
	var out operationsapp.DeploymentEnvironmentIdentity
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		e, ok := s.DeploymentEnvironments[id]
		if !ok || e.ID != id || e.TenantID != tenant || e.ProductID == "" {
			return ErrNotFound
		}
		if !memoryGovernanceText(e.ProductID, 1024) {
			return ErrConflict
		}
		p, ok := s.Products[e.ProductID]
		if !ok || p.ID != e.ProductID || p.TenantID != tenant {
			return ErrNotFound
		}
		out = operationsapp.DeploymentEnvironmentIdentity{ID: id, TenantID: tenant, ProductID: p.ID}
		return nil
	})
	if err != nil {
		return operationsapp.DeploymentEnvironmentIdentity{}, err
	}
	return out, nil
}
func (r memoryDeploymentRepository) LockDeploymentRelease(ctx context.Context, tenant, id string) (operationsapp.DeploymentReleaseIdentity, error) {
	var out operationsapp.DeploymentReleaseIdentity
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.Releases[id]
		if !ok || v.ID != id || v.TenantID != tenant || v.ProductID == "" {
			return ErrNotFound
		}
		if !memoryGovernanceText(v.ProductID, 1024) {
			return ErrConflict
		}
		p, ok := s.Products[v.ProductID]
		if !ok || p.ID != v.ProductID || p.TenantID != tenant {
			return ErrNotFound
		}
		out = operationsapp.DeploymentReleaseIdentity{ID: id, TenantID: tenant, ProductID: p.ID}
		return nil
	})
	if err != nil {
		return operationsapp.DeploymentReleaseIdentity{}, err
	}
	return out, nil
}
func (r memoryDeploymentRepository) LockDeploymentRollback(ctx context.Context, tenant, id string) (operationsapp.DeploymentRollbackIdentity, error) {
	var out operationsapp.DeploymentRollbackIdentity
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.DeploymentEvents[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		if !memoryGovernanceText(v.EnvironmentID, 1024) {
			return ErrConflict
		}
		out = operationsapp.DeploymentRollbackIdentity{ID: id, TenantID: tenant, EnvironmentID: v.EnvironmentID}
		return nil
	})
	if err != nil {
		return operationsapp.DeploymentRollbackIdentity{}, err
	}
	return out, nil
}
func (r memoryDeploymentRepository) CheckDeploymentArtifacts(ctx context.Context, tenant string, ids []string) error {
	if len(ids) > operationsapp.MaxDeploymentArtifacts {
		return ErrValidation
	}
	return memoryGovernanceRead(ctx, r.uow, tenant, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			if id == "" || strings.TrimSpace(id) != id || !memoryGovernanceText(id, 1024) {
				return ErrValidation
			}
			v, ok := s.Artifacts[id]
			if !ok || v.ID != id || v.TenantID != tenant {
				return ErrNotFound
			}
		}
		return nil
	})
}

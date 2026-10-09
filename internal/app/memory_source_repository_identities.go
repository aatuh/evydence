package app

import (
	"context"
	"strings"

	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

var _ integrationapp.SourceRepositoryCreationReader = memorySourceRepository{}
var _ integrationapp.SourceRepositoryWriteReader = memorySourceRepository{}

func memorySourceProject(s *MemoryUnitOfWorkSnapshot, tenant, id string) (integrationapp.SourceProjectIdentity, error) {
	p, ok := s.Projects[id]
	if !ok || p.ID != id || p.TenantID != tenant || !memoryGovernanceText(p.ProductID, 1024) || p.ProductID == "" {
		return integrationapp.SourceProjectIdentity{}, ErrNotFound
	}
	product, ok := s.Products[p.ProductID]
	if !ok || product.ID != p.ProductID || product.TenantID != tenant {
		return integrationapp.SourceProjectIdentity{}, ErrNotFound
	}
	return integrationapp.SourceProjectIdentity{ID: p.ID, TenantID: tenant, ProductID: product.ID}, nil
}
func memorySourceIdentity(s *MemoryUnitOfWorkSnapshot, tenant, id string) (integrationapp.SourceRepositoryIdentity, error) {
	v, ok := s.SourceRepositories[id]
	if !ok || v.ID != id || v.TenantID != tenant {
		return integrationapp.SourceRepositoryIdentity{}, ErrNotFound
	}
	if !memoryGovernanceText(v.ID, 1024) || !memoryGovernanceText(v.ProjectID, 1024) {
		return integrationapp.SourceRepositoryIdentity{}, ErrConflict
	}
	out := integrationapp.SourceRepositoryIdentity{ID: id, TenantID: tenant, ProjectID: v.ProjectID}
	if v.ProjectID != "" {
		p, err := memorySourceProject(s, tenant, v.ProjectID)
		if err != nil {
			return integrationapp.SourceRepositoryIdentity{}, err
		}
		out.ProductID = p.ProductID
	}
	return out, nil
}

// Typed identity reads retain snapshot protection, not native database fences
// or row locks. Descriptive repository/project/product metadata is omitted.
func (r memorySourceRepository) LockRepositoryCreation(ctx context.Context, tenant string) error {
	return memoryGovernanceRead(ctx, r.uow, tenant, tenant, func(*MemoryUnitOfWorkSnapshot) error { return nil })
}
func (r memorySourceRepository) LockRepositoryProject(ctx context.Context, tenant, id string) (integrationapp.SourceProjectIdentity, error) {
	var out integrationapp.SourceProjectIdentity
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memorySourceProject(s, tenant, id)
		return err
	})
	if err != nil {
		return integrationapp.SourceProjectIdentity{}, err
	}
	return out, nil
}
func (r memorySourceRepository) LockSourceRepositoryForWrite(ctx context.Context, tenant, id string) (integrationapp.SourceRepositoryIdentity, error) {
	var out integrationapp.SourceRepositoryIdentity
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memorySourceIdentity(s, tenant, id)
		return err
	})
	if err != nil {
		return integrationapp.SourceRepositoryIdentity{}, err
	}
	return out, nil
}
func (r memorySourceRepository) RepositoryIdentityByName(ctx context.Context, tenant, provider, name string) (integrationapp.SourceRepositoryIdentity, bool, error) {
	var out integrationapp.SourceRepositoryIdentity
	found := false
	err := memoryGovernanceRead(ctx, r.uow, tenant, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		if provider == "" || name == "" || strings.TrimSpace(provider) != provider || strings.TrimSpace(name) != name || !memoryGovernanceText(provider, integrationapp.MaxSourceRepositoryKeyBytes) || !memoryGovernanceText(name, integrationapp.MaxSourceRepositoryKeyBytes) || len(tenant)+len(provider)+len(name) > integrationapp.MaxSourceRepositoryKeyBytes {
			return ErrValidation
		}
		for id, v := range s.SourceRepositories {
			if err := ctx.Err(); err != nil {
				return err
			}
			if v.TenantID != tenant || v.Provider != provider || v.FullName != name {
				continue
			}
			if found {
				return ErrConflict
			}
			var err error
			out, err = memorySourceIdentity(s, tenant, id)
			if err != nil {
				return err
			}
			found = true
		}
		return nil
	})
	if err != nil {
		return integrationapp.SourceRepositoryIdentity{}, false, err
	}
	return out, found, nil
}
func (r memorySourceRepository) ReadSourceRepository(ctx context.Context, tenant, id string) (integrationdomain.SourceRepository, error) {
	var out integrationdomain.SourceRepository
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.SourceRepositories[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		for _, value := range []string{v.ID, v.TenantID, v.ProjectID, v.SchemaVersion} {
			if !memoryGovernanceText(value, 1024) {
				return ErrConflict
			}
		}
		for _, value := range []string{v.Provider, v.FullName, v.CloneURL, v.DefaultBranch} {
			if !memoryGovernanceText(value, integrationapp.MaxSourceTextBytes) {
				return ErrConflict
			}
		}
		out = integrationdomain.SourceRepository(v)
		out.CreatedAt = out.CreatedAt.UTC()
		return nil
	})
	if err != nil {
		return integrationdomain.SourceRepository{}, err
	}
	return out, nil
}

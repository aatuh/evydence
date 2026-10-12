package app

import (
	"context"
	"strings"

	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

var _ integrationapp.SourceCommitReader = memorySourceRepository{}
var _ integrationapp.SourceBranchReader = memorySourceRepository{}
var _ integrationapp.PullRequestReader = memorySourceRepository{}

// Select only current owned head coordinates. No author, hash or commit text
// is needed for authorization; snapshot protection is not a native SQL lock.
func (r memorySourceRepository) SourceCommitIdentityByID(ctx context.Context, tenant, repository, id string) (integrationapp.SourceCommitIdentity, error) {
	var out integrationapp.SourceCommitIdentity
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		if repository == "" || !memoryGovernanceText(repository, 1024) {
			return ErrValidation
		}
		v, ok := s.SourceCommits[id]
		if !ok || v.ID != id || v.TenantID != tenant || v.RepositoryID != repository {
			return ErrNotFound
		}
		out = integrationapp.SourceCommitIdentity{ID: id, TenantID: tenant, RepositoryID: repository}
		return nil
	})
	if err != nil {
		return integrationapp.SourceCommitIdentity{}, err
	}
	return out, nil
}

func (r memorySourceRepository) SourceCommitBySHA(ctx context.Context, tenant, repository, sha string) (integrationdomain.SourceCommit, bool, error) {
	var out integrationdomain.SourceCommit
	found := false
	err := memoryGovernanceRead(ctx, r.uow, tenant, repository, func(s *MemoryUnitOfWorkSnapshot) error {
		if len(sha) != 40 || !memoryGovernanceText(sha, 40) {
			return ErrValidation
		}
		for id, v := range s.SourceCommits {
			if err := ctx.Err(); err != nil {
				return err
			}
			if v.TenantID != tenant || v.RepositoryID != repository || v.SHA != sha {
				continue
			}
			if found || v.ID != id || v.ID == "" {
				return ErrConflict
			}
			for _, value := range []string{v.ID, v.TenantID, v.RepositoryID, v.SchemaVersion} {
				if !memoryGovernanceText(value, 1024) {
					return ErrConflict
				}
			}
			if !memoryGovernanceText(v.Author, integrationapp.MaxSourceTextBytes) || !memoryGovernanceText(v.MessageHash, 71) {
				return ErrConflict
			}
			out = integrationdomain.SourceCommit(v)
			out.CommittedAt, out.CreatedAt = out.CommittedAt.UTC(), out.CreatedAt.UTC()
			found = true
		}
		return nil
	})
	if err != nil {
		return integrationdomain.SourceCommit{}, false, err
	}
	return out, found, nil
}

func (r memorySourceRepository) SourceBranchByName(ctx context.Context, tenant, repository, name string) (integrationdomain.SourceBranch, bool, error) {
	var out integrationdomain.SourceBranch
	found := false
	err := memoryGovernanceRead(ctx, r.uow, tenant, repository, func(s *MemoryUnitOfWorkSnapshot) error {
		if name == "" || strings.TrimSpace(name) != name || !memoryGovernanceText(name, integrationapp.MaxSourceBranchKeyBytes) || len(tenant)+len(repository)+len(name) > integrationapp.MaxSourceBranchKeyBytes {
			return ErrValidation
		}
		for id, v := range s.SourceBranches {
			if err := ctx.Err(); err != nil {
				return err
			}
			if v.TenantID != tenant || v.RepositoryID != repository || v.Name != name {
				continue
			}
			if found || v.ID != id || v.ID == "" {
				return ErrConflict
			}
			for _, value := range []string{v.ID, v.TenantID, v.RepositoryID, v.HeadCommitID, v.SchemaVersion} {
				if !memoryGovernanceText(value, 1024) {
					return ErrConflict
				}
			}
			if !memoryGovernanceText(v.ProtectionHash, integrationapp.MaxSourceTextBytes) {
				return ErrConflict
			}
			out = integrationdomain.SourceBranch(v)
			out.CreatedAt = out.CreatedAt.UTC()
			found = true
		}
		return nil
	})
	if err != nil {
		return integrationdomain.SourceBranch{}, false, err
	}
	return out, found, nil
}

func (r memorySourceRepository) SourceRepositoryProvider(ctx context.Context, tenant, id string) (string, error) {
	var out string
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.SourceRepositories[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		if !memoryGovernanceText(v.Provider, integrationapp.MaxSourceTextBytes) {
			return ErrConflict
		}
		out = v.Provider
		return nil
	})
	if err != nil {
		return "", err
	}
	return out, nil
}

package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

// These map checks are explicit local-memory compatibility. PostgreSQL HTTP
// uses the Integration service and its transactional, identifier-only reader.
func prepareLocalSourceRepositoryCreation(ctx context.Context, a domain.Actor, in CreateRepositoryInput) (CreateRepositoryInput, error) {
	if ctx == nil {
		return in, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return in, err
	}
	if err := require(a, ScopeSourceWrite); err != nil {
		return in, err
	}
	v, err := integrationapp.NormalizeSourceRepositoryInput(integrationapp.CreateSourceRepositoryInput{ProjectID: in.ProjectID, Provider: in.Provider, FullName: in.FullName, CloneURL: in.CloneURL, DefaultBranch: in.DefaultBranch})
	if err != nil {
		return in, ErrValidation
	}
	if err := integrationapp.ValidateSourceRepositoryKey(a.TenantID, v); err != nil {
		return in, ErrValidation
	}
	return CreateRepositoryInput{ProjectID: v.ProjectID, Provider: v.Provider, FullName: v.FullName, CloneURL: v.CloneURL, DefaultBranch: v.DefaultBranch}, nil
}

func (l *Ledger) authorizeSourceRepositoryCreationLocked(a domain.Actor, in CreateRepositoryInput) (string, error) {
	if _, ok := l.tenants[a.TenantID]; !ok {
		return "", ErrNotFound
	}
	authorizeProject := func(projectID, repositoryID string) error {
		refs := resourceRefs{ProjectID: projectID, SourceRepositoryID: repositoryID}
		if projectID != "" {
			project, ok := l.projects[projectID]
			if !ok || project.TenantID != a.TenantID {
				return ErrNotFound
			}
			product, ok := l.products[project.ProductID]
			if !ok || product.TenantID != a.TenantID {
				return ErrNotFound
			}
			refs.ProductID = product.ID
		}
		return l.authorizeResourceLocked(a, ScopeSourceWrite, refs)
	}
	if err := authorizeProject(in.ProjectID, ""); err != nil {
		return "", err
	}
	for _, existing := range l.repositories {
		if existing.TenantID == a.TenantID && existing.Provider == in.Provider && existing.FullName == in.FullName {
			if err := authorizeProject(existing.ProjectID, existing.ID); err != nil {
				return "", err
			}
			return existing.ID, nil
		}
	}
	return "", nil
}

func (l *Ledger) AuthorizeSourceRepositoryCreation(ctx context.Context, a domain.Actor, in CreateRepositoryInput) error {
	in, err := prepareLocalSourceRepositoryCreation(ctx, a, in)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.authorizeSourceRepositoryCreationLocked(a, in)
	return err
}

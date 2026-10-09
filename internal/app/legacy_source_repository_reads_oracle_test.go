package app

// Historical characterization only; runtime scoped repository pages and
// creation authorization use focused Integration services and current facts.

import (
	"context"
	"sort"

	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) ListSourceRepositories(ctx context.Context, actor domain.Actor, projectID string) ([]domain.SourceRepository, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeSourceRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.SourceRepository{}
	for _, repo := range l.repositories {
		if repo.TenantID != actor.TenantID {
			continue
		}
		if projectID != "" && repo.ProjectID != projectID {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopeSourceRead, resourceRefs{ProjectID: repo.ProjectID, SourceRepositoryID: repo.ID}) {
			continue
		}
		out = append(out, repo)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
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

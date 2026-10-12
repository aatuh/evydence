package app

// Historical characterization only. Repository creation belongs to focused
// Integration commands and current repository transactions.

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

type CreateRepositoryInput struct {
	ProjectID     string
	Provider      string
	FullName      string
	CloneURL      string
	DefaultBranch string
}

func (l *Ledger) CreateSourceRepository(ctx context.Context, actor domain.Actor, in CreateRepositoryInput) (domain.SourceRepository, error) {
	in, err := prepareLocalSourceRepositoryCreation(ctx, actor, in)
	if err != nil {
		return domain.SourceRepository{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	existing, err := l.authorizeSourceRepositoryCreationLocked(actor, in)
	if err != nil {
		return domain.SourceRepository{}, err
	}
	if existing != "" {
		return l.repositories[existing], nil
	}
	repo := domain.SourceRepository{
		ID:            newID("repo"),
		TenantID:      actor.TenantID,
		ProjectID:     strings.TrimSpace(in.ProjectID),
		Provider:      in.Provider,
		FullName:      in.FullName,
		CloneURL:      strings.TrimSpace(in.CloneURL),
		DefaultBranch: strings.TrimSpace(in.DefaultBranch),
		SchemaVersion: domain.SourceRepositorySchemaVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Source.InsertSourceRepository(ctx, repo); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(repo.CreatedAt, actor.TenantID, "source_repository.created", "source_repository", repo.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.SourceRepository{}, err
		}
		l.repositories[repo.ID] = repo
		l.publishCommittedAuditEntryLocked(entry)
		return repo, nil
	}
	l.repositories[repo.ID] = repo
	_, _ = l.appendChainLocked(actor.TenantID, "source_repository.created", "source_repository", repo.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SourceRepository{}, err
	}
	return repo, nil
}

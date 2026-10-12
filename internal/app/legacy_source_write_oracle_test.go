package app

// Historical characterization only. Source writes use focused Integration
// services over current repositories, not these aggregate facades.

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type RecordCommitInput struct {
	RepositoryID string
	SHA          string
	Author       string
	Message      string
	CommittedAt  time.Time
}

type UpsertBranchInput struct {
	RepositoryID   string
	Name           string
	HeadCommitID   string
	Protected      bool
	ProtectionHash string
}

type RecordPullRequestInput struct {
	RepositoryID   string
	Provider       string
	ProviderID     string
	Title          string
	State          string
	SourceBranch   string
	TargetBranch   string
	HeadCommitID   string
	ReviewDecision string
}

func (l *Ledger) RecordSourceCommit(ctx context.Context, actor domain.Actor, in RecordCommitInput) (domain.SourceCommit, error) {
	in, err := prepareLocalSourceCommit(ctx, actor, in)
	if err != nil {
		return domain.SourceCommit{}, err
	}
	if in.CommittedAt.IsZero() {
		in.CommittedAt = l.now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeLocalSourceWriteLocked(actor, in.RepositoryID, ""); err != nil {
		return domain.SourceCommit{}, err
	}
	repo := l.repositories[in.RepositoryID]
	for _, existing := range l.commits {
		if existing.TenantID == actor.TenantID && existing.RepositoryID == repo.ID && existing.SHA == in.SHA {
			return existing, nil
		}
	}
	messageHash := ""
	if strings.TrimSpace(in.Message) != "" {
		messageHash = hashBytes([]byte(in.Message))
	}
	commit := domain.SourceCommit{
		ID:            newID("commit"),
		TenantID:      actor.TenantID,
		RepositoryID:  repo.ID,
		SHA:           strings.ToLower(in.SHA),
		Author:        strings.TrimSpace(in.Author),
		MessageHash:   messageHash,
		CommittedAt:   in.CommittedAt.UTC(),
		SchemaVersion: domain.SourceCommitSchemaVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Source.InsertSourceCommit(ctx, commit); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(commit.CreatedAt, actor.TenantID, "source_commit.recorded", "source_commit", commit.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.SourceCommit{}, err
		}
		l.commits[commit.ID] = commit
		l.publishCommittedAuditEntryLocked(entry)
		return commit, nil
	}
	l.commits[commit.ID] = commit
	_, _ = l.appendChainLocked(actor.TenantID, "source_commit.recorded", "source_commit", commit.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SourceCommit{}, err
	}
	return commit, nil
}

func (l *Ledger) UpsertSourceBranch(ctx context.Context, actor domain.Actor, in UpsertBranchInput) (domain.SourceBranch, error) {
	in, err := prepareLocalSourceBranch(ctx, actor, in)
	if err != nil {
		return domain.SourceBranch{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeLocalSourceWriteLocked(actor, in.RepositoryID, in.HeadCommitID); err != nil {
		return domain.SourceBranch{}, err
	}
	repo := l.repositories[in.RepositoryID]
	for id, existing := range l.branches {
		if existing.TenantID == actor.TenantID && existing.RepositoryID == repo.ID && existing.Name == in.Name {
			existing.HeadCommitID = strings.TrimSpace(in.HeadCommitID)
			existing.Protected = in.Protected
			existing.ProtectionHash = strings.TrimSpace(in.ProtectionHash)
			if l.unitOfWork != nil {
				var entry domain.AuditChainEntry
				if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
					if err := repos.Source.UpdateSourceBranch(ctx, existing); err != nil {
						return err
					}
					var err error
					entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(l.now(), actor.TenantID, "source_branch.updated", "source_branch", existing.ID, actorType(actor), actorID(actor), existing.ProtectionHash, ""))
					return err
				}); err != nil {
					return domain.SourceBranch{}, err
				}
				l.branches[id] = existing
				l.publishCommittedAuditEntryLocked(entry)
				return existing, nil
			}
			l.branches[id] = existing
			_, _ = l.appendChainLocked(actor.TenantID, "source_branch.updated", "source_branch", existing.ID, actorType(actor), actorID(actor), existing.ProtectionHash, "")
			if err := l.persistLocked(ctx); err != nil {
				return domain.SourceBranch{}, err
			}
			return existing, nil
		}
	}
	branch := domain.SourceBranch{
		ID:             newID("branch"),
		TenantID:       actor.TenantID,
		RepositoryID:   repo.ID,
		Name:           in.Name,
		HeadCommitID:   strings.TrimSpace(in.HeadCommitID),
		Protected:      in.Protected,
		ProtectionHash: strings.TrimSpace(in.ProtectionHash),
		SchemaVersion:  domain.SourceBranchSchemaVersion,
		CreatedAt:      l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Source.InsertSourceBranch(ctx, branch); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(branch.CreatedAt, actor.TenantID, "source_branch.created", "source_branch", branch.ID, actorType(actor), actorID(actor), branch.ProtectionHash, ""))
			return err
		}); err != nil {
			return domain.SourceBranch{}, err
		}
		l.branches[branch.ID] = branch
		l.publishCommittedAuditEntryLocked(entry)
		return branch, nil
	}
	l.branches[branch.ID] = branch
	_, _ = l.appendChainLocked(actor.TenantID, "source_branch.created", "source_branch", branch.ID, actorType(actor), actorID(actor), branch.ProtectionHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SourceBranch{}, err
	}
	return branch, nil
}

func (l *Ledger) RecordPullRequest(ctx context.Context, actor domain.Actor, in RecordPullRequestInput) (domain.PullRequest, error) {
	in, err := prepareLocalPullRequest(ctx, actor, in)
	if err != nil {
		return domain.PullRequest{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeLocalSourceWriteLocked(actor, in.RepositoryID, in.HeadCommitID); err != nil {
		return domain.PullRequest{}, err
	}
	repo := l.repositories[in.RepositoryID]
	pr := domain.PullRequest{
		ID:             newID("pr"),
		TenantID:       actor.TenantID,
		RepositoryID:   repo.ID,
		Provider:       nonEmpty(in.Provider, repo.Provider),
		ProviderID:     in.ProviderID,
		Title:          in.Title,
		State:          in.State,
		SourceBranch:   strings.TrimSpace(in.SourceBranch),
		TargetBranch:   strings.TrimSpace(in.TargetBranch),
		HeadCommitID:   strings.TrimSpace(in.HeadCommitID),
		ReviewDecision: strings.TrimSpace(in.ReviewDecision),
		SchemaVersion:  domain.PullRequestSchemaVersion,
		CreatedAt:      l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Source.InsertPullRequest(ctx, pr); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(pr.CreatedAt, actor.TenantID, "pull_request.recorded", "pull_request", pr.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.PullRequest{}, err
		}
		l.pullRequests[pr.ID] = pr
		l.publishCommittedAuditEntryLocked(entry)
		return pr, nil
	}
	l.pullRequests[pr.ID] = pr
	_, _ = l.appendChainLocked(actor.TenantID, "pull_request.recorded", "pull_request", pr.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.PullRequest{}, err
	}
	return pr, nil
}

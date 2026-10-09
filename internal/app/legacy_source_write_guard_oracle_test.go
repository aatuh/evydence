package app

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

// Explicit local-memory checks only; native PostgreSQL routes use Integration
// transactions, not these maps or aggregate-backed replay.
func prepareLocalSourceWrite(ctx context.Context, a domain.Actor) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeSourceWrite); err != nil {
		return err
	}
	if a.TenantID == "" || len(a.TenantID) > 1024 || !utf8.ValidString(a.TenantID) || strings.ContainsRune(a.TenantID, 0) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	return nil
}

func localSourceInputError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, integrationapp.ErrNotFound) {
		return ErrNotFound
	}
	return ErrValidation
}

func prepareLocalSourceCommit(ctx context.Context, a domain.Actor, in RecordCommitInput) (RecordCommitInput, error) {
	if err := prepareLocalSourceWrite(ctx, a); err != nil {
		return in, err
	}
	v, err := integrationapp.NormalizeSourceCommitInput(integrationapp.RecordSourceCommitInput{RepositoryID: in.RepositoryID, SHA: in.SHA, Author: in.Author, Message: in.Message, CommittedAt: in.CommittedAt})
	if err != nil {
		return in, localSourceInputError(err)
	}
	return RecordCommitInput{RepositoryID: v.RepositoryID, SHA: v.SHA, Author: v.Author, Message: v.Message, CommittedAt: v.CommittedAt}, nil
}
func prepareLocalSourceBranch(ctx context.Context, a domain.Actor, in UpsertBranchInput) (UpsertBranchInput, error) {
	if err := prepareLocalSourceWrite(ctx, a); err != nil {
		return in, err
	}
	v, err := integrationapp.NormalizeSourceBranchInput(integrationapp.UpsertSourceBranchInput{RepositoryID: in.RepositoryID, Name: in.Name, HeadCommitID: in.HeadCommitID, Protected: in.Protected, ProtectionHash: in.ProtectionHash})
	if err != nil {
		return in, localSourceInputError(err)
	}
	if err := integrationapp.ValidateSourceBranchKey(a.TenantID, v); err != nil {
		return in, ErrValidation
	}
	return UpsertBranchInput{RepositoryID: v.RepositoryID, Name: v.Name, HeadCommitID: v.HeadCommitID, Protected: v.Protected, ProtectionHash: v.ProtectionHash}, nil
}
func prepareLocalPullRequest(ctx context.Context, a domain.Actor, in RecordPullRequestInput) (RecordPullRequestInput, error) {
	if err := prepareLocalSourceWrite(ctx, a); err != nil {
		return in, err
	}
	v, err := integrationapp.NormalizePullRequestInput(integrationapp.RecordPullRequestInput{RepositoryID: in.RepositoryID, Provider: in.Provider, ProviderID: in.ProviderID, Title: in.Title, State: in.State, SourceBranch: in.SourceBranch, TargetBranch: in.TargetBranch, HeadCommitID: in.HeadCommitID, ReviewDecision: in.ReviewDecision})
	if err != nil {
		return in, localSourceInputError(err)
	}
	return RecordPullRequestInput{RepositoryID: v.RepositoryID, Provider: v.Provider, ProviderID: v.ProviderID, Title: v.Title, State: v.State, SourceBranch: v.SourceBranch, TargetBranch: v.TargetBranch, HeadCommitID: v.HeadCommitID, ReviewDecision: v.ReviewDecision}, nil
}

func (l *Ledger) authorizeLocalSourceWriteLocked(a domain.Actor, repository, head string) error {
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	r, ok := l.repositories[repository]
	if !ok || r.TenantID != a.TenantID {
		return ErrNotFound
	}
	refs := resourceRefs{SourceRepositoryID: r.ID, ProjectID: r.ProjectID}
	if r.ProjectID != "" {
		p, ok := l.projects[r.ProjectID]
		if !ok || p.TenantID != a.TenantID {
			return ErrNotFound
		}
		product, ok := l.products[p.ProductID]
		if !ok || product.TenantID != a.TenantID {
			return ErrNotFound
		}
		refs.ProductID = product.ID
	}
	if err := l.authorizeResourceLocked(a, ScopeSourceWrite, refs); err != nil {
		return err
	}
	if head != "" {
		h, ok := l.commits[head]
		if !ok || h.TenantID != a.TenantID || h.RepositoryID != r.ID {
			return ErrNotFound
		}
	}
	return nil
}

func (l *Ledger) AuthorizeSourceCommitRecording(ctx context.Context, a domain.Actor, in RecordCommitInput) error {
	in, err := prepareLocalSourceCommit(ctx, a, in)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.authorizeLocalSourceWriteLocked(a, in.RepositoryID, "")
}
func (l *Ledger) AuthorizeSourceBranchUpsert(ctx context.Context, a domain.Actor, in UpsertBranchInput) error {
	in, err := prepareLocalSourceBranch(ctx, a, in)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.authorizeLocalSourceWriteLocked(a, in.RepositoryID, in.HeadCommitID)
}
func (l *Ledger) AuthorizePullRequestRecording(ctx context.Context, a domain.Actor, in RecordPullRequestInput) error {
	in, err := prepareLocalPullRequest(ctx, a, in)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.authorizeLocalSourceWriteLocked(a, in.RepositoryID, in.HeadCommitID)
}

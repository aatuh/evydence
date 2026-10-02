package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

// SourceSnapshotTransaction exposes only Integration's four source commands.
// Implementations bind all four commands to the same transaction; they must
// not commit individual components or expose partial results.
type SourceSnapshotTransaction interface {
	CreateSourceRepository(context.Context, identitydomain.Actor, CreateSourceRepositoryInput) (integrationdomain.SourceRepository, error)
	RecordSourceCommit(context.Context, identitydomain.Actor, RecordSourceCommitInput) (integrationdomain.SourceCommit, error)
	UpsertSourceBranch(context.Context, identitydomain.Actor, UpsertSourceBranchInput) (integrationdomain.SourceBranch, error)
	RecordPullRequest(context.Context, identitydomain.Actor, RecordPullRequestInput) (integrationdomain.PullRequest, error)
}
type SourceSnapshotTransactions interface {
	ExecuteSourceSnapshot(context.Context, func(context.Context, SourceSnapshotTransaction) error) error
}
type SourceSnapshotConfig struct {
	Transactions SourceSnapshotTransactions
	Authorizer   application.Authorizer
}
type SourceSnapshotCommands struct{ config SourceSnapshotConfig }
type SourceSnapshotInput struct {
	ProjectID   string
	Repository  SourceSnapshotRepositoryInput
	Commit      *SourceSnapshotCommitInput
	Branch      *SourceSnapshotBranchInput
	PullRequest *SourceSnapshotPullRequestInput
}
type SourceSnapshotRepositoryInput struct{ FullName, CloneURL, DefaultBranch string }
type SourceSnapshotCommitInput struct {
	SHA, Author, Message string
	CommittedAt          time.Time
}
type SourceSnapshotBranchInput struct {
	Name           string
	Protected      bool
	ProtectionHash string
}
type SourceSnapshotPullRequestInput struct {
	ProviderID, Title, State, SourceBranch, TargetBranch, ReviewDecision string
}
type SourceSnapshotResult struct {
	Repository  integrationdomain.SourceRepository
	Commit      integrationdomain.SourceCommit
	Branch      integrationdomain.SourceBranch
	PullRequest integrationdomain.PullRequest
}

func NewSourceSnapshotCommands(c SourceSnapshotConfig) (*SourceSnapshotCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil {
		return nil, ErrValidation
	}
	return &SourceSnapshotCommands{c}, nil
}
func (s *SourceSnapshotCommands) RecordSourceSnapshot(ctx context.Context, a identitydomain.Actor, provider string, in SourceSnapshotInput) (SourceSnapshotResult, error) {
	if ctx == nil {
		return SourceSnapshotResult{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return SourceSnapshotResult{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "source:write", ScopeOnly: true}); err != nil {
		return SourceSnapshotResult{}, err
	}
	if provider != "github" && provider != "gitlab" {
		return SourceSnapshotResult{}, ErrValidation
	}
	var result SourceSnapshotResult
	err := s.config.Transactions.ExecuteSourceSnapshot(ctx, func(ctx context.Context, tx SourceSnapshotTransaction) error {
		var err error
		result.Repository, err = tx.CreateSourceRepository(ctx, a, CreateSourceRepositoryInput{ProjectID: in.ProjectID, Provider: provider, FullName: in.Repository.FullName, CloneURL: in.Repository.CloneURL, DefaultBranch: in.Repository.DefaultBranch})
		if err != nil {
			return err
		}
		if in.Commit != nil {
			v := in.Commit
			result.Commit, err = tx.RecordSourceCommit(ctx, a, RecordSourceCommitInput{RepositoryID: result.Repository.ID, SHA: v.SHA, Author: v.Author, Message: v.Message, CommittedAt: v.CommittedAt})
			if err != nil {
				return err
			}
		}
		if in.Branch != nil {
			v := in.Branch
			result.Branch, err = tx.UpsertSourceBranch(ctx, a, UpsertSourceBranchInput{RepositoryID: result.Repository.ID, HeadCommitID: result.Commit.ID, Name: v.Name, Protected: v.Protected, ProtectionHash: v.ProtectionHash})
			if err != nil {
				return err
			}
		}
		if in.PullRequest != nil {
			v := in.PullRequest
			result.PullRequest, err = tx.RecordPullRequest(ctx, a, RecordPullRequestInput{RepositoryID: result.Repository.ID, Provider: provider, HeadCommitID: result.Commit.ID, ProviderID: v.ProviderID, Title: v.Title, State: v.State, SourceBranch: v.SourceBranch, TargetBranch: v.TargetBranch, ReviewDecision: v.ReviewDecision})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return SourceSnapshotResult{}, err
	}
	return result, nil
}

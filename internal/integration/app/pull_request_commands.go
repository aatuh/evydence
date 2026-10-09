package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type PullRequestReader interface {
	SourceRepositoryWriteReader
	SourceCommitIdentityReader
	SourceRepositoryProvider(context.Context, string, string) (string, error)
}
type PullRequestTransaction interface {
	PullRequestReader
	application.Authorizer
	application.AuditAppender
	InsertPullRequest(context.Context, integrationdomain.PullRequest) error
}
type PullRequestTransactions interface {
	ExecutePullRequest(context.Context, func(context.Context, PullRequestTransaction) error) error
}
type PullRequestConfig struct {
	Transactions PullRequestTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type PullRequestCommands struct{ config PullRequestConfig }
type RecordPullRequestInput struct {
	RepositoryID, Provider, ProviderID, Title, State, SourceBranch, TargetBranch, HeadCommitID, ReviewDecision string
}

func NewPullRequestCommands(c PullRequestConfig) (*PullRequestCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &PullRequestCommands{c}, nil
}
func NormalizePullRequestInput(in RecordPullRequestInput) (RecordPullRequestInput, error) {
	if !validSourceText(in.RepositoryID, 1024, false) || !validSourceText(in.HeadCommitID, 1024, true) {
		return in, ErrValidation
	}
	for _, v := range []string{in.Provider, in.ProviderID, in.Title, in.State, in.SourceBranch, in.TargetBranch, in.ReviewDecision} {
		if !validSourceText(v, MaxSourceTextBytes, true) {
			return in, ErrValidation
		}
	}
	headProvided := in.HeadCommitID != ""
	for _, v := range []*string{&in.RepositoryID, &in.Provider, &in.ProviderID, &in.Title, &in.State, &in.SourceBranch, &in.TargetBranch, &in.HeadCommitID, &in.ReviewDecision} {
		*v = strings.TrimSpace(*v)
	}
	if in.RepositoryID == "" || in.ProviderID == "" || in.Title == "" || in.State != "open" && in.State != "closed" && in.State != "merged" {
		return in, ErrValidation
	}
	if headProvided && in.HeadCommitID == "" {
		return in, ErrNotFound
	}
	return in, nil
}

func (s *PullRequestCommands) RecordPullRequest(ctx context.Context, a identitydomain.Actor, in RecordPullRequestInput) (integrationdomain.PullRequest, error) {
	if s == nil {
		return integrationdomain.PullRequest{}, ErrValidation
	}
	if err := prepareSourceWrite(ctx, a, s.config.Authorizer); err != nil {
		return integrationdomain.PullRequest{}, err
	}
	in, err := NormalizePullRequestInput(in)
	if err != nil {
		return integrationdomain.PullRequest{}, err
	}
	now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if !validSourceTime(now) {
		return integrationdomain.PullRequest{}, ErrValidation
	}
	var result integrationdomain.PullRequest
	err = s.config.Transactions.ExecutePullRequest(ctx, func(ctx context.Context, tx PullRequestTransaction) error {
		r, err := authorizeSourceWriteRepository(ctx, tx, a, in.RepositoryID)
		if err != nil {
			return err
		}
		if err := authorizeSourceHead(ctx, tx, a, r.ID, in.HeadCommitID); err != nil {
			return err
		}
		provider := in.Provider
		if provider == "" {
			provider, err = tx.SourceRepositoryProvider(ctx, a.TenantID, r.ID)
			if err != nil {
				return err
			}
			if !validSourceText(provider, MaxSourceTextBytes, false) {
				return ErrConflict
			}
		}
		v := integrationdomain.PullRequest{ID: s.config.IDs.NewID("pr"), TenantID: a.TenantID, RepositoryID: r.ID, Provider: provider, ProviderID: in.ProviderID, Title: in.Title, State: in.State, SourceBranch: in.SourceBranch, TargetBranch: in.TargetBranch, HeadCommitID: in.HeadCommitID, ReviewDecision: in.ReviewDecision, SchemaVersion: integrationdomain.PullRequestSchemaVersion, CreatedAt: now}
		if err := tx.InsertPullRequest(ctx, v); err != nil {
			return err
		}
		actorType, actorID := sourceAuditIdentity(a)
		if _, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "pull_request.recorded", SubjectType: "pull_request", SubjectID: v.ID, ActorType: actorType, ActorID: actorID, OccurredAt: now}); err != nil {
			return err
		}
		result = v
		return nil
	})
	if err != nil {
		return integrationdomain.PullRequest{}, err
	}
	return result, nil
}

package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

// Only historical HTTP fixtures use this bridge. Real former source guards and
// writes operate on current owned records and the isolated replay clone. This
// is not production wiring or a substitute for PostgreSQL ownership fences.
type integrationFixtureCommands struct{ catalogFixtureCommands }

func fixtureRepositoryInput(in integrationapp.CreateSourceRepositoryInput) app.CreateRepositoryInput {
	return app.CreateRepositoryInput(in)
}
func fixtureCommitInput(in integrationapp.RecordSourceCommitInput) app.RecordCommitInput {
	return app.RecordCommitInput(in)
}
func fixtureBranchInput(in integrationapp.UpsertSourceBranchInput) app.UpsertBranchInput {
	return app.UpsertBranchInput{RepositoryID: in.RepositoryID, Name: in.Name, HeadCommitID: in.HeadCommitID, Protected: in.Protected, ProtectionHash: in.ProtectionHash}
}
func fixturePullRequestInput(in integrationapp.RecordPullRequestInput) app.RecordPullRequestInput {
	return app.RecordPullRequestInput(in)
}

func (f integrationFixtureCommands) AuthorizeSourceRepositoryCreation(ctx context.Context, a domain.Actor, in integrationapp.CreateSourceRepositoryInput) error {
	return f.commandLedger(ctx).AuthorizeSourceRepositoryCreation(ctx, a, fixtureRepositoryInput(in))
}
func (f integrationFixtureCommands) AuthorizeSourceCommitRecording(ctx context.Context, a domain.Actor, in integrationapp.RecordSourceCommitInput) error {
	return f.commandLedger(ctx).AuthorizeSourceCommitRecording(ctx, a, fixtureCommitInput(in))
}
func (f integrationFixtureCommands) AuthorizeSourceBranchUpsert(ctx context.Context, a domain.Actor, in integrationapp.UpsertSourceBranchInput) error {
	return f.commandLedger(ctx).AuthorizeSourceBranchUpsert(ctx, a, fixtureBranchInput(in))
}
func (f integrationFixtureCommands) AuthorizePullRequestRecording(ctx context.Context, a domain.Actor, in integrationapp.RecordPullRequestInput) error {
	return f.commandLedger(ctx).AuthorizePullRequestRecording(ctx, a, fixturePullRequestInput(in))
}
func (f integrationFixtureCommands) AuthorizeSourceSnapshot(ctx context.Context, a domain.Actor, provider string, in integrationapp.SourceSnapshotInput) error {
	if err := integrationapp.ValidateSourceSnapshotRequest(provider, in); err != nil {
		return err
	}
	if err := integrationapp.ValidateSourceSnapshotKeys(a.TenantID, provider, in); err != nil {
		return err
	}
	return f.AuthorizeSourceRepositoryCreation(ctx, a, integrationapp.CreateSourceRepositoryInput{ProjectID: in.ProjectID, Provider: provider, FullName: in.Repository.FullName, CloneURL: in.Repository.CloneURL, DefaultBranch: in.Repository.DefaultBranch})
}

func (f integrationFixtureCommands) CreateSourceRepository(ctx context.Context, a domain.Actor, in integrationapp.CreateSourceRepositoryInput) (integrationdomain.SourceRepository, error) {
	v, err := f.commandLedger(ctx).CreateSourceRepository(ctx, a, fixtureRepositoryInput(in))
	return integrationdomain.SourceRepository(v), err
}
func (f integrationFixtureCommands) RecordSourceCommit(ctx context.Context, a domain.Actor, in integrationapp.RecordSourceCommitInput) (integrationdomain.SourceCommit, error) {
	v, err := f.commandLedger(ctx).RecordSourceCommit(ctx, a, fixtureCommitInput(in))
	return integrationdomain.SourceCommit(v), err
}
func (f integrationFixtureCommands) UpsertSourceBranch(ctx context.Context, a domain.Actor, in integrationapp.UpsertSourceBranchInput) (integrationdomain.SourceBranch, error) {
	v, err := f.commandLedger(ctx).UpsertSourceBranch(ctx, a, fixtureBranchInput(in))
	return integrationdomain.SourceBranch(v), err
}
func (f integrationFixtureCommands) RecordPullRequest(ctx context.Context, a domain.Actor, in integrationapp.RecordPullRequestInput) (integrationdomain.PullRequest, error) {
	v, err := f.commandLedger(ctx).RecordPullRequest(ctx, a, fixturePullRequestInput(in))
	return integrationdomain.PullRequest(v), err
}

// Compose the same real child writes as the former fixture upload; no payload
// rewrite can alter the exact commit-message bytes used by the child hash.
func (f integrationFixtureCommands) RecordSourceSnapshot(ctx context.Context, a domain.Actor, provider string, in integrationapp.SourceSnapshotInput) (integrationapp.SourceSnapshotResult, error) {
	var result integrationapp.SourceSnapshotResult
	var err error
	result.Repository, err = f.CreateSourceRepository(ctx, a, integrationapp.CreateSourceRepositoryInput{ProjectID: in.ProjectID, Provider: provider, FullName: in.Repository.FullName, CloneURL: in.Repository.CloneURL, DefaultBranch: in.Repository.DefaultBranch})
	if err != nil {
		return result, err
	}
	if v := in.Commit; v != nil {
		result.Commit, err = f.RecordSourceCommit(ctx, a, integrationapp.RecordSourceCommitInput{RepositoryID: result.Repository.ID, SHA: v.SHA, Author: v.Author, Message: v.Message, CommittedAt: v.CommittedAt})
		if err != nil {
			return result, err
		}
	}
	if v := in.Branch; v != nil {
		result.Branch, err = f.UpsertSourceBranch(ctx, a, integrationapp.UpsertSourceBranchInput{RepositoryID: result.Repository.ID, Name: v.Name, HeadCommitID: result.Commit.ID, Protected: v.Protected, ProtectionHash: v.ProtectionHash})
		if err != nil {
			return result, err
		}
	}
	if v := in.PullRequest; v != nil {
		result.PullRequest, err = f.RecordPullRequest(ctx, a, integrationapp.RecordPullRequestInput{RepositoryID: result.Repository.ID, Provider: provider, ProviderID: v.ProviderID, Title: v.Title, State: v.State, SourceBranch: v.SourceBranch, TargetBranch: v.TargetBranch, HeadCommitID: result.Commit.ID, ReviewDecision: v.ReviewDecision})
	}
	return result, err
}

func (f integrationFixtureCommands) CreateCollector(ctx context.Context, a domain.Actor, in integrationapp.CreateCollectorInput) (integrationdomain.Collector, identitydomain.APIKey, string, error) {
	v, key, secret, err := f.commandLedger(ctx).CreateCollector(ctx, a, app.CreateCollectorInput(in))
	if err != nil {
		return integrationdomain.Collector{}, identitydomain.APIKey{}, "", err
	}
	model, err := fixtureCollector(v)
	return model, identitydomain.APIKey(key), secret, err
}
func (f integrationFixtureCommands) RecordCollectorRelease(ctx context.Context, a domain.Actor, in integrationapp.RecordCollectorReleaseInput) (integrationdomain.CollectorRelease, error) {
	v, err := f.commandLedger(ctx).RecordCollectorRelease(ctx, a, app.RecordCollectorReleaseInput(in))
	model := integrationdomain.CollectorRelease(v)
	model.Limitations = slices.Clone(v.Limitations)
	return model, err
}
func (f integrationFixtureCommands) CreateCommercialCollectorDefinition(ctx context.Context, a domain.Actor, in integrationapp.CreateCommercialCollectorInput) (integrationdomain.CommercialCollectorDefinition, error) {
	v, err := f.commandLedger(ctx).CreateCommercialCollectorDefinition(ctx, a, app.CreateCommercialCollectorInput(in))
	model := integrationdomain.CommercialCollectorDefinition(v)
	model.AllowedScopes = slices.Clone(v.AllowedScopes)
	return model, err
}

func (s *Server) bindIntegrationFixtureCommands(ledger *app.Ledger) {
	f := integrationFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.collectorCommands.(integrationFixtureCommands); s.collectorCommands == nil || fixture {
		s.collectorCommands = f
	}
	if _, fixture := s.sourceRepositoryCommands.(integrationFixtureCommands); s.sourceRepositoryCommands == nil || fixture {
		s.sourceRepositoryCommands = f
	}
	if _, fixture := s.sourceCommitCommands.(integrationFixtureCommands); s.sourceCommitCommands == nil || fixture {
		s.sourceCommitCommands = f
	}
	if _, fixture := s.sourceBranchCommands.(integrationFixtureCommands); s.sourceBranchCommands == nil || fixture {
		s.sourceBranchCommands = f
	}
	if _, fixture := s.pullRequestCommands.(integrationFixtureCommands); s.pullRequestCommands == nil || fixture {
		s.pullRequestCommands = f
	}
	if _, fixture := s.sourceSnapshotCommands.(integrationFixtureCommands); s.sourceSnapshotCommands == nil || fixture {
		s.sourceSnapshotCommands = f
	}
}

var (
	_ CollectorCommands        = integrationFixtureCommands{}
	_ SourceRepositoryCommands = integrationFixtureCommands{}
	_ SourceCommitCommands     = integrationFixtureCommands{}
	_ SourceBranchCommands     = integrationFixtureCommands{}
	_ PullRequestCommands      = integrationFixtureCommands{}
	_ SourceSnapshotCommands   = integrationFixtureCommands{}
)

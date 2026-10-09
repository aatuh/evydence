package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

// Only historical HTTP fixtures use this bridge. Real former source guards and
// writes operate on current owned records and the isolated replay clone. This
// is not production wiring or a substitute for PostgreSQL ownership fences.
type integrationFixtureCommands struct {
	catalogFixtureCommands
	credentials integrationapp.CollectorCredentials
	clock       application.Clock
}

func fixtureRepositoryInput(in integrationapp.CreateSourceRepositoryInput) app.CreateRepositoryInput {
	return app.CreateRepositoryInput(in)
}

func (f integrationFixtureCommands) AuthorizeSourceRepositoryCreation(ctx context.Context, a domain.Actor, in integrationapp.CreateSourceRepositoryInput) error {
	c, err := f.nativeSourceRepositoryPreflight()
	if err != nil {
		return err
	}
	return c.AuthorizeSourceRepositoryCreation(ctx, a, in)
}
func (f integrationFixtureCommands) AuthorizeSourceCommitRecording(ctx context.Context, a domain.Actor, in integrationapp.RecordSourceCommitInput) error {
	c, err := f.nativeSourceCommit(true)
	if err != nil {
		return err
	}
	return c.AuthorizeSourceCommitRecording(ctx, a, in)
}
func (f integrationFixtureCommands) AuthorizeSourceBranchUpsert(ctx context.Context, a domain.Actor, in integrationapp.UpsertSourceBranchInput) error {
	c, err := f.nativeSourceBranch(true)
	if err != nil {
		return err
	}
	return c.AuthorizeSourceBranchUpsert(ctx, a, in)
}
func (f integrationFixtureCommands) AuthorizePullRequestRecording(ctx context.Context, a domain.Actor, in integrationapp.RecordPullRequestInput) error {
	c, err := f.nativePullRequest(true)
	if err != nil {
		return err
	}
	return c.AuthorizePullRequestRecording(ctx, a, in)
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
	c, err := f.nativeSourceCommit(false)
	if err != nil {
		return integrationdomain.SourceCommit{}, err
	}
	v, err := c.RecordSourceCommit(ctx, a, in)
	return v, collectorReleaseFixtureError(err)
}
func (f integrationFixtureCommands) UpsertSourceBranch(ctx context.Context, a domain.Actor, in integrationapp.UpsertSourceBranchInput) (integrationdomain.SourceBranch, error) {
	c, err := f.nativeSourceBranch(false)
	if err != nil {
		return integrationdomain.SourceBranch{}, err
	}
	v, err := c.UpsertSourceBranch(ctx, a, in)
	return v, collectorReleaseFixtureError(err)
}
func (f integrationFixtureCommands) RecordPullRequest(ctx context.Context, a domain.Actor, in integrationapp.RecordPullRequestInput) (integrationdomain.PullRequest, error) {
	c, err := f.nativePullRequest(false)
	if err != nil {
		return integrationdomain.PullRequest{}, err
	}
	v, err := c.RecordPullRequest(ctx, a, in)
	return v, collectorReleaseFixtureError(err)
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
	c, err := f.nativeCollectorCreation(false)
	if err != nil {
		return integrationdomain.Collector{}, identitydomain.APIKey{}, "", err
	}
	v, key, secret, err := c.CreateCollector(ctx, a, in)
	return v, key, secret, collectorReleaseFixtureError(err)
}
func (f integrationFixtureCommands) RecordCollectorRelease(ctx context.Context, a domain.Actor, in integrationapp.RecordCollectorReleaseInput) (integrationdomain.CollectorRelease, error) {
	c, err := f.nativeCollectorRelease(false)
	if err != nil {
		return integrationdomain.CollectorRelease{}, err
	}
	v, err := c.RecordCollectorRelease(ctx, a, in)
	return v, collectorReleaseFixtureError(err)
}
func (f integrationFixtureCommands) CreateCommercialCollectorDefinition(ctx context.Context, a domain.Actor, in integrationapp.CreateCommercialCollectorInput) (integrationdomain.CommercialCollectorDefinition, error) {
	c, err := f.nativeCommercialCollector(false)
	if err != nil {
		return integrationdomain.CommercialCollectorDefinition{}, err
	}
	v, err := c.CreateCommercialCollectorDefinition(ctx, a, in)
	return v, collectorReleaseFixtureError(err)
}

func (s *Server) bindIntegrationFixtureCommands(ledger *app.Ledger) {
	f := integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if old, fixture := s.collectorCommands.(integrationFixtureCommands); fixture {
		old.ledger = ledger
		s.collectorCommands = old
	} else if s.collectorCommands == nil {
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

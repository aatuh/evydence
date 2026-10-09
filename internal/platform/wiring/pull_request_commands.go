package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func BuildPullRequestCommands(factory app.UnitOfWorkFactory) (*integrationapp.PullRequestCommands, error) {
	if factory == nil {
		return nil, errors.New("pull request transactions are required")
	}
	return integrationapp.NewPullRequestCommands(integrationapp.PullRequestConfig{Transactions: pullRequestTransactions{factory}, Authorizer: integrationquery.NewSourceWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type pullRequestTransactions struct{ factory app.UnitOfWorkFactory }

func (t pullRequestTransactions) ExecutePullRequest(ctx context.Context, fn func(context.Context, integrationapp.PullRequestTransaction) error) error {
	return mapSourceRepositoryWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Source.(integrationapp.PullRequestReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, pullRequestTransaction{reader, repos.Source, repos.Audit})
	}))
}

type pullRequestTransaction struct {
	reader integrationapp.PullRequestReader
	source app.SourceRepository
	audit  app.AuditRepository
}

func (t pullRequestTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return integrationquery.NewSourceWriteAuthorizer().Authorize(ctx, a, r)
}
func (t pullRequestTransaction) LockSourceRepositoryForWrite(ctx context.Context, tenant, id string) (integrationapp.SourceRepositoryIdentity, error) {
	v, err := t.reader.LockSourceRepositoryForWrite(ctx, tenant, id)
	return v, mapSourceRepositoryWriteError(err)
}
func (t pullRequestTransaction) SourceCommitIdentityByID(ctx context.Context, tenant, repository, id string) (integrationapp.SourceCommitIdentity, error) {
	v, err := t.reader.SourceCommitIdentityByID(ctx, tenant, repository, id)
	return v, mapSourceRepositoryWriteError(err)
}
func (t pullRequestTransaction) SourceRepositoryProvider(ctx context.Context, tenant, id string) (string, error) {
	v, err := t.reader.SourceRepositoryProvider(ctx, tenant, id)
	return v, mapSourceRepositoryWriteError(err)
}
func (t pullRequestTransaction) InsertPullRequest(ctx context.Context, v integrationdomain.PullRequest) error {
	return mapSourceRepositoryWriteError(t.source.InsertPullRequest(ctx, pullRequestToDTO(v)))
}
func (t pullRequestTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, v)
	return r, mapSourceRepositoryWriteError(err)
}
func pullRequestToDTO(v integrationdomain.PullRequest) domain.PullRequest {
	return domain.PullRequest{ID: v.ID, TenantID: v.TenantID, RepositoryID: v.RepositoryID, Provider: v.Provider, ProviderID: v.ProviderID, Title: v.Title, State: v.State, SourceBranch: v.SourceBranch, TargetBranch: v.TargetBranch, HeadCommitID: v.HeadCommitID, ReviewDecision: v.ReviewDecision, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}

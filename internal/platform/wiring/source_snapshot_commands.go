package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func BuildSourceSnapshotCommands(factory app.UnitOfWorkFactory) (*integrationapp.SourceSnapshotCommands, error) {
	if factory == nil {
		return nil, errors.New("source snapshot transactions are required")
	}
	return integrationapp.NewSourceSnapshotCommands(integrationapp.SourceSnapshotConfig{Transactions: sourceSnapshotTransactions{factory}, Authorizer: integrationquery.NewSourceWriteAuthorizer()})
}

type sourceSnapshotTransactions struct{ factory app.UnitOfWorkFactory }

func (t sourceSnapshotTransactions) ExecuteSourceSnapshot(ctx context.Context, fn func(context.Context, integrationapp.SourceSnapshotTransaction) error) error {
	return mapSourceRepositoryWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		repository, repoOK := repos.Source.(integrationapp.SourceRepositoryCreationReader)
		commit, commitOK := repos.Source.(integrationapp.SourceCommitReader)
		branch, branchOK := repos.Source.(integrationapp.SourceBranchReader)
		pr, prOK := repos.Source.(integrationapp.PullRequestReader)
		if !repoOK || !commitOK || !branchOK || !prOK || repos.Audit == nil {
			return app.ErrValidation
		}
		// Bind each child to these repositories directly. ExecuteUnitOfWork does
		// not install an ambient UoW for standalone callers, so invoking the four
		// factory-backed builders here would open separate transactions.
		bound := sourceSnapshotChildTransactions{repository: sourceRepositoryTransaction{repository, repos.Source, repos.Audit}, commit: sourceCommitTransaction{commit, repos.Source, repos.Audit}, branch: sourceBranchTransaction{branch, repos.Source, repos.Audit}, pr: pullRequestTransaction{pr, repos.Source, repos.Audit}}
		authorizer := integrationquery.NewSourceWriteAuthorizer()
		clock := application.ClockFunc(time.Now)
		ids := application.IDGeneratorFunc(application.NewID)
		rc, err := integrationapp.NewSourceRepositoryCommands(integrationapp.SourceRepositoryCreationConfig{Transactions: bound, Authorizer: authorizer, Clock: clock, IDs: ids})
		if err != nil {
			return err
		}
		cc, err := integrationapp.NewSourceCommitCommands(integrationapp.SourceCommitConfig{Transactions: bound, Authorizer: authorizer, Clock: clock, IDs: ids})
		if err != nil {
			return err
		}
		bc, err := integrationapp.NewSourceBranchCommands(integrationapp.SourceBranchConfig{Transactions: bound, Authorizer: authorizer, Clock: clock, IDs: ids})
		if err != nil {
			return err
		}
		pc, err := integrationapp.NewPullRequestCommands(integrationapp.PullRequestConfig{Transactions: bound, Authorizer: authorizer, Clock: clock, IDs: ids})
		if err != nil {
			return err
		}
		return fn(ctx, sourceSnapshotTransaction{rc, cc, bc, pc})
	}))
}

type sourceSnapshotTransaction struct {
	*integrationapp.SourceRepositoryCommands
	*integrationapp.SourceCommitCommands
	*integrationapp.SourceBranchCommands
	*integrationapp.PullRequestCommands
}
type sourceSnapshotChildTransactions struct {
	repository sourceRepositoryTransaction
	commit     sourceCommitTransaction
	branch     sourceBranchTransaction
	pr         pullRequestTransaction
}

func (t sourceSnapshotChildTransactions) ExecuteSourceRepository(ctx context.Context, fn func(context.Context, integrationapp.SourceRepositoryCreationTransaction) error) error {
	return fn(ctx, t.repository)
}
func (t sourceSnapshotChildTransactions) ExecuteSourceCommit(ctx context.Context, fn func(context.Context, integrationapp.SourceCommitTransaction) error) error {
	return fn(ctx, t.commit)
}
func (t sourceSnapshotChildTransactions) ExecuteSourceBranch(ctx context.Context, fn func(context.Context, integrationapp.SourceBranchTransaction) error) error {
	return fn(ctx, t.branch)
}
func (t sourceSnapshotChildTransactions) ExecutePullRequest(ctx context.Context, fn func(context.Context, integrationapp.PullRequestTransaction) error) error {
	return fn(ctx, t.pr)
}

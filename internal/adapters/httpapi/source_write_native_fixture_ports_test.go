package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

type sourceWriteFixtureReader interface {
	integrationapp.SourceCommitReader
	integrationapp.SourceBranchReader
	integrationapp.PullRequestReader
}
type sourceWriteFixtureTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type sourceWriteFixtureTransaction struct {
	reader   sourceWriteFixtureReader
	repos    app.Repositories
	readOnly bool
	kind     string
}

func (f sourceWriteFixtureTransactions) execute(ctx context.Context, kind string, run func(context.Context, sourceWriteFixtureTransaction) error) error {
	if ctx == nil || run == nil {
		return integrationapp.ErrValidation
	}
	return collectorReleaseFixtureCoreError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Source.(sourceWriteFixtureReader)
		if !ok || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, sourceWriteFixtureTransaction{reader, r, f.readOnly, kind})
	}))
}
func (f sourceWriteFixtureTransactions) ExecuteSourceCommit(ctx context.Context, run func(context.Context, integrationapp.SourceCommitTransaction) error) error {
	if run == nil {
		return integrationapp.ErrValidation
	}
	return f.execute(ctx, "commit", func(ctx context.Context, tx sourceWriteFixtureTransaction) error { return run(ctx, tx) })
}
func (f sourceWriteFixtureTransactions) ExecuteSourceBranch(ctx context.Context, run func(context.Context, integrationapp.SourceBranchTransaction) error) error {
	if run == nil {
		return integrationapp.ErrValidation
	}
	return f.execute(ctx, "branch", func(ctx context.Context, tx sourceWriteFixtureTransaction) error { return run(ctx, tx) })
}
func (f sourceWriteFixtureTransactions) ExecutePullRequest(ctx context.Context, run func(context.Context, integrationapp.PullRequestTransaction) error) error {
	if run == nil {
		return integrationapp.ErrValidation
	}
	return f.execute(ctx, "pull-request", func(ctx context.Context, tx sourceWriteFixtureTransaction) error { return run(ctx, tx) })
}
func (t sourceWriteFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return integrationquery.NewSourceWriteAuthorizer().Authorize(ctx, a, r)
}
func (t sourceWriteFixtureTransaction) LockSourceRepositoryForWrite(ctx context.Context, tenant, id string) (integrationapp.SourceRepositoryIdentity, error) {
	v, err := t.reader.LockSourceRepositoryForWrite(ctx, tenant, id)
	return v, collectorReleaseFixtureCoreError(err)
}
func (t sourceWriteFixtureTransaction) SourceCommitIdentityByID(ctx context.Context, tenant, repository, id string) (integrationapp.SourceCommitIdentity, error) {
	v, err := t.reader.SourceCommitIdentityByID(ctx, tenant, repository, id)
	return v, collectorReleaseFixtureCoreError(err)
}
func (t sourceWriteFixtureTransaction) SourceCommitBySHA(ctx context.Context, tenant, repository, sha string) (integrationdomain.SourceCommit, bool, error) {
	if t.readOnly {
		panic("source preflight read commit metadata")
	}
	v, found, err := t.reader.SourceCommitBySHA(ctx, tenant, repository, sha)
	return v, found, collectorReleaseFixtureCoreError(err)
}
func (t sourceWriteFixtureTransaction) SourceBranchByName(ctx context.Context, tenant, repository, name string) (integrationdomain.SourceBranch, bool, error) {
	if t.readOnly {
		panic("source preflight read branch metadata")
	}
	v, found, err := t.reader.SourceBranchByName(ctx, tenant, repository, name)
	return v, found, collectorReleaseFixtureCoreError(err)
}
func (t sourceWriteFixtureTransaction) SourceRepositoryProvider(ctx context.Context, tenant, id string) (string, error) {
	if t.readOnly {
		panic("source preflight read provider metadata")
	}
	v, err := t.reader.SourceRepositoryProvider(ctx, tenant, id)
	return v, collectorReleaseFixtureCoreError(err)
}
func (t sourceWriteFixtureTransaction) assertWrite(kind string) {
	if t.readOnly || t.kind != kind {
		panic("source fixture used unauthorized write capability")
	}
}
func (t sourceWriteFixtureTransaction) InsertSourceCommit(ctx context.Context, v integrationdomain.SourceCommit) error {
	t.assertWrite("commit")
	return collectorReleaseFixtureCoreError(t.repos.Source.InsertSourceCommit(ctx, domain.SourceCommit(v)))
}
func (t sourceWriteFixtureTransaction) InsertSourceBranch(ctx context.Context, v integrationdomain.SourceBranch) error {
	t.assertWrite("branch")
	return collectorReleaseFixtureCoreError(t.repos.Source.InsertSourceBranch(ctx, domain.SourceBranch(v)))
}
func (t sourceWriteFixtureTransaction) UpdateSourceBranch(ctx context.Context, v integrationdomain.SourceBranch) error {
	t.assertWrite("branch")
	return collectorReleaseFixtureCoreError(t.repos.Source.UpdateSourceBranch(ctx, domain.SourceBranch(v)))
}
func (t sourceWriteFixtureTransaction) InsertPullRequest(ctx context.Context, v integrationdomain.PullRequest) error {
	t.assertWrite("pull-request")
	return collectorReleaseFixtureCoreError(t.repos.Source.InsertPullRequest(ctx, domain.PullRequest(v)))
}
func (t sourceWriteFixtureTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if t.readOnly {
		panic("source preflight appended audit")
	}
	r, err := (governanceFixtureTransaction{audit: t.repos.Audit}).AppendAudit(ctx, v)
	return r, collectorReleaseFixtureCoreError(err)
}
func (f integrationFixtureCommands) sourceWriteDependencies(readOnly bool) (sourceWriteFixtureTransactions, application.Authorizer, application.Clock, application.IDGenerator) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return sourceWriteFixtureTransactions{f.catalogFixtureCommands, readOnly}, integrationquery.NewSourceWriteAuthorizer(), clock, ids
}
func (f integrationFixtureCommands) nativeSourceCommit(readOnly bool) (*integrationapp.SourceCommitCommands, error) {
	tx, a, clock, ids := f.sourceWriteDependencies(readOnly)
	return integrationapp.NewSourceCommitCommands(integrationapp.SourceCommitConfig{Transactions: tx, Authorizer: a, Clock: clock, IDs: ids})
}
func (f integrationFixtureCommands) nativeSourceBranch(readOnly bool) (*integrationapp.SourceBranchCommands, error) {
	tx, a, clock, ids := f.sourceWriteDependencies(readOnly)
	return integrationapp.NewSourceBranchCommands(integrationapp.SourceBranchConfig{Transactions: tx, Authorizer: a, Clock: clock, IDs: ids})
}
func (f integrationFixtureCommands) nativePullRequest(readOnly bool) (*integrationapp.PullRequestCommands, error) {
	tx, a, clock, ids := f.sourceWriteDependencies(readOnly)
	return integrationapp.NewPullRequestCommands(integrationapp.PullRequestConfig{Transactions: tx, Authorizer: a, Clock: clock, IDs: ids})
}

var _ integrationapp.SourceCommitTransaction = sourceWriteFixtureTransaction{}
var _ integrationapp.SourceBranchTransaction = sourceWriteFixtureTransaction{}
var _ integrationapp.PullRequestTransaction = sourceWriteFixtureTransaction{}

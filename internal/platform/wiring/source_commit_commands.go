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

func BuildSourceCommitCommands(factory app.UnitOfWorkFactory) (*integrationapp.SourceCommitCommands, error) {
	if factory == nil {
		return nil, errors.New("source commit transactions are required")
	}
	return integrationapp.NewSourceCommitCommands(integrationapp.SourceCommitConfig{Transactions: sourceCommitTransactions{factory}, Authorizer: integrationquery.NewSourceWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type sourceCommitTransactions struct{ factory app.UnitOfWorkFactory }

func (t sourceCommitTransactions) ExecuteSourceCommit(ctx context.Context, fn func(context.Context, integrationapp.SourceCommitTransaction) error) error {
	return mapSourceRepositoryWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Source.(integrationapp.SourceCommitReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, sourceCommitTransaction{reader, repos.Source, repos.Audit})
	}))
}

type sourceCommitTransaction struct {
	reader integrationapp.SourceCommitReader
	source app.SourceRepository
	audit  app.AuditRepository
}

func (t sourceCommitTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return integrationquery.NewSourceWriteAuthorizer().Authorize(ctx, a, r)
}
func (t sourceCommitTransaction) LockSourceCommitRepository(ctx context.Context, tenant, id string) (integrationapp.SourceRepositoryIdentity, error) {
	v, err := t.reader.LockSourceCommitRepository(ctx, tenant, id)
	return v, mapSourceRepositoryWriteError(err)
}
func (t sourceCommitTransaction) SourceCommitBySHA(ctx context.Context, tenant, repository, sha string) (integrationdomain.SourceCommit, bool, error) {
	v, found, err := t.reader.SourceCommitBySHA(ctx, tenant, repository, sha)
	return v, found, mapSourceRepositoryWriteError(err)
}
func (t sourceCommitTransaction) InsertSourceCommit(ctx context.Context, v integrationdomain.SourceCommit) error {
	return mapSourceRepositoryWriteError(t.source.InsertSourceCommit(ctx, sourceCommitToDTO(v)))
}
func (t sourceCommitTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, v)
	return r, mapSourceRepositoryWriteError(err)
}
func sourceCommitToDTO(v integrationdomain.SourceCommit) domain.SourceCommit {
	return domain.SourceCommit{ID: v.ID, TenantID: v.TenantID, RepositoryID: v.RepositoryID, SHA: v.SHA, Author: v.Author, MessageHash: v.MessageHash, CommittedAt: v.CommittedAt, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}

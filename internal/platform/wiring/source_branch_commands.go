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

func BuildSourceBranchCommands(factory app.UnitOfWorkFactory) (*integrationapp.SourceBranchCommands, error) {
	if factory == nil {
		return nil, errors.New("source branch transactions are required")
	}
	return integrationapp.NewSourceBranchCommands(integrationapp.SourceBranchConfig{Transactions: sourceBranchTransactions{factory}, Authorizer: integrationquery.NewSourceWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type sourceBranchTransactions struct{ factory app.UnitOfWorkFactory }

func (t sourceBranchTransactions) ExecuteSourceBranch(ctx context.Context, fn func(context.Context, integrationapp.SourceBranchTransaction) error) error {
	return mapSourceRepositoryWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Source.(integrationapp.SourceBranchReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, sourceBranchTransaction{reader, repos.Source, repos.Audit})
	}))
}

type sourceBranchTransaction struct {
	reader integrationapp.SourceBranchReader
	source app.SourceRepository
	audit  app.AuditRepository
}

func (t sourceBranchTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return integrationquery.NewSourceWriteAuthorizer().Authorize(ctx, a, r)
}
func (t sourceBranchTransaction) LockSourceRepositoryForWrite(ctx context.Context, tenant, id string) (integrationapp.SourceRepositoryIdentity, error) {
	v, err := t.reader.LockSourceRepositoryForWrite(ctx, tenant, id)
	return v, mapSourceRepositoryWriteError(err)
}
func (t sourceBranchTransaction) SourceCommitIdentityByID(ctx context.Context, tenant, repository, id string) (integrationapp.SourceCommitIdentity, error) {
	v, err := t.reader.SourceCommitIdentityByID(ctx, tenant, repository, id)
	return v, mapSourceRepositoryWriteError(err)
}
func (t sourceBranchTransaction) SourceBranchByName(ctx context.Context, tenant, repository, name string) (integrationdomain.SourceBranch, bool, error) {
	v, found, err := t.reader.SourceBranchByName(ctx, tenant, repository, name)
	return v, found, mapSourceRepositoryWriteError(err)
}
func (t sourceBranchTransaction) InsertSourceBranch(ctx context.Context, v integrationdomain.SourceBranch) error {
	return mapSourceRepositoryWriteError(t.source.InsertSourceBranch(ctx, sourceBranchToDTO(v)))
}
func (t sourceBranchTransaction) UpdateSourceBranch(ctx context.Context, v integrationdomain.SourceBranch) error {
	return mapSourceRepositoryWriteError(t.source.UpdateSourceBranch(ctx, sourceBranchToDTO(v)))
}
func (t sourceBranchTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, v)
	return r, mapSourceRepositoryWriteError(err)
}
func sourceBranchToDTO(v integrationdomain.SourceBranch) domain.SourceBranch {
	return domain.SourceBranch{ID: v.ID, TenantID: v.TenantID, RepositoryID: v.RepositoryID, Name: v.Name, HeadCommitID: v.HeadCommitID, Protected: v.Protected, ProtectionHash: v.ProtectionHash, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}

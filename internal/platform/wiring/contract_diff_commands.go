package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func BuildContractDiffCommands(factory app.UnitOfWorkFactory) (*evidenceapp.ContractDiffCommands, error) {
	if factory == nil {
		return nil, errors.New("contract diff transactions are required")
	}
	auth, err := evidencequery.NewDiffAuthorizer(sbomDiffArtifactReads{factory})
	if err != nil {
		return nil, err
	}
	return evidenceapp.NewContractDiffCommands(evidenceapp.ContractDiffCommandConfig{Authorizer: auth, Transactions: contractDiffTransactions{factory}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type contractDiffTransactions struct{ factory app.UnitOfWorkFactory }

func (t contractDiffTransactions) ExecuteContractDiff(ctx context.Context, fn func(context.Context, evidenceapp.ContractDiffTransaction) error) error {
	return mapEvidenceCreationError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Evidence.(evidenceapp.ContractDiffReader)
		if !ok || repos.Risk == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		auth, err := evidencequery.NewDiffAuthorizer(sbomDiffArtifactReads(t))
		if err != nil {
			return err
		}
		return fn(ctx, contractDiffTransaction{Authorizer: auth, reader: reader, writer: repos.Risk, audit: repos.Audit})
	}))
}

type contractDiffTransaction struct {
	application.Authorizer
	reader evidenceapp.ContractDiffReader
	writer app.RiskRepository
	audit  app.AuditRepository
}

func (t contractDiffTransaction) ReadContractDiffSubject(ctx context.Context, tenant, id string) (evidenceapp.ContractDiffSubject, error) {
	v, err := t.reader.ReadContractDiffSubject(ctx, tenant, id)
	return v, mapEvidenceCreationError(err)
}
func (t contractDiffTransaction) ReadContractDiffRelease(ctx context.Context, tenant, id string) (evidenceapp.ContractDiffRelease, error) {
	v, err := t.reader.ReadContractDiffRelease(ctx, tenant, id)
	return v, mapEvidenceCreationError(err)
}
func (t contractDiffTransaction) ReadContractDiffProjection(ctx context.Context, tenant, id string) (evidencedomain.OpenAPIContract, error) {
	v, err := t.reader.ReadContractDiffProjection(ctx, tenant, id)
	return v, mapEvidenceCreationError(err)
}
func (t contractDiffTransaction) InsertContractDiff(ctx context.Context, v evidencedomain.ContractDiff) error {
	return mapEvidenceCreationError(t.writer.InsertContractDiff(ctx, domain.ContractDiffFromContext(v)))
}
func (t contractDiffTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	receipt, err := appendAuditEvent(ctx, t.audit, v)
	return receipt, mapEvidenceCreationError(err)
}

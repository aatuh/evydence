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
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func BuildSBOMDiffCommands(factory app.UnitOfWorkFactory) (*evidenceapp.SBOMDiffCommands, error) {
	if factory == nil {
		return nil, errors.New("SBOM diff transactions are required")
	}
	auth, err := evidencequery.NewDiffAuthorizer(sbomDiffArtifactReads{factory})
	if err != nil {
		return nil, err
	}
	return evidenceapp.NewSBOMDiffCommands(evidenceapp.SBOMDiffCommandConfig{Authorizer: auth, Transactions: sbomDiffTransactions{factory}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

// Scope-only checks never invoke this adapter. Artifact checks join the active
// command UoW and never construct or refresh a Ledger.
type sbomDiffArtifactReads struct{ factory app.UnitOfWorkFactory }

func (r sbomDiffArtifactReads) Authorize(ctx context.Context, a identitydomain.Actor, v application.AuthorizationRequest) error {
	return mapEvidenceCreationError(app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.ReleaseCatalog.(evidenceCreationArtifactReader)
		if !ok {
			return app.ErrValidation
		}
		policy, err := releasequery.NewArtifactReadAuthorizer(creationArtifactGrants{reader})
		if err != nil {
			return err
		}
		return policy.Authorize(ctx, a, v)
	}))
}

type sbomDiffTransactions struct{ factory app.UnitOfWorkFactory }

func (t sbomDiffTransactions) ExecuteSBOMDiff(ctx context.Context, fn func(context.Context, evidenceapp.SBOMDiffTransaction) error) error {
	return mapEvidenceCreationError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Evidence.(evidenceapp.SBOMDiffReader)
		artifacts, valid := repos.ReleaseCatalog.(evidenceCreationArtifactReader)
		if !ok || !valid || repos.Risk == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		artifactPolicy, err := releasequery.NewArtifactReadAuthorizer(creationArtifactGrants{artifacts})
		if err != nil {
			return err
		}
		auth, err := evidencequery.NewDiffAuthorizer(artifactPolicy)
		if err != nil {
			return err
		}
		return fn(ctx, sbomDiffTransaction{Authorizer: auth, reader: reader, writer: repos.Risk, audit: repos.Audit})
	}))
}

type sbomDiffTransaction struct {
	application.Authorizer
	reader evidenceapp.SBOMDiffReader
	writer app.RiskRepository
	audit  app.AuditRepository
}

func (t sbomDiffTransaction) ReadSBOMDiffSubject(ctx context.Context, tenant, id string) (evidenceapp.SBOMDiffSubject, error) {
	v, err := t.reader.ReadSBOMDiffSubject(ctx, tenant, id)
	return v, mapEvidenceCreationError(err)
}
func (t sbomDiffTransaction) ReadSBOMDiffComponents(ctx context.Context, tenant, id string) ([]evidencedomain.SBOMComponent, error) {
	v, err := t.reader.ReadSBOMDiffComponents(ctx, tenant, id)
	return v, mapEvidenceCreationError(err)
}
func (t sbomDiffTransaction) InsertSBOMDiff(ctx context.Context, v evidencedomain.SBOMDiff) error {
	return mapEvidenceCreationError(t.writer.InsertSBOMDiff(ctx, domain.SBOMDiffFromContext(v)))
}
func (t sbomDiffTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	receipt, err := appendAuditEvent(ctx, t.audit, v)
	return receipt, mapEvidenceCreationError(err)
}

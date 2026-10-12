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
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func BuildDeploymentCommands(factory app.UnitOfWorkFactory) (*operationsapp.DeploymentCommands, error) {
	if factory == nil {
		return nil, errors.New("deployment transactions are required")
	}
	ids := application.IDGeneratorFunc(application.NewID)
	return operationsapp.NewDeploymentCommands(operationsapp.DeploymentConfig{Transactions: deploymentTransactions{factory: factory, ids: ids}, Authorizer: operationsquery.NewDeploymentWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: ids})
}

type deploymentTransactions struct {
	factory app.UnitOfWorkFactory
	ids     application.IDGenerator
}

func (t deploymentTransactions) ExecuteDeployment(ctx context.Context, fn func(context.Context, operationsapp.DeploymentTransaction) error) error {
	return mapDeploymentWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Deployments.(operationsapp.DeploymentReader)
		if !ok || repos.Evidence == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, deploymentTransaction{reader: reader, deployments: repos.Deployments, evidence: repos.Evidence, audit: repos.Audit, ids: t.ids})
	}))
}

type deploymentTransaction struct {
	reader      operationsapp.DeploymentReader
	deployments app.DeploymentRepository
	evidence    app.EvidenceRepository
	audit       app.AuditRepository
	ids         application.IDGenerator
}

func (t deploymentTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return operationsquery.NewDeploymentWriteAuthorizer().Authorize(ctx, a, r)
}

func (t deploymentTransaction) LockDeploymentTenant(ctx context.Context, tenant string) error {
	r, ok := t.reader.(operationsapp.DeploymentTenantLocker)
	if !ok {
		return operationsapp.ErrValidation
	}
	return mapDeploymentWriteError(r.LockDeploymentTenant(ctx, tenant))
}
func (t deploymentTransaction) LockDeploymentEnvironment(ctx context.Context, tenant, id string) (operationsapp.DeploymentEnvironmentIdentity, error) {
	v, err := t.reader.LockDeploymentEnvironment(ctx, tenant, id)
	return v, mapDeploymentWriteError(err)
}
func (t deploymentTransaction) LockDeploymentRelease(ctx context.Context, tenant, id string) (operationsapp.DeploymentReleaseIdentity, error) {
	v, err := t.reader.LockDeploymentRelease(ctx, tenant, id)
	return v, mapDeploymentWriteError(err)
}
func (t deploymentTransaction) LockDeploymentRollback(ctx context.Context, tenant, id string) (operationsapp.DeploymentRollbackIdentity, error) {
	v, err := t.reader.LockDeploymentRollback(ctx, tenant, id)
	return v, mapDeploymentWriteError(err)
}
func (t deploymentTransaction) CheckDeploymentArtifacts(ctx context.Context, tenant string, ids []string) error {
	return mapDeploymentWriteError(t.reader.CheckDeploymentArtifacts(ctx, tenant, ids))
}
func (t deploymentTransaction) WriteDeploymentEvidence(ctx context.Context, a identitydomain.Actor, in operationsapp.DeploymentEvidenceInput) (string, error) {
	w, err := evidenceapp.NewDeploymentEventEvidenceWriter(evidenceapp.DeploymentEventEvidenceConfig{Repository: deploymentEvidenceInsert{t.evidence}, Audit: t, Canonicalizer: evidenceCanonicalHasher{}, Authorizer: t, IDs: t.ids})
	if err != nil {
		return "", mapDeploymentWriteError(err)
	}
	id, err := w.WriteDeploymentEventEvidence(ctx, a, evidenceapp.DeploymentEventEvidenceInput{ProductID: in.ProductID, ReleaseID: in.ReleaseID, EnvironmentID: in.EnvironmentID, DeploymentID: in.DeploymentID, Status: in.Status, ArtifactIDs: in.ArtifactIDs, ObservedAt: in.ObservedAt, CreatedAt: in.CreatedAt})
	return id, mapDeploymentWriteError(err)
}

type deploymentEvidenceInsert struct{ repository app.EvidenceRepository }

func (r deploymentEvidenceInsert) InsertEvidence(ctx context.Context, v evidencedomain.EvidenceItem) error {
	return r.repository.InsertEvidence(ctx, domain.EvidenceFromContextModel(v))
}
func (t deploymentTransaction) InsertDeployment(ctx context.Context, v operationsdomain.DeploymentEvent) error {
	return mapDeploymentWriteError(t.deployments.InsertDeploymentEvent(ctx, domain.DeploymentEvent{ID: v.ID, TenantID: v.TenantID, EnvironmentID: v.EnvironmentID, ReleaseID: v.ReleaseID, ArtifactIDs: v.ArtifactIDs, Status: v.Status, StartedAt: v.StartedAt, FinishedAt: v.FinishedAt, RollbackOf: v.RollbackOf, EvidenceID: v.EvidenceID, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func (t deploymentTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, v)
	return r, mapDeploymentWriteError(err)
}
func mapDeploymentWriteError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation) || errors.Is(err, evidenceapp.ErrValidation):
		return operationsapp.ErrValidation
	case errors.Is(err, app.ErrNotFound) || errors.Is(err, evidenceapp.ErrNotFound):
		return operationsapp.ErrNotFound
	case errors.Is(err, app.ErrConflict) || errors.Is(err, evidenceapp.ErrConflict):
		return operationsapp.ErrConflict
	default:
		return err
	}
}

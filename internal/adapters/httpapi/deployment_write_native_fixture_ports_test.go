package httpapi

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

type deploymentWriteFixtureTransactions struct {
	catalogFixtureCommands
	readOnly bool
	ids      application.IDGenerator
}
type deploymentWriteFixtureTransaction struct {
	environments operationsapp.DeploymentEnvironmentReader
	deployments  operationsapp.DeploymentReader
	tenant       operationsapp.DeploymentTenantLocker
	repos        app.Repositories
	readOnly     bool
	ids          application.IDGenerator
}

func (f deploymentWriteFixtureTransactions) ExecuteEnvironment(ctx context.Context, run func(context.Context, operationsapp.DeploymentEnvironmentTransaction) error) error {
	if ctx == nil || run == nil {
		return operationsapp.ErrValidation
	}
	return deploymentFixtureCoreError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Deployments.(operationsapp.DeploymentEnvironmentReader)
		tenant, hasTenant := r.Deployments.(operationsapp.DeploymentTenantLocker)
		if !ok || !hasTenant || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, deploymentWriteFixtureTransaction{environments: reader, tenant: tenant, repos: r, readOnly: f.readOnly, ids: f.ids})
	}))
}
func (f deploymentWriteFixtureTransactions) ExecuteDeployment(ctx context.Context, run func(context.Context, operationsapp.DeploymentTransaction) error) error {
	if ctx == nil || run == nil {
		return operationsapp.ErrValidation
	}
	return deploymentFixtureCoreError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Deployments.(operationsapp.DeploymentReader)
		tenant, hasTenant := r.Deployments.(operationsapp.DeploymentTenantLocker)
		if !ok || !hasTenant || r.Evidence == nil || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, deploymentWriteFixtureTransaction{deployments: reader, tenant: tenant, repos: r, readOnly: f.readOnly, ids: f.ids})
	}))
}
func (t deploymentWriteFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return operationsquery.NewDeploymentWriteAuthorizer().Authorize(ctx, a, r)
}
func (t deploymentWriteFixtureTransaction) LockDeploymentTenant(ctx context.Context, tenant string) error {
	return deploymentFixtureCoreError(t.tenant.LockDeploymentTenant(ctx, tenant))
}
func (t deploymentWriteFixtureTransaction) LockEnvironmentProduct(ctx context.Context, tenant, id string) (operationsapp.EnvironmentProduct, error) {
	v, err := t.environments.LockEnvironmentProduct(ctx, tenant, id)
	return v, deploymentFixtureCoreError(err)
}
func (t deploymentWriteFixtureTransaction) EnvironmentByName(ctx context.Context, tenant, product, name string) (operationsdomain.DeploymentEnvironment, bool, error) {
	if t.readOnly {
		panic("environment preflight read descriptive metadata")
	}
	v, found, err := t.environments.EnvironmentByName(ctx, tenant, product, name)
	return v, found, deploymentFixtureCoreError(err)
}
func (t deploymentWriteFixtureTransaction) LockDeploymentEnvironment(ctx context.Context, tenant, id string) (operationsapp.DeploymentEnvironmentIdentity, error) {
	v, err := t.deployments.LockDeploymentEnvironment(ctx, tenant, id)
	return v, deploymentFixtureCoreError(err)
}
func (t deploymentWriteFixtureTransaction) LockDeploymentRelease(ctx context.Context, tenant, id string) (operationsapp.DeploymentReleaseIdentity, error) {
	v, err := t.deployments.LockDeploymentRelease(ctx, tenant, id)
	return v, deploymentFixtureCoreError(err)
}
func (t deploymentWriteFixtureTransaction) LockDeploymentRollback(ctx context.Context, tenant, id string) (operationsapp.DeploymentRollbackIdentity, error) {
	v, err := t.deployments.LockDeploymentRollback(ctx, tenant, id)
	return v, deploymentFixtureCoreError(err)
}
func (t deploymentWriteFixtureTransaction) CheckDeploymentArtifacts(ctx context.Context, tenant string, ids []string) error {
	return deploymentFixtureCoreError(t.deployments.CheckDeploymentArtifacts(ctx, tenant, ids))
}
func (t deploymentWriteFixtureTransaction) InsertEnvironment(ctx context.Context, v operationsdomain.DeploymentEnvironment) error {
	if t.readOnly || t.environments == nil {
		panic("deployment preflight or event inserted environment")
	}
	return deploymentFixtureCoreError(t.repos.Deployments.InsertDeploymentEnvironment(ctx, domain.DeploymentEnvironment(v)))
}
func (t deploymentWriteFixtureTransaction) InsertDeployment(ctx context.Context, v operationsdomain.DeploymentEvent) error {
	if t.readOnly || t.deployments == nil {
		panic("deployment preflight or environment inserted deployment")
	}
	return deploymentFixtureCoreError(t.repos.Deployments.InsertDeploymentEvent(ctx, domain.DeploymentEvent(v)))
}
func (t deploymentWriteFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if t.readOnly {
		panic("deployment preflight appended audit")
	}
	v, err := (governanceFixtureTransaction{audit: t.repos.Audit}).AppendAudit(ctx, e)
	return v, deploymentFixtureCoreError(err)
}
func (t deploymentWriteFixtureTransaction) WriteDeploymentEvidence(ctx context.Context, a domain.Actor, in operationsapp.DeploymentEvidenceInput) (string, error) {
	if t.readOnly || t.deployments == nil {
		panic("deployment preflight or environment wrote evidence")
	}
	w, err := evidenceapp.NewDeploymentEventEvidenceWriter(evidenceapp.DeploymentEventEvidenceConfig{Repository: t, Audit: t, Canonicalizer: t, Authorizer: t, IDs: t.ids})
	if err != nil {
		return "", deploymentFixtureCoreError(err)
	}
	id, err := w.WriteDeploymentEventEvidence(ctx, a, evidenceapp.DeploymentEventEvidenceInput{ProductID: in.ProductID, ReleaseID: in.ReleaseID, EnvironmentID: in.EnvironmentID, DeploymentID: in.DeploymentID, Status: in.Status, ArtifactIDs: in.ArtifactIDs, ObservedAt: in.ObservedAt, CreatedAt: in.CreatedAt})
	return id, deploymentFixtureCoreError(err)
}
func (t deploymentWriteFixtureTransaction) InsertEvidence(ctx context.Context, v evidencedomain.EvidenceItem) error {
	if t.readOnly || t.deployments == nil {
		panic("deployment preflight or environment inserted evidence")
	}
	return deploymentFixtureCoreError(t.repos.Evidence.InsertEvidence(ctx, domain.EvidenceFromContextModel(v)))
}
func (t deploymentWriteFixtureTransaction) HashEvidence(ctx context.Context, v evidencedomain.EvidenceItem) (string, error) {
	if t.readOnly || t.deployments == nil {
		panic("deployment preflight or environment hashed evidence")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return application.NormalizedJSONHash(domain.EvidenceFromContextModel(evidencedomain.CanonicalEvidenceFields(v)))
}
func deploymentFixtureCoreError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation), errors.Is(err, evidenceapp.ErrValidation):
		return operationsapp.ErrValidation
	case errors.Is(err, app.ErrNotFound), errors.Is(err, evidenceapp.ErrNotFound):
		return operationsapp.ErrNotFound
	case errors.Is(err, app.ErrConflict), errors.Is(err, evidenceapp.ErrConflict):
		return operationsapp.ErrConflict
	default:
		return err
	}
}
func (f deploymentFixtureCommands) nativeEnvironment(readOnly bool) (*operationsapp.DeploymentEnvironmentCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return operationsapp.NewDeploymentEnvironmentCommands(operationsapp.DeploymentEnvironmentConfig{Transactions: deploymentWriteFixtureTransactions{f.catalogFixtureCommands, readOnly, ids}, Authorizer: operationsquery.NewDeploymentWriteAuthorizer(), Clock: clock, IDs: ids})
}
func (f deploymentFixtureCommands) nativeDeployment(readOnly bool) (*operationsapp.DeploymentCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return operationsapp.NewDeploymentCommands(operationsapp.DeploymentConfig{Transactions: deploymentWriteFixtureTransactions{f.catalogFixtureCommands, readOnly, ids}, Authorizer: operationsquery.NewDeploymentWriteAuthorizer(), Clock: clock, IDs: ids})
}

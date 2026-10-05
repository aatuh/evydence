package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildStorageReader binds current parent points and output-artifact grant
// associations to one durable, tenant-scoped source.
type BuildStorageReader interface {
	releaseapp.BuildIdentityReader
	artifactGrantReader
}

type artifactGrantReader interface {
	ReadBuildArtifactGrant(context.Context, releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error)
}

// BuildBuildCommands composes build creation without Ledger state. The reader
// supplies only bounded tenant points and current artifact associations.
func BuildBuildCommands(factory app.UnitOfWorkFactory) (*releaseapp.BuildCommands, error) {
	if factory == nil {
		return nil, errors.New("build transactions are required")
	}
	reader := buildCreationReads{factory}
	authorizer, err := releasequery.NewBuildAuthorizer(buildArtifactGrants{reader})
	if err != nil {
		return nil, err
	}
	return releaseapp.NewBuildCommands(releaseapp.BuildCommandConfig{
		Reader: buildParentReader{source: reader}, Authorizer: authorizer,
		Transactions: buildTransactions{factory: factory},
		Clock:        application.ClockFunc(time.Now),
		IDs:          application.IDGeneratorFunc(application.NewID),
	})
}

// Initial checks use the enclosing idempotency transaction when present, not
// a separate pool connection that cannot see pending parent/association rows.
type buildCreationReads struct{ factory app.UnitOfWorkFactory }

func (r buildCreationReads) ReadBuildProject(ctx context.Context, tenant, id string) (releasedomain.Project, error) {
	var v releasedomain.Project
	err := r.execute(ctx, func(ctx context.Context, reader BuildStorageReader) error {
		var err error
		v, err = reader.ReadBuildProject(ctx, tenant, id)
		return err
	})
	return v, err
}
func (r buildCreationReads) ReadBuildRelease(ctx context.Context, tenant, id string) (releasedomain.Release, error) {
	var v releasedomain.Release
	err := r.execute(ctx, func(ctx context.Context, reader BuildStorageReader) error {
		var err error
		v, err = reader.ReadBuildRelease(ctx, tenant, id)
		return err
	})
	return v, err
}
func (r buildCreationReads) ReadBuildArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	var v releasedomain.Artifact
	err := r.execute(ctx, func(ctx context.Context, reader BuildStorageReader) error {
		var err error
		v, err = reader.ReadBuildArtifact(ctx, tenant, id)
		return err
	})
	return v, err
}
func (r buildCreationReads) ReadBuildArtifactGrant(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	var v releasequery.ArtifactPoint
	err := r.execute(ctx, func(ctx context.Context, reader BuildStorageReader) error {
		var err error
		v, err = reader.ReadBuildArtifactGrant(ctx, request)
		return err
	})
	return v, err
}
func (r buildCreationReads) execute(ctx context.Context, fn func(context.Context, BuildStorageReader) error) error {
	return app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.ReleaseCatalog.(BuildStorageReader)
		if !ok {
			return app.ErrValidation
		}
		return fn(ctx, reader)
	})
}

type buildParentReader struct{ source BuildStorageReader }

type buildArtifactGrants struct{ source artifactGrantReader }

func (r buildArtifactGrants) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	return r.source.ReadBuildArtifactGrant(ctx, request)
}

func (r buildParentReader) GetProject(ctx context.Context, tenantID, id string) (releasedomain.Project, error) {
	project, err := r.source.ReadBuildProject(ctx, tenantID, id)
	return project, mapProductWriteError(err)
}

func (r buildParentReader) GetRelease(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	release, err := r.source.ReadBuildRelease(ctx, tenantID, id)
	return release, mapProductWriteError(err)
}

func (r buildParentReader) GetArtifact(ctx context.Context, tenantID, id string) (releasedomain.Artifact, error) {
	artifact, err := r.source.ReadBuildArtifact(ctx, tenantID, id)
	return artifact, mapProductWriteError(err)
}

type buildTransactions struct{ factory app.UnitOfWorkFactory }

func (t buildTransactions) ExecuteBuild(ctx context.Context, command func(context.Context, releaseapp.BuildTransaction) error) error {
	return mapProductWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repositories app.Repositories) error {
		reader, ok := repositories.ReleaseCatalog.(BuildStorageReader)
		if !ok || repositories.Builds == nil || repositories.Audit == nil {
			return app.ErrValidation
		}
		auth, err := releasequery.NewBuildAuthorizer(buildArtifactGrants{reader})
		if err != nil {
			return err
		}
		return command(ctx, buildTransaction{
			reader: reader, builds: repositories.Builds, audit: repositories.Audit, authorizer: auth,
		})
	}))
}

type buildTransaction struct {
	reader     releaseapp.BuildIdentityReader
	builds     app.BuildRepository
	audit      app.AuditRepository
	authorizer application.Authorizer
}

func (t buildTransaction) ReadBuildCreationScope(ctx context.Context, tenant, project, release string) (releaseapp.BuildCreationCoordinates, error) {
	r, ok := t.reader.(releaseapp.BuildCreationGuardReader)
	if !ok {
		return releaseapp.BuildCreationCoordinates{}, releaseapp.ErrValidation
	}
	v, err := r.ReadBuildCreationScope(ctx, tenant, project, release)
	return v, mapProductWriteError(err)
}
func (t buildTransaction) ReadBuildCreationArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	r, ok := t.reader.(releaseapp.BuildCreationGuardReader)
	if !ok {
		return releasedomain.Artifact{}, releaseapp.ErrValidation
	}
	v, err := r.ReadBuildCreationArtifact(ctx, tenant, id)
	return v, mapProductWriteError(err)
}

func (t buildTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if t.authorizer == nil {
		return releaseapp.ErrValidation
	}
	return t.authorizer.Authorize(ctx, actor, request)
}

func (t buildTransaction) GetProject(ctx context.Context, tenantID, id string) (releasedomain.Project, error) {
	project, err := t.reader.ReadBuildProject(ctx, tenantID, id)
	return project, mapProductWriteError(err)
}

func (t buildTransaction) GetRelease(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	release, err := t.reader.ReadBuildRelease(ctx, tenantID, id)
	return release, mapProductWriteError(err)
}

func (t buildTransaction) GetArtifact(ctx context.Context, tenantID, id string) (releasedomain.Artifact, error) {
	artifact, err := t.reader.ReadBuildArtifact(ctx, tenantID, id)
	return artifact, mapProductWriteError(err)
}

func (t buildTransaction) InsertBuildRun(ctx context.Context, build releasedomain.BuildRun) error {
	outputs := make([]domain.BuildOutput, 0, len(build.Outputs))
	for _, output := range build.Outputs {
		outputs = append(outputs, domain.BuildOutput{ArtifactID: output.ArtifactID, Digest: output.Digest})
	}
	return mapProductWriteError(t.builds.InsertBuildRun(ctx, domain.BuildRun{
		ID: build.ID, TenantID: build.TenantID, ProjectID: build.ProjectID, ReleaseID: build.ReleaseID,
		CollectorID: build.CollectorID, Provider: build.Provider, CommitSHA: build.CommitSHA,
		Repository: build.Repository, WorkflowRef: build.WorkflowRef, RunID: build.RunID,
		RunAttempt: build.RunAttempt, JobID: build.JobID, Actor: build.Actor, Ref: build.Ref,
		OIDCSubject: build.OIDCSubject, Status: build.Status, StartedAt: build.StartedAt,
		FinishedAt: build.FinishedAt, ParametersHash: build.ParametersHash, EnvironmentHash: build.EnvironmentHash,
		SourceIdentity: build.SourceIdentity, Outputs: outputs, SchemaVersion: build.SchemaVersion,
		CreatedAt: build.CreatedAt,
	}))
}

func (t buildTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return catalogTransaction{audit: t.audit}.AppendAudit(ctx, event)
}

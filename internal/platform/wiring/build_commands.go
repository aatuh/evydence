package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildStorageReader binds current parent points and output-artifact grant
// associations to one durable, tenant-scoped source.
type BuildStorageReader interface {
	releaseapp.BuildIdentityReader
	ReadBuildArtifactGrant(context.Context, releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error)
}

// BuildBuildCommands composes build creation without Ledger state. The reader
// supplies only bounded tenant points and current artifact associations.
func BuildBuildCommands(reader BuildStorageReader, factory app.UnitOfWorkFactory) (*releaseapp.BuildCommands, error) {
	if reader == nil || factory == nil {
		return nil, errors.New("build reader and transactions are required")
	}
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

type buildParentReader struct{ source BuildStorageReader }

type buildArtifactGrants struct{ source BuildStorageReader }

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
		reader, ok := repositories.ReleaseCatalog.(releaseapp.BuildIdentityReader)
		if !ok || repositories.Builds == nil || repositories.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, buildTransaction{
			reader: reader, builds: repositories.Builds, audit: repositories.Audit,
		})
	}))
}

type buildTransaction struct {
	reader releaseapp.BuildIdentityReader
	builds app.BuildRepository
	audit  app.AuditRepository
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

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
	releasequery.CatalogPointReader
	releasequery.ArtifactPointReader
}

// BuildBuildCommands composes build creation without Ledger state. The reader
// supplies only bounded tenant points and current artifact associations.
func BuildBuildCommands(reader BuildStorageReader, factory app.UnitOfWorkFactory) (*releaseapp.BuildCommands, error) {
	if reader == nil || factory == nil {
		return nil, errors.New("build reader and transactions are required")
	}
	authorizer, err := releasequery.NewBuildAuthorizer(reader)
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

func (r buildParentReader) GetProject(ctx context.Context, tenantID, id string) (releasedomain.Project, error) {
	project, err := r.source.GetProject(ctx, tenantID, id)
	return project, mapProjectReadError(err)
}

func (r buildParentReader) GetRelease(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	release, err := r.source.GetRelease(ctx, tenantID, id)
	return release, mapProjectReadError(err)
}

func (r buildParentReader) GetArtifact(ctx context.Context, tenantID, id string) (releasedomain.Artifact, error) {
	point, err := r.source.GetArtifactPoint(ctx, releasequery.ArtifactReadRequest{TenantID: tenantID, ID: id, TenantWide: true})
	if err != nil {
		return releasedomain.Artifact{}, mapProjectReadError(err)
	}
	if !point.Visible || point.Artifact.TenantID != tenantID || point.Artifact.ID != id {
		return releasedomain.Artifact{}, releaseapp.ErrNotFound
	}
	return point.Artifact, nil
}

type buildTransactions struct{ factory app.UnitOfWorkFactory }

func (t buildTransactions) ExecuteBuild(ctx context.Context, command func(context.Context, releaseapp.BuildTransaction) error) error {
	return mapProductWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repositories app.Repositories) error {
		if repositories.ReleaseCatalog == nil || repositories.Builds == nil || repositories.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, buildTransaction{
			catalog: repositories.ReleaseCatalog, builds: repositories.Builds, audit: repositories.Audit,
		})
	}))
}

type buildTransaction struct {
	catalog app.ReleaseCatalogRepository
	builds  app.BuildRepository
	audit   app.AuditRepository
}

func (t buildTransaction) GetProject(ctx context.Context, tenantID, id string) (releasedomain.Project, error) {
	project, err := t.catalog.GetProject(ctx, tenantID, id)
	if err != nil {
		return releasedomain.Project{}, mapProductWriteError(err)
	}
	return releasedomain.Project{
		ID: project.ID, TenantID: project.TenantID, ProductID: project.ProductID,
		Name: project.Name, CreatedAt: project.CreatedAt,
	}, nil
}

func (t buildTransaction) GetRelease(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	release, err := t.catalog.GetRelease(ctx, tenantID, id)
	if err != nil {
		return releasedomain.Release{}, mapProductWriteError(err)
	}
	state, err := releasedomain.ParseReleaseState(release.State)
	if err != nil {
		return releasedomain.Release{}, releaseapp.ErrValidation
	}
	return releasedomain.Release{
		ID: release.ID, TenantID: release.TenantID, ProductID: release.ProductID,
		Version: release.Version, Revision: release.Revision, State: state,
		CreatedAt: release.CreatedAt, FrozenAt: release.FrozenAt, ApprovedAt: release.ApprovedAt,
	}, nil
}

func (t buildTransaction) GetArtifact(ctx context.Context, tenantID, id string) (releasedomain.Artifact, error) {
	artifact, err := t.catalog.GetArtifact(ctx, tenantID, id)
	if err != nil {
		return releasedomain.Artifact{}, mapProductWriteError(err)
	}
	return releasedomain.Artifact{
		ID: artifact.ID, TenantID: artifact.TenantID, Name: artifact.Name,
		MediaType: artifact.MediaType, Size: artifact.Size, Digest: artifact.Digest, CreatedAt: artifact.CreatedAt,
	}, nil
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
	return catalogTransaction{catalog: t.catalog, audit: t.audit}.AppendAudit(ctx, event)
}

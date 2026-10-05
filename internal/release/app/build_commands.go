package app

import (
	"context"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// BuildReader supplies tenant-scoped parent and output-artifact points. The
// command rechecks their immutable coordinates in its write transaction.
type BuildReader interface {
	GetProject(context.Context, string, string) (releasedomain.Project, error)
	GetRelease(context.Context, string, string) (releasedomain.Release, error)
	GetArtifact(context.Context, string, string) (releasedomain.Artifact, error)
}

// BuildIdentityReader returns only the coordinates needed by build creation:
// project ID/tenant/product, release ID/tenant/product/version, and artifact
// ID/tenant/digest. Metadata fields in the domain values remain empty. Durable
// transaction adapters lock these coordinates before returning them.
type BuildIdentityReader interface {
	ReadBuildProject(context.Context, string, string) (releasedomain.Project, error)
	ReadBuildRelease(context.Context, string, string) (releasedomain.Release, error)
	ReadBuildArtifact(context.Context, string, string) (releasedomain.Artifact, error)
}

type BuildTransaction interface {
	application.Authorizer
	GetProject(context.Context, string, string) (releasedomain.Project, error)
	GetRelease(context.Context, string, string) (releasedomain.Release, error)
	GetArtifact(context.Context, string, string) (releasedomain.Artifact, error)
	InsertBuildRun(context.Context, releasedomain.BuildRun) error
	AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error)
}

type BuildTransactionRunner interface {
	ExecuteBuild(context.Context, func(context.Context, BuildTransaction) error) error
}

type BuildCommandConfig struct {
	Reader       BuildReader
	Authorizer   application.Authorizer
	Transactions BuildTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}

type BuildCommands struct {
	reader       BuildReader
	authorizer   application.Authorizer
	transactions BuildTransactionRunner
	clock        application.Clock
	ids          application.IDGenerator
}

func NewBuildCommands(config BuildCommandConfig) (*BuildCommands, error) {
	if config.Reader == nil || config.Authorizer == nil || config.Transactions == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &BuildCommands{
		reader: config.Reader, authorizer: config.Authorizer, transactions: config.Transactions,
		clock: config.Clock, ids: config.IDs,
	}, nil
}

func (s *BuildCommands) CreateBuildRun(ctx context.Context, actor identitydomain.Actor, input CreateBuildRunInput) (releasedomain.BuildRun, error) {
	if s == nil {
		return releasedomain.BuildRun{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return releasedomain.BuildRun{}, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeBuildWrite, ScopeOnly: true}); err != nil {
		return releasedomain.BuildRun{}, err
	}
	build, err := normalizeBuildInput(input)
	if err != nil {
		return releasedomain.BuildRun{}, err
	}
	project, err := s.reader.GetProject(ctx, actor.TenantID, build.ProjectID)
	if err != nil {
		return releasedomain.BuildRun{}, err
	}
	if !projectBelongsToTenant(project, actor.TenantID, build.ProjectID) {
		return releasedomain.BuildRun{}, ErrNotFound
	}
	release, err := s.reader.GetRelease(ctx, actor.TenantID, build.ReleaseID)
	if err != nil {
		return releasedomain.BuildRun{}, err
	}
	if !releaseBelongsToTenant(release, actor.TenantID, build.ReleaseID) {
		return releasedomain.BuildRun{}, ErrNotFound
	}
	if project.ProductID != release.ProductID {
		return releasedomain.BuildRun{}, ErrValidation
	}
	resources := application.ResourceReferences{ProductID: project.ProductID, ProjectID: project.ID, ReleaseID: release.ID}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeBuildWrite, Resources: resources}); err != nil {
		return releasedomain.BuildRun{}, err
	}
	artifacts := make(map[string]releasedomain.Artifact)
	for _, output := range build.Outputs {
		if output.ArtifactID == "" {
			continue
		}
		artifact, err := s.reader.GetArtifact(ctx, actor.TenantID, output.ArtifactID)
		if err != nil {
			return releasedomain.BuildRun{}, err
		}
		if !artifactBelongsToTenant(artifact, actor.TenantID, output.ArtifactID) {
			return releasedomain.BuildRun{}, ErrNotFound
		}
		if artifact.Digest != output.Digest {
			return releasedomain.BuildRun{}, ErrValidation
		}
		if _, authorized := artifacts[artifact.ID]; !authorized {
			if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{
				Scope: ScopeBuildWrite, Resources: application.ResourceReferences{ArtifactID: artifact.ID},
			}); err != nil {
				return releasedomain.BuildRun{}, err
			}
		}
		artifacts[artifact.ID] = artifact
	}
	commandAt := s.clock.Now().UTC()
	build.ID = s.ids.NewID("build")
	build.TenantID = actor.TenantID
	build.CollectorID = actor.CollectorID
	build.SourceIdentity = buildSourceIdentity(build, actor)
	build.SchemaVersion = releasedomain.BuildRunSchemaVersion
	build.CreatedAt = commandAt

	err = s.transactions.ExecuteBuild(ctx, func(ctx context.Context, tx BuildTransaction) error {
		// Native transactions share the same locked scope guard on direct
		// fresh calls too. The old local service bridge has no such port.
		if _, native := tx.(BuildCreationGuardReader); native {
			if err := authorizeBuildCreationScope(ctx, tx, actor, build); err != nil {
				return err
			}
		}
		currentProject, err := tx.GetProject(ctx, actor.TenantID, project.ID)
		if err != nil {
			return err
		}
		if !projectBelongsToTenant(currentProject, actor.TenantID, project.ID) {
			return ErrNotFound
		}
		if !sameProjectCoordinates(currentProject, project) {
			return ErrConflict
		}
		currentRelease, err := tx.GetRelease(ctx, actor.TenantID, release.ID)
		if err != nil {
			return err
		}
		if !releaseBelongsToTenant(currentRelease, actor.TenantID, release.ID) {
			return ErrNotFound
		}
		if !sameReleaseCoordinates(currentRelease, release) || currentProject.ProductID != currentRelease.ProductID {
			return ErrConflict
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeBuildWrite, Resources: resources}); err != nil {
			return err
		}
		for id, artifact := range artifacts {
			current, err := tx.GetArtifact(ctx, actor.TenantID, id)
			if err != nil {
				return err
			}
			if !artifactBelongsToTenant(current, actor.TenantID, id) {
				return ErrNotFound
			}
			if !sameArtifactCoordinates(current, artifact) {
				return ErrConflict
			}
			if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeBuildWrite, Resources: application.ResourceReferences{ArtifactID: id}}); err != nil {
				return err
			}
		}
		if err := tx.InsertBuildRun(ctx, build); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, auditEventFor(s.ids, actor, commandAt, "build.created", "build_run", build.ID, ""))
		return err
	})
	if err != nil {
		return releasedomain.BuildRun{}, err
	}
	return build, nil
}

type releaseBuildTransactions struct{ runner TransactionRunner }

func (r releaseBuildTransactions) ExecuteBuild(ctx context.Context, command func(context.Context, BuildTransaction) error) error {
	return r.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return command(ctx, releaseBuildTransaction{tx: tx})
	})
}

type releaseBuildTransaction struct{ tx Transaction }

func (t releaseBuildTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return t.tx.Authorization().Authorize(ctx, actor, request)
}

func (t releaseBuildTransaction) GetProject(ctx context.Context, tenantID, id string) (releasedomain.Project, error) {
	return t.tx.Catalog().GetProject(ctx, tenantID, id)
}

func (t releaseBuildTransaction) GetRelease(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	return t.tx.Catalog().GetRelease(ctx, tenantID, id)
}

func (t releaseBuildTransaction) GetArtifact(ctx context.Context, tenantID, id string) (releasedomain.Artifact, error) {
	return t.tx.Catalog().GetArtifact(ctx, tenantID, id)
}

func (t releaseBuildTransaction) InsertBuildRun(ctx context.Context, build releasedomain.BuildRun) error {
	return t.tx.Builds().InsertBuildRun(ctx, build)
}

func (t releaseBuildTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.Audit().AppendAudit(ctx, event)
}

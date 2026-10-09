package httpapi

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// Explicit repository-backed guard configuration never falls back on a
// failed/missing repository to catalog caches. Artifact guards use identity-
// only ports; diff fixture reads and historical parser writes still have
// separate retirement dependencies.
type repositoryIngestionFixtureAuthority struct {
	ingestionFixtureAuthority
	repositories *app.Repositories
}

type repositoryIngestionFixtureArtifactReader interface {
	ReadBuildArtifact(context.Context, string, string) (releasedomain.Artifact, error)
	ReadBuildArtifactGrant(context.Context, releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error)
}

func (f repositoryIngestionFixtureAuthority) readArtifact(ctx context.Context, run func(context.Context, repositoryIngestionFixtureArtifactReader) error) error {
	if ctx == nil {
		return app.ErrValidation
	}
	read := func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.ReleaseCatalog.(repositoryIngestionFixtureArtifactReader)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, reader)
	}
	if f.repositories != nil {
		return read(ctx, *f.repositories)
	}
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, read)
}

func (f repositoryIngestionFixtureAuthority) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	var out releasequery.ArtifactPoint
	err := f.readArtifact(ctx, func(ctx context.Context, r repositoryIngestionFixtureArtifactReader) error {
		var err error
		out, err = r.ReadBuildArtifactGrant(ctx, request)
		return err
	})
	if err != nil {
		return releasequery.ArtifactPoint{}, err
	}
	return out, nil
}

func (f repositoryIngestionFixtureAuthority) ValidateArtifactReference(ctx context.Context, tenant, id, digest string) error {
	return f.readArtifact(ctx, func(ctx context.Context, r repositoryIngestionFixtureArtifactReader) error {
		v, err := r.ReadBuildArtifact(ctx, tenant, id)
		if err != nil {
			return err
		}
		if v.ID != id || v.TenantID != tenant || digest != "" && !strings.EqualFold(v.Digest, digest) {
			return app.ErrNotFound
		}
		return nil
	})
}

func (f repositoryIngestionFixtureAuthority) ResolveEvidenceCreationScope(ctx context.Context, tenant string, refs application.ResourceReferences) (application.ResourceReferences, error) {
	if ctx == nil || refs != (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID}) {
		return application.ResourceReferences{}, evidencequery.ErrValidation
	}
	var out application.ResourceReferences
	read := func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Evidence.(evidencequery.EvidenceCreationScopeReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ResolveEvidenceCreationScope(ctx, tenant, refs)
		return err
	}
	var err error
	if f.repositories != nil {
		err = read(ctx, *f.repositories)
	} else {
		err = f.commandLedger(ctx).ExecuteUnitOfWork(ctx, read)
	}
	if err != nil {
		return application.ResourceReferences{}, err
	}
	return out, nil
}
func (f repositoryIngestionFixtureAuthority) ValidateScope(ctx context.Context, tenant string, scope evidenceapp.EvidenceScope) error {
	if scope.AllowPendingDeployment {
		return evidencequery.ErrValidation
	}
	_, err := f.ResolveEvidenceCreationScope(ctx, tenant, application.ResourceReferences{ProductID: scope.ProductID, ProjectID: scope.ProjectID, ReleaseID: scope.ReleaseID, BuildID: scope.BuildID, DeploymentID: scope.DeploymentID})
	return err
}
func (f repositoryIngestionFixtureAuthority) authorizer(security bool) (application.Authorizer, error) {
	if security {
		artifacts, err := releasequery.NewArtifactSecurityWriteAuthorizer(f)
		if err != nil {
			return nil, err
		}
		return evidencequery.NewSecurityDocumentAuthorizer(f, artifacts)
	}
	artifacts, err := releasequery.NewArtifactWriteAuthorizer(f)
	if err != nil {
		return nil, err
	}
	return evidencequery.NewEvidenceCreationAuthorizer(f, artifacts)
}

func (s *Server) bindRepositoryIngestionFixtureScope() {
	if f, ok := s.sbomIngestionCommands.(ingestionFixtureCommands); ok {
		f.repositoryScope = true
		s.sbomIngestionCommands = f
	}
	if f, ok := s.vexIngestionCommands.(ingestionFixtureCommands); ok {
		f.repositoryScope = true
		s.vexIngestionCommands = f
	}
	if f, ok := s.scanIngestionCommands.(ingestionFixtureCommands); ok {
		f.repositoryScope = true
		s.scanIngestionCommands = f
	}
	if f, ok := s.openAPIIngestionCommands.(ingestionFixtureCommands); ok {
		f.repositoryScope = true
		s.openAPIIngestionCommands = f
	}
	if f, ok := s.securityDocumentCommands.(ingestionFixtureCommands); ok {
		f.repositoryScope = true
		s.securityDocumentCommands = f
	}
}

var _ ingestionFixtureReadAuthority = repositoryIngestionFixtureAuthority{}

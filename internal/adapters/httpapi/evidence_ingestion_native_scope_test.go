package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// Explicit repository-backed guard configuration never falls back on a
// failed/missing repository to catalog caches. Artifact/diff fixture reads and
// historical parser writes still have separate retirement dependencies.
type repositoryIngestionFixtureAuthority struct {
	ingestionFixtureAuthority
	repositories *app.Repositories
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

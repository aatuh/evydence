package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type BuildCreationCoordinates struct{ TenantID, ProjectID, ProductID, ReleaseID, ReleaseProductID string }

// BuildCreationGuardReader returns only locked ownership coordinates. In
// particular it must not read release versions, artifact digests, or builds.
type BuildCreationGuardReader interface {
	ReadBuildCreationScope(context.Context, string, string, string) (BuildCreationCoordinates, error)
	ReadBuildCreationArtifact(context.Context, string, string) (releasedomain.Artifact, error)
}

func authorizeBuildCreationScope(ctx context.Context, tx BuildTransaction, a identitydomain.Actor, b releasedomain.BuildRun) error {
	reader, ok := tx.(BuildCreationGuardReader)
	if !ok {
		return ErrValidation
	}
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeBuildWrite, ScopeOnly: true}); err != nil {
		return err
	}
	p, err := reader.ReadBuildCreationScope(ctx, a.TenantID, b.ProjectID, b.ReleaseID)
	if err != nil {
		return err
	}
	if p.TenantID != a.TenantID || p.ProjectID != b.ProjectID || p.ReleaseID != b.ReleaseID || p.ProductID == "" || p.ReleaseProductID == "" {
		return ErrNotFound
	}
	for _, id := range []string{p.TenantID, p.ProjectID, p.ProductID, p.ReleaseID, p.ReleaseProductID} {
		if len(id) > 1024 || !validBuildText(id) {
			return ErrValidation
		}
	}
	if p.ProductID != p.ReleaseProductID {
		return ErrValidation
	}
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeBuildWrite, Resources: application.ResourceReferences{ProductID: p.ProductID, ProjectID: p.ProjectID, ReleaseID: p.ReleaseID}}); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, out := range b.Outputs {
		if out.ArtifactID == "" || seen[out.ArtifactID] {
			continue
		}
		seen[out.ArtifactID] = true
		artifact, err := reader.ReadBuildCreationArtifact(ctx, a.TenantID, out.ArtifactID)
		if err != nil {
			return err
		}
		if artifact.ID != out.ArtifactID || artifact.TenantID != a.TenantID {
			return ErrNotFound
		}
		if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeBuildWrite, Resources: application.ResourceReferences{ArtifactID: artifact.ID}}); err != nil {
			return err
		}
	}
	return nil
}

func (s *BuildCommands) AuthorizeBuildCreation(ctx context.Context, a identitydomain.Actor, in CreateBuildRunInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := s.authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeBuildWrite, ScopeOnly: true}); err != nil {
		return err
	}
	if a.TenantID == "" || len(a.TenantID) > 1024 || !validBuildText(a.TenantID) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	b, err := normalizeBuildInput(in)
	if err != nil {
		return err
	}
	return s.transactions.ExecuteBuild(ctx, func(ctx context.Context, tx BuildTransaction) error {
		return authorizeBuildCreationScope(ctx, tx, a, b)
	})
}

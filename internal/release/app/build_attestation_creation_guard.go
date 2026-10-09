package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type BuildAttestationCreationCoordinates struct {
	BuildCreationCoordinates
	BuildID     string
	ArtifactIDs []string
}

// This guard projection contains no build metadata or output digests.
type BuildAttestationCreationGuardReader interface {
	ReadBuildAttestationCreationScope(context.Context, string, string) (BuildAttestationCreationCoordinates, error)
}

type buildAttestationCreationGuardTransaction interface {
	application.Authorizer
	BuildAttestationCreationGuardReader
	ReadBuildCreationArtifact(context.Context, string, string) (releasedomain.Artifact, error)
}

func NormalizeBuildAttestationBuildID(id string) (string, error) {
	if len(id) > 1024 || !validBuildText(id) {
		return "", ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return "", ErrNotFound
	}
	return id, nil
}

func (s *BuildAttestationCommands) AuthorizeBuildAttestationCreation(ctx context.Context, a identitydomain.Actor, buildID string) error {
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
	id, err := NormalizeBuildAttestationBuildID(buildID)
	if err != nil {
		return err
	}
	return s.transactions.ExecuteBuildAttestation(ctx, func(ctx context.Context, tx BuildAttestationTransaction) error {
		guard, ok := tx.(buildAttestationCreationGuardTransaction)
		if !ok {
			return ErrValidation
		}
		if err := guard.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeBuildWrite, ScopeOnly: true}); err != nil {
			return err
		}
		p, err := guard.ReadBuildAttestationCreationScope(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if p.TenantID != a.TenantID || p.BuildID != id || p.ProjectID == "" || p.ReleaseID == "" || p.ProductID == "" || p.ProductID != p.ReleaseProductID {
			return ErrNotFound
		}
		for _, coordinate := range []string{p.ProjectID, p.ProductID, p.ReleaseID, p.ReleaseProductID} {
			if len(coordinate) > 1024 || !validBuildText(coordinate) {
				return ErrConflict
			}
		}
		if len(p.ArtifactIDs) > MaxBuildOutputs {
			return ErrConflict
		}
		if err := guard.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeBuildWrite, Resources: application.ResourceReferences{ProductID: p.ProductID, ProjectID: p.ProjectID, ReleaseID: p.ReleaseID, BuildID: id}}); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, raw := range p.ArtifactIDs {
			if len(raw) > 1024 || !validBuildText(raw) {
				return ErrConflict
			}
			artifactID := strings.TrimSpace(raw)
			if artifactID == "" || seen[artifactID] {
				continue
			}
			seen[artifactID] = true
			artifact, err := guard.ReadBuildCreationArtifact(ctx, a.TenantID, artifactID)
			if err != nil {
				return err
			}
			if artifact.ID != artifactID || artifact.TenantID != a.TenantID {
				return ErrNotFound
			}
			if err := guard.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeBuildWrite, Resources: application.ResourceReferences{ArtifactID: artifact.ID}}); err != nil {
				return err
			}
		}
		return nil
	})
}

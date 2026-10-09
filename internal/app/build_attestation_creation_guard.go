package app

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

// Only the explicit local-memory HTTP profile uses this map-based guard.
func (l *Ledger) AuthorizeBuildAttestationCreation(ctx context.Context, a domain.Actor, buildID string) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeBuildWrite); err != nil {
		return err
	}
	if a.TenantID == "" || len(a.TenantID) > 1024 || !utf8.ValidString(a.TenantID) || strings.ContainsRune(a.TenantID, 0) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	id, err := releaseapp.NormalizeBuildAttestationBuildID(buildID)
	if err != nil {
		return fromReleaseContextError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	b, ok := l.buildRuns[id]
	if !ok || b.TenantID != a.TenantID {
		return ErrNotFound
	}
	p, ok := l.projects[b.ProjectID]
	if !ok || p.TenantID != a.TenantID {
		return ErrNotFound
	}
	r, ok := l.releases[b.ReleaseID]
	if !ok || r.TenantID != a.TenantID || p.ProductID != r.ProductID {
		return ErrNotFound
	}
	product, ok := l.products[p.ProductID]
	if !ok || product.TenantID != a.TenantID {
		return ErrNotFound
	}
	if err := l.authorizeResourceLocked(a, ScopeBuildWrite, resourceRefs{ProductID: p.ProductID, ProjectID: p.ID, ReleaseID: r.ID, BuildID: b.ID}); err != nil {
		return err
	}
	if len(b.Outputs) > releaseapp.MaxBuildOutputs {
		return ErrConflict
	}
	for _, out := range b.Outputs {
		artifactID, err := releaseapp.NormalizeBuildAttestationBuildID(out.ArtifactID)
		if errors.Is(err, releaseapp.ErrNotFound) {
			continue
		}
		if err != nil {
			return ErrConflict
		}
		artifact, ok := l.artifacts[artifactID]
		if !ok || artifact.TenantID != a.TenantID {
			return ErrNotFound
		}
		if err := l.authorizeResourceLocked(a, ScopeBuildWrite, resourceRefs{ArtifactID: artifact.ID}); err != nil {
			return err
		}
	}
	return nil
}

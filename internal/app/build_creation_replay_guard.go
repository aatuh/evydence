package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

// This map guard is explicit local-memory compatibility only. PostgreSQL
// build HTTP uses its focused Release transaction and flat scope readers.
func (l *Ledger) AuthorizeBuildCreation(ctx context.Context, a domain.Actor, in releaseapp.CreateBuildRunInput) error {
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
	b, err := releaseapp.NormalizeBuildCreationInput(in)
	if err != nil {
		return fromReleaseContextError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	p, ok := l.projects[b.ProjectID]
	if !ok || p.TenantID != a.TenantID {
		return ErrNotFound
	}
	r, ok := l.releases[b.ReleaseID]
	if !ok || r.TenantID != a.TenantID {
		return ErrNotFound
	}
	product, ok := l.products[p.ProductID]
	if !ok || product.TenantID != a.TenantID {
		return ErrNotFound
	}
	releaseProduct, ok := l.products[r.ProductID]
	if !ok || releaseProduct.TenantID != a.TenantID {
		return ErrNotFound
	}
	if p.ProductID != r.ProductID {
		return ErrValidation
	}
	if err := l.authorizeResourceLocked(a, ScopeBuildWrite, resourceRefs{ProductID: p.ProductID, ProjectID: p.ID, ReleaseID: r.ID}); err != nil {
		return err
	}
	for _, out := range b.Outputs {
		if out.ArtifactID == "" {
			continue
		}
		artifact, ok := l.artifacts[out.ArtifactID]
		if !ok || artifact.TenantID != a.TenantID {
			return ErrNotFound
		}
		if err := l.authorizeResourceLocked(a, ScopeBuildWrite, resourceRefs{ArtifactID: artifact.ID}); err != nil {
			return err
		}
	}
	return nil
}

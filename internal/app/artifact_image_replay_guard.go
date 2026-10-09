package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

// These guards use only explicit local-memory ownership and grant maps.
func (l *Ledger) AuthorizeArtifactRegistration(ctx context.Context, a domain.Actor, in releaseapp.RegisterArtifactInput) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeEvidenceWrite); err != nil {
		return err
	}
	if a.TenantID == "" || len(a.TenantID) > 1024 || !utf8.ValidString(a.TenantID) || strings.ContainsRune(a.TenantID, 0) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	v, err := releaseapp.NormalizeArtifactRegistrationInput(in)
	if err != nil {
		return fromReleaseContextError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	for _, artifact := range l.artifacts {
		if artifact.TenantID == a.TenantID && artifact.Digest == v.Digest {
			return l.authorizeResourceLocked(a, ScopeEvidenceWrite, resourceRefs{ArtifactID: artifact.ID})
		}
	}
	return nil
}
func (l *Ledger) AuthorizeContainerImageRegistration(ctx context.Context, a domain.Actor, in releaseapp.RegisterContainerImageInput) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeEvidenceWrite); err != nil {
		return err
	}
	if a.TenantID == "" || len(a.TenantID) > 1024 || !utf8.ValidString(a.TenantID) || strings.ContainsRune(a.TenantID, 0) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	v, err := releaseapp.NormalizeContainerImageRegistrationInput(in)
	if err != nil {
		return fromReleaseContextError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	ids := []string{v.ArtifactID}
	for _, image := range l.images {
		if image.TenantID == a.TenantID && image.Repository == v.Repository && image.Digest == v.Digest {
			ids = append(ids, image.ArtifactID)
			break
		}
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		artifact, ok := l.artifacts[id]
		if !ok || artifact.TenantID != a.TenantID {
			return ErrNotFound
		}
		if err := l.authorizeResourceLocked(a, ScopeEvidenceWrite, resourceRefs{ArtifactID: id}); err != nil {
			return err
		}
	}
	return nil
}

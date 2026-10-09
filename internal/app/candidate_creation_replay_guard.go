package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

// AuthorizeCandidateCreation is an explicit local-memory ownership/grant guard.
func (l *Ledger) AuthorizeCandidateCreation(ctx context.Context, a domain.Actor, in releaseapp.CreateReleaseCandidateInput) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeReleaseWrite); err != nil {
		return err
	}
	if a.TenantID == "" || len(a.TenantID) > 1024 || !utf8.ValidString(a.TenantID) || strings.ContainsRune(a.TenantID, 0) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	in, err := releaseapp.NormalizeCandidateCreationInput(in)
	if err != nil {
		return fromReleaseContextError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	r, ok := l.releases[in.ReleaseID]
	if !ok || r.TenantID != a.TenantID {
		return ErrNotFound
	}
	p, ok := l.products[r.ProductID]
	if !ok || p.TenantID != a.TenantID {
		return ErrNotFound
	}
	if err := l.authorizeResourceLocked(a, ScopeReleaseWrite, resourceRefs{ProductID: p.ID, ReleaseID: r.ID}); err != nil {
		return err
	}
	if err := l.validateCandidateRefsLocked(a.TenantID, r.ID, CreateReleaseCandidateInput{BuildIDs: in.BuildIDs, ArtifactIDs: in.ArtifactIDs, SBOMIDs: in.SBOMIDs, ScanIDs: in.ScanIDs, VEXIDs: in.VEXIDs, ContractIDs: in.ContractIDs, BundleIDs: in.BundleIDs}); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, id := range in.ArtifactIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		if err := l.authorizeResourceLocked(a, ScopeReleaseWrite, resourceRefs{ArtifactID: id}); err != nil {
			return err
		}
	}
	return nil
}

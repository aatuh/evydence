package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NormalizeCandidateCreationInput preserves sorted references and intentional
// duplicates, while bounding raw input before copying or trimming it.
func NormalizeCandidateCreationInput(in CreateReleaseCandidateInput) (CreateReleaseCandidateInput, error) {
	var err error
	if in.ReleaseID, err = normalizeCatalogCreationText(in.ReleaseID, 1024); err != nil {
		return CreateReleaseCandidateInput{}, err
	}
	if in.Name, err = normalizeCatalogCreationText(in.Name, 65536); err != nil {
		return CreateReleaseCandidateInput{}, err
	}
	count, bytes := 0, 0
	for _, ids := range [][]string{in.BuildIDs, in.ArtifactIDs, in.SBOMIDs, in.ScanIDs, in.VEXIDs, in.ContractIDs, in.BundleIDs} {
		if len(ids) > 4096-count {
			return CreateReleaseCandidateInput{}, ErrValidation
		}
		count += len(ids)
		for _, id := range ids {
			if len(id) > 1024 || !validBuildText(id) {
				return CreateReleaseCandidateInput{}, ErrValidation
			}
			bytes += len(id)
			if bytes > 65536 {
				return CreateReleaseCandidateInput{}, ErrValidation
			}
		}
	}
	refs := normalizeReleaseCandidateReferences(in)
	if !ValidCandidateReferences(refs) {
		return CreateReleaseCandidateInput{}, ErrValidation
	}
	in.BuildIDs, in.ArtifactIDs, in.SBOMIDs, in.ScanIDs, in.VEXIDs, in.ContractIDs, in.BundleIDs = refs.BuildIDs, refs.ArtifactIDs, refs.SBOMIDs, refs.ScanIDs, refs.VEXIDs, refs.ContractIDs, refs.BundleIDs
	return in, nil
}

func authorizeCandidateCreationScope(ctx context.Context, tx CandidateCreationTransaction, a identitydomain.Actor, in CreateReleaseCandidateInput) (CandidateReleaseCoordinates, error) {
	p, err := tx.ReadCandidateRelease(ctx, a.TenantID, in.ReleaseID)
	if err != nil {
		return CandidateReleaseCoordinates{}, err
	}
	if p.ID != in.ReleaseID || p.TenantID != a.TenantID || p.ProductID == "" {
		return CandidateReleaseCoordinates{}, ErrNotFound
	}
	if !validCandidateText(p.ProductID, 1024) {
		return CandidateReleaseCoordinates{}, ErrConflict
	}
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ProductID: p.ProductID, ReleaseID: p.ID}}); err != nil {
		return CandidateReleaseCoordinates{}, err
	}
	refs := ReleaseCandidateReferences{BuildIDs: in.BuildIDs, ArtifactIDs: in.ArtifactIDs, SBOMIDs: in.SBOMIDs, ScanIDs: in.ScanIDs, VEXIDs: in.VEXIDs, ContractIDs: in.ContractIDs, BundleIDs: in.BundleIDs}
	if err := tx.ValidateReleaseCandidateReferences(ctx, a.TenantID, p.ID, cloneReleaseCandidateReferences(refs)); err != nil {
		return CandidateReleaseCoordinates{}, err
	}
	seen := map[string]bool{}
	for _, id := range refs.ArtifactIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ArtifactID: id}}); err != nil {
			return CandidateReleaseCoordinates{}, err
		}
	}
	return p, nil
}

// AuthorizeCandidateCreation reads only current ownership, parent coherence and
// grants. It never loads a candidate document or hashes/generates a new snapshot.
func (s *CandidateCommands) AuthorizeCandidateCreation(ctx context.Context, a identitydomain.Actor, in CreateReleaseCandidateInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := validateCatalogCreationActor(ctx, a); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}); err != nil {
		return err
	}
	in, err := NormalizeCandidateCreationInput(in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteCandidateCreation(ctx, func(ctx context.Context, tx CandidateCreationTransaction) error {
		_, err := authorizeCandidateCreationScope(ctx, tx, a, in)
		return err
	})
}

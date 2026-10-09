package app

import (
	"context"
	"strings"

	releasequery "github.com/aatuh/evydence/internal/release/query"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

var _ verificationquery.ArtifactSignatureReader = memoryReleaseCatalogRepository{}

// One locked typed snapshot supplies the signature, current owned artifact
// digest and scoped association. This test model does not read payloads/keys
// or establish SQL work/transfer, row locks or durability.
func (r memoryReleaseCatalogRepository) GetArtifactSignaturePoint(ctx context.Context, req verificationquery.SignatureReadRequest) (verificationquery.SignaturePoint, error) {
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		return verificationquery.SignaturePoint{}, verificationquery.ErrSignatureNotFound
	}
	grants, err := memoryArtifactReadGrants(releasequery.ArtifactReadRequest{TenantID: req.TenantID, TenantWide: req.TenantWide, AllowedProductIDs: req.AllowedProductIDs, AllowedProjectIDs: req.AllowedProjectIDs, AllowedReleaseIDs: req.AllowedReleaseIDs})
	if err != nil {
		return verificationquery.SignaturePoint{}, verificationquery.ErrSignatureValidation
	}
	var out verificationquery.SignaturePoint
	err = memoryGovernanceRead(ctx, r.uow, req.TenantID, req.ID, func(s *MemoryUnitOfWorkSnapshot) error {
		sig, ok := s.ArtifactSignatures[req.ID]
		if !ok || sig.ID != req.ID || sig.TenantID != req.TenantID {
			return verificationquery.ErrSignatureNotFound
		}
		a, ok := s.Artifacts[sig.ArtifactID]
		if !ok || a.ID != sig.ArtifactID || a.TenantID != req.TenantID || a.Digest != sig.SubjectDigest {
			return verificationquery.ErrSignatureNotFound
		}
		out = verificationquery.SignaturePoint{Signature: verificationdomain.ArtifactSignature(sig), ArtifactDigest: a.Digest}
		if !req.TenantWide {
			refs, _ := memoryArtifactAssociation(s, a, grants.products, grants.projects, grants.releases)
			out.ProductID, out.ProjectID, out.ReleaseID = refs.ProductID, refs.ProjectID, refs.ReleaseID
		}
		return ctx.Err()
	})
	if err != nil {
		return verificationquery.SignaturePoint{}, err
	}
	return out, nil
}

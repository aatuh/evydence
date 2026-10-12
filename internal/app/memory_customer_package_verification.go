package app

import (
	"context"
	"slices"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Recorded receipts only. No provider or cryptographic check is invoked here;
// the read-only canonical audit inspection is a separate snapshot component.
func readMemoryCustomerPackageVerification(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, product, release string, budget *memoryCustomerSnapshotBudget) (map[string]any, error) {
	if err := validateMemoryCustomerSnapshotRead(ctx, s, tenant, product, release, budget); err != nil {
		return nil, err
	}
	working := *budget
	selected := map[string]bool{}
	for id, e := range s.Evidence {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if memoryCustomerEvidenceInScope(s, id, e, tenant, product, release) {
			if len(selected) == packageapp.MaxSecurityReviewEvidenceIDs {
				return nil, ErrConflict
			}
			selected[id] = true
		}
	}
	artifacts := map[string]bool{}
	if release != "" {
		var err error
		artifacts, err = memoryCustomerCatalogArtifactIDs(ctx, s, tenant, product, release, selected)
		if err != nil {
			return nil, err
		}
	}
	attestations := map[string]bool{}
	for id, a := range s.BuildAttestations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if a.ID != id || a.TenantID != tenant {
			continue
		}
		b, ok := s.BuildRuns[a.BuildID]
		if !ok {
			continue
		}
		owned, err := memoryCustomerProvenanceBuildOwned(ctx, s, a.BuildID, b, tenant, product, release)
		if err != nil {
			return nil, err
		}
		if owned && memoryCustomerAttestationSourceOwned(s, a, tenant, product, release) {
			if len(attestations) == packageapp.MaxSecurityReviewEvidenceIDs {
				return nil, ErrConflict
			}
			attestations[id] = true
		}
	}
	bundles := []map[string]any{}
	if release != "" {
		for id, b := range s.ReleaseBundles {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if b.ID != id || b.TenantID != tenant || b.ReleaseID != release {
				continue
			}
			if len(b.SignatureRefs) > packageapp.MaxSecurityReviewEvidenceIDs {
				return nil, ErrConflict
			}
			owned := true
			for _, ref := range b.SignatureRefs {
				sig, ok := s.Signatures[ref]
				key, hasKey := s.SigningKeys[sig.KeyID]
				owned = owned && ok && sig.ID == ref && sig.TenantID == tenant && sig.SubjectType == "release_bundle" && sig.SubjectID == id && hasKey && key.ID == sig.KeyID && key.TenantID == tenant
			}
			if !owned {
				continue
			}
			row := map[string]any{"id": b.ID, "state": b.State, "manifest_hash": b.ManifestHash, "signature_refs": b.SignatureRefs}
			if err := memoryCustomerMetadataTimes(row, map[string]time.Time{"created_at": b.CreatedAt}, nil); err != nil {
				return nil, err
			}
			if err := appendMemoryCustomerMetadata(&bundles, row, &working); err != nil {
				return nil, err
			}
			row["signature_refs"] = slices.Clone(b.SignatureRefs)
		}
	}
	results, cosign := []map[string]any{}, []map[string]any{}
	for id, v := range s.VerificationResults {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if v.ID != id || v.TenantID != tenant || !memoryCustomerVerificationSubject(s, v.SubjectType, v.SubjectID, tenant, release, selected, artifacts, attestations) {
			continue
		}
		row := map[string]any{"id": v.ID, "subject_type": v.SubjectType, "subject_id": v.SubjectID, "result": v.Result, "schema_version": v.SchemaVersion}
		if err := memoryCustomerMetadataTimes(row, map[string]time.Time{"verified_at": v.VerifiedAt}, nil); err != nil {
			return nil, err
		}
		if err := appendMemoryCustomerVerification(&results, row, v.Checks, v.Profile, v.Limitations, &working); err != nil {
			return nil, err
		}
	}
	for id, v := range s.CosignVerifications {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if v.ID != id || v.TenantID != tenant || !artifacts[v.ArtifactID] {
			continue
		}
		sig, ok := s.ArtifactSignatures[v.ArtifactSignatureID]
		if !ok || sig.ID != v.ArtifactSignatureID || sig.TenantID != tenant || sig.ArtifactID != v.ArtifactID || sig.SubjectDigest != v.SubjectDigest {
			continue
		}
		if v.ContainerImageID != "" {
			i, ok := s.ContainerImages[v.ContainerImageID]
			if !ok || i.ID != v.ContainerImageID || i.TenantID != tenant || i.ArtifactID != v.ArtifactID || i.Digest != v.SubjectDigest {
				continue
			}
		}
		row := map[string]any{"id": v.ID, "artifact_id": v.ArtifactID, "result": v.Result, "schema_version": v.SchemaVersion}
		if err := memoryCustomerMetadataTimes(row, map[string]time.Time{"created_at": v.CreatedAt}, nil); err != nil {
			return nil, err
		}
		if err := appendMemoryCustomerVerification(&cosign, row, v.Checks, v.Profile, v.Limitations, &working); err != nil {
			return nil, err
		}
	}
	for _, rows := range [][]map[string]any{bundles, results, cosign} {
		sortMemoryCustomerMetadata(rows)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	*budget = working
	return map[string]any{"hash_algorithm": "sha256", "canonicalization": verificationdomain.CanonicalizationProfileVersion, "manifest_hash_field": "manifest_hash", "release_bundles": bundles, "verification_results": results, "cosign_assessments": cosign}, nil
}

func memoryCustomerVerificationSubject(s *MemoryUnitOfWorkSnapshot, kind, id, tenant, release string, evidence, artifacts, attestations map[string]bool) bool {
	switch kind {
	case "release_bundle":
		b, ok := s.ReleaseBundles[id]
		return release != "" && ok && b.ID == id && b.TenantID == tenant && b.ReleaseID == release
	case "evidence_item":
		e, ok := s.Evidence[id]
		return ok && evidence[id] && e.ReleaseID == release
	case "artifact_signature":
		sig, ok := s.ArtifactSignatures[id]
		return ok && sig.ID == id && sig.TenantID == tenant && artifacts[sig.ArtifactID]
	case "build_attestation":
		return attestations[id]
	default:
		return false
	}
}

func appendMemoryCustomerVerification(rows *[]map[string]any, row map[string]any, checks []domain.VerifyCheck, p domain.VerificationProfile, limitations []string, budget *memoryCustomerSnapshotBudget) error {
	if len(checks) > 4096 || len(p.RequiredChecks) > 4096 || len(p.TrustMaterial) > 4096 || len(p.Limitations) > 4096 || len(limitations) > 4096 {
		return ErrConflict
	}
	values := make([]packageapp.CustomerPackageVerificationCheck, 0, len(checks))
	for _, c := range checks {
		values = append(values, packageapp.CustomerPackageVerificationCheck{Name: c.Name, Result: c.Result, Detail: c.Detail})
	}
	row["checks"] = packageapp.CustomerPackageVerificationCheckSummaries(values)
	row["profile"] = map[string]any{"id": p.ID, "version": p.Version, "required_checks": p.RequiredChecks, "trust_material": p.TrustMaterial, "identity_policy": p.IdentityPolicy, "transparency_proof": p.TransparencyProof, "payload_scope": p.PayloadScope, "payload_digest": p.PayloadDigest, "limitations": p.Limitations}
	row["limitations"] = limitations
	if err := appendMemoryCustomerMetadata(rows, row, budget); err != nil {
		return err
	}
	p.RequiredChecks, p.TrustMaterial, p.Limitations = slices.Clone(p.RequiredChecks), slices.Clone(p.TrustMaterial), slices.Clone(p.Limitations)
	row["profile"], row["limitations"] = p, slices.Clone(limitations)
	return nil
}

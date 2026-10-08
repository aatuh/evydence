package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// Validate only the owning parser facts, never unrelated tenant inventory.
// A queued upload may legitimately have no matching parsed row yet.
func validateMemoryWorkerEvidence(ctx context.Context, s *MemoryUnitOfWorkSnapshot, item domain.EvidenceItem, remaining *int) error {
	if item.Type == "parser_normalization" {
		return validateMemoryNormalizationEvidence(ctx, s, item, remaining)
	}
	count := 0
	check := func(id, tenant, evidenceID, artifact string, record any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if tenant != item.TenantID || evidenceID != item.ID {
			return nil
		}
		count++
		if count > verificationapp.MaxEvidenceVerificationOrigins {
			return evidencequery.ErrConflict
		}
		if _, err := memorySelectedEvidenceJSON(record, remaining); err != nil {
			return err
		}
		if err := ValidateWorkerEvidenceRecord(item, record); err != nil {
			return evidencequery.ErrConflict
		}
		var recordID string
		switch v := record.(type) {
		case domain.SBOM:
			recordID = v.ID
		case domain.VulnerabilityScan:
			recordID = v.ID
		case domain.OpenAPIContract:
			recordID = v.ID
		case domain.VEXDocument:
			recordID = v.ID
		case domain.BuildAttestation:
			recordID = v.ID
		}
		if recordID != id {
			return evidencequery.ErrConflict
		}
		if artifact != "" {
			a, ok := s.Artifacts[artifact]
			if !ok || a.ID != artifact || a.TenantID != item.TenantID {
				return evidencequery.ErrConflict
			}
		}
		return nil
	}
	switch item.Type {
	case "sbom":
		for id, v := range s.SBOMs {
			if err := check(id, v.TenantID, v.EvidenceID, v.ArtifactID, v); err != nil {
				return err
			}
		}
	case "vulnerability_scan":
		for id, v := range s.VulnerabilityScans {
			if err := check(id, v.TenantID, v.EvidenceID, "", v); err != nil {
				return err
			}
		}
	case "openapi_contract":
		for id, v := range s.OpenAPIContracts {
			if err := check(id, v.TenantID, v.EvidenceID, "", v); err != nil {
				return err
			}
		}
	case "vex":
		for id, v := range s.VEXDocuments {
			if err := check(id, v.TenantID, v.EvidenceID, v.ArtifactID, v); err != nil {
				return err
			}
		}
	case "build_attestation":
		for id, v := range s.BuildAttestations {
			if err := check(id, v.TenantID, v.EvidenceID, "", v); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

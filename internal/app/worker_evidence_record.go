package app

import (
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// ValidateWorkerEvidenceRecord checks a selected parsed record against its
// immutable source evidence. Both focused readers and legacy projections use
// these rules; parent ownership is checked by the reader in the same snapshot.
// A queued, not-yet-parsed upload may have no parsed record.
func ValidateWorkerEvidenceRecord(item domain.EvidenceItem, record any) error {
	var id, tenant, evidenceID, kind, release, artifact string
	valid := false
	switch value := record.(type) {
	case domain.SBOM:
		id, tenant, evidenceID, kind, release, artifact = value.ID, value.TenantID, value.EvidenceID, "sbom", value.ReleaseID, value.ArtifactID
		valid = value.Format != "" && !value.CreatedAt.IsZero() && validSBOMProjectionShape(value)
	case domain.VulnerabilityScan:
		id, tenant, evidenceID, kind, release = value.ID, value.TenantID, value.EvidenceID, "vulnerability_scan", value.ReleaseID
		valid = !value.CreatedAt.IsZero() && validScanProjectionShape(value)
		seen := make(map[string]bool, len(value.Findings))
		for _, finding := range value.Findings {
			if finding.ID == "" || finding.Vulnerability == "" || seen[finding.ID] {
				valid = false
			}
			seen[finding.ID] = true
		}
	case domain.OpenAPIContract:
		id, tenant, evidenceID, kind, release = value.ID, value.TenantID, value.EvidenceID, "openapi_contract", value.ReleaseID
		valid = value.ProductID != "" && value.ProductID == item.ProductID && value.Version != "" && value.Hash != "" && !value.CreatedAt.IsZero() && value.PathCount >= 0
	case domain.VEXDocument:
		id, tenant, evidenceID, kind, release, artifact = value.ID, value.TenantID, value.EvidenceID, "vex", value.ReleaseID, value.ArtifactID
		valid = value.Format != "" && value.SchemaVersion != "" && !value.CreatedAt.IsZero() && value.StatementCount >= 0
	case domain.BuildAttestation:
		id, tenant, evidenceID, kind = value.ID, value.TenantID, value.EvidenceID, "build_attestation"
		release = item.ReleaseID
		valid = value.BuildID != "" && value.BuildID == item.BuildID && value.SchemaVersion != "" && !value.CreatedAt.IsZero() && validBuildAttestationProjectionShape(value)
	default:
		return projectionConflict("worker evidence record type")
	}
	if id == "" || strings.TrimSpace(id) != id || tenant != item.TenantID || evidenceID != item.ID || kind != item.Type || release != item.ReleaseID || !valid {
		return projectionConflict("worker evidence record")
	}
	if kind == "build_attestation" {
		return nil
	}
	artifacts := map[string]bool{}
	for _, ref := range item.SubjectRefs {
		if ref.Type == "artifact" && ref.ID != "" {
			artifacts[ref.ID] = true
		}
	}
	if artifact == "" && len(artifacts) != 0 || artifact != "" && (len(artifacts) != 1 || !artifacts[artifact]) {
		return projectionConflict("worker evidence artifact relationship")
	}
	return nil
}

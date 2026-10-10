package app

import (
	"fmt"

	"github.com/aatuh/evydence/internal/domain"
)

// Native selected-record checks neither hydrate a cache nor read an inventory.
func projectionConflict(subject string) error {
	return fmt.Errorf("invalid worker projection %s: %w", subject, ErrConflict)
}

func validSBOMProjectionShape(value domain.SBOM) bool {
	if value.ComponentCount < 0 {
		return false
	}
	if value.SpecVersion == "" {
		return value.ComponentCount == 0 && len(value.Components) == 0
	}
	return value.ComponentCount == len(value.Components)
}

func validScanProjectionShape(value domain.VulnerabilityScan) bool {
	parsedFields := []string{value.Scanner, value.Adapter, value.AdapterVersion, value.SourceSchema, value.TargetRef}
	present := 0
	for _, field := range parsedFields {
		if field != "" {
			present++
		}
	}
	if present == 0 {
		return len(value.Summary) == 0 && len(value.Findings) == 0
	}
	return present == len(parsedFields)
}

func validBuildAttestationProjectionShape(value domain.BuildAttestation) bool {
	if value.PayloadSize < 0 || value.MaterialsCount < 0 || value.SignatureCount < 0 {
		return false
	}
	parsedFieldsEmpty := value.PayloadType == "" && value.PredicateType == "" && len(value.SubjectDigests) == 0 && value.BuilderID == "" && value.BuildType == "" && value.MaterialsCount == 0 && value.SignatureCount == 0
	switch value.VerificationStatus {
	case "accepted":
		return parsedFieldsEmpty
	case "structurally_valid":
		return value.PayloadType != "" && value.PredicateType != ""
	default:
		return false
	}
}

package app

import (
	"bytes"

	"github.com/aatuh/evydence/internal/domain"
)

// CycloneDXReplayProjection is the normalized subset worker replay may project
// from immutable CycloneDX source bytes. The parser contract remains owned by
// internal/app/parsers/cyclonedx; worker code must not define a second reduced
// JSON model for the same parser version.
type CycloneDXReplayProjection struct {
	SpecVersion string
	Components  []domain.SBOMComponent
}

// ParseCycloneDXReplayProjection applies the shared bounded CycloneDX parser
// and returns only the durable SBOM fields that worker replay is allowed to
// restore. Schema admission remains an ingestion trust-boundary responsibility;
// this function keeps replay interpretation aligned with the parser version.
func ParseCycloneDXReplayProjection(raw []byte, maxBytes int64) (CycloneDXReplayProjection, error) {
	normalized, err := parseCycloneDXReader(bytes.NewReader(raw), maxBytes)
	if err != nil {
		return CycloneDXReplayProjection{}, err
	}
	return CycloneDXReplayProjection{
		SpecVersion: normalized.SpecVersion,
		Components:  append([]domain.SBOMComponent(nil), normalized.Components...),
	}, nil
}

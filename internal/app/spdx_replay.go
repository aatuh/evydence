package app

import (
	"bytes"

	"github.com/aatuh/evydence/internal/domain"
)

// SPDXReplayProjection is the durable subset a worker may reproduce from
// immutable SPDX source bytes. Ingestion remains the admission boundary.
type SPDXReplayProjection struct {
	SpecVersion string
	Components  []domain.SBOMComponent
}

func ParseSPDXReplayProjection(raw []byte, maxBytes int64) (SPDXReplayProjection, error) {
	normalized, err := parseSPDXReader(bytes.NewReader(raw), maxBytes)
	if err != nil {
		return SPDXReplayProjection{}, err
	}
	return SPDXReplayProjection{SpecVersion: normalized.SpecVersion, Components: append([]domain.SBOMComponent(nil), normalized.Components...)}, nil
}

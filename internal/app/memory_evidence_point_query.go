package app

import (
	"context"
	"strings"
	"unicode/utf8"

	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.EvidencePointReader = memoryEvidenceRepository{}

// Point and lifecycle reads use the same selected current ownership/provenance
// model. Memory tests do not establish SQL JSON shapes, work bounds or locks.
func (r memoryEvidenceRepository) GetEvidencePoint(ctx context.Context, tenant, id string, guard evidencequery.EvidenceReadGuard) (evidencequery.EvidencePoint, error) {
	var out evidencequery.EvidencePoint
	if guard == nil {
		return out, evidencequery.ErrValidation
	}
	id = strings.TrimSpace(id)
	if len(id) > 1024 || !utf8.ValidString(id) || strings.ContainsRune(id, 0) {
		return out, evidencequery.ErrValidation
	}
	err := r.parsedPointRead(ctx, tenant, id, func(s *MemoryUnitOfWorkSnapshot, id string) error {
		var err error
		out, err = readMemoryEvidencePoint(ctx, s, tenant, id, guard)
		return err
	})
	if err != nil {
		return evidencequery.EvidencePoint{}, err
	}
	return out, nil
}

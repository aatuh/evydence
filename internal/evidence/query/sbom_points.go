package query

import (
	"context"
	"strings"

	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// SBOMPoint binds one parsed SBOM to the product of its current, tenant-owned
// release. The reader validates its evidence and optional artifact parents.
type SBOMPoint struct {
	SBOM      evidencedomain.SBOM
	ProductID string
}

type SBOMPointReader interface {
	GetSBOMPoint(context.Context, string, string) (SBOMPoint, error)
}

type SBOMPoints struct{ reader SBOMPointReader }

func NewSBOMPoints(reader SBOMPointReader) (*SBOMPoints, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &SBOMPoints{reader: reader}, nil
}

func (s *SBOMPoints) GetSBOM(ctx context.Context, actor identitydomain.Actor, id string) (evidencedomain.SBOM, error) {
	if s == nil || ctx == nil {
		return evidencedomain.SBOM{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return evidencedomain.SBOM{}, err
	}
	if err := authorizeEvidenceRead(actor, EvidencePoint{}, true); err != nil {
		return evidencedomain.SBOM{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return evidencedomain.SBOM{}, ErrNotFound
	}
	point, err := s.reader.GetSBOMPoint(ctx, actor.TenantID, id)
	if err != nil {
		return evidencedomain.SBOM{}, err
	}
	if !validSBOMPoint(point, actor.TenantID, id) {
		return evidencedomain.SBOM{}, ErrConflict
	}
	if err := authorizeEvidenceRead(actor, EvidencePoint{ProductID: point.ProductID, ReleaseID: point.SBOM.ReleaseID}, false); err != nil {
		return evidencedomain.SBOM{}, err
	}
	return point.SBOM, nil
}

func validSBOMPoint(point SBOMPoint, tenantID, id string) bool {
	sbom := point.SBOM
	if sbom.ID != id || sbom.TenantID != tenantID || sbom.EvidenceID == "" || sbom.Format == "" ||
		sbom.CreatedAt.IsZero() || sbom.ComponentCount < 0 || sbom.ComponentCount != len(sbom.Components) ||
		sbom.SpecVersion == "" && (sbom.ComponentCount != 0 || len(sbom.Components) != 0) ||
		(sbom.ReleaseID == "") != (point.ProductID == "") {
		return false
	}
	for _, component := range sbom.Components {
		if strings.TrimSpace(component.Name) == "" {
			return false
		}
	}
	return true
}

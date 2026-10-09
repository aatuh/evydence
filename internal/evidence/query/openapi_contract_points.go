package query

import (
	"context"
	"encoding/hex"
	"strings"

	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// OpenAPIContractPoint contains one tenant-verified contract and its current
// product/release coordinates from a single database statement.
type OpenAPIContractPoint struct {
	Contract evidencedomain.OpenAPIContract
}

type OpenAPIContractPointReader interface {
	GetOpenAPIContractPoint(context.Context, string, string) (OpenAPIContractPoint, error)
}

type OpenAPIContractPoints struct{ reader OpenAPIContractPointReader }

func NewOpenAPIContractPoints(reader OpenAPIContractPointReader) (*OpenAPIContractPoints, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &OpenAPIContractPoints{reader: reader}, nil
}

func (s *OpenAPIContractPoints) GetOpenAPIContract(ctx context.Context, actor identitydomain.Actor, id string) (evidencedomain.OpenAPIContract, error) {
	if s == nil || ctx == nil {
		return evidencedomain.OpenAPIContract{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	if err := authorizeEvidenceRead(actor, EvidencePoint{}, true); err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return evidencedomain.OpenAPIContract{}, ErrNotFound
	}
	point, err := s.reader.GetOpenAPIContractPoint(ctx, actor.TenantID, id)
	if err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	contract := point.Contract
	if !validOpenAPIContractPoint(contract, actor.TenantID, id) {
		return evidencedomain.OpenAPIContract{}, ErrConflict
	}
	if err := authorizeEvidenceRead(actor, EvidencePoint{ProductID: contract.ProductID, ReleaseID: contract.ReleaseID}, false); err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	return contract, nil
}

func validOpenAPIContractPoint(contract evidencedomain.OpenAPIContract, tenantID, id string) bool {
	if contract.ID != id || contract.TenantID != tenantID || contract.ProductID == "" || contract.Version == "" ||
		contract.EvidenceID == "" || contract.PathCount < 0 || contract.CreatedAt.IsZero() ||
		!strings.HasPrefix(contract.Hash, "sha256:") || len(contract.Hash) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(contract.Hash, "sha256:"))
	return err == nil
}

package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func openAPIContractFromQuery(value evidencedomain.OpenAPIContract) domain.OpenAPIContract {
	contract := domain.OpenAPIContract{
		ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID,
		ReleaseID: value.ReleaseID, Version: value.Version, Hash: value.Hash,
		PathCount: value.PathCount, EvidenceID: value.EvidenceID, CreatedAt: value.CreatedAt,
	}
	for _, operation := range value.Operations {
		contract.Operations = append(contract.Operations, domain.OpenAPIOperation{
			Path: operation.Path, Method: operation.Method, OperationID: operation.OperationID,
			Deprecated: operation.Deprecated, RequestBodyRequired: operation.RequestBodyRequired,
			RequiredRequestFields: append([]string(nil), operation.RequiredRequestFields...),
			ResponseStatuses:      append([]string(nil), operation.ResponseStatuses...),
		})
	}
	return contract
}

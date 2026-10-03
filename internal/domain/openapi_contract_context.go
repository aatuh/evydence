package domain

import evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"

func OpenAPIContractFromContext(v evidencedomain.OpenAPIContract) OpenAPIContract {
	var operations []OpenAPIOperation
	if v.Operations != nil {
		operations = make([]OpenAPIOperation, 0, len(v.Operations))
	}
	for _, op := range v.Operations {
		operations = append(operations, OpenAPIOperation{Path: op.Path, Method: op.Method, OperationID: op.OperationID, Deprecated: op.Deprecated, RequestBodyRequired: op.RequestBodyRequired, RequiredRequestFields: append([]string(nil), op.RequiredRequestFields...), ResponseStatuses: append([]string(nil), op.ResponseStatuses...)})
	}
	return OpenAPIContract{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Version: v.Version, Hash: v.Hash, PathCount: v.PathCount, Operations: operations, EvidenceID: v.EvidenceID, CreatedAt: v.CreatedAt}
}

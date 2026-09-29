package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.OpenAPIContractPointReader = (*Store)(nil)

const maxContractOperationsJSONBytes = 32 << 20

// GetOpenAPIContractPoint resolves the contract, source evidence, product, and
// optional release under one tenant in one PostgreSQL statement.
func (s *Store) GetOpenAPIContractPoint(ctx context.Context, tenantID, id string) (evidencequery.OpenAPIContractPoint, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return evidencequery.OpenAPIContractPoint{}, evidencequery.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return evidencequery.OpenAPIContractPoint{}, evidencequery.ErrNotFound
	}
	var point evidencequery.OpenAPIContractPoint
	var releaseID sql.NullString
	var operationsJSON []byte
	contract := &point.Contract
	err := s.pool.QueryRow(ctx, `
		SELECT c.id, c.tenant_id, p.id, c.release_id, c.version, c.hash,
		       c.path_count, c.operations, c.evidence_id, c.created_at
		FROM openapi_contracts AS c
		JOIN products AS p ON p.id = c.product_id AND p.tenant_id = c.tenant_id
		LEFT JOIN releases AS r ON r.id = c.release_id AND r.tenant_id = c.tenant_id
		    AND r.product_id = p.id
		JOIN evidence_items AS e ON e.id = c.evidence_id AND e.tenant_id = c.tenant_id
		LEFT JOIN projects AS ej ON ej.id = e.project_id AND ej.tenant_id = e.tenant_id
		    AND ej.product_id = p.id
		LEFT JOIN build_runs AS eb ON eb.id = e.build_id AND eb.tenant_id = e.tenant_id
		LEFT JOIN projects AS ebj ON ebj.id = eb.project_id AND ebj.tenant_id = eb.tenant_id
		    AND ebj.product_id = p.id
		LEFT JOIN releases AS ebr ON ebr.id = eb.release_id AND ebr.tenant_id = eb.tenant_id
		    AND ebr.product_id = p.id
		LEFT JOIN deployment_events AS ed ON ed.id = e.deployment_id AND ed.tenant_id = e.tenant_id
		LEFT JOIN deployment_environments AS ede ON ede.id = ed.environment_id AND ede.tenant_id = ed.tenant_id
		    AND ede.product_id = p.id
		LEFT JOIN releases AS edr ON edr.id = ed.release_id AND edr.tenant_id = ed.tenant_id
		    AND edr.product_id = p.id
		WHERE c.tenant_id = $1 AND c.id = $2 AND e.type = 'openapi_contract'
		  AND (c.release_id IS NULL OR r.id IS NOT NULL)
		  AND (e.product_id IS NULL OR e.product_id = p.id)
		  AND (e.project_id IS NULL OR ej.id IS NOT NULL)
		  AND (e.release_id IS NULL OR e.release_id = c.release_id)
		  AND (e.build_id IS NULL OR ebj.id IS NOT NULL AND ebr.id IS NOT NULL)
		  AND (e.deployment_id IS NULL OR ede.id IS NOT NULL AND edr.id IS NOT NULL)
		  AND (e.project_id IS NULL OR e.build_id IS NULL OR e.project_id = eb.project_id)
		  AND (e.release_id IS NULL OR e.build_id IS NULL OR e.release_id = eb.release_id)
		  AND (e.release_id IS NULL OR e.deployment_id IS NULL OR e.release_id = ed.release_id)
		  AND (e.build_id IS NULL OR e.deployment_id IS NULL OR eb.release_id = ed.release_id)`, tenantID, id).Scan(
		&contract.ID, &contract.TenantID, &contract.ProductID, &releaseID,
		&contract.Version, &contract.Hash, &contract.PathCount, &operationsJSON,
		&contract.EvidenceID, &contract.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return evidencequery.OpenAPIContractPoint{}, evidencequery.ErrNotFound
	}
	if err != nil {
		return evidencequery.OpenAPIContractPoint{}, fmt.Errorf("get OpenAPI contract point: %w", err)
	}
	if len(operationsJSON) > maxContractOperationsJSONBytes {
		return evidencequery.OpenAPIContractPoint{}, evidencequery.ErrConflict
	}
	contract.ReleaseID = nullableSQLString(releaseID)
	var stored []domain.OpenAPIOperation
	if err := json.Unmarshal(operationsJSON, &stored); err != nil || stored == nil {
		return evidencequery.OpenAPIContractPoint{}, evidencequery.ErrConflict
	}
	contract.Operations = make([]evidencedomain.OpenAPIOperation, 0, len(stored))
	for _, operation := range stored {
		contract.Operations = append(contract.Operations, evidencedomain.OpenAPIOperation{
			Path: operation.Path, Method: operation.Method, OperationID: operation.OperationID,
			Deprecated: operation.Deprecated, RequestBodyRequired: operation.RequestBodyRequired,
			RequiredRequestFields: append([]string(nil), operation.RequiredRequestFields...),
			ResponseStatuses:      append([]string(nil), operation.ResponseStatuses...),
		})
	}
	return point, nil
}

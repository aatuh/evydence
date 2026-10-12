package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

var _ evidenceapp.ContractDiffReader = evidence{}

func (r evidence) ReadContractDiffRelease(ctx context.Context, tenant, id string) (evidenceapp.ContractDiffRelease, error) {
	var empty evidenceapp.ContractDiffRelease
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return empty, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return empty, err
	}
	var v evidenceapp.ContractDiffRelease
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(r.id,1025),left(r.tenant_id,1025),left(r.product_id,1025),octet_length(r.id)>1024 OR octet_length(r.tenant_id)>1024 OR octet_length(r.product_id)>1024 FROM releases r JOIN products p ON p.id=r.product_id AND p.tenant_id=r.tenant_id WHERE r.tenant_id=$1 AND r.id=$2 FOR SHARE OF r,p`, tenant, id).Scan(&v.ID, &v.TenantID, &v.ProductID, &large)
	if err := buildIdentityReadError(err, large); err != nil {
		return empty, err
	}
	return v, nil
}

// Only identifiers cross the database boundary before resource authorization.
// Coherent source parents and parsed coordinates are share-locked under the
// same tenant projection fence as the operation read and subsequent writes.
func (r evidence) ReadContractDiffSubject(ctx context.Context, tenant, id string) (evidenceapp.ContractDiffSubject, error) {
	var empty evidenceapp.ContractDiffSubject
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return empty, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return empty, err
	}
	v := evidenceapp.ContractDiffSubject{ID: id, TenantID: tenant}
	var refs application.ResourceReferences
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(c.product_id,1025),left(COALESCE(c.release_id,''),1025),left(c.evidence_id,1025),left(COALESCE(e.product_id,''),1025),left(COALESCE(e.project_id,''),1025),left(COALESCE(e.release_id,''),1025),left(COALESCE(e.build_id,''),1025),left(COALESCE(e.deployment_id,''),1025),EXISTS(SELECT 1 FROM unnest(ARRAY[c.product_id,c.release_id,c.evidence_id,e.product_id,e.project_id,e.release_id,e.build_id,e.deployment_id]) x(id) WHERE octet_length(x.id)>1024)
 FROM openapi_contracts c JOIN evidence_items e ON e.id=c.evidence_id AND e.tenant_id=c.tenant_id AND e.type='openapi_contract'
 WHERE c.tenant_id=$1 AND c.id=$2 AND (e.release_id IS NULL OR e.release_id=c.release_id) FOR SHARE OF c,e`, tenant, id).Scan(&v.ProductID, &v.ReleaseID, &v.EvidenceID, &refs.ProductID, &refs.ProjectID, &refs.ReleaseID, &refs.BuildID, &refs.DeploymentID, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, app.ErrNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("read contract diff coordinates: %w", err)
	}
	if large {
		return empty, app.ErrValidation
	}
	if refs.ProductID != "" && refs.ProductID != v.ProductID {
		return empty, app.ErrNotFound
	}
	refs.ProductID = v.ProductID
	if _, err := r.ResolveEvidenceCreationScope(ctx, tenant, refs); err != nil {
		return empty, err
	}
	if v.ReleaseID != "" {
		release, err := r.ReadContractDiffRelease(ctx, tenant, v.ReleaseID)
		if err != nil {
			return empty, err
		}
		if release.ProductID != v.ProductID {
			return empty, app.ErrNotFound
		}
	}
	return v, nil
}
func (r evidence) ReadContractDiffProjection(ctx context.Context, tenant, id string) (evidencedomain.OpenAPIContract, error) {
	var empty evidencedomain.OpenAPIContract
	subject, err := r.ReadContractDiffSubject(ctx, tenant, id)
	if err != nil {
		return empty, err
	}
	var raw []byte
	var invalid bool
	v := evidencedomain.OpenAPIContract{ID: subject.ID, TenantID: subject.TenantID, ProductID: subject.ProductID, ReleaseID: subject.ReleaseID, EvidenceID: subject.EvidenceID}
	// Mask oversized or structurally invalid operation JSON before transfer.
	err = r.tx.QueryRow(ctx, `WITH selected AS(SELECT hash,path_count,operations,
 CASE WHEN jsonb_typeof(operations)='array' THEN jsonb_array_length(operations)<=$4 ELSE operations='null'::jsonb END AND octet_length(operations::text)<=$3 AND octet_length(hash)<=71 AS bounded FROM openapi_contracts WHERE tenant_id=$1 AND id=$2)
 SELECT left(hash,72),path_count,CASE WHEN bounded THEN operations ELSE '[]'::jsonb END,NOT bounded FROM selected`, tenant, id, evidenceapp.ContractDiffProjectionByteLimit, evidenceapp.ContractDiffOperationLimit).Scan(&v.Hash, &v.PathCount, &raw, &invalid)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, app.ErrNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("read bounded contract diff operations: %w", err)
	}
	if invalid {
		return empty, app.ErrValidation
	}
	var operations []domain.OpenAPIOperation
	if json.Unmarshal(raw, &operations) != nil {
		return empty, app.ErrValidation
	}
	v.Operations = make([]evidencedomain.OpenAPIOperation, 0, len(operations))
	for _, op := range operations {
		v.Operations = append(v.Operations, evidencedomain.OpenAPIOperation{Path: op.Path, Method: op.Method, OperationID: op.OperationID, Deprecated: op.Deprecated, RequestBodyRequired: op.RequestBodyRequired, RequiredRequestFields: op.RequiredRequestFields, ResponseStatuses: op.ResponseStatuses})
	}
	return v, nil
}

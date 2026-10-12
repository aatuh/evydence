package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

var _ riskapp.ApprovalReader = governance{}

func (r governance) approvalReadFence(ctx context.Context, tenant, id string) error {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return err
	}
	return coordination.LockWorkerProjection(ctx, r.tx, tenant)
}

func (r governance) ApprovalEvidenceExists(ctx context.Context, tenant, id string) (bool, error) {
	if err := r.approvalReadFence(ctx, tenant, id); err != nil {
		return false, err
	}
	var exists bool
	err := r.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM evidence_items WHERE tenant_id=$1 AND id=$2)`, tenant, id).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("read approval evidence ownership: %w", err)
	}
	return exists, nil
}

func (r governance) ReadApprovalSubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	if err := r.approvalReadFence(ctx, tenant, id); err != nil {
		return riskapp.GovernanceSubjectReference{}, err
	}
	switch kind {
	case "release", "contract_diff", "waiver", "security_review", "customer_package":
	default:
		return riskapp.GovernanceSubjectReference{}, app.ErrValidation
	}
	owner, err := r.readApprovalOwner(ctx, tenant, kind, id)
	if err != nil {
		return riskapp.GovernanceSubjectReference{}, err
	}
	owner.Type, owner.ID = kind, id
	return owner, nil
}

func (r governance) readApprovalOwner(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	if kind == "finding" {
		finding, err := decisions(r).readDecisionFinding(ctx, tenant, id, false)
		if err != nil {
			return riskapp.GovernanceSubjectReference{}, err
		}
		return riskapp.GovernanceSubjectReference{TenantID: tenant, ProductID: finding.ProductID, ReleaseID: finding.ReleaseID}, nil
	}
	if kind == "waiver" {
		var scope, scopeID string
		var invalid bool
		err := r.tx.QueryRow(ctx, `SELECT left(scope_type,129),left(scope_id,1025),octet_length(scope_type)>128 OR octet_length(scope_id)>1024 FROM waivers WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&scope, &scopeID, &invalid)
		if errors.Is(err, pgx.ErrNoRows) {
			return riskapp.GovernanceSubjectReference{}, app.ErrNotFound
		}
		if err != nil {
			return riskapp.GovernanceSubjectReference{}, fmt.Errorf("read approval waiver scope: %w", err)
		}
		if invalid {
			return riskapp.GovernanceSubjectReference{}, app.ErrValidation
		}
		switch scope {
		case "release", "control", "policy", "finding":
			return r.readApprovalOwner(ctx, tenant, scope, scopeID)
		default:
			return riskapp.GovernanceSubjectReference{}, app.ErrNotFound
		}
	}
	projection := approvalSubjectProjection(kind)
	if projection == "" {
		return riskapp.GovernanceSubjectReference{}, app.ErrNotFound
	}
	v := riskapp.GovernanceSubjectReference{TenantID: tenant}
	var invalid bool
	err := r.tx.QueryRow(ctx, controlEvidenceParentCTEs+approvalContractParentCTE+` SELECT left(COALESCE(product_id,''),1025),left(COALESCE(release_id,''),1025),octet_length(COALESCE(product_id,''))>1024 OR octet_length(COALESCE(release_id,''))>1024 FROM (`+projection+`) subject LIMIT 1`, tenant, id).Scan(&v.ProductID, &v.ReleaseID, &invalid)
	if errors.Is(err, pgx.ErrNoRows) {
		return riskapp.GovernanceSubjectReference{}, app.ErrNotFound
	}
	if err != nil {
		return riskapp.GovernanceSubjectReference{}, fmt.Errorf("read approval subject ownership: %w", err)
	}
	if invalid {
		return riskapp.GovernanceSubjectReference{}, app.ErrValidation
	}
	return v, nil
}

const approvalContractParentCTE = `, valid_approval_contracts AS NOT MATERIALIZED (
 SELECT c.id,c.tenant_id,c.product_id FROM openapi_contracts c JOIN products p ON p.id=c.product_id AND p.tenant_id=c.tenant_id
 JOIN valid_evidence e ON e.id=c.evidence_id AND e.tenant_id=c.tenant_id AND e.type='openapi_contract'
 LEFT JOIN valid_releases r ON r.id=c.release_id AND r.tenant_id=c.tenant_id AND r.product_id=c.product_id
 WHERE c.tenant_id=$1 AND (c.release_id IS NULL OR r.id IS NOT NULL) AND (e.product_id IS NULL OR e.product_id=c.product_id)
 AND (c.release_id IS NULL OR e.release_id IS NULL OR c.release_id=e.release_id)
) `

// Closed internal SQL fragments only; no request text is interpolated.
func approvalSubjectProjection(kind string) string {
	switch kind {
	case "release":
		return `SELECT product_id,id AS release_id FROM valid_releases WHERE id=$2`
	case "contract_diff":
		return `SELECT d.product_id,d.release_id FROM contract_diffs d
 JOIN products p ON p.id=d.product_id AND p.tenant_id=d.tenant_id
 JOIN valid_approval_contracts b ON b.id=d.base_contract_id AND b.tenant_id=d.tenant_id AND b.product_id=d.product_id
 JOIN valid_approval_contracts t ON t.id=d.target_contract_id AND t.tenant_id=d.tenant_id AND t.product_id=d.product_id
 LEFT JOIN valid_releases r ON r.id=d.release_id AND r.tenant_id=d.tenant_id AND r.product_id=d.product_id
 WHERE d.tenant_id=$1 AND d.id=$2 AND (d.release_id IS NULL OR r.id IS NOT NULL)`
	case "security_review":
		return `SELECT d.product_id,d.release_id FROM manual_security_documents d
 JOIN products p ON p.id=d.product_id AND p.tenant_id=d.tenant_id
 JOIN valid_evidence e ON e.id=d.evidence_id AND e.tenant_id=d.tenant_id AND e.type='security_review'
 LEFT JOIN valid_releases r ON r.id=d.release_id AND r.tenant_id=d.tenant_id AND r.product_id=d.product_id
 WHERE d.tenant_id=$1 AND d.id=$2 AND d.document_type='security_review' AND (d.release_id IS NULL OR r.id IS NOT NULL)
 AND (e.product_id IS NULL OR e.product_id=d.product_id) AND (e.release_id IS NULL OR d.release_id IS NULL OR e.release_id=d.release_id)`
	case "customer_package":
		return `SELECT c.product_id,c.release_id FROM customer_security_packages c
 JOIN products p ON p.id=c.product_id AND p.tenant_id=c.tenant_id
 JOIN redaction_profiles d ON d.id=c.redaction_profile_id AND d.tenant_id=c.tenant_id
 LEFT JOIN valid_releases r ON r.id=c.release_id AND r.tenant_id=c.tenant_id AND r.product_id=c.product_id
 WHERE c.tenant_id=$1 AND c.id=$2 AND (c.release_id IS NULL OR r.id IS NOT NULL)`
	case "control":
		return `SELECT NULL::text AS product_id,NULL::text AS release_id FROM security_controls c JOIN control_frameworks f ON f.id=c.framework_id AND f.tenant_id=c.tenant_id WHERE c.tenant_id=$1 AND c.id=$2`
	case "policy":
		return `SELECT NULL::text AS product_id,NULL::text AS release_id FROM custom_policies WHERE tenant_id=$1 AND id=$2`
	default:
		return ""
	}
}

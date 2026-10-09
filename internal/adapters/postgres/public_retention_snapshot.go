package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Shared bounded facts for package-safe renderers, not the operator policy
// point reader. Only location presence and known check fields cross the driver.
// The caller owns the read-only repeatable-read view and tenant authorization.
func readPublicRetentionPoliciesTx(ctx context.Context, tx pgx.Tx, tenant string, maxRows, maxBytes int) ([]verificationdomain.ObjectRetentionPolicy, int, error) {
	if ctx == nil || tx == nil || !customerSnapshotID(tenant, false) || maxRows < 0 || maxRows > packageapp.MaxBundleSnapshotRows || maxBytes < 0 || maxBytes > maxBundleProofBytes {
		return nil, 0, packageapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	// Bound the source before expanding check objects. Retain the bundle's
	// combined detail limit; do not allow many individually valid lists to
	// evade it. Array dimensions are checked before array_position is called.
	var rejected bool
	err := tx.QueryRow(ctx, `WITH selected AS MATERIALIZED (
	 SELECT verification_checks AS checks,verification_limitations AS limitations FROM object_retention_policies WHERE tenant_id=$1 ORDER BY id LIMIT $2
	) SELECT count(*) >= $2 OR coalesce(sum(octet_length(checks::text)+octet_length(limitations::text)),0)>$3
	 OR coalesce(sum(CASE WHEN jsonb_typeof(checks)='array' THEN jsonb_array_length(checks) ELSE 0 END + cardinality(limitations)),0)>4096
	 OR coalesce(bool_or(jsonb_typeof(checks) IS DISTINCT FROM 'array' OR `+customerVerificationChecksInvalidSQL("checks")+` OR `+customerGovernanceTextArrayInvalidSQL("limitations")+`),false)
	 FROM selected`, tenant, maxRows+1, maxBundleProofBytes).Scan(&rejected)
	if err != nil {
		return nil, 0, fmt.Errorf("read public retention source budget: %w", err)
	}
	if rejected {
		return nil, 0, packageapp.ErrConflict
	}
	budget := &customerSnapshotBudget{remainingBytes: maxBytes}
	rows, err := readCustomerSnapshotMetadataRowsAtLimit(ctx, tx, publicRetentionPoliciesSQL, tenant, "", "", budget, time.Time{}, maxRows)
	if err != nil {
		return nil, 0, err
	}
	policies := make([]verificationdomain.ObjectRetentionPolicy, 0, len(rows))
	for _, row := range rows {
		var policy verificationdomain.ObjectRetentionPolicy
		raw, err := json.Marshal(row)
		if err != nil || json.Unmarshal(raw, &policy) != nil || !customerSnapshotID(policy.ID, false) {
			return nil, 0, packageapp.ErrConflict
		}
		policy.TenantID = tenant
		policies = append(policies, policy)
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	return policies, maxBytes - budget.remainingBytes, nil
}

func publicRetentionTimeSQL(column string) string {
	return `to_char(` + column + ` AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`
}

var publicRetentionPoliciesSQL = `SELECT p.id AS sort_id,jsonb_build_object(
	'ID',p.id,'Name',p.name,'ObjectPrefix',CASE WHEN p.object_prefix<>'' THEN 'configured' ELSE '' END,
	'ObjectKey',CASE WHEN coalesce(p.object_key,'')<>'' THEN 'configured' ELSE '' END,'RequireLegalHold',p.require_legal_hold,
	'Mode',p.mode,'RetentionDays',p.retention_days,'Status',p.status,'VerificationHash',coalesce(p.verification_hash,''),
	'VerificationProvider',p.verification_provider,'VerificationMode',p.verification_mode,'VerificationRetentionDays',p.verification_retention_days,
	'VerificationChecks',` + customerVerificationChecksSQL("p.verification_checks") + `,'VerificationLimitations',p.verification_limitations,
	'CreatedAt',` + publicRetentionTimeSQL("p.created_at") + `,'VerifiedAt',` + publicRetentionTimeSQL("p.verified_at") + `,
	'VerificationObservedAt',` + publicRetentionTimeSQL("p.verification_observed_at") + `,'VerificationExpiresAt',` + publicRetentionTimeSQL("p.verification_expires_at") + `,
	'VerificationLegalHold',p.verification_legal_hold) AS metadata,
	(octet_length(p.id)>1024 OR octet_length(p.name)>4096 OR octet_length(p.mode)>64 OR octet_length(p.status)>64
	 OR octet_length(coalesce(p.verification_hash,''))>1024 OR octet_length(p.verification_provider)>64 OR octet_length(p.verification_mode)>64
	 OR p.retention_days<0 OR p.verification_retention_days<0
	 OR ` + customerGovernanceTimeInvalidSQL("p.created_at") + ` OR ` + customerGovernanceTimeInvalidSQL("p.verified_at") + `
	 OR ` + customerGovernanceTimeInvalidSQL("p.verification_observed_at") + ` OR ` + customerGovernanceTimeInvalidSQL("p.verification_expires_at") + `) AS invalid
	FROM scope s JOIN object_retention_policies p ON p.tenant_id=s.tenant_id ORDER BY p.id`

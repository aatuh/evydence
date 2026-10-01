package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

var _ verificationquery.SigningCustodyReader = (*Store)(nil)

// One SELECT gives both inventories one committed PostgreSQL snapshot.
// Explicit columns exclude future storage-only fields, and no signing-key
// table, private material, uploaded payload or whole-tenant projection is read.
const signingCustodySnapshotSQL = `WITH selected_ids AS MATERIALIZED (
	SELECT kind,id FROM (
		(SELECT 'provider' AS kind,id FROM signing_providers WHERE tenant_id=$1 ORDER BY id LIMIT $3)
		UNION ALL
		(SELECT 'policy' AS kind,id FROM object_retention_policies WHERE tenant_id=$1 ORDER BY id LIMIT $3)
	) coordinates ORDER BY kind,id LIMIT $3
)
SELECT kind,
	CASE WHEN octet_length(body::text)<=$2 THEN body ELSE NULL END
	FROM (
		SELECT 'provider' AS kind,jsonb_build_object(
			'id',id,'tenant_id',tenant_id,'name',name,'type',type,'status',status,
			'key_ref',key_ref,'encrypted',encrypted,'schema_version',schema_version,'created_at',created_at
		) AS body FROM signing_providers JOIN selected_ids USING(id) WHERE tenant_id=$1 AND kind='provider'
		UNION ALL
		SELECT 'policy' AS kind,jsonb_build_object(
			'id',id,'tenant_id',tenant_id,'name',name,'object_prefix',object_prefix,'object_key',object_key,
			'require_legal_hold',require_legal_hold,'mode',mode,'retention_days',retention_days,
			'max_verification_age_hours',max_verification_age_hours,'status',status,'verified_at',verified_at,
			'verification_hash',verification_hash,'verification_checks',verification_checks,'verification_limitations',verification_limitations,
			'verification_provider',verification_provider,'verification_bucket',verification_bucket,'verification_mode',verification_mode,
			'verification_retention_days',verification_retention_days,'verification_legal_hold',verification_legal_hold,
			'verification_observed_at',verification_observed_at,'verification_expires_at',verification_expires_at,
			'schema_version',schema_version,'created_at',created_at
		) AS body FROM object_retention_policies JOIN selected_ids USING(id) WHERE tenant_id=$1 AND kind='policy'
	) selected`

func (s *Store) ReadSigningCustodySnapshot(ctx context.Context, tenantID string) (verificationapp.SigningCustodySnapshot, error) {
	var empty verificationapp.SigningCustodySnapshot
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return empty, verificationquery.ErrSigningCustodyValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	rows, err := s.pool.Query(ctx, signingCustodySnapshotSQL, tenantID, verificationquery.MaxSigningCustodyBytes, verificationquery.MaxSigningCustodyRecords+1)
	if err != nil {
		return empty, fmt.Errorf("read signing custody snapshot: %w", err)
	}
	defer rows.Close()
	snapshot := verificationapp.SigningCustodySnapshot{TenantID: tenantID, SigningProviders: []verificationdomain.SigningProvider{}, ObjectRetentionPolicies: []verificationdomain.ObjectRetentionPolicy{}}
	remaining := verificationquery.MaxSigningCustodyBytes
	count := 0
	for rows.Next() {
		var kind string
		var body []byte
		if err := rows.Scan(&kind, &body); err != nil {
			return empty, fmt.Errorf("scan signing custody snapshot: %w", err)
		}
		if count == verificationquery.MaxSigningCustodyRecords || len(body) == 0 || len(body) > remaining {
			return empty, verificationquery.ErrSigningCustodyProjection
		}
		count++
		remaining -= len(body)
		switch kind {
		case "provider":
			var provider domain.SigningProvider
			if err := json.Unmarshal(body, &provider); err != nil {
				return empty, verificationquery.ErrSigningCustodyProjection
			}
			snapshot.SigningProviders = append(snapshot.SigningProviders, domain.SigningProviderToContextModel(provider))
		case "policy":
			var policy domain.ObjectRetentionPolicy
			if err := json.Unmarshal(body, &policy); err != nil {
				return empty, verificationquery.ErrSigningCustodyProjection
			}
			snapshot.ObjectRetentionPolicies = append(snapshot.ObjectRetentionPolicies, domain.ObjectRetentionPolicyToContextModel(policy))
		default:
			return empty, verificationquery.ErrSigningCustodyProjection
		}
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("iterate signing custody snapshot: %w", err)
	}
	return snapshot, nil
}

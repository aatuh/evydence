package repositories

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

var _ riskapp.CustomPolicyReader = risk{}

func (r risk) PolicyTenantExists(ctx context.Context, tenant string) (bool, error) {
	if err := governance(r).approvalReadFence(ctx, tenant, tenant); err != nil {
		return false, err
	}
	var exists bool
	err := r.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)`, tenant).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("read policy tenant: %w", err)
	}
	return exists, nil
}
func (r risk) ReadCustomPolicySubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	if kind != "policy" && kind != "release" {
		return riskapp.GovernanceSubjectReference{}, app.ErrValidation
	}
	return governance(r).ReadWaiverSubject(ctx, tenant, kind, id)
}
func (r risk) ReadCustomPolicy(ctx context.Context, tenant, id string) (riskdomain.CustomPolicy, error) {
	var p domain.CustomPolicy
	if err := governance(r).approvalReadFence(ctx, tenant, id); err != nil {
		return riskdomain.CustomPolicy{}, err
	}
	p.ID, p.TenantID = id, tenant
	var raw []byte
	var invalid bool
	err := r.tx.QueryRow(ctx, `SELECT left(name,1025),left(version,1025),left(COALESCE(description,''),65537),
 CASE WHEN octet_length(rules::text)<=8388608 AND CASE WHEN jsonb_typeof(rules)='array' THEN jsonb_array_length(rules) BETWEEN 1 AND 4096 ELSE false END THEN rules ELSE '[]'::jsonb END,
 left(schema_version,1025),created_at,
 octet_length(name)>1024 OR octet_length(version)>1024 OR octet_length(COALESCE(description,''))>65536 OR octet_length(schema_version)>1024 OR octet_length(rules::text)>8388608 OR NOT CASE WHEN jsonb_typeof(rules)='array' THEN jsonb_array_length(rules) BETWEEN 1 AND 4096 ELSE false END
 FROM custom_policies WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&p.Name, &p.Version, &p.Description, &raw, &p.SchemaVersion, &p.CreatedAt, &invalid)
	if errors.Is(err, pgx.ErrNoRows) {
		return riskdomain.CustomPolicy{}, app.ErrNotFound
	}
	if err != nil {
		return riskdomain.CustomPolicy{}, fmt.Errorf("read bounded custom policy: %w", err)
	}
	if invalid || json.Unmarshal(raw, &p.Rules) != nil {
		return riskdomain.CustomPolicy{}, app.ErrValidation
	}
	var fields []map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return riskdomain.CustomPolicy{}, app.ErrValidation
	}
	for _, rule := range fields {
		if rule == nil {
			return riskdomain.CustomPolicy{}, app.ErrValidation
		}
		for _, name := range []string{"name", "evidence_type", "severity", "required"} {
			if bytes.Equal(bytes.TrimSpace(rule[name]), []byte("null")) {
				return riskdomain.CustomPolicy{}, app.ErrValidation
			}
		}
	}
	p.CreatedAt = p.CreatedAt.UTC()
	return domain.CustomPolicyToContext(p), nil
}
func (r risk) ReadCustomPolicyEvidencePresence(ctx context.Context, tenant, release string, types []string) (map[string]bool, error) {
	if err := governance(r).approvalReadFence(ctx, tenant, release); err != nil {
		return nil, err
	}
	if len(types) > 19 {
		return nil, app.ErrValidation
	}
	seen := map[string]bool{}
	for _, kind := range types {
		if !riskdomain.ValidPolicyEvidenceType(kind) || seen[kind] {
			return nil, app.ErrValidation
		}
		seen[kind] = true
	}
	result := map[string]bool{}
	if len(types) == 0 {
		return result, nil
	}
	rows, err := r.tx.Query(ctx, controlEvidenceParentCTEs+` SELECT wanted.type,EXISTS(SELECT 1 FROM valid_evidence e WHERE e.release_id=$2 AND e.type=wanted.type) FROM unnest($3::text[]) wanted(type)`, tenant, release, types)
	if err != nil {
		return nil, fmt.Errorf("read policy evidence presence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var exists bool
		if err := rows.Scan(&kind, &exists); err != nil {
			return nil, fmt.Errorf("read policy evidence fact: %w", err)
		}
		result[kind] = exists
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read policy evidence facts: %w", err)
	}
	return result, nil
}

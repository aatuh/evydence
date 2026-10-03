package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Explicit public policy fields, shared by point reads and custody reports.
// Future storage-only fields must not silently become part of the projection.
const ObjectRetentionPolicyJSONProjection = `jsonb_build_object(
	'id',id,'tenant_id',tenant_id,'name',name,'object_prefix',object_prefix,'object_key',object_key,
	'require_legal_hold',require_legal_hold,'mode',mode,'retention_days',retention_days,
	'max_verification_age_hours',max_verification_age_hours,'status',status,'verified_at',verified_at,
	'verification_hash',verification_hash,'verification_checks',verification_checks,'verification_limitations',verification_limitations,
	'verification_provider',verification_provider,'verification_bucket',verification_bucket,'verification_mode',verification_mode,
	'verification_retention_days',verification_retention_days,'verification_legal_hold',verification_legal_hold,
	'verification_observed_at',verification_observed_at,'verification_expires_at',verification_expires_at,
	'schema_version',schema_version,'created_at',created_at
)`

type RetentionPolicyQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// ReadObjectRetentionPolicy selects one tenant-owned policy, never tenant state
// or raw objects. The SQL byte guard prevents oversized metadata crossing the
// driver boundary; locking callers keep the row locked through receipt/audit.
func ReadObjectRetentionPolicy(ctx context.Context, query RetentionPolicyQueryer, tenantID, id string, forUpdate bool) (verificationdomain.ObjectRetentionPolicy, error) {
	var empty verificationdomain.ObjectRetentionPolicy
	if ctx == nil || query == nil || !validRetentionCoordinate(tenantID) || !validRetentionCoordinate(id) {
		return empty, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	lock := ""
	if forUpdate {
		lock = " FOR UPDATE"
	}
	sql := `SELECT CASE WHEN octet_length(body::text)<=$3 THEN body ELSE NULL END FROM (
		SELECT ` + ObjectRetentionPolicyJSONProjection + ` AS body FROM object_retention_policies WHERE tenant_id=$1 AND id=$2` + lock + `
	) selected`
	var body []byte
	err := query.QueryRow(ctx, sql, tenantID, id, verificationapp.MaxRetentionPolicyBytes).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, app.ErrNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("read object retention policy: %w", err)
	}
	if len(body) == 0 || len(body) > verificationapp.MaxRetentionPolicyBytes {
		return empty, app.ErrConflict
	}
	var policy domain.ObjectRetentionPolicy
	if err := json.Unmarshal(body, &policy); err != nil || policy.ID != id || policy.TenantID != tenantID {
		return empty, app.ErrConflict
	}
	return domain.ObjectRetentionPolicyToContextModel(policy), nil
}

func validRetentionCoordinate(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && len(value) <= 1024 && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func (r integrity) GetObjectRetentionPolicyForUpdate(ctx context.Context, tenantID, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	return ReadObjectRetentionPolicy(ctx, r.tx, tenantID, id, true)
}

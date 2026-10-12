package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

var _ verificationquery.SigningKeyReader = (*Store)(nil)

// PageSigningKeys selects only public lifecycle metadata. The encrypted
// private key is deliberately absent from the SELECT list.
func (s *Store) PageSigningKeys(ctx context.Context, request verificationquery.SigningKeyPageRequest) (appquery.Result[verificationdomain.SigningKey], error) {
	var empty appquery.Result[verificationdomain.SigningKey]
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" {
		return empty, verificationquery.ErrSigningKeyValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return empty, err
	}
	where, args, order, err := appendCreatedAtKeyset("k", []string{"k.tenant_id = $1"}, []any{request.TenantID}, request.Page, request.After)
	if err != nil {
		return empty, err
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT k.id, k.tenant_id, k.kid, k.version, k.provider,
		       k.algorithm, k.status, k.public_key, k.public_key_fingerprint,
		       k.valid_from, k.valid_until, k.created_at, k.revoked_at,
		       k.revocation_reason, k.revocation_semantics,
		       k.historical_validity_policy, k.compromised_at
		FROM signing_keys AS k
		WHERE %s
		ORDER BY %s LIMIT $%d`, joinAnd(where), order, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return empty, fmt.Errorf("page signing keys: %w", err)
	}
	defer rows.Close()
	items := make([]verificationdomain.SigningKey, 0, request.Page.PageSize+1)
	for rows.Next() {
		var key verificationdomain.SigningKey
		var status string
		var validUntil, revokedAt, compromisedAt sql.NullTime
		if err := rows.Scan(&key.ID, &key.TenantID, &key.KID, &key.Version,
			&key.Provider, &key.Algorithm, &status, &key.PublicKey,
			&key.PublicKeyFingerprint, &key.ValidFrom, &validUntil,
			&key.CreatedAt, &revokedAt, &key.RevocationReason,
			&key.RevocationSemantics, &key.HistoricalValidityPolicy,
			&compromisedAt); err != nil {
			return empty, fmt.Errorf("scan signing key page: %w", err)
		}
		key.Status, err = verificationdomain.ParseSigningKeyStatus(status)
		if err != nil {
			return empty, fmt.Errorf("invalid stored signing key status: %w", err)
		}
		key.ValidUntil = nullableSQLTime(validUntil)
		key.RevokedAt = nullableSQLTime(revokedAt)
		key.CompromisedAt = nullableSQLTime(compromisedAt)
		items = append(items, key)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("iterate signing key page: %w", err)
	}
	result := appquery.Result[verificationdomain.SigningKey]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1]
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}

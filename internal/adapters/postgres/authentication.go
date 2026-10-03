package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const (
	maxCredentialPrefixMatches = 64
	maxSessionGroups           = 256
	maxUserRoleBindings        = 256
	maxStoredAuthJSONBytes     = 1 << 20
)

var (
	_ identityapp.AuthenticationReader   = (*Store)(nil)
	_ identityapp.AuthenticationActivity = (*Store)(nil)
)

// APIKeysByPrefix returns bounded credential candidates. Secret comparison
// remains in the identity application service, not in the SQL adapter.
func (s *Store) APIKeysByPrefix(ctx context.Context, prefix string) ([]identitydomain.APIKey, error) {
	if s == nil || s.pool == nil || ctx == nil || prefix == "" || len(prefix) > 12 {
		return nil, identityapp.ErrValidation
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, prefix, hash, scopes, expires_at, revoked_at,
		       last_used_at, created_at
		FROM api_keys WHERE prefix = $1 AND revoked_at IS NULL
		ORDER BY id LIMIT 65`, prefix)
	if err != nil {
		return nil, fmt.Errorf("read API-key candidates: %w", err)
	}
	defer rows.Close()
	keys := make([]identitydomain.APIKey, 0)
	for rows.Next() {
		var key identitydomain.APIKey
		var scopes []byte
		var expiresAt, revokedAt, lastUsedAt sql.NullTime
		if err := rows.Scan(&key.ID, &key.TenantID, &key.Name, &key.Prefix, &key.Hash,
			&scopes, &expiresAt, &revokedAt, &lastUsedAt, &key.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan API-key candidate: %w", err)
		}
		if len(scopes) > maxStoredAuthJSONBytes {
			return nil, errors.New("oversized stored API-key scopes")
		}
		if err := json.Unmarshal(scopes, &key.Scopes); err != nil || len(key.Scopes) > maxSessionGroups {
			return nil, errors.New("invalid stored API-key scopes")
		}
		key.ExpiresAt = nullTimePtr(expiresAt)
		key.RevokedAt = nullTimePtr(revokedAt)
		key.LastUsedAt = nullTimePtr(lastUsedAt)
		keys = append(keys, key)
		if len(keys) > maxCredentialPrefixMatches {
			return nil, errors.New("too many API-key candidates")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read API-key candidates: %w", err)
	}
	return keys, nil
}

func (s *Store) SessionsByPrefix(ctx context.Context, prefix string) ([]identitydomain.SSOSession, error) {
	if s == nil || s.pool == nil || ctx == nil || prefix == "" || len(prefix) > 12 {
		return nil, identityapp.ErrValidation
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, user_id, provider_id, prefix, hash, groups,
		       expires_at, revoked_at, schema_version, created_at
		FROM sso_sessions WHERE prefix = $1 AND revoked_at IS NULL
		ORDER BY id LIMIT 65`, prefix)
	if err != nil {
		return nil, fmt.Errorf("read session candidates: %w", err)
	}
	defer rows.Close()
	sessions := make([]identitydomain.SSOSession, 0)
	for rows.Next() {
		var session identitydomain.SSOSession
		var groups []byte
		var revokedAt sql.NullTime
		if err := rows.Scan(&session.ID, &session.TenantID, &session.UserID, &session.ProviderID,
			&session.Prefix, &session.Hash, &groups, &session.ExpiresAt,
			&revokedAt, &session.SchemaVersion, &session.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan session candidate: %w", err)
		}
		if len(groups) > maxStoredAuthJSONBytes {
			return nil, errors.New("oversized stored session groups")
		}
		if err := json.Unmarshal(groups, &session.Groups); err != nil || len(session.Groups) > maxSessionGroups {
			return nil, errors.New("invalid stored session groups")
		}
		session.RevokedAt = nullTimePtr(revokedAt)
		sessions = append(sessions, session)
		if len(sessions) > maxCredentialPrefixMatches {
			return nil, errors.New("too many session candidates")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read session candidates: %w", err)
	}
	return sessions, nil
}

func (s *Store) CollectorByAPIKey(ctx context.Context, tenantID, keyID string) (identityapp.CollectorBinding, bool, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(keyID) == "" {
		return identityapp.CollectorBinding{}, false, identityapp.ErrValidation
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, api_key_id FROM collectors
		WHERE tenant_id = $1 AND api_key_id = $2 ORDER BY id LIMIT 2`, tenantID, keyID)
	if err != nil {
		return identityapp.CollectorBinding{}, false, fmt.Errorf("read collector binding: %w", err)
	}
	defer rows.Close()
	var binding identityapp.CollectorBinding
	count := 0
	for rows.Next() {
		count++
		if count > 1 {
			return identityapp.CollectorBinding{}, false, errors.New("multiple collector bindings for API key")
		}
		if err := rows.Scan(&binding.ID, &binding.TenantID, &binding.APIKeyID); err != nil {
			return identityapp.CollectorBinding{}, false, fmt.Errorf("scan collector binding: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return identityapp.CollectorBinding{}, false, fmt.Errorf("read collector binding: %w", err)
	}
	return binding, count == 1, nil
}

// SessionIdentity reads the user and both role-grant sources in one read-only
// snapshot. A foreign-tenant binding or provider cannot contribute a grant.
func (s *Store) SessionIdentity(ctx context.Context, session identitydomain.SSOSession) (identityapp.SessionIdentity, error) {
	if s == nil || s.pool == nil || ctx == nil || session.TenantID == "" || session.UserID == "" || session.ProviderID == "" {
		return identityapp.SessionIdentity{}, identityapp.ErrValidation
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return identityapp.SessionIdentity{}, fmt.Errorf("begin session identity read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var user identitydomain.HumanUser
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, email, status FROM human_users
		WHERE tenant_id = $1 AND id = $2`, session.TenantID, session.UserID).
		Scan(&user.ID, &user.TenantID, &user.Email, &user.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityapp.SessionIdentity{}, identityapp.ErrNotFound
	}
	if err != nil {
		return identityapp.SessionIdentity{}, fmt.Errorf("read session user: %w", err)
	}
	rows, err := tx.Query(ctx, `
		SELECT role, COALESCE(resource_type, ''), COALESCE(resource_id, '')
		FROM role_bindings
		WHERE tenant_id = $1 AND subject_type = 'user' AND subject_id = $2
		ORDER BY created_at, id LIMIT 257`, session.TenantID, session.UserID)
	if err != nil {
		return identityapp.SessionIdentity{}, fmt.Errorf("read user grants: %w", err)
	}
	grants := make([]identitydomain.ResourceGrant, 0)
	bindingCount := 0
	for rows.Next() {
		bindingCount++
		var role, resourceType, resourceID string
		if err := rows.Scan(&role, &resourceType, &resourceID); err != nil {
			rows.Close()
			return identityapp.SessionIdentity{}, fmt.Errorf("scan user grant: %w", err)
		}
		if bindingCount > maxUserRoleBindings {
			rows.Close()
			return identityapp.SessionIdentity{}, errors.New("too many user grants")
		}
		if scopes := identityapp.RoleScopes(role); len(scopes) > 0 {
			grants = append(grants, identitydomain.ResourceGrant{
				Role: role, ResourceType: resourceType, ResourceID: resourceID, Scopes: scopes,
			})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return identityapp.SessionIdentity{}, fmt.Errorf("read user grants: %w", err)
	}
	rows.Close()
	var providerTenantID, groupsClaim string
	var mappingJSON []byte
	err = tx.QueryRow(ctx, `
		SELECT tenant_id, COALESCE(groups_claim, ''), role_mapping
		FROM sso_providers WHERE tenant_id = $1 AND id = $2`, session.TenantID, session.ProviderID).
		Scan(&providerTenantID, &groupsClaim, &mappingJSON)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return identityapp.SessionIdentity{}, fmt.Errorf("read session provider: %w", err)
	}
	if err == nil {
		provider := identitydomain.SSOProvider{TenantID: providerTenantID, GroupsClaim: groupsClaim}
		if len(mappingJSON) > maxStoredAuthJSONBytes {
			return identityapp.SessionIdentity{}, errors.New("oversized stored provider group mapping")
		}
		if err := json.Unmarshal(mappingJSON, &provider.RoleMapping); err != nil {
			return identityapp.SessionIdentity{}, errors.New("invalid stored provider group mapping")
		}
		grants = append(grants, identityapp.ProviderGroupGrants(provider, session.Groups)...)
	}
	return identityapp.SessionIdentity{User: user, Grants: grants}, nil
}

// RecordAPIKeyUse applies the key and optional collector activity changes in
// one transaction, rechecking current revocation and ownership under SQL.
func (s *Store) RecordAPIKeyUse(ctx context.Context, key identitydomain.APIKey, collector identityapp.CollectorActivity) error {
	if s == nil || s.pool == nil || ctx == nil || key.ID == "" || key.TenantID == "" || key.Prefix == "" || key.Hash == "" || key.LastUsedAt == nil {
		return identityapp.ErrValidation
	}
	if collector.ID != "" && (collector.TenantID != key.TenantID || collector.LastSeenAt.IsZero()) {
		return identityapp.ErrUnauthorized
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin API-key activity: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `
		UPDATE api_keys SET last_used_at = CASE
			WHEN last_used_at IS NULL OR last_used_at < $5 THEN $5 ELSE last_used_at END
		WHERE id = $1 AND tenant_id = $2 AND prefix = $3 AND hash = $4
		  AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $5)`,
		key.ID, key.TenantID, key.Prefix, key.Hash, key.LastUsedAt.UTC())
	if err != nil {
		return fmt.Errorf("record API-key activity: %w", err)
	}
	if result.RowsAffected() != 1 {
		return identityapp.ErrUnauthorized
	}
	if collector.ID != "" {
		result, err = tx.Exec(ctx, `
			UPDATE collectors SET last_seen_at = CASE
				WHEN last_seen_at IS NULL OR last_seen_at < $4 THEN $4 ELSE last_seen_at END
			WHERE id = $1 AND tenant_id = $2 AND api_key_id = $3`,
			collector.ID, collector.TenantID, key.ID, collector.LastSeenAt.UTC())
		if err != nil {
			return fmt.Errorf("record collector activity: %w", err)
		}
		if result.RowsAffected() != 1 {
			return identityapp.ErrUnauthorized
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit API-key activity: %w", err)
	}
	return nil
}

func (s *Store) ValidateActiveSession(ctx context.Context, session identitydomain.SSOSession, now time.Time) error {
	if s == nil || s.pool == nil || ctx == nil || session.ID == "" || session.TenantID == "" || session.UserID == "" || session.ProviderID == "" || session.Prefix == "" || session.Hash == "" || now.IsZero() {
		return identityapp.ErrValidation
	}
	var active int
	err := s.pool.QueryRow(ctx, `
		SELECT 1 FROM sso_sessions AS session
		JOIN human_users AS user_record
		  ON user_record.id = session.user_id AND user_record.tenant_id = session.tenant_id
		WHERE session.id = $1 AND session.tenant_id = $2 AND session.user_id = $3
		  AND session.provider_id = $4 AND session.prefix = $5 AND session.hash = $6
		  AND session.revoked_at IS NULL AND session.expires_at > $7
		  AND user_record.status = 'active'`,
		session.ID, session.TenantID, session.UserID, session.ProviderID, session.Prefix, session.Hash, now).
		Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityapp.ErrUnauthorized
	}
	if err != nil {
		return fmt.Errorf("validate active session: %w", err)
	}
	return nil
}

func nullTimePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time.UTC()
	return &result
}

// Package repositories contains PostgreSQL implementations of the focused,
// transaction-scoped application persistence ports.
package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// New returns focused repositories bound to tx. The caller owns committing or
// rolling back tx; repositories never start independent transactions.
func New(tx pgx.Tx) app.Repositories {
	return app.Repositories{
		Identity:       identity{tx: tx},
		ReleaseCatalog: releaseCatalog{tx: tx},
		Evidence:       evidence{tx: tx},
		Decisions:      decisions{tx: tx},
		Audit:          audit{tx: tx},
		Idempotency:    idempotency{tx: tx},
		Outbox:         outbox{tx: tx},
		Controls:       controls{tx: tx},
		Governance:     governance{tx: tx},
		Builds:         builds{tx: tx},
		SupplyChain:    supplyChain{tx: tx},
		Source:         source{tx: tx},
		Deployments:    deployments{tx: tx},
		Packages:       packages{tx: tx},
		Signatures:     signatures{tx: tx},
		Integrity:      integrity{tx: tx},
		Verification:   verification{tx: tx},
	}
}

type identity struct{ tx pgx.Tx }

func (r identity) InsertTenant(ctx context.Context, tenant domain.Tenant) error {
	if tenant.ID == "" || tenant.Name == "" || tenant.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO tenants (id, name, created_at)
		VALUES ($1, $2, $3)
	`, tenant.ID, tenant.Name, tenant.CreatedAt)
	return writeError("insert tenant", err)
}

func (r identity) InsertAPIKey(ctx context.Context, key domain.APIKey) error {
	if key.ID == "" || key.TenantID == "" || key.Name == "" || key.Prefix == "" || key.Hash == "" || key.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, key.TenantID); err != nil {
		return err
	}
	scopes, err := json.Marshal(key.Scopes)
	if err != nil {
		return fmt.Errorf("encode API key scopes: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO api_keys (
			id, tenant_id, name, prefix, hash, scopes, expires_at,
			revoked_at, last_used_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, key.ID, key.TenantID, key.Name, key.Prefix, key.Hash, scopes, key.ExpiresAt, key.RevokedAt, key.LastUsedAt, key.CreatedAt)
	return writeError("insert API key", err)
}

func (r identity) UpdateAPIKeyLastUsed(ctx context.Context, key domain.APIKey) error {
	if key.ID == "" || key.TenantID == "" || key.Prefix == "" || key.Hash == "" || key.LastUsedAt == nil {
		return app.ErrValidation
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE api_keys
		SET last_used_at = $5
		WHERE id = $1 AND tenant_id = $2 AND prefix = $3 AND hash = $4
		  AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $5)
	`, key.ID, key.TenantID, key.Prefix, key.Hash, *key.LastUsedAt)
	if err != nil {
		return writeError("update API key last used", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r identity) UpdateCollectorLastSeen(ctx context.Context, collector domain.Collector) error {
	if collector.ID == "" || collector.TenantID == "" || collector.APIKeyID == "" || collector.LastSeenAt == nil {
		return app.ErrValidation
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE collectors
		SET last_seen_at = $4
		WHERE id = $1 AND tenant_id = $2 AND api_key_id = $3
	`, collector.ID, collector.TenantID, collector.APIKeyID, *collector.LastSeenAt)
	if err != nil {
		return writeError("update collector last seen", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r identity) InsertOrganization(ctx context.Context, organization domain.Organization) error {
	if organization.ID == "" || organization.TenantID == "" || organization.Name == "" || organization.Slug == "" || organization.Status == "" || organization.SchemaVersion == "" || organization.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, organization.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO organizations (id, tenant_id, name, slug, status, schema_version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, organization.ID, organization.TenantID, organization.Name, organization.Slug, organization.Status, organization.SchemaVersion, organization.CreatedAt)
	return writeError("insert organization", err)
}

func (r identity) InsertHumanUser(ctx context.Context, user domain.HumanUser) error {
	if user.ID == "" || user.TenantID == "" || user.Email == "" || user.DisplayName == "" || user.Status == "" || user.SchemaVersion == "" || user.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, user.TenantID); err != nil {
		return err
	}
	if err := requireOptionalOrganization(ctx, r.tx, user.TenantID, user.OrganizationID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO human_users (
			id, tenant_id, organization_id, email, display_name, status,
			deactivated_at, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, user.ID, user.TenantID, nullableString(user.OrganizationID), user.Email, user.DisplayName, user.Status, user.DeactivatedAt, user.SchemaVersion, user.CreatedAt)
	return writeError("insert human user", err)
}

func (r identity) DeactivateHumanUser(ctx context.Context, user domain.HumanUser) error {
	if user.ID == "" || user.TenantID == "" || user.Status != "deactivated" || user.DeactivatedAt == nil {
		return app.ErrValidation
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE human_users
		SET status = 'deactivated', deactivated_at = $3
		WHERE id = $1 AND tenant_id = $2 AND status = 'active'
	`, user.ID, user.TenantID, *user.DeactivatedAt)
	if err != nil {
		return writeError("deactivate human user", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r identity) InsertRoleBinding(ctx context.Context, binding domain.RoleBinding) error {
	if binding.ID == "" || binding.TenantID == "" || binding.SubjectType == "" || binding.SubjectID == "" || binding.Role == "" || binding.SchemaVersion == "" || binding.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, binding.TenantID); err != nil {
		return err
	}
	if err := requireRoleSubject(ctx, r.tx, binding.TenantID, binding.SubjectType, binding.SubjectID); err != nil {
		return err
	}
	if err := requireRoleResource(ctx, r.tx, binding.TenantID, binding.ResourceType, binding.ResourceID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO role_bindings (
			id, tenant_id, subject_type, subject_id, role, resource_type,
			resource_id, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, binding.ID, binding.TenantID, binding.SubjectType, binding.SubjectID, binding.Role, nullableString(binding.ResourceType), nullableString(binding.ResourceID), binding.SchemaVersion, binding.CreatedAt)
	return writeError("insert role binding", err)
}

func (r identity) InsertSSOProvider(ctx context.Context, provider domain.SSOProvider) error {
	if provider.ID == "" || provider.TenantID == "" || provider.Name == "" || provider.Type == "" || provider.Issuer == "" || provider.ClientID == "" || provider.Status == "" || provider.SchemaVersion == "" || provider.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, provider.TenantID); err != nil {
		return err
	}
	roleMapping, err := json.Marshal(provider.RoleMapping)
	if err != nil {
		return fmt.Errorf("encode SSO provider role mapping: %w", err)
	}
	jwks, err := json.Marshal(provider.JWKS)
	if err != nil {
		return fmt.Errorf("encode SSO provider JWKS: %w", err)
	}
	certificates, err := json.Marshal(provider.SAMLSigningCertificates)
	if err != nil {
		return fmt.Errorf("encode SSO provider certificates: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO sso_providers (
			id, tenant_id, name, type, issuer, client_id, groups_claim,
			role_mapping, jwks, saml_signing_certificates, trust_material_updated_at,
			status, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`, provider.ID, provider.TenantID, provider.Name, provider.Type, provider.Issuer, provider.ClientID, nullableString(provider.GroupsClaim), roleMapping, jwks, certificates, provider.TrustMaterialUpdatedAt, provider.Status, provider.SchemaVersion, provider.CreatedAt)
	return writeError("insert SSO provider", err)
}

func (r identity) UpdateSSOProviderTrustMaterial(ctx context.Context, provider domain.SSOProvider) error {
	if provider.ID == "" || provider.TenantID == "" || provider.Type == "" || provider.TrustMaterialUpdatedAt == nil {
		return app.ErrValidation
	}
	jwks, err := json.Marshal(provider.JWKS)
	if err != nil {
		return fmt.Errorf("encode SSO provider JWKS: %w", err)
	}
	certificates, err := json.Marshal(provider.SAMLSigningCertificates)
	if err != nil {
		return fmt.Errorf("encode SSO provider certificates: %w", err)
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE sso_providers
		SET jwks = $3, saml_signing_certificates = $4, trust_material_updated_at = $5
		WHERE id = $1 AND tenant_id = $2 AND type = $6
	`, provider.ID, provider.TenantID, jwks, certificates, *provider.TrustMaterialUpdatedAt, provider.Type)
	if err != nil {
		return writeError("update SSO provider trust material", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r identity) InsertUserIdentityLink(ctx context.Context, link domain.UserIdentityLink) error {
	if link.ID == "" || link.TenantID == "" || link.UserID == "" || link.ProviderID == "" || link.Subject == "" || link.Email == "" || !link.Verified || link.SchemaVersion == "" || link.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedHumanUser(ctx, r.tx, link.TenantID, link.UserID); err != nil {
		return err
	}
	if err := requireOwnedSSOProvider(ctx, r.tx, link.TenantID, link.ProviderID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO user_identity_links (
			id, tenant_id, user_id, provider_id, subject, email, verified,
			schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, link.ID, link.TenantID, link.UserID, link.ProviderID, link.Subject, link.Email, link.Verified, link.SchemaVersion, link.CreatedAt)
	return writeError("insert user identity link", err)
}

func (r identity) InsertProviderVerification(ctx context.Context, verification domain.ProviderVerification) error {
	if verification.ID == "" || verification.TenantID == "" || verification.ProviderType == "" || verification.ProviderID == "" || verification.Subject == "" || verification.Result == "" || verification.SchemaVersion == "" || verification.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedSSOProvider(ctx, r.tx, verification.TenantID, verification.ProviderID); err != nil {
		return err
	}
	checks, err := json.Marshal(verification.Checks)
	if err != nil {
		return fmt.Errorf("encode provider verification checks: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO provider_verifications (
			id, tenant_id, provider_type, provider_id, subject, result, checks,
			limitations, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, verification.ID, verification.TenantID, verification.ProviderType, verification.ProviderID, verification.Subject, verification.Result, checks, textArray(verification.Limitations), verification.SchemaVersion, verification.CreatedAt)
	return writeError("insert provider verification", err)
}

func (r identity) InsertSSOSession(ctx context.Context, session domain.SSOSession) error {
	if session.ID == "" || session.TenantID == "" || session.UserID == "" || session.ProviderID == "" || session.Prefix == "" || session.Hash == "" || session.ExpiresAt.IsZero() || session.SchemaVersion == "" || session.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedActiveHumanUser(ctx, r.tx, session.TenantID, session.UserID); err != nil {
		return err
	}
	if err := requireOwnedSSOProvider(ctx, r.tx, session.TenantID, session.ProviderID); err != nil {
		return err
	}
	groups, err := json.Marshal(session.Groups)
	if err != nil {
		return fmt.Errorf("encode SSO session groups: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO sso_sessions (
			id, tenant_id, user_id, provider_id, prefix, hash, groups, expires_at,
			revoked_at, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, session.ID, session.TenantID, session.UserID, session.ProviderID, session.Prefix, session.Hash, groups, session.ExpiresAt, session.RevokedAt, session.SchemaVersion, session.CreatedAt)
	return writeError("insert SSO session", err)
}

func (r identity) ValidateActiveSSOSession(ctx context.Context, session domain.SSOSession, now time.Time) error {
	if session.ID == "" || session.TenantID == "" || session.UserID == "" || session.ProviderID == "" || session.Prefix == "" || session.Hash == "" || now.IsZero() {
		return app.ErrValidation
	}
	err := requireRow(ctx, r.tx, `
		SELECT 1
		FROM sso_sessions AS session
		JOIN human_users AS user_record
		  ON user_record.id = session.user_id AND user_record.tenant_id = session.tenant_id
		WHERE session.id = $1 AND session.tenant_id = $2 AND session.user_id = $3
		  AND session.provider_id = $4 AND session.prefix = $5 AND session.hash = $6
		  AND session.revoked_at IS NULL AND session.expires_at > $7
		  AND user_record.status = 'active'
	`, session.ID, session.TenantID, session.UserID, session.ProviderID, session.Prefix, session.Hash, now)
	if errors.Is(err, app.ErrNotFound) {
		return app.ErrUnauthorized
	}
	return err
}

func (r identity) RevokeSSOSession(ctx context.Context, session domain.SSOSession) error {
	if session.ID == "" || session.TenantID == "" || session.UserID == "" || session.ProviderID == "" || session.Prefix == "" || session.Hash == "" || session.RevokedAt == nil {
		return app.ErrValidation
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE sso_sessions
		SET revoked_at = $7
		WHERE id = $1 AND tenant_id = $2 AND user_id = $3 AND provider_id = $4
		  AND prefix = $5 AND hash = $6 AND revoked_at IS NULL
	`, session.ID, session.TenantID, session.UserID, session.ProviderID, session.Prefix, session.Hash, *session.RevokedAt)
	if err != nil {
		return writeError("revoke SSO session", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r identity) InsertCustomerPortalAccess(ctx context.Context, access domain.CustomerPortalAccess) error {
	if access.ID == "" || access.TenantID == "" || access.PackageID == "" || access.CustomerName == "" || access.Prefix == "" || access.Hash == "" || access.ExpiresAt.IsZero() || access.SchemaVersion == "" || access.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, access.TenantID); err != nil {
		return err
	}
	if err := requireOwnedCustomerPackage(ctx, r.tx, access.TenantID, access.PackageID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO customer_portal_access (
			id, tenant_id, package_id, customer_name, reviewer_name, reviewer_email,
			prefix, hash, expires_at, revoked_at, access_count, failed_access_count,
			last_accessed_at, last_failed_at, require_nda, nda_accepted_at,
			nda_accepted_by, watermark, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	`, access.ID, access.TenantID, access.PackageID, access.CustomerName, nullableString(access.ReviewerName), nullableString(access.ReviewerEmail), access.Prefix, access.Hash, access.ExpiresAt, access.RevokedAt, access.AccessCount, access.FailedAccessCount, access.LastAccessedAt, access.LastFailedAt, access.RequireNDA, access.NDAAcceptedAt, nullableString(access.NDAAcceptedBy), nullableString(access.Watermark), access.SchemaVersion, access.CreatedAt)
	return writeError("insert customer portal access", err)
}

func (r identity) UpdateCustomerPortalAccess(ctx context.Context, previous, current domain.CustomerPortalAccess) error {
	if current.ID == "" || current.TenantID == "" || current.Prefix == "" || current.Hash == "" || previous.ID != current.ID || previous.TenantID != current.TenantID || previous.Prefix != current.Prefix || previous.Hash != current.Hash {
		return app.ErrValidation
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE customer_portal_access
		SET revoked_at = $3, access_count = $4, failed_access_count = $5,
			last_accessed_at = $6, last_failed_at = $7, require_nda = $8,
			nda_accepted_at = $9, nda_accepted_by = $10, watermark = $11
		WHERE id = $1 AND tenant_id = $2 AND prefix = $12 AND hash = $13
		  AND access_count = $14 AND failed_access_count = $15
		  AND revoked_at IS NOT DISTINCT FROM $16
	`, current.ID, current.TenantID, current.RevokedAt, current.AccessCount, current.FailedAccessCount, current.LastAccessedAt, current.LastFailedAt, current.RequireNDA, current.NDAAcceptedAt, nullableString(current.NDAAcceptedBy), nullableString(current.Watermark), current.Prefix, current.Hash, previous.AccessCount, previous.FailedAccessCount, previous.RevokedAt)
	if err != nil {
		return writeError("update customer portal access", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

type releaseCatalog struct{ tx pgx.Tx }

func (r releaseCatalog) InsertProduct(ctx context.Context, product domain.Product) error {
	if product.ID == "" || product.TenantID == "" || product.Name == "" || product.Slug == "" || product.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, product.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO products (id, tenant_id, name, slug, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, product.ID, product.TenantID, product.Name, product.Slug, product.CreatedAt)
	return writeError("insert product", err)
}

func (r releaseCatalog) InsertProject(ctx context.Context, project domain.Project) error {
	if project.ID == "" || project.TenantID == "" || project.ProductID == "" || project.Name == "" || project.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, project.TenantID); err != nil {
		return err
	}
	result, err := r.tx.Exec(ctx, `
		INSERT INTO projects (id, tenant_id, product_id, name, created_at)
		SELECT $1, $2, product.id, $4, $5
		FROM products product
		WHERE product.id = $3 AND product.tenant_id = $2
	`, project.ID, project.TenantID, project.ProductID, project.Name, project.CreatedAt)
	if err != nil {
		return writeError("insert project", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrNotFound
	}
	return nil
}

func (r releaseCatalog) InsertRelease(ctx context.Context, release domain.Release) error {
	if release.ID == "" || release.TenantID == "" || release.ProductID == "" || release.Version == "" || release.State == "" || release.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, release.TenantID); err != nil {
		return err
	}
	result, err := r.tx.Exec(ctx, `
		INSERT INTO releases (id, tenant_id, product_id, version, state, frozen_at, approved_at, created_at)
		SELECT $1, $2, product.id, $4, $5, $6, $7, $8
		FROM products product
		WHERE product.id = $3 AND product.tenant_id = $2
	`, release.ID, release.TenantID, release.ProductID, release.Version, release.State, release.FrozenAt, release.ApprovedAt, release.CreatedAt)
	if err != nil {
		return writeError("insert release", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrNotFound
	}
	return nil
}

func (r releaseCatalog) UpdateReleaseState(ctx context.Context, release domain.Release, expectedState string) error {
	if release.ID == "" || release.TenantID == "" || release.ProductID == "" || release.State == "" || expectedState == "" {
		return app.ErrValidation
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE releases
		SET state = $4, frozen_at = $5, approved_at = $6
		WHERE id = $1 AND tenant_id = $2 AND product_id = $3 AND state = $7
	`, release.ID, release.TenantID, release.ProductID, release.State, release.FrozenAt, release.ApprovedAt, expectedState)
	if err != nil {
		return writeError("update release state", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r releaseCatalog) InsertArtifact(ctx context.Context, artifact domain.Artifact) error {
	if artifact.ID == "" || artifact.TenantID == "" || artifact.Name == "" || artifact.MediaType == "" || artifact.Digest == "" || artifact.Size < 0 || artifact.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, artifact.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO artifacts (id, tenant_id, name, media_type, size, digest, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, artifact.ID, artifact.TenantID, artifact.Name, artifact.MediaType, artifact.Size, artifact.Digest, artifact.CreatedAt)
	return writeError("insert artifact", err)
}

func (r releaseCatalog) InsertReleaseCandidate(ctx context.Context, candidate domain.ReleaseCandidate) error {
	if candidate.ID == "" || candidate.TenantID == "" || candidate.ReleaseID == "" || candidate.Name == "" || candidate.State == "" || candidate.SnapshotHash == "" || candidate.SchemaVersion == "" || candidate.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOptionalRelease(ctx, r.tx, candidate.TenantID, candidate.ReleaseID); err != nil {
		return err
	}
	document, err := json.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("encode release candidate document: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO release_candidates (id, tenant_id, release_id, name, state, snapshot_hash, document, schema_version, created_at, promoted_at, rejected_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, candidate.ID, candidate.TenantID, candidate.ReleaseID, candidate.Name, candidate.State, candidate.SnapshotHash, document, candidate.SchemaVersion, candidate.CreatedAt, candidate.PromotedAt, candidate.RejectedAt)
	return writeError("insert release candidate", err)
}

func (r releaseCatalog) UpdateReleaseCandidateState(ctx context.Context, candidate domain.ReleaseCandidate, expectedState string) error {
	if candidate.ID == "" || candidate.TenantID == "" || candidate.ReleaseID == "" || candidate.State == "" || expectedState == "" {
		return app.ErrValidation
	}
	document, err := json.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("encode release candidate document: %w", err)
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE release_candidates
		SET state = $4, document = $5, promoted_at = $6, rejected_at = $7
		WHERE id = $1 AND tenant_id = $2 AND release_id = $3 AND state = $8
	`, candidate.ID, candidate.TenantID, candidate.ReleaseID, candidate.State, document, candidate.PromotedAt, candidate.RejectedAt, expectedState)
	if err != nil {
		return writeError("update release candidate state", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

type evidence struct{ tx pgx.Tx }

func (r evidence) InsertEvidence(ctx context.Context, item domain.EvidenceItem) error {
	if item.ID == "" || item.TenantID == "" || item.Type == "" || item.Title == "" || item.SourceSystem == "" || item.PayloadHash == "" || item.CanonicalHash == "" || item.Canonicalization == "" || item.TrustLevel == "" || item.VerificationStatus == "" || item.ObservedAt.IsZero() || item.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, item.TenantID); err != nil {
		return err
	}
	if err := requireOptionalProduct(ctx, r.tx, item.TenantID, item.ProductID); err != nil {
		return err
	}
	if err := requireOptionalProject(ctx, r.tx, item.TenantID, item.ProjectID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, item.TenantID, item.ReleaseID); err != nil {
		return err
	}
	sourceIdentity, err := json.Marshal(item.SourceIdentity)
	if err != nil {
		return fmt.Errorf("encode evidence source identity: %w", err)
	}
	subjectRefs, err := json.Marshal(item.SubjectRefs)
	if err != nil {
		return fmt.Errorf("encode evidence subject refs: %w", err)
	}
	relatedRefs, err := json.Marshal(item.RelatedEvidenceRefs)
	if err != nil {
		return fmt.Errorf("encode evidence related references: %w", err)
	}
	signatureRefs, err := json.Marshal(item.SignatureRefs)
	if err != nil {
		return fmt.Errorf("encode evidence signature references: %w", err)
	}
	tags, err := json.Marshal(item.Tags)
	if err != nil {
		return fmt.Errorf("encode evidence tags: %w", err)
	}
	metadata, err := json.Marshal(item.Metadata)
	if err != nil {
		return fmt.Errorf("encode evidence metadata: %w", err)
	}
	warnings, err := json.Marshal(item.Warnings)
	if err != nil {
		return fmt.Errorf("encode evidence warnings: %w", err)
	}
	limitations, err := json.Marshal(item.Limitations)
	if err != nil {
		return fmt.Errorf("encode evidence limitations: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO evidence_items (
			id, tenant_id, product_id, project_id, release_id, build_id, deployment_id,
			type, subtype, title, source_system, source_identity, collector_id,
			uploaded_by, observed_at, evidence_version, schema_version, payload_ref,
			payload_hash, payload_media_type, payload_size, canonical_hash,
			canonicalization, subject_refs, related_evidence_refs, supersedes,
			superseded_by, trust_level, verification_status, signature_refs,
			chain_entry_id, tags, metadata, warnings, limitations, created_at
		)
		VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13,
			$14, $15, $16, $17, $18,
			$19, $20, $21, $22,
			$23, $24, $25, $26,
			$27, $28, $29, $30,
			$31, $32, $33, $34, $35, $36
		)
	`, item.ID, item.TenantID, nullableString(item.ProductID), nullableString(item.ProjectID), nullableString(item.ReleaseID), nullableString(item.BuildID), nullableString(item.DeploymentID),
		item.Type, nullableString(item.Subtype), item.Title, item.SourceSystem, sourceIdentity, nullableString(item.CollectorID),
		nullableString(item.UploadedBy), item.ObservedAt, nonZeroInt(item.EvidenceVersion, 1), item.SchemaVersion, nullableString(item.PayloadRef),
		item.PayloadHash, nullableString(item.PayloadMediaType), nullableInt64(item.PayloadSize), item.CanonicalHash,
		item.Canonicalization, subjectRefs, relatedRefs, nullableString(item.Supersedes),
		nullableString(item.SupersededBy), item.TrustLevel, item.VerificationStatus, signatureRefs,
		nullableString(item.ChainEntryID), tags, metadata, warnings, limitations, item.CreatedAt)
	return writeError("insert evidence", err)
}

func (r evidence) UpdateEvidenceLinks(ctx context.Context, item domain.EvidenceItem) error {
	if item.ID == "" || item.TenantID == "" {
		return app.ErrValidation
	}
	if err := requireOptionalProduct(ctx, r.tx, item.TenantID, item.ProductID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, item.TenantID, item.ReleaseID); err != nil {
		return err
	}
	relatedRefs, err := json.Marshal(item.RelatedEvidenceRefs)
	if err != nil {
		return fmt.Errorf("encode evidence related references: %w", err)
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE evidence_items
		SET product_id = $3, release_id = $4, related_evidence_refs = $5
		WHERE id = $1 AND tenant_id = $2
	`, item.ID, item.TenantID, nullableString(item.ProductID), nullableString(item.ReleaseID), relatedRefs)
	if err != nil {
		return writeError("update evidence links", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrNotFound
	}
	return nil
}

func (r evidence) RecordSupersession(ctx context.Context, superseded, replacement domain.EvidenceItem) error {
	if superseded.ID == "" || superseded.TenantID == "" || replacement.ID == "" || superseded.TenantID != replacement.TenantID || superseded.SupersededBy != replacement.ID || replacement.Supersedes != superseded.ID {
		return app.ErrValidation
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE evidence_items
		SET superseded_by = $3
		WHERE id = $1 AND tenant_id = $2 AND superseded_by IS NULL
	`, superseded.ID, superseded.TenantID, replacement.ID)
	if err != nil {
		return writeError("record evidence supersession", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	result, err = r.tx.Exec(ctx, `
		UPDATE evidence_items
		SET supersedes = $1
		WHERE id = $3 AND tenant_id = $2 AND supersedes IS NULL
	`, superseded.ID, superseded.TenantID, replacement.ID)
	if err != nil {
		return writeError("record replacement evidence", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r evidence) AppendLifecycle(ctx context.Context, event domain.EvidenceLifecycleEvent) error {
	if event.ID == "" || event.TenantID == "" || event.EvidenceID == "" || event.Action == "" || event.Reason == "" || event.ActorID == "" || event.SchemaVersion == "" || event.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedEvidence(ctx, r.tx, event.TenantID, event.EvidenceID); err != nil {
		return err
	}
	details, err := json.Marshal(event.Details)
	if err != nil {
		return fmt.Errorf("encode evidence lifecycle details: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO evidence_lifecycle_events (
			id, tenant_id, evidence_id, action, reason, details, replacement_id,
			actor_id, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, event.ID, event.TenantID, event.EvidenceID, event.Action, event.Reason, details, nullableString(event.ReplacementID), event.ActorID, event.SchemaVersion, event.CreatedAt)
	return writeError("append evidence lifecycle event", err)
}

func (r evidence) InsertSBOM(ctx context.Context, sbom domain.SBOM) error {
	if sbom.ID == "" || sbom.TenantID == "" || sbom.EvidenceID == "" || sbom.Format == "" || sbom.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedEvidence(ctx, r.tx, sbom.TenantID, sbom.EvidenceID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, sbom.TenantID, sbom.ReleaseID); err != nil {
		return err
	}
	if err := requireOptionalArtifact(ctx, r.tx, sbom.TenantID, sbom.ArtifactID); err != nil {
		return err
	}
	components, err := json.Marshal(sbom.Components)
	if err != nil {
		return fmt.Errorf("encode SBOM components: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO sboms (id, tenant_id, evidence_id, release_id, artifact_id, format, spec_version, component_count, components, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, sbom.ID, sbom.TenantID, sbom.EvidenceID, nullableString(sbom.ReleaseID), nullableString(sbom.ArtifactID), sbom.Format, sbom.SpecVersion, sbom.ComponentCount, components, sbom.CreatedAt)
	return writeError("insert SBOM", err)
}

func (r evidence) InsertVulnerabilityScan(ctx context.Context, scan domain.VulnerabilityScan) error {
	if scan.ID == "" || scan.TenantID == "" || scan.EvidenceID == "" || scan.Scanner == "" || scan.TargetRef == "" || scan.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedEvidence(ctx, r.tx, scan.TenantID, scan.EvidenceID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, scan.TenantID, scan.ReleaseID); err != nil {
		return err
	}
	summary, err := json.Marshal(scan.Summary)
	if err != nil {
		return fmt.Errorf("encode vulnerability scan summary: %w", err)
	}
	findings, err := json.Marshal(scan.Findings)
	if err != nil {
		return fmt.Errorf("encode vulnerability scan findings: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO vulnerability_scans (id, tenant_id, evidence_id, release_id, scanner, target_ref, summary, findings, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, scan.ID, scan.TenantID, scan.EvidenceID, nullableString(scan.ReleaseID), scan.Scanner, scan.TargetRef, summary, findings, scan.CreatedAt)
	return writeError("insert vulnerability scan", err)
}

func (r evidence) InsertOpenAPIContract(ctx context.Context, contract domain.OpenAPIContract) error {
	if contract.ID == "" || contract.TenantID == "" || contract.ProductID == "" || contract.EvidenceID == "" || contract.Version == "" || contract.Hash == "" || contract.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOptionalProduct(ctx, r.tx, contract.TenantID, contract.ProductID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, contract.TenantID, contract.ReleaseID); err != nil {
		return err
	}
	if err := requireOwnedEvidence(ctx, r.tx, contract.TenantID, contract.EvidenceID); err != nil {
		return err
	}
	operations, err := json.Marshal(contract.Operations)
	if err != nil {
		return fmt.Errorf("encode OpenAPI operations: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO openapi_contracts (id, tenant_id, product_id, release_id, version, hash, path_count, operations, evidence_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, contract.ID, contract.TenantID, contract.ProductID, nullableString(contract.ReleaseID), contract.Version, contract.Hash, contract.PathCount, operations, contract.EvidenceID, contract.CreatedAt)
	return writeError("insert OpenAPI contract", err)
}

func (r evidence) InsertVEXDocument(ctx context.Context, document domain.VEXDocument) error {
	if document.ID == "" || document.TenantID == "" || document.EvidenceID == "" || document.ReleaseID == "" || document.Format == "" || document.SchemaVersion == "" || document.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedEvidence(ctx, r.tx, document.TenantID, document.EvidenceID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, document.TenantID, document.ReleaseID); err != nil {
		return err
	}
	if err := requireOptionalArtifact(ctx, r.tx, document.TenantID, document.ArtifactID); err != nil {
		return err
	}
	statusSummary, err := json.Marshal(document.StatusSummary)
	if err != nil {
		return fmt.Errorf("encode VEX status summary: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO vex_documents (id, tenant_id, evidence_id, release_id, artifact_id, format, author, version, statement_count, status_summary, schema_version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, document.ID, document.TenantID, document.EvidenceID, document.ReleaseID, nullableString(document.ArtifactID), document.Format, document.Author, nullableString(document.Version), document.StatementCount, statusSummary, document.SchemaVersion, document.CreatedAt)
	return writeError("insert VEX document", err)
}

func (r evidence) InsertVEXImportReport(ctx context.Context, report domain.VEXImportReport) error {
	if report.ID == "" || report.TenantID == "" || report.VEXDocumentID == "" || report.EvidenceID == "" || report.ParserVersion == "" || report.Status == "" || report.SchemaVersion == "" || report.CreatedAt.IsZero() || report.UpdatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedVEXDocument(ctx, r.tx, report.TenantID, report.VEXDocumentID); err != nil {
		return err
	}
	if err := requireOwnedEvidence(ctx, r.tx, report.TenantID, report.EvidenceID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, report.TenantID, report.ReleaseID); err != nil {
		return err
	}
	if err := requireOptionalArtifact(ctx, r.tx, report.TenantID, report.ArtifactID); err != nil {
		return err
	}
	warnings, err := json.Marshal(report.Warnings)
	if err != nil {
		return fmt.Errorf("encode VEX import warnings: %w", err)
	}
	invalidStatements, err := json.Marshal(report.InvalidStatements)
	if err != nil {
		return fmt.Errorf("encode VEX invalid statements: %w", err)
	}
	mappingFailures, err := json.Marshal(report.MappingFailures)
	if err != nil {
		return fmt.Errorf("encode VEX mapping failures: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO vex_import_reports (
			id, tenant_id, vex_document_id, evidence_id, release_id, artifact_id,
			parser_version, status, statement_count, decisions_created, decisions_superseded,
			unsupported_fields, warnings, invalid_statements, mapping_failures, failure_code,
			failure_detail, schema_version, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	`, report.ID, report.TenantID, report.VEXDocumentID, report.EvidenceID, nullableString(report.ReleaseID), nullableString(report.ArtifactID), report.ParserVersion, report.Status, report.StatementCount, report.DecisionsCreated, report.DecisionsSuperseded, textArray(report.UnsupportedFields), warnings, invalidStatements, mappingFailures, report.FailureCode, report.FailureDetail, report.SchemaVersion, report.CreatedAt, report.UpdatedAt)
	return writeError("insert VEX import report", err)
}

type decisions struct{ tx pgx.Tx }

func (r decisions) InsertVulnerabilityDecision(ctx context.Context, decision domain.VulnerabilityDecision) error {
	if decision.ID == "" || decision.TenantID == "" || decision.FindingID == "" || decision.ScanID == "" || decision.Vulnerability == "" || decision.Status == "" || decision.Justification == "" || decision.Source == "" || decision.SchemaVersion == "" || decision.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, decision.TenantID); err != nil {
		return err
	}
	if err := requireOwnedScan(ctx, r.tx, decision.TenantID, decision.ScanID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, decision.TenantID, decision.ReleaseID); err != nil {
		return err
	}
	if err := requireOptionalOwnedEvidence(ctx, r.tx, decision.TenantID, decision.EvidenceID); err != nil {
		return err
	}
	supportingRefs := decision.SupportingRefs
	if supportingRefs == nil {
		supportingRefs = []domain.SubjectRef{}
	}
	supportingRefsJSON, err := json.Marshal(supportingRefs)
	if err != nil {
		return fmt.Errorf("encode vulnerability decision supporting references: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO vulnerability_decisions (
			id, tenant_id, finding_id, scan_id, release_id, vulnerability,
			component, sbom_id, sbom_component_purl, sbom_component_name,
			status, justification, impact_statement, action_statement,
			customer_visible, internal_notes, source, evidence_id, evidence_ids, supporting_refs, vex_document_id,
			supersedes, superseded_by, approved_by, reviewed_at, review_due_at, schema_version, created_at
		)
		VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14,
			$15, $16, $17, $18, $19, $20,
			$21, $22, $23, $24, $25, $26, $27, $28
		)
	`, decision.ID, decision.TenantID, decision.FindingID, decision.ScanID, nullableString(decision.ReleaseID), decision.Vulnerability,
		nullableString(decision.Component), nullableString(decision.SBOMID), nullableString(decision.SBOMComponentPURL), nullableString(decision.SBOMComponentName),
		decision.Status, decision.Justification, nullableString(decision.ImpactStatement), nullableString(decision.ActionStatement),
		decision.CustomerVisible, nullableString(decision.InternalNotes), decision.Source, nullableString(decision.EvidenceID), textArray(decision.EvidenceIDs), supportingRefsJSON, nullableString(decision.VEXDocumentID), nullableString(decision.Supersedes), nullableString(decision.SupersededBy),
		nullableString(decision.ApprovedBy), decision.ReviewedAt, decision.ReviewDueAt, decision.SchemaVersion, decision.CreatedAt)
	return writeError("insert vulnerability decision", err)
}

func (r decisions) SupersedeAndInsert(ctx context.Context, decision domain.VulnerabilityDecision, superseded []domain.VulnerabilityDecision) error {
	for _, prior := range superseded {
		if prior.ID == "" || prior.TenantID != decision.TenantID || prior.SupersededBy != decision.ID {
			return app.ErrValidation
		}
		result, err := r.tx.Exec(ctx, `
			UPDATE vulnerability_decisions
			SET superseded_by = $3
			WHERE id = $1 AND tenant_id = $2 AND superseded_by IS NULL
		`, prior.ID, prior.TenantID, decision.ID)
		if err != nil {
			return writeError("supersede vulnerability decision", err)
		}
		if result.RowsAffected() != 1 {
			return app.ErrConflict
		}
	}
	return r.InsertVulnerabilityDecision(ctx, decision)
}

func (r decisions) InsertException(ctx context.Context, exception domain.Exception) error {
	if exception.ID == "" || exception.TenantID == "" || exception.ReleaseID == "" || exception.Reason == "" || exception.Owner == "" || !exception.ExpiresAt.After(exception.CreatedAt) || exception.CreatedAt.IsZero() || exception.Approved || exception.ApprovedBy != "" || exception.ApprovedAt != nil {
		return app.ErrValidation
	}
	if err := requireOptionalRelease(ctx, r.tx, exception.TenantID, exception.ReleaseID); err != nil {
		return err
	}
	if exception.ControlID != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM security_controls WHERE id = $1 AND tenant_id = $2`, exception.ControlID, exception.TenantID); err != nil {
			return err
		}
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO exceptions (
			id, tenant_id, release_id, finding_id, control_id, reason, owner,
			expires_at, approved, approved_by, approved_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false, NULL, NULL, $9)
	`, exception.ID, exception.TenantID, exception.ReleaseID, nullableString(exception.FindingID), nullableString(exception.ControlID), exception.Reason, exception.Owner, exception.ExpiresAt, exception.CreatedAt)
	return writeError("insert exception", err)
}

func (r decisions) ApproveException(ctx context.Context, exception domain.Exception) error {
	if exception.ID == "" || exception.TenantID == "" || !exception.Approved || exception.ApprovedBy == "" || exception.ApprovedAt == nil || !exception.ExpiresAt.After(*exception.ApprovedAt) {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, exception.TenantID); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM exceptions WHERE id = $1 AND tenant_id = $2`, exception.ID, exception.TenantID); err != nil {
		return err
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE exceptions
		SET approved = true, approved_by = $3, approved_at = $4
		WHERE id = $1 AND tenant_id = $2 AND approved = false AND expires_at > $4
	`, exception.ID, exception.TenantID, exception.ApprovedBy, *exception.ApprovedAt)
	if err != nil {
		return writeError("approve exception", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

type audit struct{ tx pgx.Tx }

func (r audit) Append(ctx context.Context, entry domain.AuditChainEntry) (domain.AuditChainEntry, error) {
	if entry.ID == "" || entry.TenantID == "" || entry.EntryType == "" || entry.SubjectType == "" || entry.SubjectID == "" || entry.ActorType == "" || entry.ActorID == "" || entry.OccurredAt.IsZero() {
		return domain.AuditChainEntry{}, app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, entry.TenantID); err != nil {
		return domain.AuditChainEntry{}, err
	}
	if _, err := r.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, entry.TenantID); err != nil {
		return domain.AuditChainEntry{}, writeError("lock tenant audit chain", err)
	}
	var sequence int64
	var previous string
	err := r.tx.QueryRow(ctx, `
		SELECT sequence, entry_hash
		FROM audit_chain_entries
		WHERE tenant_id = $1
		ORDER BY sequence DESC
		LIMIT 1
		FOR UPDATE
	`, entry.TenantID).Scan(&sequence, &previous)
	if errors.Is(err, pgx.ErrNoRows) {
		sequence, previous = 0, ""
	} else if err != nil {
		return domain.AuditChainEntry{}, writeError("load audit chain head", err)
	}
	entry.Sequence = sequence + 1
	entry.PreviousEntryHash = previous
	if entry.SchemaVersion == "" {
		entry.SchemaVersion = domain.AuditChainEntrySchemaVersion
	}
	if err := app.RehashAuditChainEntry(&entry); err != nil {
		return domain.AuditChainEntry{}, err
	}
	metadata, err := json.Marshal(entry.Metadata)
	if err != nil {
		return domain.AuditChainEntry{}, fmt.Errorf("encode audit metadata: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO audit_chain_entries (
			id, tenant_id, sequence, entry_type, subject_type, subject_id,
			actor_type, actor_id, occurred_at, request_id, idempotency_key, payload_hash,
			canonical_entry_hash, previous_entry_hash, entry_hash,
			signature_ref, metadata, schema_version
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`, entry.ID, entry.TenantID, entry.Sequence, entry.EntryType, entry.SubjectType, entry.SubjectID,
		entry.ActorType, entry.ActorID, entry.OccurredAt, entry.RequestID, entry.IdempotencyKey, nullableString(entry.PayloadHash),
		entry.CanonicalEntryHash, entry.PreviousEntryHash, entry.EntryHash,
		nullableString(entry.SignatureRef), metadata, entry.SchemaVersion)
	if err != nil {
		return domain.AuditChainEntry{}, writeError("append audit chain entry", err)
	}
	return entry, nil
}

type idempotency struct{ tx pgx.Tx }

func (r idempotency) Insert(ctx context.Context, key app.IdempotencyRecordKey, record app.IdempotencyRecord) error {
	if key.TenantID == "" || key.ActorID == "" || key.Method == "" || key.Path == "" || key.IdempotencyKey == "" || record.RequestHash == "" || record.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, key.TenantID); err != nil {
		return err
	}
	response, err := json.Marshal(record.Response)
	if err != nil {
		return fmt.Errorf("encode idempotency response: %w", err)
	}
	result, err := r.tx.Exec(ctx, `
		INSERT INTO idempotency_records (
			tenant_id, actor_key_id, method, path, idempotency_key,
			request_hash, status, response, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT DO NOTHING
	`, key.TenantID, key.ActorID, key.Method, key.Path, key.IdempotencyKey, record.RequestHash, record.Status, response, record.CreatedAt)
	if err != nil {
		return writeError("insert idempotency record", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

type outbox struct{ tx pgx.Tx }

func (r outbox) Enqueue(ctx context.Context, job app.OutboxJob) error {
	if job.ID == "" || job.TenantID == "" || job.Kind == "" || job.SubjectType == "" || job.SubjectID == "" || job.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, job.TenantID); err != nil {
		return err
	}
	payload, err := json.Marshal(job.Payload)
	if err != nil {
		return fmt.Errorf("encode outbox payload: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO outbox_jobs (
			id, tenant_id, kind, subject_type, subject_id, payload, status,
			attempts, max_attempts, run_after, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, 'queued', 0, 5, now(), $7, now())
	`, job.ID, job.TenantID, job.Kind, job.SubjectType, job.SubjectID, payload, job.CreatedAt)
	return writeError("enqueue outbox job", err)
}

type controls struct{ tx pgx.Tx }

func (r controls) InsertControlFramework(ctx context.Context, framework domain.ControlFramework) error {
	if framework.ID == "" || framework.TenantID == "" || framework.Name == "" || framework.Slug == "" || framework.Version == "" || framework.Status == "" || framework.SchemaVersion == "" || framework.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, framework.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO control_frameworks (
			id, tenant_id, name, slug, version, description, status,
			schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, framework.ID, framework.TenantID, framework.Name, framework.Slug, framework.Version, nullableString(framework.Description), framework.Status, framework.SchemaVersion, framework.CreatedAt)
	return writeError("insert control framework", err)
}

func (r controls) InsertSecurityControl(ctx context.Context, control domain.SecurityControl) error {
	if control.ID == "" || control.TenantID == "" || control.FrameworkID == "" || control.Code == "" || control.Title == "" || control.Objective == "" || control.SchemaVersion == "" || control.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, control.TenantID); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM control_frameworks WHERE id = $1 AND tenant_id = $2`, control.FrameworkID, control.TenantID); err != nil {
		return err
	}
	requirements, err := json.Marshal(control.EvidenceRequirements)
	if err != nil {
		return fmt.Errorf("encode control evidence requirements: %w", err)
	}
	applicability, err := json.Marshal(control.Applicability)
	if err != nil {
		return fmt.Errorf("encode control applicability: %w", err)
	}
	limitations, err := json.Marshal(control.Limitations)
	if err != nil {
		return fmt.Errorf("encode control limitations: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO security_controls (
			id, tenant_id, framework_id, code, title, objective,
			evidence_requirements, applicability, limitations, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, control.ID, control.TenantID, control.FrameworkID, control.Code, control.Title, control.Objective, requirements, applicability, limitations, control.SchemaVersion, control.CreatedAt)
	return writeError("insert security control", err)
}

func (r controls) InsertControlEvidence(ctx context.Context, evidence domain.ControlEvidence) error {
	if evidence.ID == "" || evidence.TenantID == "" || evidence.ControlID == "" || evidence.EvidenceType == "" || evidence.SubjectType == "" || evidence.SubjectID == "" || evidence.Confidence == "" || evidence.SchemaVersion == "" || evidence.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, evidence.TenantID); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM security_controls WHERE id = $1 AND tenant_id = $2`, evidence.ControlID, evidence.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO control_evidence (
			id, tenant_id, control_id, evidence_type, subject_type, subject_id,
			product_id, release_id, confidence, notes, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, evidence.ID, evidence.TenantID, evidence.ControlID, evidence.EvidenceType, evidence.SubjectType, evidence.SubjectID, nullableString(evidence.ProductID), nullableString(evidence.ReleaseID), evidence.Confidence, nullableString(evidence.Notes), evidence.SchemaVersion, evidence.CreatedAt)
	return writeError("insert control evidence", err)
}

type governance struct{ tx pgx.Tx }

func (r governance) InsertWaiver(ctx context.Context, waiver domain.Waiver) error {
	if waiver.ID == "" || waiver.TenantID == "" || waiver.ScopeType == "" || waiver.ScopeID == "" || waiver.Owner == "" || waiver.Risk == "" || waiver.Reason == "" || !waiver.ExpiresAt.After(waiver.CreatedAt) || waiver.SchemaVersion == "" || waiver.CreatedAt.IsZero() || waiver.Approved || waiver.ApprovedBy != "" || waiver.ApprovedAt != nil || waiver.SupersededBy != "" {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, waiver.TenantID); err != nil {
		return err
	}
	if waiver.ControlID != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM security_controls WHERE id = $1 AND tenant_id = $2`, waiver.ControlID, waiver.TenantID); err != nil {
			return err
		}
	}
	if waiver.PolicyID != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM custom_policies WHERE id = $1 AND tenant_id = $2`, waiver.PolicyID, waiver.TenantID); err != nil {
			return err
		}
	}
	if waiver.Supersedes != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM waivers WHERE id = $1 AND tenant_id = $2`, waiver.Supersedes, waiver.TenantID); err != nil {
			return err
		}
		result, err := r.tx.Exec(ctx, `
			UPDATE waivers
			SET superseded_by = $3
			WHERE id = $1 AND tenant_id = $2 AND superseded_by IS NULL
		`, waiver.Supersedes, waiver.TenantID, waiver.ID)
		if err != nil {
			return writeError("supersede waiver", err)
		}
		if result.RowsAffected() != 1 {
			return app.ErrConflict
		}
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO waivers (
			id, tenant_id, scope_type, scope_id, control_id, policy_id, owner,
			risk, reason, expires_at, approved, approved_by, approved_at,
			supersedes, superseded_by, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`, waiver.ID, waiver.TenantID, waiver.ScopeType, waiver.ScopeID, nullableString(waiver.ControlID), nullableString(waiver.PolicyID), waiver.Owner, waiver.Risk, waiver.Reason, waiver.ExpiresAt, waiver.Approved, nullableString(waiver.ApprovedBy), waiver.ApprovedAt, nullableString(waiver.Supersedes), nullableString(waiver.SupersededBy), waiver.SchemaVersion, waiver.CreatedAt)
	return writeError("insert waiver", err)
}

func (r governance) ApproveWaiver(ctx context.Context, waiver domain.Waiver) error {
	if waiver.ID == "" || waiver.TenantID == "" || !waiver.Approved || waiver.ApprovedBy == "" || waiver.ApprovedAt == nil || !waiver.ExpiresAt.After(*waiver.ApprovedAt) {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, waiver.TenantID); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM waivers WHERE id = $1 AND tenant_id = $2`, waiver.ID, waiver.TenantID); err != nil {
		return err
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE waivers
		SET approved = true, approved_by = $3, approved_at = $4
		WHERE id = $1 AND tenant_id = $2 AND approved = false AND expires_at > $4
	`, waiver.ID, waiver.TenantID, waiver.ApprovedBy, *waiver.ApprovedAt)
	if err != nil {
		return writeError("approve waiver", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r governance) InsertApprovalRecord(ctx context.Context, approval domain.ApprovalRecord) error {
	if approval.ID == "" || approval.TenantID == "" || approval.SubjectType == "" || approval.SubjectID == "" || approval.Decision == "" || approval.Reason == "" || approval.ApproverID == "" || approval.SchemaVersion == "" || approval.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, approval.TenantID); err != nil {
		return err
	}
	if err := requireOptionalOwnedEvidence(ctx, r.tx, approval.TenantID, approval.EvidenceID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO approval_records (
			id, tenant_id, subject_type, subject_id, decision, reason,
			approver_id, evidence_id, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, approval.ID, approval.TenantID, approval.SubjectType, approval.SubjectID, approval.Decision, approval.Reason, approval.ApproverID, nullableString(approval.EvidenceID), approval.SchemaVersion, approval.CreatedAt)
	return writeError("insert approval record", err)
}

func (r governance) InsertRedactionProfile(ctx context.Context, profile domain.RedactionProfile) error {
	if profile.ID == "" || profile.TenantID == "" || profile.Name == "" || len(profile.AllowedTypes) == 0 || profile.SchemaVersion == "" || profile.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, profile.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO redaction_profiles (
			id, tenant_id, name, description, allowed_types, excluded_fields,
			schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, profile.ID, profile.TenantID, profile.Name, nullableString(profile.Description), profile.AllowedTypes, profile.ExcludedFields, profile.SchemaVersion, profile.CreatedAt)
	return writeError("insert redaction profile", err)
}

func (r governance) InsertLegalHold(ctx context.Context, hold domain.LegalHold) error {
	if hold.ID == "" || hold.TenantID == "" || hold.ScopeType == "" || hold.ScopeID == "" || hold.Reason == "" || hold.Owner == "" || hold.ReleasedAt != nil || hold.SchemaVersion == "" || hold.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireRetentionScope(ctx, r.tx, hold.TenantID, hold.ScopeType, hold.ScopeID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO legal_holds (
			id, tenant_id, scope_type, scope_id, reason, owner,
			schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, hold.ID, hold.TenantID, hold.ScopeType, hold.ScopeID, hold.Reason, hold.Owner, hold.SchemaVersion, hold.CreatedAt)
	return writeError("insert legal hold", err)
}

func (r governance) InsertRetentionOverride(ctx context.Context, override domain.RetentionOverride) error {
	if override.ID == "" || override.TenantID == "" || override.ScopeType == "" || override.ScopeID == "" || !override.RetentionUntil.After(override.CreatedAt) || override.Reason == "" || override.Owner == "" || override.SchemaVersion == "" || override.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireRetentionScope(ctx, r.tx, override.TenantID, override.ScopeType, override.ScopeID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO retention_overrides (
			id, tenant_id, scope_type, scope_id, retention_until, reason,
			owner, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, override.ID, override.TenantID, override.ScopeType, override.ScopeID, override.RetentionUntil, override.Reason, override.Owner, override.SchemaVersion, override.CreatedAt)
	return writeError("insert retention override", err)
}

type builds struct{ tx pgx.Tx }

func (r builds) InsertCollector(ctx context.Context, collector domain.Collector) error {
	if collector.ID == "" || collector.TenantID == "" || collector.Name == "" || collector.Type == "" || collector.Version == "" || collector.APIKeyID == "" || collector.Status == "" || len(collector.AllowedScopes) == 0 || collector.SchemaVersion == "" || collector.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, collector.TenantID); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM api_keys WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL`, collector.APIKeyID, collector.TenantID); err != nil {
		return err
	}
	allowedScopes, err := json.Marshal(collector.AllowedScopes)
	if err != nil {
		return fmt.Errorf("encode collector allowed scopes: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO collectors (
			id, tenant_id, name, type, version, api_key_id, status,
			allowed_scopes, last_seen_at, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, collector.ID, collector.TenantID, collector.Name, collector.Type, collector.Version, collector.APIKeyID, collector.Status, allowedScopes, collector.LastSeenAt, collector.SchemaVersion, collector.CreatedAt)
	return writeError("insert collector", err)
}

func (r builds) InsertCollectorRelease(ctx context.Context, release domain.CollectorRelease) error {
	if release.ID == "" || release.TenantID == "" || release.CollectorID == "" || release.Version == "" || release.ArtifactDigest == "" || release.VerificationStatus == "" || release.HealthStatus == "" || release.SchemaVersion == "" || release.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, release.TenantID); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM collectors WHERE id = $1 AND tenant_id = $2`, release.CollectorID, release.TenantID); err != nil {
		return err
	}
	if release.SignatureID != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM artifact_signatures WHERE id = $1 AND tenant_id = $2 AND subject_digest = $3`, release.SignatureID, release.TenantID, release.ArtifactDigest); err != nil {
			return err
		}
	}
	if release.SBOMID != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM sboms WHERE id = $1 AND tenant_id = $2`, release.SBOMID, release.TenantID); err != nil {
			return err
		}
	}
	if release.ScanID != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM vulnerability_scans WHERE id = $1 AND tenant_id = $2`, release.ScanID, release.TenantID); err != nil {
			return err
		}
	}
	if release.Pinned {
		if _, err := r.tx.Exec(ctx, `UPDATE collector_releases SET pinned = false WHERE tenant_id = $1 AND collector_id = $2 AND pinned = true`, release.TenantID, release.CollectorID); err != nil {
			return writeError("unpin collector releases", err)
		}
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO collector_releases (
			id, tenant_id, collector_id, version, artifact_digest, signature_id,
			sbom_id, scan_id, pinned, verification_status, health_status,
			limitations, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`, release.ID, release.TenantID, release.CollectorID, release.Version, release.ArtifactDigest, nullableString(release.SignatureID), nullableString(release.SBOMID), nullableString(release.ScanID), release.Pinned, release.VerificationStatus, release.HealthStatus, textArray(release.Limitations), release.SchemaVersion, release.CreatedAt)
	return writeError("insert collector release", err)
}

func (r builds) InsertBuildRun(ctx context.Context, build domain.BuildRun) error {
	if build.ID == "" || build.TenantID == "" || build.ProjectID == "" || build.ReleaseID == "" || build.Provider == "" || build.CommitSHA == "" || build.Status == "" || build.StartedAt.IsZero() || build.SchemaVersion == "" || build.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, build.TenantID); err != nil {
		return err
	}
	if err := requireOptionalProject(ctx, r.tx, build.TenantID, build.ProjectID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, build.TenantID, build.ReleaseID); err != nil {
		return err
	}
	if build.CollectorID != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM collectors WHERE id = $1 AND tenant_id = $2`, build.CollectorID, build.TenantID); err != nil {
			return err
		}
	}
	for _, output := range build.Outputs {
		if output.Digest == "" {
			return app.ErrValidation
		}
		if output.ArtifactID == "" {
			continue
		}
		var digest string
		err := r.tx.QueryRow(ctx, `SELECT digest FROM artifacts WHERE id = $1 AND tenant_id = $2`, output.ArtifactID, build.TenantID).Scan(&digest)
		if errors.Is(err, pgx.ErrNoRows) {
			return app.ErrNotFound
		}
		if err != nil {
			return writeError("read build output artifact", err)
		}
		if digest != output.Digest {
			return app.ErrValidation
		}
	}
	sourceIdentity, err := json.Marshal(build.SourceIdentity)
	if err != nil {
		return fmt.Errorf("encode build source identity: %w", err)
	}
	outputs, err := json.Marshal(build.Outputs)
	if err != nil {
		return fmt.Errorf("encode build outputs: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO build_runs (
			id, tenant_id, project_id, release_id, collector_id, provider,
			commit_sha, repository, workflow_ref, run_id, run_attempt, job_id,
			actor, ref, oidc_subject, status, started_at, finished_at,
			parameters_hash, environment_hash, source_identity, outputs,
			schema_version, created_at
		)
		VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17, $18,
			$19, $20, $21, $22, $23, $24
		)
	`, build.ID, build.TenantID, build.ProjectID, build.ReleaseID, nullableString(build.CollectorID), build.Provider,
		build.CommitSHA, nullableString(build.Repository), nullableString(build.WorkflowRef), nullableString(build.RunID), nullableInt64(int64(build.RunAttempt)), nullableString(build.JobID),
		nullableString(build.Actor), nullableString(build.Ref), nullableString(build.OIDCSubject), build.Status, build.StartedAt, build.FinishedAt,
		nullableString(build.ParametersHash), nullableString(build.EnvironmentHash), sourceIdentity, outputs, build.SchemaVersion, build.CreatedAt)
	return writeError("insert build run", err)
}

func (r builds) InsertBuildAttestation(ctx context.Context, attestation domain.BuildAttestation) error {
	if attestation.ID == "" || attestation.TenantID == "" || attestation.BuildID == "" || attestation.EvidenceID == "" || attestation.PayloadHash == "" || attestation.PayloadSize < 0 || attestation.VerificationStatus == "" || attestation.SchemaVersion == "" || attestation.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, attestation.TenantID); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM build_runs WHERE id = $1 AND tenant_id = $2`, attestation.BuildID, attestation.TenantID); err != nil {
		return err
	}
	var evidenceBuildID string
	if err := r.tx.QueryRow(ctx, `SELECT build_id FROM evidence_items WHERE id = $1 AND tenant_id = $2`, attestation.EvidenceID, attestation.TenantID).Scan(&evidenceBuildID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return app.ErrNotFound
		}
		return writeError("read attestation evidence", err)
	}
	if evidenceBuildID != attestation.BuildID {
		return app.ErrValidation
	}
	subjectDigests, err := json.Marshal(attestation.SubjectDigests)
	if err != nil {
		return fmt.Errorf("encode attestation subject digests: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO build_attestations (
			id, tenant_id, build_id, evidence_id, payload_ref, payload_hash,
			payload_size, payload_type, predicate_type, subject_digests,
			builder_id, build_type, materials_count, signature_count,
			verification_status, schema_version, created_at
		)
		VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14,
			$15, $16, $17
		)
	`, attestation.ID, attestation.TenantID, attestation.BuildID, attestation.EvidenceID, nullableString(attestation.PayloadRef), attestation.PayloadHash,
		attestation.PayloadSize, attestation.PayloadType, attestation.PredicateType, subjectDigests,
		nullableString(attestation.BuilderID), nullableString(attestation.BuildType), attestation.MaterialsCount, attestation.SignatureCount,
		attestation.VerificationStatus, attestation.SchemaVersion, attestation.CreatedAt)
	return writeError("insert build attestation", err)
}

type packages struct{ tx pgx.Tx }

type source struct{ tx pgx.Tx }

type deployments struct{ tx pgx.Tx }

func (r deployments) InsertDeploymentEnvironment(ctx context.Context, env domain.DeploymentEnvironment) error {
	if env.ID == "" || env.TenantID == "" || env.ProductID == "" || env.Name == "" || env.Kind == "" || env.SchemaVersion == "" || env.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, env.TenantID); err != nil {
		return err
	}
	if err := requireOptionalProduct(ctx, r.tx, env.TenantID, env.ProductID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO deployment_environments (id, tenant_id, product_id, name, kind, schema_version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, env.ID, env.TenantID, env.ProductID, env.Name, env.Kind, env.SchemaVersion, env.CreatedAt)
	return writeError("insert deployment environment", err)
}

func (r deployments) InsertDeploymentEvent(ctx context.Context, deployment domain.DeploymentEvent) error {
	if deployment.ID == "" || deployment.TenantID == "" || deployment.EnvironmentID == "" || deployment.ReleaseID == "" || deployment.Status == "" || deployment.StartedAt.IsZero() || deployment.EvidenceID == "" || deployment.SchemaVersion == "" || deployment.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, deployment.TenantID); err != nil {
		return err
	}
	var productID string
	if err := r.tx.QueryRow(ctx, `SELECT product_id FROM deployment_environments WHERE id = $1 AND tenant_id = $2`, deployment.EnvironmentID, deployment.TenantID).Scan(&productID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return app.ErrNotFound
		}
		return writeError("read deployment environment", err)
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM releases WHERE id = $1 AND tenant_id = $2 AND product_id = $3`, deployment.ReleaseID, deployment.TenantID, productID); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM evidence_items WHERE id = $1 AND tenant_id = $2 AND deployment_id = $3`, deployment.EvidenceID, deployment.TenantID, deployment.ID); err != nil {
		return err
	}
	for _, artifactID := range deployment.ArtifactIDs {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM artifacts WHERE id = $1 AND tenant_id = $2`, artifactID, deployment.TenantID); err != nil {
			return err
		}
	}
	if deployment.RollbackOf != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM deployment_events WHERE id = $1 AND tenant_id = $2 AND environment_id = $3`, deployment.RollbackOf, deployment.TenantID, deployment.EnvironmentID); err != nil {
			return err
		}
	}
	_, err := r.tx.Exec(ctx, `INSERT INTO deployment_events (id, tenant_id, environment_id, release_id, artifact_ids, status, started_at, finished_at, rollback_of, evidence_id, schema_version, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, deployment.ID, deployment.TenantID, deployment.EnvironmentID, deployment.ReleaseID, deployment.ArtifactIDs, deployment.Status, deployment.StartedAt, deployment.FinishedAt, nullableString(deployment.RollbackOf), deployment.EvidenceID, deployment.SchemaVersion, deployment.CreatedAt)
	return writeError("insert deployment event", err)
}

func (r source) InsertSourceRepository(ctx context.Context, repository domain.SourceRepository) error {
	if repository.ID == "" || repository.TenantID == "" || repository.Provider == "" || repository.FullName == "" || repository.SchemaVersion == "" || repository.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, repository.TenantID); err != nil {
		return err
	}
	if err := requireOptionalProject(ctx, r.tx, repository.TenantID, repository.ProjectID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO source_repositories (id, tenant_id, project_id, provider, full_name, clone_url, default_branch, schema_version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, repository.ID, repository.TenantID, nullableString(repository.ProjectID), repository.Provider, repository.FullName, nullableString(repository.CloneURL), nullableString(repository.DefaultBranch), repository.SchemaVersion, repository.CreatedAt)
	return writeError("insert source repository", err)
}

func (r source) InsertSourceCommit(ctx context.Context, commit domain.SourceCommit) error {
	if commit.ID == "" || commit.TenantID == "" || commit.RepositoryID == "" || commit.SHA == "" || commit.CommittedAt.IsZero() || commit.SchemaVersion == "" || commit.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, commit.TenantID); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM source_repositories WHERE id = $1 AND tenant_id = $2`, commit.RepositoryID, commit.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO source_commits (id, tenant_id, repository_id, sha, author, message_hash, committed_at, schema_version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, commit.ID, commit.TenantID, commit.RepositoryID, commit.SHA, nullableString(commit.Author), nullableString(commit.MessageHash), commit.CommittedAt, commit.SchemaVersion, commit.CreatedAt)
	return writeError("insert source commit", err)
}

func (r source) InsertSourceBranch(ctx context.Context, branch domain.SourceBranch) error {
	if branch.ID == "" || branch.TenantID == "" || branch.RepositoryID == "" || branch.Name == "" || branch.SchemaVersion == "" || branch.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, branch.TenantID); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM source_repositories WHERE id = $1 AND tenant_id = $2`, branch.RepositoryID, branch.TenantID); err != nil {
		return err
	}
	if branch.HeadCommitID != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM source_commits WHERE id = $1 AND tenant_id = $2 AND repository_id = $3`, branch.HeadCommitID, branch.TenantID, branch.RepositoryID); err != nil {
			return err
		}
	}
	_, err := r.tx.Exec(ctx, `INSERT INTO source_branches (id, tenant_id, repository_id, name, head_commit_id, protected, protection_hash, schema_version, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, branch.ID, branch.TenantID, branch.RepositoryID, branch.Name, nullableString(branch.HeadCommitID), branch.Protected, nullableString(branch.ProtectionHash), branch.SchemaVersion, branch.CreatedAt)
	return writeError("insert source branch", err)
}

func (r source) UpdateSourceBranch(ctx context.Context, branch domain.SourceBranch) error {
	if branch.ID == "" || branch.TenantID == "" || branch.RepositoryID == "" || branch.Name == "" {
		return app.ErrValidation
	}
	if branch.HeadCommitID != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM source_commits WHERE id = $1 AND tenant_id = $2 AND repository_id = $3`, branch.HeadCommitID, branch.TenantID, branch.RepositoryID); err != nil {
			return err
		}
	}
	result, err := r.tx.Exec(ctx, `UPDATE source_branches SET head_commit_id = $4, protected = $5, protection_hash = $6 WHERE id = $1 AND tenant_id = $2 AND repository_id = $3 AND name = $7`, branch.ID, branch.TenantID, branch.RepositoryID, nullableString(branch.HeadCommitID), branch.Protected, nullableString(branch.ProtectionHash), branch.Name)
	if err != nil {
		return writeError("update source branch", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r source) InsertPullRequest(ctx context.Context, pr domain.PullRequest) error {
	if pr.ID == "" || pr.TenantID == "" || pr.RepositoryID == "" || pr.Provider == "" || pr.ProviderID == "" || pr.Title == "" || pr.State == "" || pr.SchemaVersion == "" || pr.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, pr.TenantID); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM source_repositories WHERE id = $1 AND tenant_id = $2`, pr.RepositoryID, pr.TenantID); err != nil {
		return err
	}
	if pr.HeadCommitID != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM source_commits WHERE id = $1 AND tenant_id = $2 AND repository_id = $3`, pr.HeadCommitID, pr.TenantID, pr.RepositoryID); err != nil {
			return err
		}
	}
	_, err := r.tx.Exec(ctx, `INSERT INTO pull_requests (id, tenant_id, repository_id, provider, provider_id, title, state, source_branch, target_branch, head_commit_id, review_decision, schema_version, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, pr.ID, pr.TenantID, pr.RepositoryID, pr.Provider, pr.ProviderID, pr.Title, pr.State, nullableString(pr.SourceBranch), nullableString(pr.TargetBranch), nullableString(pr.HeadCommitID), nullableString(pr.ReviewDecision), pr.SchemaVersion, pr.CreatedAt)
	return writeError("insert pull request", err)
}

type supplyChain struct{ tx pgx.Tx }

func (r supplyChain) InsertContainerImage(ctx context.Context, image domain.ContainerImage) error {
	if image.ID == "" || image.TenantID == "" || image.Repository == "" || image.Digest == "" || image.SchemaVersion == "" || image.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, image.TenantID); err != nil {
		return err
	}
	if image.ArtifactID != "" {
		var digest string
		if err := r.tx.QueryRow(ctx, `SELECT digest FROM artifacts WHERE id = $1 AND tenant_id = $2`, image.ArtifactID, image.TenantID).Scan(&digest); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return app.ErrNotFound
			}
			return writeError("read image artifact", err)
		}
		if digest != image.Digest {
			return app.ErrValidation
		}
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO container_images (id, tenant_id, artifact_id, repository, tag, digest, platform, schema_version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, image.ID, image.TenantID, nullableString(image.ArtifactID), image.Repository, nullableString(image.Tag), image.Digest, nullableString(image.Platform), image.SchemaVersion, image.CreatedAt)
	return writeError("insert container image", err)
}

func (r supplyChain) InsertArtifactSignature(ctx context.Context, signature domain.ArtifactSignature) error {
	if signature.ID == "" || signature.TenantID == "" || signature.ArtifactID == "" || signature.SubjectDigest == "" || signature.Algorithm == "" || signature.Signature == "" || signature.VerificationStatus == "" || signature.SchemaVersion == "" || signature.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, signature.TenantID); err != nil {
		return err
	}
	var digest string
	if err := r.tx.QueryRow(ctx, `SELECT digest FROM artifacts WHERE id = $1 AND tenant_id = $2`, signature.ArtifactID, signature.TenantID).Scan(&digest); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return app.ErrNotFound
		}
		return writeError("read signature artifact", err)
	}
	if digest != signature.SubjectDigest {
		return app.ErrValidation
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO artifact_signatures (
			id, tenant_id, artifact_id, subject_digest, algorithm, key_id,
			signature, payload_ref, payload_hash, verification_status,
			schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, signature.ID, signature.TenantID, signature.ArtifactID, signature.SubjectDigest, signature.Algorithm, nullableString(signature.KeyID),
		signature.Signature, nullableString(signature.PayloadRef), nullableString(signature.PayloadHash), signature.VerificationStatus,
		signature.SchemaVersion, signature.CreatedAt)
	return writeError("insert artifact signature", err)
}

func (r packages) InsertReleaseBundle(ctx context.Context, bundle domain.ReleaseBundle) error {
	if bundle.ID == "" || bundle.TenantID == "" || bundle.ReleaseID == "" || bundle.State == "" || bundle.ManifestHash == "" || bundle.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOptionalRelease(ctx, r.tx, bundle.TenantID, bundle.ReleaseID); err != nil {
		return err
	}
	manifest, err := json.Marshal(bundle.Manifest)
	if err != nil {
		return fmt.Errorf("encode release bundle manifest: %w", err)
	}
	signatureRefs, err := json.Marshal(bundle.SignatureRefs)
	if err != nil {
		return fmt.Errorf("encode release bundle signatures: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO release_bundles (
			id, tenant_id, release_id, state, manifest, manifest_hash, signature_refs,
			created_at, published_at, revoked_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, bundle.ID, bundle.TenantID, bundle.ReleaseID, bundle.State, manifest, bundle.ManifestHash, signatureRefs, bundle.CreatedAt, bundle.PublishedAt, bundle.RevokedAt)
	return writeError("insert release bundle", err)
}

type signatures struct{ tx pgx.Tx }

func (r signatures) InsertSigningKey(ctx context.Context, key domain.SigningKey) error {
	if key.ID == "" || key.TenantID == "" || key.KID == "" || key.Algorithm == "" || key.Status == "" || key.PublicKey == "" || key.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, key.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO signing_keys (
			id, tenant_id, kid, algorithm, status, public_key,
			encrypted_private_key, created_at, revoked_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, key.ID, key.TenantID, key.KID, key.Algorithm, key.Status, key.PublicKey, nullableBytes(key.Private), key.CreatedAt, key.RevokedAt)
	return writeError("insert signing key", err)
}

func (r signatures) UpdateSigningKey(ctx context.Context, key domain.SigningKey, expectedStatus string) error {
	if key.ID == "" || key.TenantID == "" || key.Status == "" || expectedStatus == "" {
		return app.ErrValidation
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE signing_keys
		SET status = $3, revoked_at = $4
		WHERE id = $1 AND tenant_id = $2 AND status = $5
	`, key.ID, key.TenantID, key.Status, key.RevokedAt, expectedStatus)
	if err != nil {
		return writeError("update signing key", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r signatures) InsertSignature(ctx context.Context, signature domain.Signature) error {
	if signature.ID == "" || signature.TenantID == "" || signature.SubjectType == "" || signature.SubjectID == "" || signature.KeyID == "" || signature.Algorithm == "" || signature.Value == "" || signature.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedSigningKey(ctx, r.tx, signature.TenantID, signature.KeyID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO signatures (id, tenant_id, subject_type, subject_id, key_id, algorithm, value, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, signature.ID, signature.TenantID, signature.SubjectType, signature.SubjectID, signature.KeyID, signature.Algorithm, signature.Value, signature.CreatedAt)
	return writeError("insert signature", err)
}

type integrity struct{ tx pgx.Tx }

func (r integrity) InsertSigningProvider(ctx context.Context, provider domain.SigningProvider) error {
	if provider.ID == "" || provider.TenantID == "" || provider.Name == "" || !validSigningProviderType(provider.Type) || provider.Status == "" || provider.KeyRef == "" || provider.SchemaVersion == "" || provider.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if provider.Type == "local_encrypted_dev" && !provider.Encrypted {
		return app.ErrValidation
	}
	if provider.Type == "native_pkcs11_hsm" && (!provider.Encrypted || !strings.HasPrefix(provider.KeyRef, "pkcs11:") || signingProviderRefContainsSecret(provider.KeyRef)) {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, provider.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO signing_providers (
			id, tenant_id, name, type, status, key_ref, encrypted,
			schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, provider.ID, provider.TenantID, provider.Name, provider.Type, provider.Status, provider.KeyRef, provider.Encrypted, provider.SchemaVersion, provider.CreatedAt)
	return writeError("insert signing provider", err)
}

func (r integrity) InsertObjectRetentionPolicy(ctx context.Context, policy domain.ObjectRetentionPolicy) error {
	if policy.ID == "" || policy.TenantID == "" || policy.Name == "" || policy.ObjectPrefix == "" || (policy.Mode != "governance" && policy.Mode != "compliance") || policy.RetentionDays <= 0 || policy.MaxVerificationAgeHours < 1 || policy.Status != "configured" || policy.SchemaVersion == "" || policy.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	expectedPrefix := "tenants/" + policy.TenantID + "/"
	if !strings.HasPrefix(policy.ObjectPrefix, expectedPrefix) || (policy.ObjectKey != "" && (!strings.HasPrefix(policy.ObjectKey, expectedPrefix) || !strings.HasPrefix(policy.ObjectKey, policy.ObjectPrefix))) || (policy.RequireLegalHold && policy.ObjectKey == "") {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, policy.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO object_retention_policies (
			id, tenant_id, name, object_prefix, object_key, require_legal_hold,
			mode, retention_days, max_verification_age_hours, status,
			schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, policy.ID, policy.TenantID, policy.Name, policy.ObjectPrefix, policy.ObjectKey, policy.RequireLegalHold,
		policy.Mode, policy.RetentionDays, policy.MaxVerificationAgeHours, policy.Status, policy.SchemaVersion, policy.CreatedAt)
	return writeError("insert object retention policy", err)
}

func (r integrity) UpdateObjectRetentionPolicy(ctx context.Context, policy domain.ObjectRetentionPolicy, expectedStatus string) error {
	if policy.ID == "" || policy.TenantID == "" || policy.Status == "" || expectedStatus == "" || policy.MaxVerificationAgeHours < 1 || policy.VerifiedAt == nil || policy.VerificationHash == "" || policy.VerificationChecks == nil || policy.SchemaVersion == "" {
		return app.ErrValidation
	}
	checks, err := json.Marshal(policy.VerificationChecks)
	if err != nil {
		return fmt.Errorf("encode object retention verification checks: %w", err)
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE object_retention_policies
		SET max_verification_age_hours = $3, status = $4, verified_at = $5,
			verification_hash = $6, verification_checks = $7, verification_limitations = $8,
			verification_provider = $9, verification_bucket = $10, verification_mode = $11,
			verification_retention_days = $12, verification_legal_hold = $13,
			verification_observed_at = $14, verification_expires_at = $15, schema_version = $16
		WHERE id = $1 AND tenant_id = $2 AND status = $17
	`, policy.ID, policy.TenantID, policy.MaxVerificationAgeHours, policy.Status, policy.VerifiedAt,
		policy.VerificationHash, checks, textArray(policy.VerificationLimitations), policy.VerificationProvider,
		policy.VerificationBucket, policy.VerificationMode, policy.VerificationRetentionDays,
		nullableBool(policy.VerificationLegalHold), policy.VerificationObservedAt, policy.VerificationExpiresAt,
		policy.SchemaVersion, expectedStatus)
	if err != nil {
		return writeError("update object retention policy", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r integrity) InsertBackupManifest(ctx context.Context, manifest domain.BackupManifest) error {
	if manifest.ID == "" || manifest.TenantID == "" || manifest.StateHash == "" || manifest.ResourceCounts == nil || manifest.ConsistencyChecks == nil || manifest.SchemaVersion == "" || manifest.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, manifest.TenantID); err != nil {
		return err
	}
	counts, err := json.Marshal(manifest.ResourceCounts)
	if err != nil {
		return fmt.Errorf("encode backup manifest resource counts: %w", err)
	}
	checks, err := json.Marshal(manifest.ConsistencyChecks)
	if err != nil {
		return fmt.Errorf("encode backup manifest checks: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO backup_manifests (
			id, tenant_id, state_hash, resource_counts, consistency_checks,
			limitations, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, manifest.ID, manifest.TenantID, manifest.StateHash, counts, checks, textArray(manifest.Limitations), manifest.SchemaVersion, manifest.CreatedAt)
	return writeError("insert backup manifest", err)
}

func (r integrity) InsertMerkleBatch(ctx context.Context, batch domain.MerkleBatch) error {
	if batch.ID == "" || batch.TenantID == "" || batch.FromSequence < 1 || batch.ToSequence < batch.FromSequence || batch.EntryCount != len(batch.LeafHashes) || batch.EntryCount < 1 || batch.RootHash == "" || batch.SchemaVersion == "" || batch.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, batch.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `INSERT INTO merkle_batches (id, tenant_id, from_sequence, to_sequence, entry_count, leaf_hashes, root_hash, signature_refs, schema_version, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, batch.ID, batch.TenantID, batch.FromSequence, batch.ToSequence, batch.EntryCount, batch.LeafHashes, batch.RootHash, textArray(batch.SignatureRefs), batch.SchemaVersion, batch.CreatedAt)
	return writeError("insert Merkle batch", err)
}

func (r integrity) InsertTransparencyCheckpoint(ctx context.Context, checkpoint domain.TransparencyCheckpoint) error {
	if checkpoint.ID == "" || checkpoint.TenantID == "" || checkpoint.BatchID == "" || checkpoint.Provider == "" || (checkpoint.ExternalURL == "" && checkpoint.ExternalID == "") || checkpoint.TimestampHash == "" || checkpoint.State == "" || checkpoint.SchemaVersion == "" || checkpoint.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, checkpoint.TenantID); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM merkle_batches WHERE id = $1 AND tenant_id = $2`, checkpoint.BatchID, checkpoint.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `INSERT INTO transparency_checkpoints (id, tenant_id, batch_id, provider, external_url, external_id, timestamp_hash, state, schema_version, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, checkpoint.ID, checkpoint.TenantID, checkpoint.BatchID, checkpoint.Provider, nullableString(checkpoint.ExternalURL), nullableString(checkpoint.ExternalID), checkpoint.TimestampHash, checkpoint.State, checkpoint.SchemaVersion, checkpoint.CreatedAt)
	return writeError("insert transparency checkpoint", err)
}

type verification struct{ tx pgx.Tx }

func (r verification) InsertVerificationResult(ctx context.Context, result domain.VerificationResult) error {
	if result.ID == "" || result.TenantID == "" || result.SubjectType == "" || result.SubjectID == "" || result.Result == "" || result.VerifiedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, result.TenantID); err != nil {
		return err
	}
	checks, err := json.Marshal(result.Checks)
	if err != nil {
		return fmt.Errorf("encode verification checks: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO verification_results (id, tenant_id, subject_type, subject_id, result, checks, verified_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, result.ID, result.TenantID, result.SubjectType, result.SubjectID, result.Result, checks, result.VerifiedAt)
	return writeError("insert verification result", err)
}

func (r verification) InsertPolicyEvaluation(ctx context.Context, evaluation domain.PolicyEvaluation) error {
	if evaluation.ID == "" || evaluation.TenantID == "" || evaluation.ReleaseID == "" || evaluation.Result == "" || evaluation.PolicySet == "" || evaluation.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, evaluation.TenantID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, evaluation.TenantID, evaluation.ReleaseID); err != nil {
		return err
	}
	checks, err := json.Marshal(evaluation.Checks)
	if err != nil {
		return fmt.Errorf("encode policy evaluation checks: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO policy_evaluations (id, tenant_id, release_id, result, policy_set, checks, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, evaluation.ID, evaluation.TenantID, evaluation.ReleaseID, evaluation.Result, evaluation.PolicySet, checks, evaluation.CreatedAt)
	return writeError("insert policy evaluation", err)
}

func requireTenant(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if tenantID == "" {
		return app.ErrValidation
	}
	return requireRow(ctx, tx, `SELECT 1 FROM tenants WHERE id = $1`, tenantID)
}

func requireRetentionScope(ctx context.Context, tx pgx.Tx, tenantID, scopeType, scopeID string) error {
	if tenantID == "" || scopeID == "" {
		return app.ErrValidation
	}
	switch scopeType {
	case "tenant":
		if scopeID != tenantID {
			return app.ErrNotFound
		}
		return requireTenant(ctx, tx, tenantID)
	case "product":
		return requireOptionalProduct(ctx, tx, tenantID, scopeID)
	case "project":
		return requireOptionalProject(ctx, tx, tenantID, scopeID)
	case "release":
		return requireOptionalRelease(ctx, tx, tenantID, scopeID)
	case "evidence":
		return requireOwnedEvidence(ctx, tx, tenantID, scopeID)
	default:
		return app.ErrValidation
	}
}

func requireOptionalOrganization(ctx context.Context, tx pgx.Tx, tenantID, organizationID string) error {
	if organizationID == "" {
		return nil
	}
	return requireRow(ctx, tx, `SELECT 1 FROM organizations WHERE id = $1 AND tenant_id = $2`, organizationID, tenantID)
}

func requireOwnedHumanUser(ctx context.Context, tx pgx.Tx, tenantID, userID string) error {
	if userID == "" {
		return app.ErrValidation
	}
	return requireRow(ctx, tx, `SELECT 1 FROM human_users WHERE id = $1 AND tenant_id = $2`, userID, tenantID)
}

func requireOwnedActiveHumanUser(ctx context.Context, tx pgx.Tx, tenantID, userID string) error {
	if userID == "" {
		return app.ErrValidation
	}
	return requireRow(ctx, tx, `SELECT 1 FROM human_users WHERE id = $1 AND tenant_id = $2 AND status = 'active'`, userID, tenantID)
}

func requireOwnedSSOProvider(ctx context.Context, tx pgx.Tx, tenantID, providerID string) error {
	if providerID == "" {
		return app.ErrValidation
	}
	return requireRow(ctx, tx, `SELECT 1 FROM sso_providers WHERE id = $1 AND tenant_id = $2`, providerID, tenantID)
}

func requireOwnedCustomerPackage(ctx context.Context, tx pgx.Tx, tenantID, packageID string) error {
	if packageID == "" {
		return app.ErrValidation
	}
	return requireRow(ctx, tx, `SELECT 1 FROM customer_security_packages WHERE id = $1 AND tenant_id = $2`, packageID, tenantID)
}

func requireRoleSubject(ctx context.Context, tx pgx.Tx, tenantID, subjectType, subjectID string) error {
	switch subjectType {
	case "user":
		return requireOwnedHumanUser(ctx, tx, tenantID, subjectID)
	case "collector":
		if subjectID == "" {
			return app.ErrValidation
		}
		return requireRow(ctx, tx, `SELECT 1 FROM collectors WHERE id = $1 AND tenant_id = $2`, subjectID, tenantID)
	default:
		return app.ErrValidation
	}
}

func requireRoleResource(ctx context.Context, tx pgx.Tx, tenantID, resourceType, resourceID string) error {
	switch resourceType {
	case "":
		if resourceID != "" {
			return app.ErrValidation
		}
		return nil
	case "tenant":
		if resourceID == "" || resourceID == tenantID {
			return nil
		}
		return app.ErrNotFound
	case "product":
		return requireOptionalProduct(ctx, tx, tenantID, resourceID)
	case "project":
		return requireOptionalProject(ctx, tx, tenantID, resourceID)
	case "release":
		return requireOptionalRelease(ctx, tx, tenantID, resourceID)
	case "customer_security_package":
		return requireOwnedCustomerPackage(ctx, tx, tenantID, resourceID)
	case "evidence_bundle":
		if resourceID == "" {
			return app.ErrValidation
		}
		return requireRow(ctx, tx, `SELECT 1 FROM evidence_bundles WHERE id = $1 AND tenant_id = $2`, resourceID, tenantID)
	default:
		return app.ErrValidation
	}
}

func requireOptionalProduct(ctx context.Context, tx pgx.Tx, tenantID, productID string) error {
	if productID == "" {
		return nil
	}
	return requireRow(ctx, tx, `SELECT 1 FROM products WHERE id = $1 AND tenant_id = $2`, productID, tenantID)
}

func requireOptionalProject(ctx context.Context, tx pgx.Tx, tenantID, projectID string) error {
	if projectID == "" {
		return nil
	}
	return requireRow(ctx, tx, `SELECT 1 FROM projects WHERE id = $1 AND tenant_id = $2`, projectID, tenantID)
}

func requireOptionalRelease(ctx context.Context, tx pgx.Tx, tenantID, releaseID string) error {
	if releaseID == "" {
		return nil
	}
	return requireRow(ctx, tx, `SELECT 1 FROM releases WHERE id = $1 AND tenant_id = $2`, releaseID, tenantID)
}

func requireOptionalArtifact(ctx context.Context, tx pgx.Tx, tenantID, artifactID string) error {
	if artifactID == "" {
		return nil
	}
	return requireRow(ctx, tx, `SELECT 1 FROM artifacts WHERE id = $1 AND tenant_id = $2`, artifactID, tenantID)
}

func requireOwnedEvidence(ctx context.Context, tx pgx.Tx, tenantID, evidenceID string) error {
	if evidenceID == "" {
		return app.ErrValidation
	}
	return requireOptionalOwnedEvidence(ctx, tx, tenantID, evidenceID)
}

func requireOptionalOwnedEvidence(ctx context.Context, tx pgx.Tx, tenantID, evidenceID string) error {
	if evidenceID == "" {
		return nil
	}
	return requireRow(ctx, tx, `SELECT 1 FROM evidence_items WHERE id = $1 AND tenant_id = $2`, evidenceID, tenantID)
}

func requireOwnedScan(ctx context.Context, tx pgx.Tx, tenantID, scanID string) error {
	return requireRow(ctx, tx, `SELECT 1 FROM vulnerability_scans WHERE id = $1 AND tenant_id = $2`, scanID, tenantID)
}

func requireOwnedVEXDocument(ctx context.Context, tx pgx.Tx, tenantID, vexDocumentID string) error {
	return requireRow(ctx, tx, `SELECT 1 FROM vex_documents WHERE id = $1 AND tenant_id = $2`, vexDocumentID, tenantID)
}

func requireOwnedSigningKey(ctx context.Context, tx pgx.Tx, tenantID, keyID string) error {
	return requireRow(ctx, tx, `SELECT 1 FROM signing_keys WHERE id = $1 AND tenant_id = $2`, keyID, tenantID)
}

func validSigningProviderType(value string) bool {
	switch value {
	case "local_encrypted_dev", "aws_kms", "gcp_kms", "azure_key_vault", "pkcs11_hsm", "native_pkcs11_hsm":
		return true
	default:
		return false
	}
}

func signingProviderRefContainsSecret(value string) bool {
	lowered := strings.ToLower(value)
	for _, marker := range []string{"pin-value=", "pin-source=", "password=", "secret=", "token=" + "secret"} {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}

func requireRow(ctx context.Context, tx pgx.Tx, query string, arguments ...any) error {
	var found int
	err := tx.QueryRow(ctx, query, arguments...).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return writeError("read scoped repository row", err)
	}
	return nil
}

func writeError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "23505":
			return fmt.Errorf("%w: %s", app.ErrConflict, operation)
		case "23503":
			return fmt.Errorf("%w: %s", app.ErrNotFound, operation)
		}
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableInt64(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func nullableBool(value *bool) any {
	if value == nil {
		return nil
	}
	return *value
}

func nonZeroInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func textArray(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

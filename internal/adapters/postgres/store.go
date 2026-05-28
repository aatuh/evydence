package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

type Store struct {
	pool *pgxpool.Pool
}

type ClaimedJob struct {
	ID          string
	TenantID    string
	Kind        string
	SubjectType string
	SubjectID   string
	Attempts    int
	Payload     map[string]any
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

func (s *Store) LoadState(ctx context.Context) (app.PersistedState, bool, error) {
	var body []byte
	err := s.pool.QueryRow(ctx, `SELECT state FROM ledger_state WHERE id = 'default'`).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.loadRelationalState(ctx)
	}
	if err != nil {
		return app.PersistedState{}, false, fmt.Errorf("load ledger state: %w", err)
	}
	var state app.PersistedState
	if err := json.Unmarshal(body, &state); err != nil {
		return app.PersistedState{}, false, fmt.Errorf("decode ledger state: %w", err)
	}
	return state, true, nil
}

func (s *Store) loadRelationalState(ctx context.Context) (app.PersistedState, bool, error) {
	state := relationalEmptyState()
	loaded := false
	if err := s.loadRelationalTenants(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	if err := s.loadRelationalIdentity(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	if err := s.loadRelationalAPIKeys(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	if err := s.loadRelationalCustomerPortalAccess(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	if err := s.loadRelationalReleaseCore(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	if err := s.loadRelationalPackageReportRetention(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	if err := s.loadRelationalIdempotency(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	return state, loaded, nil
}

func relationalEmptyState() app.PersistedState {
	return app.PersistedState{
		Tenants:                 map[string]domain.Tenant{},
		Organizations:           map[string]domain.Organization{},
		Users:                   map[string]domain.HumanUser{},
		RoleBindings:            map[string]domain.RoleBinding{},
		SSOProviders:            map[string]domain.SSOProvider{},
		IdentityLinks:           map[string]domain.UserIdentityLink{},
		SSOSessions:             map[string]domain.SSOSession{},
		SSOSessionHashes:        map[string]string{},
		APIKeys:                 map[string]domain.APIKey{},
		APIKeyHashes:            map[string]string{},
		CustomerPortalAccess:    map[string]domain.CustomerPortalAccess{},
		CustomerPortalHashes:    map[string]string{},
		RedactionProfiles:       map[string]domain.RedactionProfile{},
		CustomerPackages:        map[string]domain.CustomerSecurityPackage{},
		HTMLReports:             map[string]domain.HTMLReportPackage{},
		ReportTemplates:         map[string]domain.CustomReportTemplate{},
		RenderedReports:         map[string]domain.RenderedCustomReport{},
		EvidenceBundles:         map[string]domain.EvidenceBundle{},
		BundleImports:           map[string]domain.EvidenceBundleImport{},
		ObjectRetentionPolicies: map[string]domain.ObjectRetentionPolicy{},
		BackupManifests:         map[string]domain.BackupManifest{},
		LegalHolds:              map[string]domain.LegalHold{},
		RetentionOverrides:      map[string]domain.RetentionOverride{},
		QuestionnaireTemplates:  map[string]domain.QuestionnaireTemplate{},
		QuestionnairePackages:   map[string]domain.QuestionnairePackage{},
		PDFReports:              map[string]domain.PDFReportPackage{},
		AnomalyReports:          map[string]domain.AnomalyReport{},
		Products:                map[string]domain.Product{},
		Projects:                map[string]domain.Project{},
		Releases:                map[string]domain.Release{},
		Artifacts:               map[string]domain.Artifact{},
		Evidence:                map[string]domain.EvidenceItem{},
		SBOMs:                   map[string]domain.SBOM{},
		Scans:                   map[string]domain.VulnerabilityScan{},
		Contracts:               map[string]domain.OpenAPIContract{},
		Policies:                map[string]domain.PolicyEvaluation{},
		Bundles:                 map[string]domain.ReleaseBundle{},
		SigningKeys:             map[string]domain.SigningKey{},
		SigningKeyPrivate:       map[string][]byte{},
		Signatures:              map[string]domain.Signature{},
		Verifications:           map[string]domain.VerificationResult{},
		Chain:                   map[string][]domain.AuditChainEntry{},
		Idempotency:             map[string]app.IdempotencyRecord{},
	}
}

func (s *Store) loadRelationalTenants(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, name, created_at FROM tenants`)
	if err != nil {
		return fmt.Errorf("load relational tenants: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tenant domain.Tenant
		if err := rows.Scan(&tenant.ID, &tenant.Name, &tenant.CreatedAt); err != nil {
			return fmt.Errorf("scan relational tenant: %w", err)
		}
		state.Tenants[tenant.ID] = tenant
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalIdentity(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	if err := s.loadRelationalOrganizations(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalUsers(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalRoleBindings(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalSSOProviders(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalIdentityLinks(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalSSOSessions(ctx, state, loaded); err != nil {
		return err
	}
	return nil
}

func (s *Store) loadRelationalOrganizations(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, slug, status, schema_version, created_at FROM organizations`)
	if err != nil {
		return fmt.Errorf("load relational organizations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var org domain.Organization
		if err := rows.Scan(&org.ID, &org.TenantID, &org.Name, &org.Slug, &org.Status, &org.SchemaVersion, &org.CreatedAt); err != nil {
			return fmt.Errorf("scan relational organization: %w", err)
		}
		state.Organizations[org.ID] = org
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalUsers(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, organization_id, email, display_name, status, deactivated_at, schema_version, created_at FROM human_users`)
	if err != nil {
		return fmt.Errorf("load relational users: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var user domain.HumanUser
		var organizationID sql.NullString
		var deactivatedAt sql.NullTime
		if err := rows.Scan(&user.ID, &user.TenantID, &organizationID, &user.Email, &user.DisplayName, &user.Status, &deactivatedAt, &user.SchemaVersion, &user.CreatedAt); err != nil {
			return fmt.Errorf("scan relational user: %w", err)
		}
		user.OrganizationID = nullableSQLString(organizationID)
		user.DeactivatedAt = nullableSQLTime(deactivatedAt)
		state.Users[user.ID] = user
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalRoleBindings(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, subject_type, subject_id, role, resource_type, resource_id, schema_version, created_at FROM role_bindings`)
	if err != nil {
		return fmt.Errorf("load relational role bindings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var binding domain.RoleBinding
		var resourceType, resourceID sql.NullString
		if err := rows.Scan(&binding.ID, &binding.TenantID, &binding.SubjectType, &binding.SubjectID, &binding.Role, &resourceType, &resourceID, &binding.SchemaVersion, &binding.CreatedAt); err != nil {
			return fmt.Errorf("scan relational role binding: %w", err)
		}
		binding.ResourceType = nullableSQLString(resourceType)
		binding.ResourceID = nullableSQLString(resourceID)
		state.RoleBindings[binding.ID] = binding
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalSSOProviders(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, type, issuer, client_id, groups_claim,
		       role_mapping, status, schema_version, created_at, jwks,
		       saml_signing_certificates, trust_material_updated_at
		FROM sso_providers
	`)
	if err != nil {
		return fmt.Errorf("load relational sso providers: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var provider domain.SSOProvider
		var groupsClaim sql.NullString
		var roleMapping, jwks, samlCerts []byte
		var trustMaterialUpdatedAt sql.NullTime
		if err := rows.Scan(
			&provider.ID, &provider.TenantID, &provider.Name, &provider.Type, &provider.Issuer, &provider.ClientID, &groupsClaim,
			&roleMapping, &provider.Status, &provider.SchemaVersion, &provider.CreatedAt, &jwks,
			&samlCerts, &trustMaterialUpdatedAt,
		); err != nil {
			return fmt.Errorf("scan relational sso provider: %w", err)
		}
		provider.GroupsClaim = nullableSQLString(groupsClaim)
		provider.TrustMaterialUpdatedAt = nullableSQLTime(trustMaterialUpdatedAt)
		if err := decodeJSON(roleMapping, &provider.RoleMapping); err != nil {
			return fmt.Errorf("decode relational sso role mapping: %w", err)
		}
		if err := decodeJSON(jwks, &provider.JWKS); err != nil {
			return fmt.Errorf("decode relational sso jwks: %w", err)
		}
		if err := decodeJSON(samlCerts, &provider.SAMLSigningCertificates); err != nil {
			return fmt.Errorf("decode relational sso certificates: %w", err)
		}
		state.SSOProviders[provider.ID] = provider
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalIdentityLinks(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, user_id, provider_id, subject, email, verified, schema_version, created_at FROM user_identity_links`)
	if err != nil {
		return fmt.Errorf("load relational identity links: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var link domain.UserIdentityLink
		if err := rows.Scan(&link.ID, &link.TenantID, &link.UserID, &link.ProviderID, &link.Subject, &link.Email, &link.Verified, &link.SchemaVersion, &link.CreatedAt); err != nil {
			return fmt.Errorf("scan relational identity link: %w", err)
		}
		state.IdentityLinks[link.ID] = link
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalSSOSessions(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, user_id, provider_id, prefix, hash, expires_at, revoked_at, schema_version, created_at FROM sso_sessions`)
	if err != nil {
		return fmt.Errorf("load relational sso sessions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var session domain.SSOSession
		var hash string
		var revokedAt sql.NullTime
		if err := rows.Scan(&session.ID, &session.TenantID, &session.UserID, &session.ProviderID, &session.Prefix, &hash, &session.ExpiresAt, &revokedAt, &session.SchemaVersion, &session.CreatedAt); err != nil {
			return fmt.Errorf("scan relational sso session: %w", err)
		}
		session.RevokedAt = nullableSQLTime(revokedAt)
		state.SSOSessions[session.ID] = session
		state.SSOSessionHashes[session.ID] = hash
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalAPIKeys(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, prefix, hash, scopes, expires_at,
		       revoked_at, last_used_at, created_at
		FROM api_keys
	`)
	if err != nil {
		return fmt.Errorf("load relational api keys: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key domain.APIKey
		var hash string
		var scopes []byte
		var expiresAt, revokedAt, lastUsedAt sql.NullTime
		if err := rows.Scan(&key.ID, &key.TenantID, &key.Name, &key.Prefix, &hash, &scopes, &expiresAt, &revokedAt, &lastUsedAt, &key.CreatedAt); err != nil {
			return fmt.Errorf("scan relational api key: %w", err)
		}
		if err := decodeJSON(scopes, &key.Scopes); err != nil {
			return fmt.Errorf("decode relational api key scopes: %w", err)
		}
		key.ExpiresAt = nullableSQLTime(expiresAt)
		key.RevokedAt = nullableSQLTime(revokedAt)
		key.LastUsedAt = nullableSQLTime(lastUsedAt)
		state.APIKeys[key.ID] = key
		state.APIKeyHashes[key.ID] = hash
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalCustomerPortalAccess(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, package_id, customer_name, prefix, hash,
		       expires_at, revoked_at, access_count, failed_access_count,
		       last_accessed_at, last_failed_at, schema_version, created_at
		FROM customer_portal_access
	`)
	if err != nil {
		return fmt.Errorf("load relational customer portal access: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var access domain.CustomerPortalAccess
		var hash string
		var revokedAt, lastAccessedAt, lastFailedAt sql.NullTime
		if err := rows.Scan(
			&access.ID, &access.TenantID, &access.PackageID, &access.CustomerName, &access.Prefix, &hash,
			&access.ExpiresAt, &revokedAt, &access.AccessCount, &access.FailedAccessCount,
			&lastAccessedAt, &lastFailedAt, &access.SchemaVersion, &access.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan relational customer portal access: %w", err)
		}
		access.RevokedAt = nullableSQLTime(revokedAt)
		access.LastAccessedAt = nullableSQLTime(lastAccessedAt)
		access.LastFailedAt = nullableSQLTime(lastFailedAt)
		state.CustomerPortalAccess[access.ID] = access
		state.CustomerPortalHashes[access.ID] = hash
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalReleaseCore(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	if err := s.loadRelationalProducts(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalProjects(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalReleases(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalArtifacts(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalEvidence(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalAuditChain(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalSigning(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalParsedResources(ctx, state, loaded); err != nil {
		return err
	}
	return nil
}

func (s *Store) loadRelationalProducts(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, slug, created_at FROM products`)
	if err != nil {
		return fmt.Errorf("load relational products: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var product domain.Product
		if err := rows.Scan(&product.ID, &product.TenantID, &product.Name, &product.Slug, &product.CreatedAt); err != nil {
			return fmt.Errorf("scan relational product: %w", err)
		}
		state.Products[product.ID] = product
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalProjects(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, product_id, name, created_at FROM projects`)
	if err != nil {
		return fmt.Errorf("load relational projects: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var project domain.Project
		if err := rows.Scan(&project.ID, &project.TenantID, &project.ProductID, &project.Name, &project.CreatedAt); err != nil {
			return fmt.Errorf("scan relational project: %w", err)
		}
		state.Projects[project.ID] = project
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalReleases(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, product_id, version, state, frozen_at, approved_at, created_at FROM releases`)
	if err != nil {
		return fmt.Errorf("load relational releases: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var release domain.Release
		var frozenAt, approvedAt sql.NullTime
		if err := rows.Scan(&release.ID, &release.TenantID, &release.ProductID, &release.Version, &release.State, &frozenAt, &approvedAt, &release.CreatedAt); err != nil {
			return fmt.Errorf("scan relational release: %w", err)
		}
		release.FrozenAt = nullableSQLTime(frozenAt)
		release.ApprovedAt = nullableSQLTime(approvedAt)
		state.Releases[release.ID] = release
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalArtifacts(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, media_type, size, digest, created_at FROM artifacts`)
	if err != nil {
		return fmt.Errorf("load relational artifacts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var artifact domain.Artifact
		if err := rows.Scan(&artifact.ID, &artifact.TenantID, &artifact.Name, &artifact.MediaType, &artifact.Size, &artifact.Digest, &artifact.CreatedAt); err != nil {
			return fmt.Errorf("scan relational artifact: %w", err)
		}
		state.Artifacts[artifact.ID] = artifact
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalEvidence(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, product_id, project_id, release_id, build_id, deployment_id,
		       type, subtype, title, source_system, source_identity, collector_id,
		       uploaded_by, observed_at, evidence_version, schema_version, payload_ref,
		       payload_hash, payload_media_type, payload_size, canonical_hash,
		       canonicalization, subject_refs, related_evidence_refs, supersedes,
		       superseded_by, trust_level, verification_status, signature_refs,
		       chain_entry_id, tags, metadata, warnings, limitations, created_at
		FROM evidence_items
	`)
	if err != nil {
		return fmt.Errorf("load relational evidence items: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var evidence domain.EvidenceItem
		var productID, projectID, releaseID, buildID, deploymentID, subtype, collectorID, uploadedBy, payloadRef, payloadMediaType, supersedes, supersededBy, chainEntryID sql.NullString
		var payloadSize sql.NullInt64
		var sourceIdentity, subjectRefs, relatedRefs, signatureRefs, tags, metadata, warnings, limitations []byte
		if err := rows.Scan(
			&evidence.ID, &evidence.TenantID, &productID, &projectID, &releaseID, &buildID, &deploymentID,
			&evidence.Type, &subtype, &evidence.Title, &evidence.SourceSystem, &sourceIdentity, &collectorID,
			&uploadedBy, &evidence.ObservedAt, &evidence.EvidenceVersion, &evidence.SchemaVersion, &payloadRef,
			&evidence.PayloadHash, &payloadMediaType, &payloadSize, &evidence.CanonicalHash,
			&evidence.Canonicalization, &subjectRefs, &relatedRefs, &supersedes,
			&supersededBy, &evidence.TrustLevel, &evidence.VerificationStatus, &signatureRefs,
			&chainEntryID, &tags, &metadata, &warnings, &limitations, &evidence.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan relational evidence item: %w", err)
		}
		evidence.ProductID = nullableSQLString(productID)
		evidence.ProjectID = nullableSQLString(projectID)
		evidence.ReleaseID = nullableSQLString(releaseID)
		evidence.BuildID = nullableSQLString(buildID)
		evidence.DeploymentID = nullableSQLString(deploymentID)
		evidence.Subtype = nullableSQLString(subtype)
		evidence.CollectorID = nullableSQLString(collectorID)
		evidence.UploadedBy = nullableSQLString(uploadedBy)
		evidence.PayloadRef = nullableSQLString(payloadRef)
		evidence.PayloadMediaType = nullableSQLString(payloadMediaType)
		if payloadSize.Valid {
			evidence.PayloadSize = payloadSize.Int64
		}
		evidence.Supersedes = nullableSQLString(supersedes)
		evidence.SupersededBy = nullableSQLString(supersededBy)
		evidence.ChainEntryID = nullableSQLString(chainEntryID)
		if err := decodeJSON(sourceIdentity, &evidence.SourceIdentity); err != nil {
			return fmt.Errorf("decode relational evidence source identity: %w", err)
		}
		if err := decodeJSON(subjectRefs, &evidence.SubjectRefs); err != nil {
			return fmt.Errorf("decode relational evidence subject refs: %w", err)
		}
		if err := decodeJSON(relatedRefs, &evidence.RelatedEvidenceRefs); err != nil {
			return fmt.Errorf("decode relational evidence related refs: %w", err)
		}
		if err := decodeJSON(signatureRefs, &evidence.SignatureRefs); err != nil {
			return fmt.Errorf("decode relational evidence signature refs: %w", err)
		}
		if err := decodeJSON(tags, &evidence.Tags); err != nil {
			return fmt.Errorf("decode relational evidence tags: %w", err)
		}
		if err := decodeJSON(metadata, &evidence.Metadata); err != nil {
			return fmt.Errorf("decode relational evidence metadata: %w", err)
		}
		if err := decodeJSON(warnings, &evidence.Warnings); err != nil {
			return fmt.Errorf("decode relational evidence warnings: %w", err)
		}
		if err := decodeJSON(limitations, &evidence.Limitations); err != nil {
			return fmt.Errorf("decode relational evidence limitations: %w", err)
		}
		state.Evidence[evidence.ID] = evidence
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalAuditChain(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, sequence, entry_type, subject_type, subject_id,
		       actor_type, actor_id, occurred_at, payload_hash,
		       canonical_entry_hash, previous_entry_hash, entry_hash,
		       signature_ref, metadata, schema_version
		FROM audit_chain_entries
		ORDER BY tenant_id, sequence
	`)
	if err != nil {
		return fmt.Errorf("load relational audit chain: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var entry domain.AuditChainEntry
		var payloadHash, signatureRef sql.NullString
		var metadata []byte
		if err := rows.Scan(
			&entry.ID, &entry.TenantID, &entry.Sequence, &entry.EntryType, &entry.SubjectType, &entry.SubjectID,
			&entry.ActorType, &entry.ActorID, &entry.OccurredAt, &payloadHash,
			&entry.CanonicalEntryHash, &entry.PreviousEntryHash, &entry.EntryHash,
			&signatureRef, &metadata, &entry.SchemaVersion,
		); err != nil {
			return fmt.Errorf("scan relational audit chain entry: %w", err)
		}
		entry.PayloadHash = nullableSQLString(payloadHash)
		entry.SignatureRef = nullableSQLString(signatureRef)
		if err := decodeJSON(metadata, &entry.Metadata); err != nil {
			return fmt.Errorf("decode relational audit metadata: %w", err)
		}
		state.Chain[entry.TenantID] = append(state.Chain[entry.TenantID], entry)
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalSigning(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	keyRows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, kid, algorithm, status, public_key,
		       encrypted_private_key, created_at, revoked_at
		FROM signing_keys
	`)
	if err != nil {
		return fmt.Errorf("load relational signing keys: %w", err)
	}
	defer keyRows.Close()
	for keyRows.Next() {
		var key domain.SigningKey
		var private []byte
		var revokedAt sql.NullTime
		if err := keyRows.Scan(&key.ID, &key.TenantID, &key.KID, &key.Algorithm, &key.Status, &key.PublicKey, &private, &key.CreatedAt, &revokedAt); err != nil {
			return fmt.Errorf("scan relational signing key: %w", err)
		}
		key.RevokedAt = nullableSQLTime(revokedAt)
		state.SigningKeys[key.ID] = key
		if len(private) != 0 {
			state.SigningKeyPrivate[key.ID] = append([]byte(nil), private...)
		}
		*loaded = true
	}
	if err := keyRows.Err(); err != nil {
		return err
	}

	sigRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, subject_type, subject_id, key_id, algorithm, value, created_at FROM signatures`)
	if err != nil {
		return fmt.Errorf("load relational signatures: %w", err)
	}
	defer sigRows.Close()
	for sigRows.Next() {
		var signature domain.Signature
		if err := sigRows.Scan(&signature.ID, &signature.TenantID, &signature.SubjectType, &signature.SubjectID, &signature.KeyID, &signature.Algorithm, &signature.Value, &signature.CreatedAt); err != nil {
			return fmt.Errorf("scan relational signature: %w", err)
		}
		state.Signatures[signature.ID] = signature
		*loaded = true
	}
	return sigRows.Err()
}

func (s *Store) loadRelationalParsedResources(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	if err := s.loadRelationalSBOMs(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalScans(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalContracts(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalPolicies(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalBundles(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalVerifications(ctx, state, loaded); err != nil {
		return err
	}
	return nil
}

func (s *Store) loadRelationalSBOMs(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, evidence_id, release_id, artifact_id, format, spec_version, component_count, components, created_at FROM sboms`)
	if err != nil {
		return fmt.Errorf("load relational sboms: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sbom domain.SBOM
		var releaseID, artifactID sql.NullString
		var components []byte
		if err := rows.Scan(&sbom.ID, &sbom.TenantID, &sbom.EvidenceID, &releaseID, &artifactID, &sbom.Format, &sbom.SpecVersion, &sbom.ComponentCount, &components, &sbom.CreatedAt); err != nil {
			return fmt.Errorf("scan relational sbom: %w", err)
		}
		sbom.ReleaseID = nullableSQLString(releaseID)
		sbom.ArtifactID = nullableSQLString(artifactID)
		if err := decodeJSON(components, &sbom.Components); err != nil {
			return fmt.Errorf("decode relational sbom components: %w", err)
		}
		state.SBOMs[sbom.ID] = sbom
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalScans(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, evidence_id, release_id, scanner, target_ref, summary, findings, created_at FROM vulnerability_scans`)
	if err != nil {
		return fmt.Errorf("load relational vulnerability scans: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var scan domain.VulnerabilityScan
		var releaseID sql.NullString
		var summary, findings []byte
		if err := rows.Scan(&scan.ID, &scan.TenantID, &scan.EvidenceID, &releaseID, &scan.Scanner, &scan.TargetRef, &summary, &findings, &scan.CreatedAt); err != nil {
			return fmt.Errorf("scan relational vulnerability scan: %w", err)
		}
		scan.ReleaseID = nullableSQLString(releaseID)
		if err := decodeJSON(summary, &scan.Summary); err != nil {
			return fmt.Errorf("decode relational vulnerability scan summary: %w", err)
		}
		if err := decodeJSON(findings, &scan.Findings); err != nil {
			return fmt.Errorf("decode relational vulnerability scan findings: %w", err)
		}
		state.Scans[scan.ID] = scan
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalContracts(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, product_id, release_id, version, hash, path_count, operations, evidence_id, created_at FROM openapi_contracts`)
	if err != nil {
		return fmt.Errorf("load relational openapi contracts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var contract domain.OpenAPIContract
		var releaseID sql.NullString
		var operations []byte
		if err := rows.Scan(&contract.ID, &contract.TenantID, &contract.ProductID, &releaseID, &contract.Version, &contract.Hash, &contract.PathCount, &operations, &contract.EvidenceID, &contract.CreatedAt); err != nil {
			return fmt.Errorf("scan relational openapi contract: %w", err)
		}
		contract.ReleaseID = nullableSQLString(releaseID)
		if err := decodeJSON(operations, &contract.Operations); err != nil {
			return fmt.Errorf("decode relational openapi operations: %w", err)
		}
		state.Contracts[contract.ID] = contract
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalPolicies(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, release_id, result, policy_set, checks, created_at FROM policy_evaluations`)
	if err != nil {
		return fmt.Errorf("load relational policy evaluations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var policy domain.PolicyEvaluation
		var checks []byte
		if err := rows.Scan(&policy.ID, &policy.TenantID, &policy.ReleaseID, &policy.Result, &policy.PolicySet, &checks, &policy.CreatedAt); err != nil {
			return fmt.Errorf("scan relational policy evaluation: %w", err)
		}
		if err := decodeJSON(checks, &policy.Checks); err != nil {
			return fmt.Errorf("decode relational policy checks: %w", err)
		}
		state.Policies[policy.ID] = policy
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalBundles(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, release_id, state, manifest, manifest_hash, signature_refs, created_at, published_at, revoked_at FROM release_bundles`)
	if err != nil {
		return fmt.Errorf("load relational release bundles: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var bundle domain.ReleaseBundle
		var manifest, signatureRefs []byte
		var publishedAt, revokedAt sql.NullTime
		if err := rows.Scan(&bundle.ID, &bundle.TenantID, &bundle.ReleaseID, &bundle.State, &manifest, &bundle.ManifestHash, &signatureRefs, &bundle.CreatedAt, &publishedAt, &revokedAt); err != nil {
			return fmt.Errorf("scan relational release bundle: %w", err)
		}
		if err := decodeJSON(manifest, &bundle.Manifest); err != nil {
			return fmt.Errorf("decode relational release bundle manifest: %w", err)
		}
		if err := decodeJSON(signatureRefs, &bundle.SignatureRefs); err != nil {
			return fmt.Errorf("decode relational release bundle signature refs: %w", err)
		}
		bundle.PublishedAt = nullableSQLTime(publishedAt)
		bundle.RevokedAt = nullableSQLTime(revokedAt)
		state.Bundles[bundle.ID] = bundle
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalVerifications(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, subject_type, subject_id, result, checks, verified_at FROM verification_results`)
	if err != nil {
		return fmt.Errorf("load relational verification results: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var verification domain.VerificationResult
		var checks []byte
		if err := rows.Scan(&verification.ID, &verification.TenantID, &verification.SubjectType, &verification.SubjectID, &verification.Result, &checks, &verification.VerifiedAt); err != nil {
			return fmt.Errorf("scan relational verification result: %w", err)
		}
		if err := decodeJSON(checks, &verification.Checks); err != nil {
			return fmt.Errorf("decode relational verification checks: %w", err)
		}
		state.Verifications[verification.ID] = verification
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) loadRelationalPackageReportRetention(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	if err := s.loadRelationalPackages(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalReports(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalRetention(ctx, state, loaded); err != nil {
		return err
	}
	return nil
}

func (s *Store) loadRelationalPackages(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	profileRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, description, allowed_types, excluded_fields, schema_version, created_at FROM redaction_profiles`)
	if err != nil {
		return fmt.Errorf("load relational redaction profiles: %w", err)
	}
	defer profileRows.Close()
	for profileRows.Next() {
		var profile domain.RedactionProfile
		var description sql.NullString
		if err := profileRows.Scan(&profile.ID, &profile.TenantID, &profile.Name, &description, &profile.AllowedTypes, &profile.ExcludedFields, &profile.SchemaVersion, &profile.CreatedAt); err != nil {
			return fmt.Errorf("scan relational redaction profile: %w", err)
		}
		profile.Description = nullableSQLString(description)
		state.RedactionProfiles[profile.ID] = profile
		*loaded = true
	}
	if err := profileRows.Err(); err != nil {
		return err
	}

	packageRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, product_id, release_id, redaction_profile_id, title, state, manifest, manifest_hash, expires_at, access_count, schema_version, created_at FROM customer_security_packages`)
	if err != nil {
		return fmt.Errorf("load relational customer packages: %w", err)
	}
	defer packageRows.Close()
	for packageRows.Next() {
		var pkg domain.CustomerSecurityPackage
		var releaseID sql.NullString
		var manifest []byte
		if err := packageRows.Scan(&pkg.ID, &pkg.TenantID, &pkg.ProductID, &releaseID, &pkg.RedactionProfileID, &pkg.Title, &pkg.State, &manifest, &pkg.ManifestHash, &pkg.ExpiresAt, &pkg.AccessCount, &pkg.SchemaVersion, &pkg.CreatedAt); err != nil {
			return fmt.Errorf("scan relational customer package: %w", err)
		}
		pkg.ReleaseID = nullableSQLString(releaseID)
		if err := decodeJSON(manifest, &pkg.Manifest); err != nil {
			return fmt.Errorf("decode relational customer package manifest: %w", err)
		}
		state.CustomerPackages[pkg.ID] = pkg
		*loaded = true
	}
	if err := packageRows.Err(); err != nil {
		return err
	}

	bundleRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, release_id, evidence_ids, manifest, manifest_hash, signature_refs, verification_text, schema_version, created_at FROM evidence_bundles`)
	if err != nil {
		return fmt.Errorf("load relational evidence bundles: %w", err)
	}
	defer bundleRows.Close()
	for bundleRows.Next() {
		var bundle domain.EvidenceBundle
		var releaseID sql.NullString
		var manifest []byte
		if err := bundleRows.Scan(&bundle.ID, &bundle.TenantID, &releaseID, &bundle.EvidenceIDs, &manifest, &bundle.ManifestHash, &bundle.SignatureRefs, &bundle.VerificationText, &bundle.SchemaVersion, &bundle.CreatedAt); err != nil {
			return fmt.Errorf("scan relational evidence bundle: %w", err)
		}
		bundle.ReleaseID = nullableSQLString(releaseID)
		if err := decodeJSON(manifest, &bundle.Manifest); err != nil {
			return fmt.Errorf("decode relational evidence bundle manifest: %w", err)
		}
		state.EvidenceBundles[bundle.ID] = bundle
		*loaded = true
	}
	if err := bundleRows.Err(); err != nil {
		return err
	}

	importRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, bundle_hash, result, imported_count, schema_version, created_at FROM evidence_bundle_imports`)
	if err != nil {
		return fmt.Errorf("load relational evidence bundle imports: %w", err)
	}
	defer importRows.Close()
	for importRows.Next() {
		var imported domain.EvidenceBundleImport
		if err := importRows.Scan(&imported.ID, &imported.TenantID, &imported.BundleHash, &imported.Result, &imported.ImportedCount, &imported.SchemaVersion, &imported.CreatedAt); err != nil {
			return fmt.Errorf("scan relational evidence bundle import: %w", err)
		}
		state.BundleImports[imported.ID] = imported
		*loaded = true
	}
	return importRows.Err()
}

func (s *Store) loadRelationalReports(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	htmlRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, report_type, product_id, release_id, html, hash, schema_version, created_at FROM html_report_packages`)
	if err != nil {
		return fmt.Errorf("load relational html reports: %w", err)
	}
	defer htmlRows.Close()
	for htmlRows.Next() {
		var report domain.HTMLReportPackage
		var releaseID sql.NullString
		if err := htmlRows.Scan(&report.ID, &report.TenantID, &report.ReportType, &report.ProductID, &releaseID, &report.HTML, &report.Hash, &report.SchemaVersion, &report.CreatedAt); err != nil {
			return fmt.Errorf("scan relational html report: %w", err)
		}
		report.ReleaseID = nullableSQLString(releaseID)
		state.HTMLReports[report.ID] = report
		*loaded = true
	}
	if err := htmlRows.Err(); err != nil {
		return err
	}

	templateRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, version, report_type, allowed_fields, template, schema_version, created_at FROM report_templates`)
	if err != nil {
		return fmt.Errorf("load relational report templates: %w", err)
	}
	defer templateRows.Close()
	for templateRows.Next() {
		var template domain.CustomReportTemplate
		if err := templateRows.Scan(&template.ID, &template.TenantID, &template.Name, &template.Version, &template.ReportType, &template.AllowedFields, &template.Template, &template.SchemaVersion, &template.CreatedAt); err != nil {
			return fmt.Errorf("scan relational report template: %w", err)
		}
		state.ReportTemplates[template.ID] = template
		*loaded = true
	}
	if err := templateRows.Err(); err != nil {
		return err
	}

	renderRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, template_id, subject_type, subject_id, output, hash, schema_version, created_at FROM rendered_reports`)
	if err != nil {
		return fmt.Errorf("load relational rendered reports: %w", err)
	}
	defer renderRows.Close()
	for renderRows.Next() {
		var report domain.RenderedCustomReport
		var output []byte
		if err := renderRows.Scan(&report.ID, &report.TenantID, &report.TemplateID, &report.SubjectType, &report.SubjectID, &output, &report.Hash, &report.SchemaVersion, &report.CreatedAt); err != nil {
			return fmt.Errorf("scan relational rendered report: %w", err)
		}
		if err := decodeJSON(output, &report.Output); err != nil {
			return fmt.Errorf("decode relational rendered report output: %w", err)
		}
		state.RenderedReports[report.ID] = report
		*loaded = true
	}
	if err := renderRows.Err(); err != nil {
		return err
	}

	pdfRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, report_type, product_id, release_id, title, payload_ref, payload_hash, payload_size, limitations, schema_version, created_at FROM pdf_report_packages`)
	if err != nil {
		return fmt.Errorf("load relational pdf reports: %w", err)
	}
	defer pdfRows.Close()
	for pdfRows.Next() {
		var report domain.PDFReportPackage
		var productID, releaseID, payloadRef sql.NullString
		if err := pdfRows.Scan(&report.ID, &report.TenantID, &report.ReportType, &productID, &releaseID, &report.Title, &payloadRef, &report.PayloadHash, &report.PayloadSize, &report.Limitations, &report.SchemaVersion, &report.CreatedAt); err != nil {
			return fmt.Errorf("scan relational pdf report: %w", err)
		}
		report.ProductID = nullableSQLString(productID)
		report.ReleaseID = nullableSQLString(releaseID)
		report.PayloadRef = nullableSQLString(payloadRef)
		state.PDFReports[report.ID] = report
		*loaded = true
	}
	if err := pdfRows.Err(); err != nil {
		return err
	}

	anomalyRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, subject_type, subject_id, result, signals, assumptions, limitations, schema_version, created_at FROM anomaly_reports`)
	if err != nil {
		return fmt.Errorf("load relational anomaly reports: %w", err)
	}
	defer anomalyRows.Close()
	for anomalyRows.Next() {
		var report domain.AnomalyReport
		var signals []byte
		if err := anomalyRows.Scan(&report.ID, &report.TenantID, &report.SubjectType, &report.SubjectID, &report.Result, &signals, &report.Assumptions, &report.Limitations, &report.SchemaVersion, &report.CreatedAt); err != nil {
			return fmt.Errorf("scan relational anomaly report: %w", err)
		}
		if err := decodeJSON(signals, &report.Signals); err != nil {
			return fmt.Errorf("decode relational anomaly report signals: %w", err)
		}
		state.AnomalyReports[report.ID] = report
		*loaded = true
	}
	return anomalyRows.Err()
}

func (s *Store) loadRelationalRetention(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	policyRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, object_prefix, mode, retention_days, status, verified_at, verification_hash, verification_checks, verification_limitations, schema_version, created_at FROM object_retention_policies`)
	if err != nil {
		return fmt.Errorf("load relational object retention policies: %w", err)
	}
	defer policyRows.Close()
	for policyRows.Next() {
		var policy domain.ObjectRetentionPolicy
		var verifiedAt sql.NullTime
		var verificationHash sql.NullString
		var checks []byte
		if err := policyRows.Scan(&policy.ID, &policy.TenantID, &policy.Name, &policy.ObjectPrefix, &policy.Mode, &policy.RetentionDays, &policy.Status, &verifiedAt, &verificationHash, &checks, &policy.VerificationLimitations, &policy.SchemaVersion, &policy.CreatedAt); err != nil {
			return fmt.Errorf("scan relational object retention policy: %w", err)
		}
		policy.VerifiedAt = nullableSQLTime(verifiedAt)
		policy.VerificationHash = nullableSQLString(verificationHash)
		if err := decodeJSON(checks, &policy.VerificationChecks); err != nil {
			return fmt.Errorf("decode relational object retention checks: %w", err)
		}
		state.ObjectRetentionPolicies[policy.ID] = policy
		*loaded = true
	}
	if err := policyRows.Err(); err != nil {
		return err
	}

	backupRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, state_hash, resource_counts, consistency_checks, limitations, schema_version, created_at FROM backup_manifests`)
	if err != nil {
		return fmt.Errorf("load relational backup manifests: %w", err)
	}
	defer backupRows.Close()
	for backupRows.Next() {
		var manifest domain.BackupManifest
		var counts, checks []byte
		if err := backupRows.Scan(&manifest.ID, &manifest.TenantID, &manifest.StateHash, &counts, &checks, &manifest.Limitations, &manifest.SchemaVersion, &manifest.CreatedAt); err != nil {
			return fmt.Errorf("scan relational backup manifest: %w", err)
		}
		if err := decodeJSON(counts, &manifest.ResourceCounts); err != nil {
			return fmt.Errorf("decode relational backup manifest counts: %w", err)
		}
		if err := decodeJSON(checks, &manifest.ConsistencyChecks); err != nil {
			return fmt.Errorf("decode relational backup manifest checks: %w", err)
		}
		state.BackupManifests[manifest.ID] = manifest
		*loaded = true
	}
	if err := backupRows.Err(); err != nil {
		return err
	}

	holdRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, scope_type, scope_id, reason, owner, released_at, schema_version, created_at FROM legal_holds`)
	if err != nil {
		return fmt.Errorf("load relational legal holds: %w", err)
	}
	defer holdRows.Close()
	for holdRows.Next() {
		var hold domain.LegalHold
		var releasedAt sql.NullTime
		if err := holdRows.Scan(&hold.ID, &hold.TenantID, &hold.ScopeType, &hold.ScopeID, &hold.Reason, &hold.Owner, &releasedAt, &hold.SchemaVersion, &hold.CreatedAt); err != nil {
			return fmt.Errorf("scan relational legal hold: %w", err)
		}
		hold.ReleasedAt = nullableSQLTime(releasedAt)
		state.LegalHolds[hold.ID] = hold
		*loaded = true
	}
	if err := holdRows.Err(); err != nil {
		return err
	}

	overrideRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, scope_type, scope_id, retention_until, reason, owner, schema_version, created_at FROM retention_overrides`)
	if err != nil {
		return fmt.Errorf("load relational retention overrides: %w", err)
	}
	defer overrideRows.Close()
	for overrideRows.Next() {
		var override domain.RetentionOverride
		if err := overrideRows.Scan(&override.ID, &override.TenantID, &override.ScopeType, &override.ScopeID, &override.RetentionUntil, &override.Reason, &override.Owner, &override.SchemaVersion, &override.CreatedAt); err != nil {
			return fmt.Errorf("scan relational retention override: %w", err)
		}
		state.RetentionOverrides[override.ID] = override
		*loaded = true
	}
	if err := overrideRows.Err(); err != nil {
		return err
	}

	questionRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, version, questions, schema_version, created_at FROM questionnaire_templates`)
	if err != nil {
		return fmt.Errorf("load relational questionnaire templates: %w", err)
	}
	defer questionRows.Close()
	for questionRows.Next() {
		var template domain.QuestionnaireTemplate
		var questions []byte
		if err := questionRows.Scan(&template.ID, &template.TenantID, &template.Name, &template.Version, &questions, &template.SchemaVersion, &template.CreatedAt); err != nil {
			return fmt.Errorf("scan relational questionnaire template: %w", err)
		}
		if err := decodeJSON(questions, &template.Questions); err != nil {
			return fmt.Errorf("decode relational questionnaire questions: %w", err)
		}
		state.QuestionnaireTemplates[template.ID] = template
		*loaded = true
	}
	if err := questionRows.Err(); err != nil {
		return err
	}

	qpRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, template_id, package_id, product_id, release_id, responses, manifest_hash, schema_version, created_at FROM questionnaire_packages`)
	if err != nil {
		return fmt.Errorf("load relational questionnaire packages: %w", err)
	}
	defer qpRows.Close()
	for qpRows.Next() {
		var pkg domain.QuestionnairePackage
		var packageID, productID, releaseID sql.NullString
		var responses []byte
		if err := qpRows.Scan(&pkg.ID, &pkg.TenantID, &pkg.TemplateID, &packageID, &productID, &releaseID, &responses, &pkg.ManifestHash, &pkg.SchemaVersion, &pkg.CreatedAt); err != nil {
			return fmt.Errorf("scan relational questionnaire package: %w", err)
		}
		pkg.PackageID = nullableSQLString(packageID)
		pkg.ProductID = nullableSQLString(productID)
		pkg.ReleaseID = nullableSQLString(releaseID)
		if err := decodeJSON(responses, &pkg.Responses); err != nil {
			return fmt.Errorf("decode relational questionnaire responses: %w", err)
		}
		state.QuestionnairePackages[pkg.ID] = pkg
		*loaded = true
	}
	return qpRows.Err()
}

func (s *Store) loadRelationalIdempotency(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	rows, err := s.pool.Query(ctx, `SELECT tenant_id, actor_key_id, method, path, idempotency_key, request_hash, status, response, created_at FROM idempotency_records`)
	if err != nil {
		return fmt.Errorf("load relational idempotency records: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tenantID, actorID, method, path, idempotencyKey string
		var record app.IdempotencyRecord
		var response []byte
		if err := rows.Scan(&tenantID, &actorID, &method, &path, &idempotencyKey, &record.RequestHash, &record.Status, &response, &record.CreatedAt); err != nil {
			return fmt.Errorf("scan relational idempotency record: %w", err)
		}
		if err := decodeJSON(response, &record.Response); err != nil {
			return fmt.Errorf("decode relational idempotency response: %w", err)
		}
		key := app.NewIdempotencyRecordKey(tenantID, actorID, method, path, idempotencyKey)
		state.Idempotency[key] = record
		*loaded = true
	}
	return rows.Err()
}

func (s *Store) SaveState(ctx context.Context, state app.PersistedState) error {
	body, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode ledger state: %w", err)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin save ledger state transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO ledger_state (id, state, updated_at)
		VALUES ('default', $1, now())
		ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, updated_at = EXCLUDED.updated_at
	`, body)
	if err != nil {
		return fmt.Errorf("save ledger state: %w", err)
	}
	if err := syncResourceIndex(ctx, tx, state); err != nil {
		return err
	}
	if err := syncIdentityAndIdempotency(ctx, tx, state); err != nil {
		return err
	}
	if err := syncReleaseLedgerCore(ctx, tx, state); err != nil {
		return err
	}
	if err := syncPackageReportRetentionRows(ctx, tx, state); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit save ledger state transaction: %w", err)
	}
	return nil
}

func syncReleaseLedgerCore(ctx context.Context, tx pgx.Tx, state app.PersistedState) error {
	for _, product := range state.Products {
		if product.ID == "" || product.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO products (id, tenant_id, name, slug, created_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, slug = EXCLUDED.slug
		`, product.ID, product.TenantID, product.Name, product.Slug, nonZeroTime(product.CreatedAt)); err != nil {
			return fmt.Errorf("upsert product row: %w", err)
		}
	}
	for _, project := range state.Projects {
		if project.ID == "" || project.TenantID == "" || project.ProductID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO projects (id, tenant_id, product_id, name, created_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (id) DO UPDATE SET product_id = EXCLUDED.product_id, name = EXCLUDED.name
		`, project.ID, project.TenantID, project.ProductID, project.Name, nonZeroTime(project.CreatedAt)); err != nil {
			return fmt.Errorf("upsert project row: %w", err)
		}
	}
	for _, release := range state.Releases {
		if release.ID == "" || release.TenantID == "" || release.ProductID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO releases (id, tenant_id, product_id, version, state, frozen_at, approved_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (id) DO UPDATE SET
				state = EXCLUDED.state,
				frozen_at = EXCLUDED.frozen_at,
				approved_at = EXCLUDED.approved_at
		`, release.ID, release.TenantID, release.ProductID, release.Version, release.State, nullableTime(release.FrozenAt), nullableTime(release.ApprovedAt), nonZeroTime(release.CreatedAt)); err != nil {
			return fmt.Errorf("upsert release row: %w", err)
		}
	}
	for _, artifact := range state.Artifacts {
		if artifact.ID == "" || artifact.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO artifacts (id, tenant_id, name, media_type, size, digest, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				media_type = EXCLUDED.media_type,
				size = EXCLUDED.size,
				digest = EXCLUDED.digest
		`, artifact.ID, artifact.TenantID, artifact.Name, artifact.MediaType, artifact.Size, artifact.Digest, nonZeroTime(artifact.CreatedAt)); err != nil {
			return fmt.Errorf("upsert artifact row: %w", err)
		}
	}
	for _, evidence := range state.Evidence {
		if evidence.ID == "" || evidence.TenantID == "" {
			continue
		}
		sourceIdentity, err := json.Marshal(evidence.SourceIdentity)
		if err != nil {
			return fmt.Errorf("encode evidence source identity: %w", err)
		}
		subjectRefs, err := json.Marshal(evidence.SubjectRefs)
		if err != nil {
			return fmt.Errorf("encode evidence subject refs: %w", err)
		}
		relatedRefs, err := json.Marshal(evidence.RelatedEvidenceRefs)
		if err != nil {
			return fmt.Errorf("encode evidence related refs: %w", err)
		}
		signatureRefs, err := json.Marshal(evidence.SignatureRefs)
		if err != nil {
			return fmt.Errorf("encode evidence signature refs: %w", err)
		}
		tags, err := json.Marshal(evidence.Tags)
		if err != nil {
			return fmt.Errorf("encode evidence tags: %w", err)
		}
		metadata, err := json.Marshal(evidence.Metadata)
		if err != nil {
			return fmt.Errorf("encode evidence metadata: %w", err)
		}
		warnings, err := json.Marshal(evidence.Warnings)
		if err != nil {
			return fmt.Errorf("encode evidence warnings: %w", err)
		}
		limitations, err := json.Marshal(evidence.Limitations)
		if err != nil {
			return fmt.Errorf("encode evidence limitations: %w", err)
		}
		if _, err := tx.Exec(ctx, `
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
			ON CONFLICT (id) DO UPDATE SET
				superseded_by = EXCLUDED.superseded_by,
				verification_status = EXCLUDED.verification_status,
				signature_refs = EXCLUDED.signature_refs,
				chain_entry_id = EXCLUDED.chain_entry_id,
				tags = EXCLUDED.tags,
				metadata = EXCLUDED.metadata,
				warnings = EXCLUDED.warnings,
				limitations = EXCLUDED.limitations
		`, evidence.ID, evidence.TenantID, nullableString(evidence.ProductID), nullableString(evidence.ProjectID), nullableString(evidence.ReleaseID), nullableString(evidence.BuildID), nullableString(evidence.DeploymentID),
			evidence.Type, nullableString(evidence.Subtype), evidence.Title, evidence.SourceSystem, sourceIdentity, nullableString(evidence.CollectorID),
			nullableString(evidence.UploadedBy), nonZeroTime(evidence.ObservedAt), nonZeroInt(evidence.EvidenceVersion, 1), evidence.SchemaVersion, nullableString(evidence.PayloadRef),
			evidence.PayloadHash, nullableString(evidence.PayloadMediaType), nullableInt64(evidence.PayloadSize), evidence.CanonicalHash,
			evidence.Canonicalization, subjectRefs, relatedRefs, nullableString(evidence.Supersedes),
			nullableString(evidence.SupersededBy), evidence.TrustLevel, evidence.VerificationStatus, signatureRefs,
			nullableString(evidence.ChainEntryID), tags, metadata, warnings, limitations, nonZeroTime(evidence.CreatedAt)); err != nil {
			return fmt.Errorf("upsert evidence item row: %w", err)
		}
	}
	for _, tenantChain := range state.Chain {
		for _, entry := range tenantChain {
			if entry.ID == "" || entry.TenantID == "" {
				continue
			}
			metadata, err := json.Marshal(entry.Metadata)
			if err != nil {
				return fmt.Errorf("encode audit chain metadata: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO audit_chain_entries (
					id, tenant_id, sequence, entry_type, subject_type, subject_id,
					actor_type, actor_id, occurred_at, payload_hash,
					canonical_entry_hash, previous_entry_hash, entry_hash,
					signature_ref, metadata, schema_version
				)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
				ON CONFLICT (id) DO NOTHING
			`, entry.ID, entry.TenantID, entry.Sequence, entry.EntryType, entry.SubjectType, entry.SubjectID,
				entry.ActorType, entry.ActorID, nonZeroTime(entry.OccurredAt), nullableString(entry.PayloadHash),
				entry.CanonicalEntryHash, entry.PreviousEntryHash, entry.EntryHash,
				nullableString(entry.SignatureRef), metadata, entry.SchemaVersion); err != nil {
				return fmt.Errorf("insert audit chain row: %w", err)
			}
		}
	}
	for id, key := range state.SigningKeys {
		if key.ID == "" || key.TenantID == "" {
			continue
		}
		private := state.SigningKeyPrivate[id]
		if len(private) == 0 {
			private = key.Private
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO signing_keys (
				id, tenant_id, kid, algorithm, status, public_key,
				encrypted_private_key, created_at, revoked_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET
				status = EXCLUDED.status,
				public_key = EXCLUDED.public_key,
				encrypted_private_key = EXCLUDED.encrypted_private_key,
				revoked_at = EXCLUDED.revoked_at
		`, key.ID, key.TenantID, key.KID, key.Algorithm, key.Status, key.PublicKey, nullableBytes(private), nonZeroTime(key.CreatedAt), nullableTime(key.RevokedAt)); err != nil {
			return fmt.Errorf("upsert signing key row: %w", err)
		}
	}
	for _, signature := range state.Signatures {
		if signature.ID == "" || signature.TenantID == "" || signature.KeyID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO signatures (
				id, tenant_id, subject_type, subject_id, key_id, algorithm, value, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (id) DO NOTHING
		`, signature.ID, signature.TenantID, signature.SubjectType, signature.SubjectID, signature.KeyID, signature.Algorithm, signature.Value, nonZeroTime(signature.CreatedAt)); err != nil {
			return fmt.Errorf("insert signature row: %w", err)
		}
	}
	for _, sbom := range state.SBOMs {
		if sbom.ID == "" || sbom.TenantID == "" || sbom.EvidenceID == "" {
			continue
		}
		components, err := json.Marshal(sbom.Components)
		if err != nil {
			return fmt.Errorf("encode sbom components: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO sboms (
				id, tenant_id, evidence_id, release_id, artifact_id, format,
				spec_version, component_count, components, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET components = EXCLUDED.components, component_count = EXCLUDED.component_count
		`, sbom.ID, sbom.TenantID, sbom.EvidenceID, nullableString(sbom.ReleaseID), nullableString(sbom.ArtifactID), sbom.Format, sbom.SpecVersion, sbom.ComponentCount, components, nonZeroTime(sbom.CreatedAt)); err != nil {
			return fmt.Errorf("upsert sbom row: %w", err)
		}
	}
	for _, scan := range state.Scans {
		if scan.ID == "" || scan.TenantID == "" || scan.EvidenceID == "" {
			continue
		}
		summary, err := json.Marshal(scan.Summary)
		if err != nil {
			return fmt.Errorf("encode vulnerability scan summary: %w", err)
		}
		findings, err := json.Marshal(scan.Findings)
		if err != nil {
			return fmt.Errorf("encode vulnerability scan findings: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO vulnerability_scans (
				id, tenant_id, evidence_id, release_id, scanner, target_ref,
				summary, findings, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET summary = EXCLUDED.summary, findings = EXCLUDED.findings
		`, scan.ID, scan.TenantID, scan.EvidenceID, nullableString(scan.ReleaseID), scan.Scanner, scan.TargetRef, summary, findings, nonZeroTime(scan.CreatedAt)); err != nil {
			return fmt.Errorf("upsert vulnerability scan row: %w", err)
		}
	}
	for _, contract := range state.Contracts {
		if contract.ID == "" || contract.TenantID == "" || contract.ProductID == "" || contract.EvidenceID == "" {
			continue
		}
		operations, err := json.Marshal(contract.Operations)
		if err != nil {
			return fmt.Errorf("encode openapi operations: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO openapi_contracts (
				id, tenant_id, product_id, release_id, version, hash,
				path_count, operations, evidence_id, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET path_count = EXCLUDED.path_count, operations = EXCLUDED.operations
		`, contract.ID, contract.TenantID, contract.ProductID, nullableString(contract.ReleaseID), contract.Version, contract.Hash, contract.PathCount, operations, contract.EvidenceID, nonZeroTime(contract.CreatedAt)); err != nil {
			return fmt.Errorf("upsert openapi contract row: %w", err)
		}
	}
	for _, policy := range state.Policies {
		if policy.ID == "" || policy.TenantID == "" || policy.ReleaseID == "" {
			continue
		}
		checks, err := json.Marshal(policy.Checks)
		if err != nil {
			return fmt.Errorf("encode policy checks: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO policy_evaluations (
				id, tenant_id, release_id, result, policy_set, checks, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET result = EXCLUDED.result, checks = EXCLUDED.checks
		`, policy.ID, policy.TenantID, policy.ReleaseID, policy.Result, policy.PolicySet, checks, nonZeroTime(policy.CreatedAt)); err != nil {
			return fmt.Errorf("upsert policy evaluation row: %w", err)
		}
	}
	for _, bundle := range state.Bundles {
		if bundle.ID == "" || bundle.TenantID == "" || bundle.ReleaseID == "" {
			continue
		}
		manifest, err := json.Marshal(bundle.Manifest)
		if err != nil {
			return fmt.Errorf("encode release bundle manifest: %w", err)
		}
		signatureRefs, err := json.Marshal(bundle.SignatureRefs)
		if err != nil {
			return fmt.Errorf("encode release bundle signature refs: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO release_bundles (
				id, tenant_id, release_id, state, manifest, manifest_hash,
				signature_refs, created_at, published_at, revoked_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET
				state = EXCLUDED.state,
				signature_refs = EXCLUDED.signature_refs,
				published_at = EXCLUDED.published_at,
				revoked_at = EXCLUDED.revoked_at
		`, bundle.ID, bundle.TenantID, bundle.ReleaseID, bundle.State, manifest, bundle.ManifestHash, signatureRefs, nonZeroTime(bundle.CreatedAt), nullableTime(bundle.PublishedAt), nullableTime(bundle.RevokedAt)); err != nil {
			return fmt.Errorf("upsert release bundle row: %w", err)
		}
	}
	for _, verification := range state.Verifications {
		if verification.ID == "" || verification.TenantID == "" {
			continue
		}
		checks, err := json.Marshal(verification.Checks)
		if err != nil {
			return fmt.Errorf("encode verification checks: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO verification_results (
				id, tenant_id, subject_type, subject_id, result, checks, verified_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET result = EXCLUDED.result, checks = EXCLUDED.checks
		`, verification.ID, verification.TenantID, verification.SubjectType, verification.SubjectID, verification.Result, checks, nonZeroTime(verification.VerifiedAt)); err != nil {
			return fmt.Errorf("upsert verification result row: %w", err)
		}
	}
	return nil
}

func syncPackageReportRetentionRows(ctx context.Context, tx pgx.Tx, state app.PersistedState) error {
	for _, profile := range state.RedactionProfiles {
		if profile.ID == "" || profile.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO redaction_profiles (
				id, tenant_id, name, description, allowed_types, excluded_fields,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				description = EXCLUDED.description,
				allowed_types = EXCLUDED.allowed_types,
				excluded_fields = EXCLUDED.excluded_fields,
				schema_version = EXCLUDED.schema_version
		`, profile.ID, profile.TenantID, profile.Name, nullableString(profile.Description), profile.AllowedTypes, profile.ExcludedFields, profile.SchemaVersion, nonZeroTime(profile.CreatedAt)); err != nil {
			return fmt.Errorf("upsert redaction profile row: %w", err)
		}
	}
	for _, pkg := range state.CustomerPackages {
		if pkg.ID == "" || pkg.TenantID == "" {
			continue
		}
		manifest, err := json.Marshal(pkg.Manifest)
		if err != nil {
			return fmt.Errorf("encode customer package manifest: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO customer_security_packages (
				id, tenant_id, product_id, release_id, redaction_profile_id,
				title, state, manifest, manifest_hash, expires_at, access_count,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			ON CONFLICT (id) DO UPDATE SET
				state = EXCLUDED.state,
				manifest = EXCLUDED.manifest,
				manifest_hash = EXCLUDED.manifest_hash,
				expires_at = EXCLUDED.expires_at,
				access_count = EXCLUDED.access_count,
				schema_version = EXCLUDED.schema_version
		`, pkg.ID, pkg.TenantID, pkg.ProductID, nullableString(pkg.ReleaseID), pkg.RedactionProfileID, pkg.Title, pkg.State, manifest, pkg.ManifestHash, pkg.ExpiresAt, pkg.AccessCount, pkg.SchemaVersion, nonZeroTime(pkg.CreatedAt)); err != nil {
			return fmt.Errorf("upsert customer package row: %w", err)
		}
	}
	for _, report := range state.HTMLReports {
		if report.ID == "" || report.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO html_report_packages (
				id, tenant_id, report_type, product_id, release_id, html, hash,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET html = EXCLUDED.html, hash = EXCLUDED.hash, schema_version = EXCLUDED.schema_version
		`, report.ID, report.TenantID, report.ReportType, report.ProductID, nullableString(report.ReleaseID), report.HTML, report.Hash, report.SchemaVersion, nonZeroTime(report.CreatedAt)); err != nil {
			return fmt.Errorf("upsert html report row: %w", err)
		}
	}
	for _, template := range state.ReportTemplates {
		if template.ID == "" || template.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO report_templates (
				id, tenant_id, name, version, report_type, allowed_fields,
				template, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET
				report_type = EXCLUDED.report_type,
				allowed_fields = EXCLUDED.allowed_fields,
				template = EXCLUDED.template,
				schema_version = EXCLUDED.schema_version
		`, template.ID, template.TenantID, template.Name, template.Version, template.ReportType, template.AllowedFields, template.Template, template.SchemaVersion, nonZeroTime(template.CreatedAt)); err != nil {
			return fmt.Errorf("upsert report template row: %w", err)
		}
	}
	for _, report := range state.RenderedReports {
		if report.ID == "" || report.TenantID == "" {
			continue
		}
		output, err := json.Marshal(report.Output)
		if err != nil {
			return fmt.Errorf("encode rendered report output: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO rendered_reports (
				id, tenant_id, template_id, subject_type, subject_id, output,
				hash, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET output = EXCLUDED.output, hash = EXCLUDED.hash, schema_version = EXCLUDED.schema_version
		`, report.ID, report.TenantID, report.TemplateID, report.SubjectType, report.SubjectID, output, report.Hash, report.SchemaVersion, nonZeroTime(report.CreatedAt)); err != nil {
			return fmt.Errorf("upsert rendered report row: %w", err)
		}
	}
	for _, bundle := range state.EvidenceBundles {
		if bundle.ID == "" || bundle.TenantID == "" {
			continue
		}
		manifest, err := json.Marshal(bundle.Manifest)
		if err != nil {
			return fmt.Errorf("encode evidence bundle manifest: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO evidence_bundles (
				id, tenant_id, release_id, evidence_ids, manifest, manifest_hash,
				signature_refs, verification_text, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET
				manifest = EXCLUDED.manifest,
				manifest_hash = EXCLUDED.manifest_hash,
				signature_refs = EXCLUDED.signature_refs,
				verification_text = EXCLUDED.verification_text,
				schema_version = EXCLUDED.schema_version
		`, bundle.ID, bundle.TenantID, nullableString(bundle.ReleaseID), bundle.EvidenceIDs, manifest, bundle.ManifestHash, bundle.SignatureRefs, bundle.VerificationText, bundle.SchemaVersion, nonZeroTime(bundle.CreatedAt)); err != nil {
			return fmt.Errorf("upsert evidence bundle row: %w", err)
		}
	}
	for _, imported := range state.BundleImports {
		if imported.ID == "" || imported.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO evidence_bundle_imports (
				id, tenant_id, bundle_hash, result, imported_count,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET result = EXCLUDED.result, imported_count = EXCLUDED.imported_count, schema_version = EXCLUDED.schema_version
		`, imported.ID, imported.TenantID, imported.BundleHash, imported.Result, imported.ImportedCount, imported.SchemaVersion, nonZeroTime(imported.CreatedAt)); err != nil {
			return fmt.Errorf("upsert evidence bundle import row: %w", err)
		}
	}
	for _, policy := range state.ObjectRetentionPolicies {
		if policy.ID == "" || policy.TenantID == "" {
			continue
		}
		checks, err := json.Marshal(policy.VerificationChecks)
		if err != nil {
			return fmt.Errorf("encode object retention checks: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO object_retention_policies (
				id, tenant_id, name, object_prefix, mode, retention_days, status,
				verified_at, verification_hash, verification_checks,
				verification_limitations, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			ON CONFLICT (id) DO UPDATE SET
				status = EXCLUDED.status,
				verified_at = EXCLUDED.verified_at,
				verification_hash = EXCLUDED.verification_hash,
				verification_checks = EXCLUDED.verification_checks,
				verification_limitations = EXCLUDED.verification_limitations,
				schema_version = EXCLUDED.schema_version
		`, policy.ID, policy.TenantID, policy.Name, policy.ObjectPrefix, policy.Mode, policy.RetentionDays, policy.Status, nullableTime(policy.VerifiedAt), nullableString(policy.VerificationHash), checks, policy.VerificationLimitations, policy.SchemaVersion, nonZeroTime(policy.CreatedAt)); err != nil {
			return fmt.Errorf("upsert object retention policy row: %w", err)
		}
	}
	for _, manifest := range state.BackupManifests {
		if manifest.ID == "" || manifest.TenantID == "" {
			continue
		}
		counts, err := json.Marshal(manifest.ResourceCounts)
		if err != nil {
			return fmt.Errorf("encode backup manifest counts: %w", err)
		}
		checks, err := json.Marshal(manifest.ConsistencyChecks)
		if err != nil {
			return fmt.Errorf("encode backup manifest checks: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO backup_manifests (
				id, tenant_id, state_hash, resource_counts, consistency_checks,
				limitations, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (id) DO UPDATE SET
				resource_counts = EXCLUDED.resource_counts,
				consistency_checks = EXCLUDED.consistency_checks,
				limitations = EXCLUDED.limitations,
				schema_version = EXCLUDED.schema_version
		`, manifest.ID, manifest.TenantID, manifest.StateHash, counts, checks, manifest.Limitations, manifest.SchemaVersion, nonZeroTime(manifest.CreatedAt)); err != nil {
			return fmt.Errorf("upsert backup manifest row: %w", err)
		}
	}
	for _, hold := range state.LegalHolds {
		if hold.ID == "" || hold.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO legal_holds (
				id, tenant_id, scope_type, scope_id, reason, owner, released_at,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET
				reason = EXCLUDED.reason,
				owner = EXCLUDED.owner,
				released_at = EXCLUDED.released_at,
				schema_version = EXCLUDED.schema_version
		`, hold.ID, hold.TenantID, hold.ScopeType, hold.ScopeID, hold.Reason, hold.Owner, nullableTime(hold.ReleasedAt), hold.SchemaVersion, nonZeroTime(hold.CreatedAt)); err != nil {
			return fmt.Errorf("upsert legal hold row: %w", err)
		}
	}
	for _, override := range state.RetentionOverrides {
		if override.ID == "" || override.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO retention_overrides (
				id, tenant_id, scope_type, scope_id, retention_until, reason,
				owner, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET
				retention_until = EXCLUDED.retention_until,
				reason = EXCLUDED.reason,
				owner = EXCLUDED.owner,
				schema_version = EXCLUDED.schema_version
		`, override.ID, override.TenantID, override.ScopeType, override.ScopeID, override.RetentionUntil, override.Reason, override.Owner, override.SchemaVersion, nonZeroTime(override.CreatedAt)); err != nil {
			return fmt.Errorf("upsert retention override row: %w", err)
		}
	}
	for _, template := range state.QuestionnaireTemplates {
		if template.ID == "" || template.TenantID == "" {
			continue
		}
		questions, err := json.Marshal(template.Questions)
		if err != nil {
			return fmt.Errorf("encode questionnaire template questions: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO questionnaire_templates (
				id, tenant_id, name, version, questions, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET questions = EXCLUDED.questions, schema_version = EXCLUDED.schema_version
		`, template.ID, template.TenantID, template.Name, template.Version, questions, template.SchemaVersion, nonZeroTime(template.CreatedAt)); err != nil {
			return fmt.Errorf("upsert questionnaire template row: %w", err)
		}
	}
	for _, pkg := range state.QuestionnairePackages {
		if pkg.ID == "" || pkg.TenantID == "" {
			continue
		}
		responses, err := json.Marshal(pkg.Responses)
		if err != nil {
			return fmt.Errorf("encode questionnaire package responses: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO questionnaire_packages (
				id, tenant_id, template_id, package_id, product_id, release_id,
				responses, manifest_hash, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET responses = EXCLUDED.responses, manifest_hash = EXCLUDED.manifest_hash, schema_version = EXCLUDED.schema_version
		`, pkg.ID, pkg.TenantID, pkg.TemplateID, nullableString(pkg.PackageID), nullableString(pkg.ProductID), nullableString(pkg.ReleaseID), responses, pkg.ManifestHash, pkg.SchemaVersion, nonZeroTime(pkg.CreatedAt)); err != nil {
			return fmt.Errorf("upsert questionnaire package row: %w", err)
		}
	}
	for _, report := range state.PDFReports {
		if report.ID == "" || report.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO pdf_report_packages (
				id, tenant_id, report_type, product_id, release_id, title,
				payload_ref, payload_hash, payload_size, limitations,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (id) DO UPDATE SET
				payload_ref = EXCLUDED.payload_ref,
				payload_hash = EXCLUDED.payload_hash,
				payload_size = EXCLUDED.payload_size,
				limitations = EXCLUDED.limitations,
				schema_version = EXCLUDED.schema_version
		`, report.ID, report.TenantID, report.ReportType, nullableString(report.ProductID), nullableString(report.ReleaseID), report.Title, nullableString(report.PayloadRef), report.PayloadHash, report.PayloadSize, report.Limitations, report.SchemaVersion, nonZeroTime(report.CreatedAt)); err != nil {
			return fmt.Errorf("upsert pdf report row: %w", err)
		}
	}
	for _, report := range state.AnomalyReports {
		if report.ID == "" || report.TenantID == "" {
			continue
		}
		signals, err := json.Marshal(report.Signals)
		if err != nil {
			return fmt.Errorf("encode anomaly report signals: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO anomaly_reports (
				id, tenant_id, subject_type, subject_id, result, signals,
				assumptions, limitations, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET
				result = EXCLUDED.result,
				signals = EXCLUDED.signals,
				assumptions = EXCLUDED.assumptions,
				limitations = EXCLUDED.limitations,
				schema_version = EXCLUDED.schema_version
		`, report.ID, report.TenantID, report.SubjectType, report.SubjectID, report.Result, signals, report.Assumptions, report.Limitations, report.SchemaVersion, nonZeroTime(report.CreatedAt)); err != nil {
			return fmt.Errorf("upsert anomaly report row: %w", err)
		}
	}
	return nil
}

func syncIdentityAndIdempotency(ctx context.Context, tx pgx.Tx, state app.PersistedState) error {
	for _, tenant := range state.Tenants {
		if tenant.ID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO tenants (id, name, created_at)
			VALUES ($1, $2, $3)
			ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
		`, tenant.ID, tenant.Name, nonZeroTime(tenant.CreatedAt)); err != nil {
			return fmt.Errorf("upsert tenant row: %w", err)
		}
	}
	for id, key := range state.APIKeys {
		if key.ID == "" || key.TenantID == "" {
			continue
		}
		hash := state.APIKeyHashes[id]
		if hash == "" {
			hash = key.Hash
		}
		scopes, err := json.Marshal(key.Scopes)
		if err != nil {
			return fmt.Errorf("encode api key scopes: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO api_keys (
				id, tenant_id, name, prefix, hash, scopes, expires_at,
				revoked_at, last_used_at, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				prefix = EXCLUDED.prefix,
				hash = EXCLUDED.hash,
				scopes = EXCLUDED.scopes,
				expires_at = EXCLUDED.expires_at,
				revoked_at = EXCLUDED.revoked_at,
				last_used_at = EXCLUDED.last_used_at
		`, key.ID, key.TenantID, key.Name, key.Prefix, hash, scopes, nullableTime(key.ExpiresAt), nullableTime(key.RevokedAt), nullableTime(key.LastUsedAt), nonZeroTime(key.CreatedAt)); err != nil {
			return fmt.Errorf("upsert api key row: %w", err)
		}
	}
	for _, org := range state.Organizations {
		if org.ID == "" || org.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO organizations (id, tenant_id, name, slug, status, schema_version, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				slug = EXCLUDED.slug,
				status = EXCLUDED.status,
				schema_version = EXCLUDED.schema_version
		`, org.ID, org.TenantID, org.Name, org.Slug, org.Status, org.SchemaVersion, nonZeroTime(org.CreatedAt)); err != nil {
			return fmt.Errorf("upsert organization row: %w", err)
		}
	}
	for _, user := range state.Users {
		if user.ID == "" || user.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO human_users (
				id, tenant_id, organization_id, email, display_name, status,
				deactivated_at, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET
				organization_id = EXCLUDED.organization_id,
				email = EXCLUDED.email,
				display_name = EXCLUDED.display_name,
				status = EXCLUDED.status,
				deactivated_at = EXCLUDED.deactivated_at,
				schema_version = EXCLUDED.schema_version
		`, user.ID, user.TenantID, nullableString(user.OrganizationID), user.Email, user.DisplayName, user.Status, nullableTime(user.DeactivatedAt), user.SchemaVersion, nonZeroTime(user.CreatedAt)); err != nil {
			return fmt.Errorf("upsert human user row: %w", err)
		}
	}
	for _, binding := range state.RoleBindings {
		if binding.ID == "" || binding.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO role_bindings (
				id, tenant_id, subject_type, subject_id, role, resource_type,
				resource_id, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET
				subject_type = EXCLUDED.subject_type,
				subject_id = EXCLUDED.subject_id,
				role = EXCLUDED.role,
				resource_type = EXCLUDED.resource_type,
				resource_id = EXCLUDED.resource_id,
				schema_version = EXCLUDED.schema_version
		`, binding.ID, binding.TenantID, binding.SubjectType, binding.SubjectID, binding.Role, nullableString(binding.ResourceType), nullableString(binding.ResourceID), binding.SchemaVersion, nonZeroTime(binding.CreatedAt)); err != nil {
			return fmt.Errorf("upsert role binding row: %w", err)
		}
	}
	for _, provider := range state.SSOProviders {
		if provider.ID == "" || provider.TenantID == "" {
			continue
		}
		roleMapping, err := json.Marshal(provider.RoleMapping)
		if err != nil {
			return fmt.Errorf("encode sso role mapping: %w", err)
		}
		jwks, err := json.Marshal(provider.JWKS)
		if err != nil {
			return fmt.Errorf("encode sso jwks: %w", err)
		}
		samlCerts, err := json.Marshal(provider.SAMLSigningCertificates)
		if err != nil {
			return fmt.Errorf("encode sso signing certificates: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO sso_providers (
				id, tenant_id, name, type, issuer, client_id, groups_claim,
				role_mapping, status, schema_version, created_at, jwks,
				saml_signing_certificates, trust_material_updated_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				type = EXCLUDED.type,
				issuer = EXCLUDED.issuer,
				client_id = EXCLUDED.client_id,
				groups_claim = EXCLUDED.groups_claim,
				role_mapping = EXCLUDED.role_mapping,
				status = EXCLUDED.status,
				schema_version = EXCLUDED.schema_version,
				jwks = EXCLUDED.jwks,
				saml_signing_certificates = EXCLUDED.saml_signing_certificates,
				trust_material_updated_at = EXCLUDED.trust_material_updated_at
		`, provider.ID, provider.TenantID, provider.Name, provider.Type, provider.Issuer, provider.ClientID, nullableString(provider.GroupsClaim), roleMapping, provider.Status, provider.SchemaVersion, nonZeroTime(provider.CreatedAt), jwks, samlCerts, nullableTime(provider.TrustMaterialUpdatedAt)); err != nil {
			return fmt.Errorf("upsert sso provider row: %w", err)
		}
	}
	for _, link := range state.IdentityLinks {
		if link.ID == "" || link.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_identity_links (
				id, tenant_id, user_id, provider_id, subject, email, verified,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET
				user_id = EXCLUDED.user_id,
				provider_id = EXCLUDED.provider_id,
				subject = EXCLUDED.subject,
				email = EXCLUDED.email,
				verified = EXCLUDED.verified,
				schema_version = EXCLUDED.schema_version
		`, link.ID, link.TenantID, link.UserID, link.ProviderID, link.Subject, link.Email, link.Verified, link.SchemaVersion, nonZeroTime(link.CreatedAt)); err != nil {
			return fmt.Errorf("upsert user identity link row: %w", err)
		}
	}
	for id, session := range state.SSOSessions {
		if session.ID == "" || session.TenantID == "" {
			continue
		}
		hash := state.SSOSessionHashes[id]
		if hash == "" {
			hash = session.Hash
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO sso_sessions (
				id, tenant_id, user_id, provider_id, prefix, hash, expires_at,
				revoked_at, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET
				prefix = EXCLUDED.prefix,
				hash = EXCLUDED.hash,
				expires_at = EXCLUDED.expires_at,
				revoked_at = EXCLUDED.revoked_at,
				schema_version = EXCLUDED.schema_version
		`, session.ID, session.TenantID, session.UserID, session.ProviderID, session.Prefix, hash, session.ExpiresAt, nullableTime(session.RevokedAt), session.SchemaVersion, nonZeroTime(session.CreatedAt)); err != nil {
			return fmt.Errorf("upsert sso session row: %w", err)
		}
	}
	for id, access := range state.CustomerPortalAccess {
		if access.ID == "" || access.TenantID == "" {
			continue
		}
		hash := state.CustomerPortalHashes[id]
		if hash == "" {
			hash = access.Hash
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO customer_portal_access (
				id, tenant_id, package_id, customer_name, prefix, hash,
				expires_at, revoked_at, access_count, failed_access_count,
				last_accessed_at, last_failed_at, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			ON CONFLICT (id) DO UPDATE SET
				customer_name = EXCLUDED.customer_name,
				prefix = EXCLUDED.prefix,
				hash = EXCLUDED.hash,
				expires_at = EXCLUDED.expires_at,
				revoked_at = EXCLUDED.revoked_at,
				access_count = EXCLUDED.access_count,
				failed_access_count = EXCLUDED.failed_access_count,
				last_accessed_at = EXCLUDED.last_accessed_at,
				last_failed_at = EXCLUDED.last_failed_at,
				schema_version = EXCLUDED.schema_version
		`, access.ID, access.TenantID, access.PackageID, access.CustomerName, access.Prefix, hash, access.ExpiresAt, nullableTime(access.RevokedAt), access.AccessCount, access.FailedAccessCount, nullableTime(access.LastAccessedAt), nullableTime(access.LastFailedAt), access.SchemaVersion, nonZeroTime(access.CreatedAt)); err != nil {
			return fmt.Errorf("upsert customer portal access row: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM idempotency_records`); err != nil {
		return fmt.Errorf("clear idempotency records: %w", err)
	}
	for key, record := range state.Idempotency {
		parts, ok := app.ParseIdempotencyRecordKey(key)
		if !ok {
			continue
		}
		response, err := json.Marshal(record.Response)
		if err != nil {
			return fmt.Errorf("encode idempotency response: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO idempotency_records (
				tenant_id, actor_key_id, method, path, idempotency_key,
				request_hash, status, response, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, parts.TenantID, parts.ActorID, parts.Method, parts.Path, parts.IdempotencyKey, record.RequestHash, record.Status, response, nonZeroTime(record.CreatedAt)); err != nil {
			return fmt.Errorf("insert idempotency record row: %w", err)
		}
	}
	return nil
}

type resourceProjection struct {
	TenantID     string
	ResourceType string
	ResourceID   string
	ProductID    string
	ProjectID    string
	ReleaseID    string
	CreatedAt    time.Time
}

func syncResourceIndex(ctx context.Context, tx pgx.Tx, state app.PersistedState) error {
	if _, err := tx.Exec(ctx, `DELETE FROM resource_index`); err != nil {
		return fmt.Errorf("clear resource index: %w", err)
	}
	projections := resourceProjections(state)
	for _, projection := range projections {
		if projection.TenantID == "" || projection.ResourceID == "" || projection.ResourceType == "" {
			continue
		}
		if projection.CreatedAt.IsZero() {
			projection.CreatedAt = time.Now().UTC()
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO resource_index (
				tenant_id, resource_type, resource_id, product_id, project_id,
				release_id, created_at, updated_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, now())
			ON CONFLICT (tenant_id, resource_type, resource_id)
			DO UPDATE SET product_id = EXCLUDED.product_id,
			              project_id = EXCLUDED.project_id,
			              release_id = EXCLUDED.release_id,
			              created_at = EXCLUDED.created_at,
			              updated_at = EXCLUDED.updated_at
		`, projection.TenantID, projection.ResourceType, projection.ResourceID, nullableString(projection.ProductID), nullableString(projection.ProjectID), nullableString(projection.ReleaseID), projection.CreatedAt); err != nil {
			return fmt.Errorf("upsert resource index: %w", err)
		}
	}
	return nil
}

func resourceProjections(state app.PersistedState) []resourceProjection {
	out := []resourceProjection{}
	for _, v := range state.Tenants {
		out = append(out, resourceProjection{TenantID: v.ID, ResourceType: "tenant", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Organizations {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "organization", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Users {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "human_user", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.RoleBindings {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "role_binding", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.SSOProviders {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "sso_provider", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.IdentityLinks {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "user_identity_link", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.SSOSessions {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "sso_session", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Products {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "product", ResourceID: v.ID, ProductID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Projects {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "project", ResourceID: v.ID, ProductID: v.ProductID, ProjectID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Releases {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "release", ResourceID: v.ID, ProductID: v.ProductID, ReleaseID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Artifacts {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "artifact", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Evidence {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "evidence_item", ResourceID: v.ID, ProductID: v.ProductID, ProjectID: v.ProjectID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.ReleaseCandidates {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "release_candidate", ResourceID: v.ID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.BuildRuns {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "build_run", ResourceID: v.ID, ProjectID: v.ProjectID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.BuildAttestations {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "build_attestation", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.SBOMs {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "sbom", ResourceID: v.ID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Scans {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "vulnerability_scan", ResourceID: v.ID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.VEXDocuments {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "vex_document", ResourceID: v.ID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Contracts {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "openapi_contract", ResourceID: v.ID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Bundles {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "release_bundle", ResourceID: v.ID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.ControlFrameworks {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "control_framework", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.SecurityControls {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "security_control", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.ControlEvidence {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "control_evidence", ResourceID: v.ID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.ContainerImages {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "container_image", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.ArtifactSignatures {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "artifact_signature", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Repositories {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "source_repository", ResourceID: v.ID, ProjectID: v.ProjectID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Commits {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "source_commit", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Branches {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "source_branch", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.PullRequests {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "pull_request", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Environments {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "deployment_environment", ResourceID: v.ID, ProductID: v.ProductID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Deployments {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "deployment", ResourceID: v.ID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Incidents {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "incident", ResourceID: v.ID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.TimelineEvents {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "incident_timeline_event", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.RemediationTasks {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "remediation_task", ResourceID: v.ID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.SecurityScans {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "security_scan", ResourceID: v.ID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.ManualSecurityDocs {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "manual_security_document", ResourceID: v.ID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.SBOMDiffs {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "sbom_diff", ResourceID: v.ID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.DependencyChanges {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "dependency_change", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.VulnerabilityWorkflow {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "vulnerability_workflow", ResourceID: v.ID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.ContractDiffs {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "contract_diff", ResourceID: v.ID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.CustomPolicies {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "custom_policy", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.CustomPolicyEvaluations {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "custom_policy_evaluation", ResourceID: v.ID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Waivers {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "waiver", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.Approvals {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "approval", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.RedactionProfiles {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "redaction_profile", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.CustomerPackages {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "customer_security_package", ResourceID: v.ID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.HTMLReports {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "html_report", ResourceID: v.ID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.ReportTemplates {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "report_template", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.RenderedReports {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "rendered_report", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.EvidenceBundles {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "evidence_bundle", ResourceID: v.ID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.BundleImports {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "evidence_bundle_import", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.DSSETrustRoots {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "dsse_trust_root", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.CollectorReleases {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "collector_release", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.CosignVerifications {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "cosign_verification", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.SigningProviders {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "signing_provider", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.MerkleBatches {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "merkle_batch", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.TransparencyCheckpoints {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "transparency_checkpoint", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.ObjectRetentionPolicies {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "object_retention_policy", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.BackupManifests {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "backup_manifest", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.LegalHolds {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "legal_hold", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.RetentionOverrides {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "retention_override", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.CustomerPortalAccess {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "customer_portal_access", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.QuestionnaireTemplates {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "questionnaire_template", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.QuestionnairePackages {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "questionnaire_package", ResourceID: v.ID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.CommercialCollectors {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "commercial_collector", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.EvidenceSummaries {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "evidence_summary", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.QuestionnaireDrafts {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "questionnaire_draft", ResourceID: v.ID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.GraphSnapshots {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "evidence_graph_snapshot", ResourceID: v.ID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.SaaSProfiles {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "saas_profile", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.PublicTransparencyLogs {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "public_transparency_log", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.PublicTransparencyItems {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "public_transparency_log_entry", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.MarketplaceCollectors {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "marketplace_collector", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.PDFReports {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "pdf_report", ResourceID: v.ID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.AnomalyReports {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "anomaly_report", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.ProviderVerifications {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "provider_verification", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	for _, v := range state.SigningOperations {
		out = append(out, resourceProjection{TenantID: v.TenantID, ResourceType: "signing_operation", ResourceID: v.ID, CreatedAt: v.CreatedAt})
	}
	return out
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableSQLString(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func nullableSQLTime(value sql.NullTime) *time.Time {
	if !value.Valid || value.Time.IsZero() {
		return nil
	}
	t := value.Time.UTC()
	return &t
}

func decodeJSON(raw []byte, out any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func nullableTime(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return value.UTC()
}

func nullableInt64(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func nonZeroInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func nonZeroTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}

func (s *Store) Enqueue(ctx context.Context, job app.OutboxJob) error {
	payload, err := json.Marshal(job.Payload)
	if err != nil {
		return fmt.Errorf("encode outbox payload: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO outbox_jobs (
			id, tenant_id, kind, subject_type, subject_id, payload, status,
			attempts, max_attempts, run_after, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, 'queued', 0, 5, now(), $7, now())
		ON CONFLICT (id) DO NOTHING
	`, job.ID, job.TenantID, job.Kind, job.SubjectType, job.SubjectID, payload, job.CreatedAt)
	if err != nil {
		return fmt.Errorf("enqueue outbox job: %w", err)
	}
	return nil
}

func (s *Store) ClaimJobs(ctx context.Context, limit int) ([]ClaimedJob, error) {
	if limit <= 0 {
		limit = 10
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin claim jobs transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `
		WITH claimed AS (
			SELECT id
			FROM outbox_jobs
			WHERE status IN ('queued', 'retrying')
			  AND run_after <= now()
			ORDER BY run_after, created_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE outbox_jobs j
		SET status = 'running',
		    attempts = attempts + 1,
		    locked_at = now(),
		    updated_at = now()
		FROM claimed
		WHERE j.id = claimed.id
		RETURNING j.id, j.tenant_id, j.kind, j.subject_type, j.subject_id, j.attempts, j.payload
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("claim jobs: %w", err)
	}
	defer rows.Close()
	jobs := []ClaimedJob{}
	for rows.Next() {
		var job ClaimedJob
		var payload []byte
		if err := rows.Scan(&job.ID, &job.TenantID, &job.Kind, &job.SubjectType, &job.SubjectID, &job.Attempts, &payload); err != nil {
			return nil, fmt.Errorf("scan claimed job: %w", err)
		}
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &job.Payload); err != nil {
				return nil, fmt.Errorf("decode claimed job payload: %w", err)
			}
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read claimed jobs: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit claim jobs transaction: %w", err)
	}
	return jobs, nil
}

func (s *Store) CompleteJob(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE outbox_jobs
		SET status = 'succeeded', locked_at = NULL, last_error = NULL, updated_at = now()
		WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("complete outbox job: %w", err)
	}
	return nil
}

func (s *Store) FailJob(ctx context.Context, id string, cause error) error {
	message := "job failed"
	if cause != nil {
		message = cause.Error()
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE outbox_jobs
		SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'retrying' END,
		    run_after = now() + make_interval(secs => LEAST(300, POWER(2, attempts)::int)),
		    locked_at = NULL,
		    last_error = $2,
		    updated_at = now()
		WHERE id = $1
	`, id, message)
	if err != nil {
		return fmt.Errorf("fail outbox job: %w", err)
	}
	return nil
}

func (s *Store) CountPendingJobs(ctx context.Context) (int, error) {
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_jobs WHERE status IN ('queued', 'retrying', 'running')`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count outbox jobs: %w", err)
	}
	return count, nil
}

func (s *Store) Now(ctx context.Context) (time.Time, error) {
	var now time.Time
	if err := s.pool.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
		return time.Time{}, fmt.Errorf("postgres now: %w", err)
	}
	return now, nil
}

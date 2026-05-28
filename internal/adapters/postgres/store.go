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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

type Store struct {
	pool     *pgxpool.Pool
	loadMode LoadMode
}

type LoadMode string

const (
	LoadModeSnapshotPreferred   LoadMode = "snapshot_preferred"
	LoadModeRelationalPreferred LoadMode = "relational_preferred"
	LoadModeRelationalOnly      LoadMode = "relational_only"
)

type StoreOptions struct {
	LoadMode LoadMode
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
	return OpenWithOptions(ctx, databaseURL, StoreOptions{})
}

func OpenWithOptions(ctx context.Context, databaseURL string, opts StoreOptions) (*Store, error) {
	loadMode, err := normalizeLoadMode(opts.LoadMode)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool, loadMode: loadMode}, nil
}

func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

func (s *Store) LoadState(ctx context.Context) (app.PersistedState, bool, error) {
	switch s.loadMode {
	case LoadModeRelationalPreferred:
		state, ok, err := s.loadRelationalState(ctx)
		if err != nil || ok {
			return state, ok, err
		}
		return s.loadSnapshotState(ctx)
	case LoadModeRelationalOnly:
		return s.loadRelationalState(ctx)
	default:
		state, ok, err := s.loadSnapshotState(ctx)
		if err != nil || ok {
			return state, ok, err
		}
		return s.loadRelationalState(ctx)
	}
}

func ResolveLoadMode(raw string, production bool) (LoadMode, error) {
	if strings.TrimSpace(raw) == "" && production {
		return LoadModeRelationalPreferred, nil
	}
	return normalizeLoadMode(LoadMode(raw))
}

func normalizeLoadMode(mode LoadMode) (LoadMode, error) {
	switch strings.ToLower(strings.TrimSpace(string(mode))) {
	case "", "snapshot", "snapshot_preferred", "snapshot-preferred":
		return LoadModeSnapshotPreferred, nil
	case "relational", "relational_preferred", "relational-preferred":
		return LoadModeRelationalPreferred, nil
	case "relational_only", "relational-only":
		return LoadModeRelationalOnly, nil
	default:
		return "", fmt.Errorf("unsupported postgres load mode %q", mode)
	}
}

func (s *Store) loadSnapshotState(ctx context.Context) (app.PersistedState, bool, error) {
	var body []byte
	err := s.pool.QueryRow(ctx, `SELECT state FROM ledger_state WHERE id = 'default'`).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.PersistedState{}, false, nil
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
	if err := s.loadRelationalRiskBuildControls(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	if err := s.loadRelationalSourceDeploymentLifecycle(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	if err := s.loadRelationalIncidentSecurityGovernance(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	if err := s.loadRelationalIntegrityProviderRows(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	if err := s.loadRelationalPackageReportRetention(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	if err := s.loadRelationalFutureExtensionRows(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	if err := s.loadRelationalIdempotency(ctx, &state, &loaded); err != nil {
		return app.PersistedState{}, false, err
	}
	return state, loaded, nil
}

func relationalEmptyState() app.PersistedState {
	return app.PersistedState{
		Tenants:                  map[string]domain.Tenant{},
		Organizations:            map[string]domain.Organization{},
		Users:                    map[string]domain.HumanUser{},
		RoleBindings:             map[string]domain.RoleBinding{},
		SSOProviders:             map[string]domain.SSOProvider{},
		IdentityLinks:            map[string]domain.UserIdentityLink{},
		SSOSessions:              map[string]domain.SSOSession{},
		SSOSessionHashes:         map[string]string{},
		APIKeys:                  map[string]domain.APIKey{},
		APIKeyHashes:             map[string]string{},
		Collectors:               map[string]domain.Collector{},
		CollectorReleases:        map[string]domain.CollectorRelease{},
		BuildRuns:                map[string]domain.BuildRun{},
		BuildAttestations:        map[string]domain.BuildAttestation{},
		EvidenceLifecycle:        map[string]domain.EvidenceLifecycleEvent{},
		ReleaseCandidates:        map[string]domain.ReleaseCandidate{},
		ContainerImages:          map[string]domain.ContainerImage{},
		ArtifactSignatures:       map[string]domain.ArtifactSignature{},
		Repositories:             map[string]domain.SourceRepository{},
		Commits:                  map[string]domain.SourceCommit{},
		Branches:                 map[string]domain.SourceBranch{},
		PullRequests:             map[string]domain.PullRequest{},
		Environments:             map[string]domain.DeploymentEnvironment{},
		Deployments:              map[string]domain.DeploymentEvent{},
		Incidents:                map[string]domain.Incident{},
		TimelineEvents:           map[string]domain.IncidentTimelineEvent{},
		IncidentWebhookReceivers: map[string]domain.IncidentWebhookReceiver{},
		IncidentWebhookEvents:    map[string]domain.IncidentWebhookEvent{},
		RemediationTasks:         map[string]domain.RemediationTask{},
		SecurityScans:            map[string]domain.SecurityScan{},
		ManualSecurityDocs:       map[string]domain.ManualSecurityDocument{},
		SBOMDiffs:                map[string]domain.SBOMDiff{},
		DependencyChanges:        map[string]domain.DependencyChange{},
		VulnerabilityWorkflow:    map[string]domain.VulnerabilityWorkflowRecord{},
		ContractDiffs:            map[string]domain.ContractDiff{},
		CustomPolicies:           map[string]domain.CustomPolicy{},
		CustomPolicyEvaluations:  map[string]domain.CustomPolicyEvaluation{},
		Waivers:                  map[string]domain.Waiver{},
		Approvals:                map[string]domain.ApprovalRecord{},
		DSSETrustRoots:           map[string]domain.DSSETrustRoot{},
		CosignVerifications:      map[string]domain.CosignVerification{},
		SigningProviders:         map[string]domain.SigningProvider{},
		MerkleBatches:            map[string]domain.MerkleBatch{},
		TransparencyCheckpoints:  map[string]domain.TransparencyCheckpoint{},
		CustomerPortalAccess:     map[string]domain.CustomerPortalAccess{},
		CustomerPortalHashes:     map[string]string{},
		RedactionProfiles:        map[string]domain.RedactionProfile{},
		CustomerPackages:         map[string]domain.CustomerSecurityPackage{},
		HTMLReports:              map[string]domain.HTMLReportPackage{},
		ReportTemplates:          map[string]domain.CustomReportTemplate{},
		RenderedReports:          map[string]domain.RenderedCustomReport{},
		EvidenceBundles:          map[string]domain.EvidenceBundle{},
		BundleImports:            map[string]domain.EvidenceBundleImport{},
		ObjectRetentionPolicies:  map[string]domain.ObjectRetentionPolicy{},
		BackupManifests:          map[string]domain.BackupManifest{},
		LegalHolds:               map[string]domain.LegalHold{},
		RetentionOverrides:       map[string]domain.RetentionOverride{},
		QuestionnaireTemplates:   map[string]domain.QuestionnaireTemplate{},
		QuestionnairePackages:    map[string]domain.QuestionnairePackage{},
		CommercialCollectors:     map[string]domain.CommercialCollectorDefinition{},
		EvidenceSummaries:        map[string]domain.EvidenceSummary{},
		QuestionnaireDrafts:      map[string]domain.QuestionnaireDraft{},
		GraphSnapshots:           map[string]domain.EvidenceGraphSnapshot{},
		SaaSProfiles:             map[string]domain.SaaSEditionProfile{},
		PublicTransparencyLogs:   map[string]domain.PublicTransparencyLog{},
		PublicTransparencyItems:  map[string]domain.PublicTransparencyLogEntry{},
		MarketplaceCollectors:    map[string]domain.MarketplaceCollector{},
		PDFReports:               map[string]domain.PDFReportPackage{},
		AnomalyReports:           map[string]domain.AnomalyReport{},
		ProviderVerifications:    map[string]domain.ProviderVerification{},
		SigningOperations:        map[string]domain.SigningOperation{},
		ControlFrameworks:        map[string]domain.ControlFramework{},
		SecurityControls:         map[string]domain.SecurityControl{},
		ControlEvidence:          map[string]domain.ControlEvidence{},
		Products:                 map[string]domain.Product{},
		Projects:                 map[string]domain.Project{},
		Releases:                 map[string]domain.Release{},
		Artifacts:                map[string]domain.Artifact{},
		Evidence:                 map[string]domain.EvidenceItem{},
		SBOMs:                    map[string]domain.SBOM{},
		Scans:                    map[string]domain.VulnerabilityScan{},
		VEXDocuments:             map[string]domain.VEXDocument{},
		Decisions:                map[string]domain.VulnerabilityDecision{},
		Contracts:                map[string]domain.OpenAPIContract{},
		Policies:                 map[string]domain.PolicyEvaluation{},
		Exceptions:               map[string]domain.Exception{},
		Bundles:                  map[string]domain.ReleaseBundle{},
		SigningKeys:              map[string]domain.SigningKey{},
		SigningKeyPrivate:        map[string][]byte{},
		Signatures:               map[string]domain.Signature{},
		Verifications:            map[string]domain.VerificationResult{},
		Chain:                    map[string][]domain.AuditChainEntry{},
		Idempotency:              map[string]app.IdempotencyRecord{},
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

func (s *Store) loadRelationalRiskBuildControls(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	if err := s.loadRelationalCollectorsAndBuilds(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalRiskDecisions(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalControls(ctx, state, loaded); err != nil {
		return err
	}
	return nil
}

func (s *Store) loadRelationalCollectorsAndBuilds(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	collectorRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, type, version, api_key_id, status, allowed_scopes, last_seen_at, schema_version, created_at FROM collectors`)
	if err != nil {
		return fmt.Errorf("load relational collectors: %w", err)
	}
	defer collectorRows.Close()
	for collectorRows.Next() {
		var collector domain.Collector
		var allowedScopes []byte
		var lastSeenAt sql.NullTime
		if err := collectorRows.Scan(&collector.ID, &collector.TenantID, &collector.Name, &collector.Type, &collector.Version, &collector.APIKeyID, &collector.Status, &allowedScopes, &lastSeenAt, &collector.SchemaVersion, &collector.CreatedAt); err != nil {
			return fmt.Errorf("scan relational collector: %w", err)
		}
		if err := decodeJSON(allowedScopes, &collector.AllowedScopes); err != nil {
			return fmt.Errorf("decode relational collector scopes: %w", err)
		}
		collector.LastSeenAt = nullableSQLTime(lastSeenAt)
		state.Collectors[collector.ID] = collector
		*loaded = true
	}
	if err := collectorRows.Err(); err != nil {
		return err
	}

	buildRows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, project_id, release_id, collector_id, provider,
		       commit_sha, repository, workflow_ref, run_id, run_attempt,
		       job_id, actor, ref, oidc_subject, status, started_at,
		       finished_at, parameters_hash, environment_hash, source_identity,
		       outputs, schema_version, created_at
		FROM build_runs
	`)
	if err != nil {
		return fmt.Errorf("load relational build runs: %w", err)
	}
	defer buildRows.Close()
	for buildRows.Next() {
		var build domain.BuildRun
		var collectorID, repository, workflowRef, runID, jobID, actor, ref, oidcSubject, parametersHash, environmentHash sql.NullString
		var runAttempt sql.NullInt32
		var finishedAt sql.NullTime
		var sourceIdentity, outputs []byte
		if err := buildRows.Scan(
			&build.ID, &build.TenantID, &build.ProjectID, &build.ReleaseID, &collectorID, &build.Provider,
			&build.CommitSHA, &repository, &workflowRef, &runID, &runAttempt,
			&jobID, &actor, &ref, &oidcSubject, &build.Status, &build.StartedAt,
			&finishedAt, &parametersHash, &environmentHash, &sourceIdentity,
			&outputs, &build.SchemaVersion, &build.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan relational build run: %w", err)
		}
		build.CollectorID = nullableSQLString(collectorID)
		build.Repository = nullableSQLString(repository)
		build.WorkflowRef = nullableSQLString(workflowRef)
		build.RunID = nullableSQLString(runID)
		if runAttempt.Valid {
			build.RunAttempt = int(runAttempt.Int32)
		}
		build.JobID = nullableSQLString(jobID)
		build.Actor = nullableSQLString(actor)
		build.Ref = nullableSQLString(ref)
		build.OIDCSubject = nullableSQLString(oidcSubject)
		build.FinishedAt = nullableSQLTime(finishedAt)
		build.ParametersHash = nullableSQLString(parametersHash)
		build.EnvironmentHash = nullableSQLString(environmentHash)
		if err := decodeJSON(sourceIdentity, &build.SourceIdentity); err != nil {
			return fmt.Errorf("decode relational build source identity: %w", err)
		}
		if err := decodeJSON(outputs, &build.Outputs); err != nil {
			return fmt.Errorf("decode relational build outputs: %w", err)
		}
		state.BuildRuns[build.ID] = build
		*loaded = true
	}
	if err := buildRows.Err(); err != nil {
		return err
	}

	attestationRows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, build_id, evidence_id, payload_ref, payload_hash,
		       payload_size, payload_type, predicate_type, subject_digests,
		       builder_id, build_type, materials_count, signature_count,
		       verification_status, schema_version, created_at
		FROM build_attestations
	`)
	if err != nil {
		return fmt.Errorf("load relational build attestations: %w", err)
	}
	defer attestationRows.Close()
	for attestationRows.Next() {
		var attestation domain.BuildAttestation
		var payloadRef, builderID, buildType sql.NullString
		var subjectDigests []byte
		if err := attestationRows.Scan(
			&attestation.ID, &attestation.TenantID, &attestation.BuildID, &attestation.EvidenceID, &payloadRef, &attestation.PayloadHash,
			&attestation.PayloadSize, &attestation.PayloadType, &attestation.PredicateType, &subjectDigests,
			&builderID, &buildType, &attestation.MaterialsCount, &attestation.SignatureCount,
			&attestation.VerificationStatus, &attestation.SchemaVersion, &attestation.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan relational build attestation: %w", err)
		}
		attestation.PayloadRef = nullableSQLString(payloadRef)
		attestation.BuilderID = nullableSQLString(builderID)
		attestation.BuildType = nullableSQLString(buildType)
		if err := decodeJSON(subjectDigests, &attestation.SubjectDigests); err != nil {
			return fmt.Errorf("decode relational attestation subject digests: %w", err)
		}
		state.BuildAttestations[attestation.ID] = attestation
		*loaded = true
	}
	return attestationRows.Err()
}

func (s *Store) loadRelationalRiskDecisions(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	vexRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, evidence_id, release_id, artifact_id, format, author, version, statement_count, status_summary, schema_version, created_at FROM vex_documents`)
	if err != nil {
		return fmt.Errorf("load relational vex documents: %w", err)
	}
	defer vexRows.Close()
	for vexRows.Next() {
		var document domain.VEXDocument
		var releaseID, artifactID, version sql.NullString
		var statusSummary []byte
		if err := vexRows.Scan(&document.ID, &document.TenantID, &document.EvidenceID, &releaseID, &artifactID, &document.Format, &document.Author, &version, &document.StatementCount, &statusSummary, &document.SchemaVersion, &document.CreatedAt); err != nil {
			return fmt.Errorf("scan relational vex document: %w", err)
		}
		document.ReleaseID = nullableSQLString(releaseID)
		document.ArtifactID = nullableSQLString(artifactID)
		document.Version = nullableSQLString(version)
		if err := decodeJSON(statusSummary, &document.StatusSummary); err != nil {
			return fmt.Errorf("decode relational vex summary: %w", err)
		}
		state.VEXDocuments[document.ID] = document
		*loaded = true
	}
	if err := vexRows.Err(); err != nil {
		return err
	}

	decisionRows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, finding_id, scan_id, release_id, vulnerability,
		       component, status, justification, impact_statement, action_statement,
		       source, evidence_id, vex_document_id, supersedes, superseded_by,
		       approved_by, schema_version, created_at
		FROM vulnerability_decisions
	`)
	if err != nil {
		return fmt.Errorf("load relational vulnerability decisions: %w", err)
	}
	defer decisionRows.Close()
	for decisionRows.Next() {
		var decision domain.VulnerabilityDecision
		var releaseID, component, impactStatement, actionStatement, evidenceID, vexDocumentID, supersedes, supersededBy, approvedBy sql.NullString
		if err := decisionRows.Scan(
			&decision.ID, &decision.TenantID, &decision.FindingID, &decision.ScanID, &releaseID, &decision.Vulnerability,
			&component, &decision.Status, &decision.Justification, &impactStatement, &actionStatement,
			&decision.Source, &evidenceID, &vexDocumentID, &supersedes, &supersededBy,
			&approvedBy, &decision.SchemaVersion, &decision.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan relational vulnerability decision: %w", err)
		}
		decision.ReleaseID = nullableSQLString(releaseID)
		decision.Component = nullableSQLString(component)
		decision.ImpactStatement = nullableSQLString(impactStatement)
		decision.ActionStatement = nullableSQLString(actionStatement)
		decision.EvidenceID = nullableSQLString(evidenceID)
		decision.VEXDocumentID = nullableSQLString(vexDocumentID)
		decision.Supersedes = nullableSQLString(supersedes)
		decision.SupersededBy = nullableSQLString(supersededBy)
		decision.ApprovedBy = nullableSQLString(approvedBy)
		state.Decisions[decision.ID] = decision
		*loaded = true
	}
	if err := decisionRows.Err(); err != nil {
		return err
	}

	exceptionRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, release_id, finding_id, control_id, reason, owner, expires_at, approved, approved_by, approved_at, created_at FROM exceptions`)
	if err != nil {
		return fmt.Errorf("load relational exceptions: %w", err)
	}
	defer exceptionRows.Close()
	for exceptionRows.Next() {
		var exception domain.Exception
		var findingID, controlID, approvedBy sql.NullString
		var approvedAt sql.NullTime
		if err := exceptionRows.Scan(&exception.ID, &exception.TenantID, &exception.ReleaseID, &findingID, &controlID, &exception.Reason, &exception.Owner, &exception.ExpiresAt, &exception.Approved, &approvedBy, &approvedAt, &exception.CreatedAt); err != nil {
			return fmt.Errorf("scan relational exception: %w", err)
		}
		exception.FindingID = nullableSQLString(findingID)
		exception.ControlID = nullableSQLString(controlID)
		exception.ApprovedBy = nullableSQLString(approvedBy)
		exception.ApprovedAt = nullableSQLTime(approvedAt)
		state.Exceptions[exception.ID] = exception
		*loaded = true
	}
	return exceptionRows.Err()
}

func (s *Store) loadRelationalControls(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	frameworkRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, slug, version, description, status, schema_version, created_at FROM control_frameworks`)
	if err != nil {
		return fmt.Errorf("load relational control frameworks: %w", err)
	}
	defer frameworkRows.Close()
	for frameworkRows.Next() {
		var framework domain.ControlFramework
		var description sql.NullString
		if err := frameworkRows.Scan(&framework.ID, &framework.TenantID, &framework.Name, &framework.Slug, &framework.Version, &description, &framework.Status, &framework.SchemaVersion, &framework.CreatedAt); err != nil {
			return fmt.Errorf("scan relational control framework: %w", err)
		}
		framework.Description = nullableSQLString(description)
		state.ControlFrameworks[framework.ID] = framework
		*loaded = true
	}
	if err := frameworkRows.Err(); err != nil {
		return err
	}

	controlRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, framework_id, code, title, objective, evidence_requirements, applicability, limitations, schema_version, created_at FROM security_controls`)
	if err != nil {
		return fmt.Errorf("load relational security controls: %w", err)
	}
	defer controlRows.Close()
	for controlRows.Next() {
		var control domain.SecurityControl
		var requirements, applicability, limitations []byte
		if err := controlRows.Scan(&control.ID, &control.TenantID, &control.FrameworkID, &control.Code, &control.Title, &control.Objective, &requirements, &applicability, &limitations, &control.SchemaVersion, &control.CreatedAt); err != nil {
			return fmt.Errorf("scan relational security control: %w", err)
		}
		if err := decodeJSON(requirements, &control.EvidenceRequirements); err != nil {
			return fmt.Errorf("decode relational control requirements: %w", err)
		}
		if err := decodeJSON(applicability, &control.Applicability); err != nil {
			return fmt.Errorf("decode relational control applicability: %w", err)
		}
		if err := decodeJSON(limitations, &control.Limitations); err != nil {
			return fmt.Errorf("decode relational control limitations: %w", err)
		}
		state.SecurityControls[control.ID] = control
		*loaded = true
	}
	if err := controlRows.Err(); err != nil {
		return err
	}

	evidenceRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, control_id, evidence_type, subject_type, subject_id, product_id, release_id, confidence, notes, schema_version, created_at FROM control_evidence`)
	if err != nil {
		return fmt.Errorf("load relational control evidence: %w", err)
	}
	defer evidenceRows.Close()
	for evidenceRows.Next() {
		var evidence domain.ControlEvidence
		var productID, releaseID, notes sql.NullString
		if err := evidenceRows.Scan(&evidence.ID, &evidence.TenantID, &evidence.ControlID, &evidence.EvidenceType, &evidence.SubjectType, &evidence.SubjectID, &productID, &releaseID, &evidence.Confidence, &notes, &evidence.SchemaVersion, &evidence.CreatedAt); err != nil {
			return fmt.Errorf("scan relational control evidence: %w", err)
		}
		evidence.ProductID = nullableSQLString(productID)
		evidence.ReleaseID = nullableSQLString(releaseID)
		evidence.Notes = nullableSQLString(notes)
		state.ControlEvidence[evidence.ID] = evidence
		*loaded = true
	}
	return evidenceRows.Err()
}

func (s *Store) loadRelationalSourceDeploymentLifecycle(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	if err := s.loadRelationalLifecycleAndCandidates(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalContainerAndSignatures(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalSource(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalDeployments(ctx, state, loaded); err != nil {
		return err
	}
	return nil
}

func (s *Store) loadRelationalLifecycleAndCandidates(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	lifecycleRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, evidence_id, action, reason, details, replacement_id, actor_id, schema_version, created_at FROM evidence_lifecycle_events`)
	if err != nil {
		return fmt.Errorf("load relational evidence lifecycle: %w", err)
	}
	defer lifecycleRows.Close()
	for lifecycleRows.Next() {
		var event domain.EvidenceLifecycleEvent
		var details []byte
		var replacementID sql.NullString
		if err := lifecycleRows.Scan(&event.ID, &event.TenantID, &event.EvidenceID, &event.Action, &event.Reason, &details, &replacementID, &event.ActorID, &event.SchemaVersion, &event.CreatedAt); err != nil {
			return fmt.Errorf("scan relational evidence lifecycle: %w", err)
		}
		event.ReplacementID = nullableSQLString(replacementID)
		if err := decodeJSON(details, &event.Details); err != nil {
			return fmt.Errorf("decode relational evidence lifecycle details: %w", err)
		}
		state.EvidenceLifecycle[event.ID] = event
		*loaded = true
	}
	if err := lifecycleRows.Err(); err != nil {
		return err
	}

	candidateRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, release_id, name, state, snapshot_hash, document, schema_version, created_at, promoted_at, rejected_at FROM release_candidates`)
	if err != nil {
		return fmt.Errorf("load relational release candidates: %w", err)
	}
	defer candidateRows.Close()
	for candidateRows.Next() {
		var candidate domain.ReleaseCandidate
		var document []byte
		var promotedAt, rejectedAt sql.NullTime
		if err := candidateRows.Scan(&candidate.ID, &candidate.TenantID, &candidate.ReleaseID, &candidate.Name, &candidate.State, &candidate.SnapshotHash, &document, &candidate.SchemaVersion, &candidate.CreatedAt, &promotedAt, &rejectedAt); err != nil {
			return fmt.Errorf("scan relational release candidate: %w", err)
		}
		var embedded domain.ReleaseCandidate
		if err := decodeJSON(document, &embedded); err != nil {
			return fmt.Errorf("decode relational release candidate document: %w", err)
		}
		candidate.BuildIDs = embedded.BuildIDs
		candidate.ArtifactIDs = embedded.ArtifactIDs
		candidate.SBOMIDs = embedded.SBOMIDs
		candidate.ScanIDs = embedded.ScanIDs
		candidate.VEXIDs = embedded.VEXIDs
		candidate.ContractIDs = embedded.ContractIDs
		candidate.BundleIDs = embedded.BundleIDs
		candidate.PromotedAt = nullableSQLTime(promotedAt)
		candidate.RejectedAt = nullableSQLTime(rejectedAt)
		state.ReleaseCandidates[candidate.ID] = candidate
		*loaded = true
	}
	return candidateRows.Err()
}

func (s *Store) loadRelationalContainerAndSignatures(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	imageRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, artifact_id, repository, tag, digest, platform, schema_version, created_at FROM container_images`)
	if err != nil {
		return fmt.Errorf("load relational container images: %w", err)
	}
	defer imageRows.Close()
	for imageRows.Next() {
		var image domain.ContainerImage
		var artifactID, tag, platform sql.NullString
		if err := imageRows.Scan(&image.ID, &image.TenantID, &artifactID, &image.Repository, &tag, &image.Digest, &platform, &image.SchemaVersion, &image.CreatedAt); err != nil {
			return fmt.Errorf("scan relational container image: %w", err)
		}
		image.ArtifactID = nullableSQLString(artifactID)
		image.Tag = nullableSQLString(tag)
		image.Platform = nullableSQLString(platform)
		state.ContainerImages[image.ID] = image
		*loaded = true
	}
	if err := imageRows.Err(); err != nil {
		return err
	}

	signatureRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, artifact_id, subject_digest, algorithm, key_id, signature, payload_ref, payload_hash, verification_status, schema_version, created_at FROM artifact_signatures`)
	if err != nil {
		return fmt.Errorf("load relational artifact signatures: %w", err)
	}
	defer signatureRows.Close()
	for signatureRows.Next() {
		var signature domain.ArtifactSignature
		var keyID, payloadRef, payloadHash sql.NullString
		if err := signatureRows.Scan(&signature.ID, &signature.TenantID, &signature.ArtifactID, &signature.SubjectDigest, &signature.Algorithm, &keyID, &signature.Signature, &payloadRef, &payloadHash, &signature.VerificationStatus, &signature.SchemaVersion, &signature.CreatedAt); err != nil {
			return fmt.Errorf("scan relational artifact signature: %w", err)
		}
		signature.KeyID = nullableSQLString(keyID)
		signature.PayloadRef = nullableSQLString(payloadRef)
		signature.PayloadHash = nullableSQLString(payloadHash)
		state.ArtifactSignatures[signature.ID] = signature
		*loaded = true
	}
	return signatureRows.Err()
}

func (s *Store) loadRelationalSource(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	repositoryRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, project_id, provider, full_name, clone_url, default_branch, schema_version, created_at FROM source_repositories`)
	if err != nil {
		return fmt.Errorf("load relational source repositories: %w", err)
	}
	defer repositoryRows.Close()
	for repositoryRows.Next() {
		var repository domain.SourceRepository
		var projectID, cloneURL, defaultBranch sql.NullString
		if err := repositoryRows.Scan(&repository.ID, &repository.TenantID, &projectID, &repository.Provider, &repository.FullName, &cloneURL, &defaultBranch, &repository.SchemaVersion, &repository.CreatedAt); err != nil {
			return fmt.Errorf("scan relational source repository: %w", err)
		}
		repository.ProjectID = nullableSQLString(projectID)
		repository.CloneURL = nullableSQLString(cloneURL)
		repository.DefaultBranch = nullableSQLString(defaultBranch)
		state.Repositories[repository.ID] = repository
		*loaded = true
	}
	if err := repositoryRows.Err(); err != nil {
		return err
	}

	commitRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, repository_id, sha, author, message_hash, committed_at, schema_version, created_at FROM source_commits`)
	if err != nil {
		return fmt.Errorf("load relational source commits: %w", err)
	}
	defer commitRows.Close()
	for commitRows.Next() {
		var commit domain.SourceCommit
		var author, messageHash sql.NullString
		if err := commitRows.Scan(&commit.ID, &commit.TenantID, &commit.RepositoryID, &commit.SHA, &author, &messageHash, &commit.CommittedAt, &commit.SchemaVersion, &commit.CreatedAt); err != nil {
			return fmt.Errorf("scan relational source commit: %w", err)
		}
		commit.Author = nullableSQLString(author)
		commit.MessageHash = nullableSQLString(messageHash)
		state.Commits[commit.ID] = commit
		*loaded = true
	}
	if err := commitRows.Err(); err != nil {
		return err
	}

	branchRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, repository_id, name, head_commit_id, protected, protection_hash, schema_version, created_at FROM source_branches`)
	if err != nil {
		return fmt.Errorf("load relational source branches: %w", err)
	}
	defer branchRows.Close()
	for branchRows.Next() {
		var branch domain.SourceBranch
		var headCommitID, protectionHash sql.NullString
		if err := branchRows.Scan(&branch.ID, &branch.TenantID, &branch.RepositoryID, &branch.Name, &headCommitID, &branch.Protected, &protectionHash, &branch.SchemaVersion, &branch.CreatedAt); err != nil {
			return fmt.Errorf("scan relational source branch: %w", err)
		}
		branch.HeadCommitID = nullableSQLString(headCommitID)
		branch.ProtectionHash = nullableSQLString(protectionHash)
		state.Branches[branch.ID] = branch
		*loaded = true
	}
	if err := branchRows.Err(); err != nil {
		return err
	}

	prRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, repository_id, provider, provider_id, title, state, source_branch, target_branch, head_commit_id, review_decision, schema_version, created_at FROM pull_requests`)
	if err != nil {
		return fmt.Errorf("load relational pull requests: %w", err)
	}
	defer prRows.Close()
	for prRows.Next() {
		var pr domain.PullRequest
		var sourceBranch, targetBranch, headCommitID, reviewDecision sql.NullString
		if err := prRows.Scan(&pr.ID, &pr.TenantID, &pr.RepositoryID, &pr.Provider, &pr.ProviderID, &pr.Title, &pr.State, &sourceBranch, &targetBranch, &headCommitID, &reviewDecision, &pr.SchemaVersion, &pr.CreatedAt); err != nil {
			return fmt.Errorf("scan relational pull request: %w", err)
		}
		pr.SourceBranch = nullableSQLString(sourceBranch)
		pr.TargetBranch = nullableSQLString(targetBranch)
		pr.HeadCommitID = nullableSQLString(headCommitID)
		pr.ReviewDecision = nullableSQLString(reviewDecision)
		state.PullRequests[pr.ID] = pr
		*loaded = true
	}
	return prRows.Err()
}

func (s *Store) loadRelationalDeployments(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	environmentRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, product_id, name, kind, schema_version, created_at FROM deployment_environments`)
	if err != nil {
		return fmt.Errorf("load relational deployment environments: %w", err)
	}
	defer environmentRows.Close()
	for environmentRows.Next() {
		var environment domain.DeploymentEnvironment
		if err := environmentRows.Scan(&environment.ID, &environment.TenantID, &environment.ProductID, &environment.Name, &environment.Kind, &environment.SchemaVersion, &environment.CreatedAt); err != nil {
			return fmt.Errorf("scan relational deployment environment: %w", err)
		}
		state.Environments[environment.ID] = environment
		*loaded = true
	}
	if err := environmentRows.Err(); err != nil {
		return err
	}

	deploymentRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, environment_id, release_id, artifact_ids, status, started_at, finished_at, rollback_of, evidence_id, schema_version, created_at FROM deployment_events`)
	if err != nil {
		return fmt.Errorf("load relational deployment events: %w", err)
	}
	defer deploymentRows.Close()
	for deploymentRows.Next() {
		var deployment domain.DeploymentEvent
		var finishedAt sql.NullTime
		var rollbackOf, evidenceID sql.NullString
		if err := deploymentRows.Scan(&deployment.ID, &deployment.TenantID, &deployment.EnvironmentID, &deployment.ReleaseID, &deployment.ArtifactIDs, &deployment.Status, &deployment.StartedAt, &finishedAt, &rollbackOf, &evidenceID, &deployment.SchemaVersion, &deployment.CreatedAt); err != nil {
			return fmt.Errorf("scan relational deployment event: %w", err)
		}
		deployment.FinishedAt = nullableSQLTime(finishedAt)
		deployment.RollbackOf = nullableSQLString(rollbackOf)
		deployment.EvidenceID = nullableSQLString(evidenceID)
		state.Deployments[deployment.ID] = deployment
		*loaded = true
	}
	return deploymentRows.Err()
}

func (s *Store) loadRelationalIncidentSecurityGovernance(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	if err := s.loadRelationalIncidents(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalSecurityEvidence(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalDiffsAndPolicies(ctx, state, loaded); err != nil {
		return err
	}
	if err := s.loadRelationalWaiversApprovalsTrust(ctx, state, loaded); err != nil {
		return err
	}
	return nil
}

func (s *Store) loadRelationalIncidents(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	incidentRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, product_id, release_id, title, severity, status, opened_at, closed_at, schema_version, created_at FROM incidents`)
	if err != nil {
		return fmt.Errorf("load relational incidents: %w", err)
	}
	defer incidentRows.Close()
	for incidentRows.Next() {
		var incident domain.Incident
		var releaseID sql.NullString
		var closedAt sql.NullTime
		if err := incidentRows.Scan(&incident.ID, &incident.TenantID, &incident.ProductID, &releaseID, &incident.Title, &incident.Severity, &incident.Status, &incident.OpenedAt, &closedAt, &incident.SchemaVersion, &incident.CreatedAt); err != nil {
			return fmt.Errorf("scan relational incident: %w", err)
		}
		incident.ReleaseID = nullableSQLString(releaseID)
		incident.ClosedAt = nullableSQLTime(closedAt)
		state.Incidents[incident.ID] = incident
		*loaded = true
	}
	if err := incidentRows.Err(); err != nil {
		return err
	}

	timelineRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, incident_id, event_type, summary, evidence_id, occurred_at, schema_version, created_at FROM incident_timeline_events`)
	if err != nil {
		return fmt.Errorf("load relational incident timeline: %w", err)
	}
	defer timelineRows.Close()
	for timelineRows.Next() {
		var event domain.IncidentTimelineEvent
		var evidenceID sql.NullString
		if err := timelineRows.Scan(&event.ID, &event.TenantID, &event.IncidentID, &event.EventType, &event.Summary, &evidenceID, &event.OccurredAt, &event.SchemaVersion, &event.CreatedAt); err != nil {
			return fmt.Errorf("scan relational incident timeline: %w", err)
		}
		event.EvidenceID = nullableSQLString(evidenceID)
		state.TimelineEvents[event.ID] = event
		*loaded = true
	}
	if err := timelineRows.Err(); err != nil {
		return err
	}

	receiverRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, incident_id, name, provider, public_key, status, schema_version, created_at FROM incident_webhook_receivers`)
	if err != nil {
		return fmt.Errorf("load relational incident webhook receivers: %w", err)
	}
	defer receiverRows.Close()
	for receiverRows.Next() {
		var receiver domain.IncidentWebhookReceiver
		if err := receiverRows.Scan(&receiver.ID, &receiver.TenantID, &receiver.IncidentID, &receiver.Name, &receiver.Provider, &receiver.PublicKey, &receiver.Status, &receiver.SchemaVersion, &receiver.CreatedAt); err != nil {
			return fmt.Errorf("scan relational incident webhook receiver: %w", err)
		}
		state.IncidentWebhookReceivers[receiver.ID] = receiver
		*loaded = true
	}
	if err := receiverRows.Err(); err != nil {
		return err
	}

	webhookRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, receiver_id, incident_id, provider, event_id, payload_hash, signature_hash, timeline_event_id, result, schema_version, created_at FROM incident_webhook_events`)
	if err != nil {
		return fmt.Errorf("load relational incident webhook events: %w", err)
	}
	defer webhookRows.Close()
	for webhookRows.Next() {
		var event domain.IncidentWebhookEvent
		var timelineEventID sql.NullString
		if err := webhookRows.Scan(&event.ID, &event.TenantID, &event.ReceiverID, &event.IncidentID, &event.Provider, &event.EventID, &event.PayloadHash, &event.SignatureHash, &timelineEventID, &event.Result, &event.SchemaVersion, &event.CreatedAt); err != nil {
			return fmt.Errorf("scan relational incident webhook event: %w", err)
		}
		event.TimelineEventID = nullableSQLString(timelineEventID)
		state.IncidentWebhookEvents[event.ID] = event
		*loaded = true
	}
	if err := webhookRows.Err(); err != nil {
		return err
	}

	taskRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, incident_id, release_id, title, owner, status, due_at, evidence_id, schema_version, created_at FROM remediation_tasks`)
	if err != nil {
		return fmt.Errorf("load relational remediation tasks: %w", err)
	}
	defer taskRows.Close()
	for taskRows.Next() {
		var task domain.RemediationTask
		var incidentID, releaseID, evidenceID sql.NullString
		var dueAt sql.NullTime
		if err := taskRows.Scan(&task.ID, &task.TenantID, &incidentID, &releaseID, &task.Title, &task.Owner, &task.Status, &dueAt, &evidenceID, &task.SchemaVersion, &task.CreatedAt); err != nil {
			return fmt.Errorf("scan relational remediation task: %w", err)
		}
		task.IncidentID = nullableSQLString(incidentID)
		task.ReleaseID = nullableSQLString(releaseID)
		task.DueAt = nullableSQLTime(dueAt)
		task.EvidenceID = nullableSQLString(evidenceID)
		state.RemediationTasks[task.ID] = task
		*loaded = true
	}
	return taskRows.Err()
}

func (s *Store) loadRelationalSecurityEvidence(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	scanRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, product_id, release_id, artifact_id, category, format, scanner, target_ref, evidence_id, payload_ref, payload_hash, finding_count, summary, redacted, quarantined, schema_version, created_at FROM security_scans`)
	if err != nil {
		return fmt.Errorf("load relational security scans: %w", err)
	}
	defer scanRows.Close()
	for scanRows.Next() {
		var scan domain.SecurityScan
		var productID, releaseID, artifactID, payloadRef sql.NullString
		var summary []byte
		if err := scanRows.Scan(&scan.ID, &scan.TenantID, &productID, &releaseID, &artifactID, &scan.Category, &scan.Format, &scan.Scanner, &scan.TargetRef, &scan.EvidenceID, &payloadRef, &scan.PayloadHash, &scan.FindingCount, &summary, &scan.Redacted, &scan.Quarantined, &scan.SchemaVersion, &scan.CreatedAt); err != nil {
			return fmt.Errorf("scan relational security scan: %w", err)
		}
		scan.ProductID = nullableSQLString(productID)
		scan.ReleaseID = nullableSQLString(releaseID)
		scan.ArtifactID = nullableSQLString(artifactID)
		scan.PayloadRef = nullableSQLString(payloadRef)
		if err := decodeJSON(summary, &scan.Summary); err != nil {
			return fmt.Errorf("decode relational security scan summary: %w", err)
		}
		state.SecurityScans[scan.ID] = scan
		*loaded = true
	}
	if err := scanRows.Err(); err != nil {
		return err
	}

	docRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, product_id, release_id, document_type, title, sensitivity, evidence_id, payload_ref, payload_hash, schema_version, created_at FROM manual_security_documents`)
	if err != nil {
		return fmt.Errorf("load relational manual security documents: %w", err)
	}
	defer docRows.Close()
	for docRows.Next() {
		var document domain.ManualSecurityDocument
		var productID, releaseID, payloadRef sql.NullString
		if err := docRows.Scan(&document.ID, &document.TenantID, &productID, &releaseID, &document.DocumentType, &document.Title, &document.Sensitivity, &document.EvidenceID, &payloadRef, &document.PayloadHash, &document.SchemaVersion, &document.CreatedAt); err != nil {
			return fmt.Errorf("scan relational manual security document: %w", err)
		}
		document.ProductID = nullableSQLString(productID)
		document.ReleaseID = nullableSQLString(releaseID)
		document.PayloadRef = nullableSQLString(payloadRef)
		state.ManualSecurityDocs[document.ID] = document
		*loaded = true
	}
	return docRows.Err()
}

func (s *Store) loadRelationalDiffsAndPolicies(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	sbomRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, base_sbom_id, target_sbom_id, release_id, document, schema_version, created_at FROM sbom_diffs`)
	if err != nil {
		return fmt.Errorf("load relational sbom diffs: %w", err)
	}
	defer sbomRows.Close()
	for sbomRows.Next() {
		var diff domain.SBOMDiff
		var releaseID sql.NullString
		var document []byte
		if err := sbomRows.Scan(&diff.ID, &diff.TenantID, &diff.BaseSBOMID, &diff.TargetSBOMID, &releaseID, &document, &diff.SchemaVersion, &diff.CreatedAt); err != nil {
			return fmt.Errorf("scan relational sbom diff: %w", err)
		}
		diff.ReleaseID = nullableSQLString(releaseID)
		var embedded domain.SBOMDiff
		if err := decodeJSON(document, &embedded); err != nil {
			return fmt.Errorf("decode relational sbom diff document: %w", err)
		}
		diff.AddedComponents = embedded.AddedComponents
		diff.RemovedComponents = embedded.RemovedComponents
		diff.UnchangedCount = embedded.UnchangedCount
		diff.DependencyChanges = embedded.DependencyChanges
		state.SBOMDiffs[diff.ID] = diff
		*loaded = true
	}
	if err := sbomRows.Err(); err != nil {
		return err
	}

	dependencyRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, sbom_diff_id, change_type, component, schema_version, created_at FROM dependency_changes`)
	if err != nil {
		return fmt.Errorf("load relational dependency changes: %w", err)
	}
	defer dependencyRows.Close()
	for dependencyRows.Next() {
		var change domain.DependencyChange
		var component []byte
		if err := dependencyRows.Scan(&change.ID, &change.TenantID, &change.SBOMDiffID, &change.ChangeType, &component, &change.SchemaVersion, &change.CreatedAt); err != nil {
			return fmt.Errorf("scan relational dependency change: %w", err)
		}
		if err := decodeJSON(component, &change.Component); err != nil {
			return fmt.Errorf("decode relational dependency component: %w", err)
		}
		state.DependencyChanges[change.ID] = change
		*loaded = true
	}
	if err := dependencyRows.Err(); err != nil {
		return err
	}

	workflowRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, finding_id, release_id, action, reason, actor_id, schema_version, created_at FROM vulnerability_workflow_records`)
	if err != nil {
		return fmt.Errorf("load relational vulnerability workflow: %w", err)
	}
	defer workflowRows.Close()
	for workflowRows.Next() {
		var record domain.VulnerabilityWorkflowRecord
		var releaseID sql.NullString
		if err := workflowRows.Scan(&record.ID, &record.TenantID, &record.FindingID, &releaseID, &record.Action, &record.Reason, &record.ActorID, &record.SchemaVersion, &record.CreatedAt); err != nil {
			return fmt.Errorf("scan relational vulnerability workflow: %w", err)
		}
		record.ReleaseID = nullableSQLString(releaseID)
		state.VulnerabilityWorkflow[record.ID] = record
		*loaded = true
	}
	if err := workflowRows.Err(); err != nil {
		return err
	}

	contractRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, base_contract_id, target_contract_id, product_id, release_id, result, document, schema_version, created_at FROM contract_diffs`)
	if err != nil {
		return fmt.Errorf("load relational contract diffs: %w", err)
	}
	defer contractRows.Close()
	for contractRows.Next() {
		var diff domain.ContractDiff
		var releaseID sql.NullString
		var document []byte
		if err := contractRows.Scan(&diff.ID, &diff.TenantID, &diff.BaseContractID, &diff.TargetContractID, &diff.ProductID, &releaseID, &diff.Result, &document, &diff.SchemaVersion, &diff.CreatedAt); err != nil {
			return fmt.Errorf("scan relational contract diff: %w", err)
		}
		diff.ReleaseID = nullableSQLString(releaseID)
		var embedded domain.ContractDiff
		if err := decodeJSON(document, &embedded); err != nil {
			return fmt.Errorf("decode relational contract diff document: %w", err)
		}
		diff.BreakingChanges = embedded.BreakingChanges
		diff.NonBreakingChanges = embedded.NonBreakingChanges
		state.ContractDiffs[diff.ID] = diff
		*loaded = true
	}
	if err := contractRows.Err(); err != nil {
		return err
	}

	policyRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, version, description, rules, schema_version, created_at FROM custom_policies`)
	if err != nil {
		return fmt.Errorf("load relational custom policies: %w", err)
	}
	defer policyRows.Close()
	for policyRows.Next() {
		var policy domain.CustomPolicy
		var description sql.NullString
		var rules []byte
		if err := policyRows.Scan(&policy.ID, &policy.TenantID, &policy.Name, &policy.Version, &description, &rules, &policy.SchemaVersion, &policy.CreatedAt); err != nil {
			return fmt.Errorf("scan relational custom policy: %w", err)
		}
		policy.Description = nullableSQLString(description)
		if err := decodeJSON(rules, &policy.Rules); err != nil {
			return fmt.Errorf("decode relational custom policy rules: %w", err)
		}
		state.CustomPolicies[policy.ID] = policy
		*loaded = true
	}
	if err := policyRows.Err(); err != nil {
		return err
	}

	evalRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, policy_id, release_id, result, checks, input_hash, schema_version, created_at FROM custom_policy_evaluations`)
	if err != nil {
		return fmt.Errorf("load relational custom policy evaluations: %w", err)
	}
	defer evalRows.Close()
	for evalRows.Next() {
		var evaluation domain.CustomPolicyEvaluation
		var checks []byte
		if err := evalRows.Scan(&evaluation.ID, &evaluation.TenantID, &evaluation.PolicyID, &evaluation.ReleaseID, &evaluation.Result, &checks, &evaluation.InputHash, &evaluation.SchemaVersion, &evaluation.CreatedAt); err != nil {
			return fmt.Errorf("scan relational custom policy evaluation: %w", err)
		}
		if err := decodeJSON(checks, &evaluation.Checks); err != nil {
			return fmt.Errorf("decode relational custom policy checks: %w", err)
		}
		state.CustomPolicyEvaluations[evaluation.ID] = evaluation
		*loaded = true
	}
	return evalRows.Err()
}

func (s *Store) loadRelationalWaiversApprovalsTrust(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	waiverRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, scope_type, scope_id, control_id, policy_id, owner, risk, reason, expires_at, approved, approved_by, approved_at, supersedes, superseded_by, schema_version, created_at FROM waivers`)
	if err != nil {
		return fmt.Errorf("load relational waivers: %w", err)
	}
	defer waiverRows.Close()
	for waiverRows.Next() {
		var waiver domain.Waiver
		var controlID, policyID, approvedBy, supersedes, supersededBy sql.NullString
		var approvedAt sql.NullTime
		if err := waiverRows.Scan(&waiver.ID, &waiver.TenantID, &waiver.ScopeType, &waiver.ScopeID, &controlID, &policyID, &waiver.Owner, &waiver.Risk, &waiver.Reason, &waiver.ExpiresAt, &waiver.Approved, &approvedBy, &approvedAt, &supersedes, &supersededBy, &waiver.SchemaVersion, &waiver.CreatedAt); err != nil {
			return fmt.Errorf("scan relational waiver: %w", err)
		}
		waiver.ControlID = nullableSQLString(controlID)
		waiver.PolicyID = nullableSQLString(policyID)
		waiver.ApprovedBy = nullableSQLString(approvedBy)
		waiver.ApprovedAt = nullableSQLTime(approvedAt)
		waiver.Supersedes = nullableSQLString(supersedes)
		waiver.SupersededBy = nullableSQLString(supersededBy)
		state.Waivers[waiver.ID] = waiver
		*loaded = true
	}
	if err := waiverRows.Err(); err != nil {
		return err
	}

	approvalRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, subject_type, subject_id, decision, reason, approver_id, evidence_id, schema_version, created_at FROM approval_records`)
	if err != nil {
		return fmt.Errorf("load relational approvals: %w", err)
	}
	defer approvalRows.Close()
	for approvalRows.Next() {
		var approval domain.ApprovalRecord
		var evidenceID sql.NullString
		if err := approvalRows.Scan(&approval.ID, &approval.TenantID, &approval.SubjectType, &approval.SubjectID, &approval.Decision, &approval.Reason, &approval.ApproverID, &evidenceID, &approval.SchemaVersion, &approval.CreatedAt); err != nil {
			return fmt.Errorf("scan relational approval: %w", err)
		}
		approval.EvidenceID = nullableSQLString(evidenceID)
		state.Approvals[approval.ID] = approval
		*loaded = true
	}
	if err := approvalRows.Err(); err != nil {
		return err
	}

	trustRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, key_id, algorithm, public_key, status, schema_version, created_at FROM dsse_trust_roots`)
	if err != nil {
		return fmt.Errorf("load relational dsse trust roots: %w", err)
	}
	defer trustRows.Close()
	for trustRows.Next() {
		var root domain.DSSETrustRoot
		if err := trustRows.Scan(&root.ID, &root.TenantID, &root.Name, &root.KeyID, &root.Algorithm, &root.PublicKey, &root.Status, &root.SchemaVersion, &root.CreatedAt); err != nil {
			return fmt.Errorf("scan relational dsse trust root: %w", err)
		}
		state.DSSETrustRoots[root.ID] = root
		*loaded = true
	}
	return trustRows.Err()
}

func (s *Store) loadRelationalIntegrityProviderRows(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	collectorRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, collector_id, version, artifact_digest, signature_id, sbom_id, scan_id, pinned, verification_status, health_status, limitations, schema_version, created_at FROM collector_releases`)
	if err != nil {
		return fmt.Errorf("load relational collector releases: %w", err)
	}
	defer collectorRows.Close()
	for collectorRows.Next() {
		var release domain.CollectorRelease
		var signatureID, sbomID, scanID sql.NullString
		if err := collectorRows.Scan(&release.ID, &release.TenantID, &release.CollectorID, &release.Version, &release.ArtifactDigest, &signatureID, &sbomID, &scanID, &release.Pinned, &release.VerificationStatus, &release.HealthStatus, &release.Limitations, &release.SchemaVersion, &release.CreatedAt); err != nil {
			return fmt.Errorf("scan relational collector release: %w", err)
		}
		release.SignatureID = nullableSQLString(signatureID)
		release.SBOMID = nullableSQLString(sbomID)
		release.ScanID = nullableSQLString(scanID)
		state.CollectorReleases[release.ID] = release
		*loaded = true
	}
	if err := collectorRows.Err(); err != nil {
		return err
	}

	cosignRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, artifact_id, container_image_id, artifact_signature_id, subject_digest, rekor_uuid, rekor_log_index, certificate_identity, certificate_issuer, result, checks, schema_version, created_at FROM cosign_verifications`)
	if err != nil {
		return fmt.Errorf("load relational cosign verifications: %w", err)
	}
	defer cosignRows.Close()
	for cosignRows.Next() {
		var verification domain.CosignVerification
		var artifactID, imageID, rekorUUID, rekorLogIndex, certIdentity, certIssuer sql.NullString
		var checks []byte
		if err := cosignRows.Scan(&verification.ID, &verification.TenantID, &artifactID, &imageID, &verification.ArtifactSignatureID, &verification.SubjectDigest, &rekorUUID, &rekorLogIndex, &certIdentity, &certIssuer, &verification.Result, &checks, &verification.SchemaVersion, &verification.CreatedAt); err != nil {
			return fmt.Errorf("scan relational cosign verification: %w", err)
		}
		verification.ArtifactID = nullableSQLString(artifactID)
		verification.ContainerImageID = nullableSQLString(imageID)
		verification.RekorUUID = nullableSQLString(rekorUUID)
		verification.RekorLogIndex = nullableSQLString(rekorLogIndex)
		verification.CertificateIdentity = nullableSQLString(certIdentity)
		verification.CertificateIssuer = nullableSQLString(certIssuer)
		if err := decodeJSON(checks, &verification.Checks); err != nil {
			return fmt.Errorf("decode relational cosign checks: %w", err)
		}
		state.CosignVerifications[verification.ID] = verification
		*loaded = true
	}
	if err := cosignRows.Err(); err != nil {
		return err
	}

	providerRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, type, status, key_ref, encrypted, schema_version, created_at FROM signing_providers`)
	if err != nil {
		return fmt.Errorf("load relational signing providers: %w", err)
	}
	defer providerRows.Close()
	for providerRows.Next() {
		var provider domain.SigningProvider
		if err := providerRows.Scan(&provider.ID, &provider.TenantID, &provider.Name, &provider.Type, &provider.Status, &provider.KeyRef, &provider.Encrypted, &provider.SchemaVersion, &provider.CreatedAt); err != nil {
			return fmt.Errorf("scan relational signing provider: %w", err)
		}
		state.SigningProviders[provider.ID] = provider
		*loaded = true
	}
	if err := providerRows.Err(); err != nil {
		return err
	}

	batchRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, from_sequence, to_sequence, entry_count, leaf_hashes, root_hash, signature_refs, schema_version, created_at FROM merkle_batches`)
	if err != nil {
		return fmt.Errorf("load relational merkle batches: %w", err)
	}
	defer batchRows.Close()
	for batchRows.Next() {
		var batch domain.MerkleBatch
		if err := batchRows.Scan(&batch.ID, &batch.TenantID, &batch.FromSequence, &batch.ToSequence, &batch.EntryCount, &batch.LeafHashes, &batch.RootHash, &batch.SignatureRefs, &batch.SchemaVersion, &batch.CreatedAt); err != nil {
			return fmt.Errorf("scan relational merkle batch: %w", err)
		}
		state.MerkleBatches[batch.ID] = batch
		*loaded = true
	}
	if err := batchRows.Err(); err != nil {
		return err
	}

	checkpointRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, batch_id, provider, external_url, external_id, timestamp_hash, state, schema_version, created_at FROM transparency_checkpoints`)
	if err != nil {
		return fmt.Errorf("load relational transparency checkpoints: %w", err)
	}
	defer checkpointRows.Close()
	for checkpointRows.Next() {
		var checkpoint domain.TransparencyCheckpoint
		var externalURL, externalID sql.NullString
		if err := checkpointRows.Scan(&checkpoint.ID, &checkpoint.TenantID, &checkpoint.BatchID, &checkpoint.Provider, &externalURL, &externalID, &checkpoint.TimestampHash, &checkpoint.State, &checkpoint.SchemaVersion, &checkpoint.CreatedAt); err != nil {
			return fmt.Errorf("scan relational transparency checkpoint: %w", err)
		}
		checkpoint.ExternalURL = nullableSQLString(externalURL)
		checkpoint.ExternalID = nullableSQLString(externalID)
		state.TransparencyCheckpoints[checkpoint.ID] = checkpoint
		*loaded = true
	}
	return checkpointRows.Err()
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

func (s *Store) loadRelationalFutureExtensionRows(ctx context.Context, state *app.PersistedState, loaded *bool) error {
	commercialRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, provider, version, manifest_hash, allowed_scopes, status, schema_version, created_at FROM commercial_collectors`)
	if err != nil {
		return fmt.Errorf("load relational commercial collectors: %w", err)
	}
	defer commercialRows.Close()
	for commercialRows.Next() {
		var collector domain.CommercialCollectorDefinition
		if err := commercialRows.Scan(&collector.ID, &collector.TenantID, &collector.Name, &collector.Provider, &collector.Version, &collector.ManifestHash, &collector.AllowedScopes, &collector.Status, &collector.SchemaVersion, &collector.CreatedAt); err != nil {
			return fmt.Errorf("scan relational commercial collector: %w", err)
		}
		state.CommercialCollectors[collector.ID] = collector
		*loaded = true
	}
	if err := commercialRows.Err(); err != nil {
		return err
	}

	summaryRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, subject_type, subject_id, evidence_ids, summary, citations, assumptions, limitations, schema_version, created_at FROM evidence_summaries`)
	if err != nil {
		return fmt.Errorf("load relational evidence summaries: %w", err)
	}
	defer summaryRows.Close()
	for summaryRows.Next() {
		var summary domain.EvidenceSummary
		var citations []byte
		if err := summaryRows.Scan(&summary.ID, &summary.TenantID, &summary.SubjectType, &summary.SubjectID, &summary.EvidenceIDs, &summary.Summary, &citations, &summary.Assumptions, &summary.Limitations, &summary.SchemaVersion, &summary.CreatedAt); err != nil {
			return fmt.Errorf("scan relational evidence summary: %w", err)
		}
		if err := decodeJSON(citations, &summary.Citations); err != nil {
			return fmt.Errorf("decode relational evidence summary citations: %w", err)
		}
		state.EvidenceSummaries[summary.ID] = summary
		*loaded = true
	}
	if err := summaryRows.Err(); err != nil {
		return err
	}

	draftRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, template_id, product_id, release_id, responses, manifest_hash, limitations, schema_version, created_at FROM questionnaire_drafts`)
	if err != nil {
		return fmt.Errorf("load relational questionnaire drafts: %w", err)
	}
	defer draftRows.Close()
	for draftRows.Next() {
		var draft domain.QuestionnaireDraft
		var productID, releaseID sql.NullString
		var responses []byte
		if err := draftRows.Scan(&draft.ID, &draft.TenantID, &draft.TemplateID, &productID, &releaseID, &responses, &draft.ManifestHash, &draft.Limitations, &draft.SchemaVersion, &draft.CreatedAt); err != nil {
			return fmt.Errorf("scan relational questionnaire draft: %w", err)
		}
		draft.ProductID = nullableSQLString(productID)
		draft.ReleaseID = nullableSQLString(releaseID)
		if err := decodeJSON(responses, &draft.Responses); err != nil {
			return fmt.Errorf("decode relational questionnaire draft responses: %w", err)
		}
		state.QuestionnaireDrafts[draft.ID] = draft
		*loaded = true
	}
	if err := draftRows.Err(); err != nil {
		return err
	}

	graphRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, product_id, release_id, nodes, edges, graph_hash, limitations, schema_version, created_at FROM evidence_graph_snapshots`)
	if err != nil {
		return fmt.Errorf("load relational graph snapshots: %w", err)
	}
	defer graphRows.Close()
	for graphRows.Next() {
		var graph domain.EvidenceGraphSnapshot
		var productID, releaseID sql.NullString
		var nodes, edges []byte
		if err := graphRows.Scan(&graph.ID, &graph.TenantID, &productID, &releaseID, &nodes, &edges, &graph.GraphHash, &graph.Limitations, &graph.SchemaVersion, &graph.CreatedAt); err != nil {
			return fmt.Errorf("scan relational graph snapshot: %w", err)
		}
		graph.ProductID = nullableSQLString(productID)
		graph.ReleaseID = nullableSQLString(releaseID)
		if err := decodeJSON(nodes, &graph.Nodes); err != nil {
			return fmt.Errorf("decode relational graph nodes: %w", err)
		}
		if err := decodeJSON(edges, &graph.Edges); err != nil {
			return fmt.Errorf("decode relational graph edges: %w", err)
		}
		state.GraphSnapshots[graph.ID] = graph
		*loaded = true
	}
	if err := graphRows.Err(); err != nil {
		return err
	}

	saasRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, region, admin_tenant_id, isolation_model, status, config_hash, limitations, schema_version, created_at FROM saas_edition_profiles`)
	if err != nil {
		return fmt.Errorf("load relational saas profiles: %w", err)
	}
	defer saasRows.Close()
	for saasRows.Next() {
		var profile domain.SaaSEditionProfile
		if err := saasRows.Scan(&profile.ID, &profile.TenantID, &profile.Name, &profile.Region, &profile.AdminTenantID, &profile.IsolationModel, &profile.Status, &profile.ConfigHash, &profile.Limitations, &profile.SchemaVersion, &profile.CreatedAt); err != nil {
			return fmt.Errorf("scan relational saas profile: %w", err)
		}
		state.SaaSProfiles[profile.ID] = profile
		*loaded = true
	}
	if err := saasRows.Err(); err != nil {
		return err
	}

	logRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, endpoint, public_key, state, schema_version, created_at FROM public_transparency_logs`)
	if err != nil {
		return fmt.Errorf("load relational public transparency logs: %w", err)
	}
	defer logRows.Close()
	for logRows.Next() {
		var log domain.PublicTransparencyLog
		if err := logRows.Scan(&log.ID, &log.TenantID, &log.Name, &log.Endpoint, &log.PublicKey, &log.State, &log.SchemaVersion, &log.CreatedAt); err != nil {
			return fmt.Errorf("scan relational public transparency log: %w", err)
		}
		state.PublicTransparencyLogs[log.ID] = log
		*loaded = true
	}
	if err := logRows.Err(); err != nil {
		return err
	}

	entryRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, log_id, checkpoint_id, merkle_batch_id, external_id, entry_hash, inclusion_root_hash, inclusion_proof_hash, inclusion_verified_at, verification_checks, verification_limitations, state, schema_version, created_at FROM public_transparency_log_entries`)
	if err != nil {
		return fmt.Errorf("load relational public transparency entries: %w", err)
	}
	defer entryRows.Close()
	for entryRows.Next() {
		var entry domain.PublicTransparencyLogEntry
		var rootHash, proofHash sql.NullString
		var verifiedAt sql.NullTime
		var checks []byte
		if err := entryRows.Scan(&entry.ID, &entry.TenantID, &entry.LogID, &entry.CheckpointID, &entry.MerkleBatchID, &entry.ExternalID, &entry.EntryHash, &rootHash, &proofHash, &verifiedAt, &checks, &entry.VerificationLimitations, &entry.State, &entry.SchemaVersion, &entry.CreatedAt); err != nil {
			return fmt.Errorf("scan relational public transparency entry: %w", err)
		}
		entry.InclusionRootHash = nullableSQLString(rootHash)
		entry.InclusionProofHash = nullableSQLString(proofHash)
		entry.InclusionVerifiedAt = nullableSQLTime(verifiedAt)
		if err := decodeJSON(checks, &entry.VerificationChecks); err != nil {
			return fmt.Errorf("decode relational transparency checks: %w", err)
		}
		state.PublicTransparencyItems[entry.ID] = entry
		*loaded = true
	}
	if err := entryRows.Err(); err != nil {
		return err
	}

	marketRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, provider, version, publisher, manifest_hash, signature_id, sbom_id, scan_id, state, limitations, schema_version, created_at FROM marketplace_collectors`)
	if err != nil {
		return fmt.Errorf("load relational marketplace collectors: %w", err)
	}
	defer marketRows.Close()
	for marketRows.Next() {
		var collector domain.MarketplaceCollector
		var signatureID, sbomID, scanID sql.NullString
		if err := marketRows.Scan(&collector.ID, &collector.TenantID, &collector.Name, &collector.Provider, &collector.Version, &collector.Publisher, &collector.ManifestHash, &signatureID, &sbomID, &scanID, &collector.State, &collector.Limitations, &collector.SchemaVersion, &collector.CreatedAt); err != nil {
			return fmt.Errorf("scan relational marketplace collector: %w", err)
		}
		collector.SignatureID = nullableSQLString(signatureID)
		collector.SBOMID = nullableSQLString(sbomID)
		collector.ScanID = nullableSQLString(scanID)
		state.MarketplaceCollectors[collector.ID] = collector
		*loaded = true
	}
	if err := marketRows.Err(); err != nil {
		return err
	}

	providerRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, provider_type, provider_id, subject, result, checks, limitations, schema_version, created_at FROM provider_verifications`)
	if err != nil {
		return fmt.Errorf("load relational provider verifications: %w", err)
	}
	defer providerRows.Close()
	for providerRows.Next() {
		var verification domain.ProviderVerification
		var checks []byte
		if err := providerRows.Scan(&verification.ID, &verification.TenantID, &verification.ProviderType, &verification.ProviderID, &verification.Subject, &verification.Result, &checks, &verification.Limitations, &verification.SchemaVersion, &verification.CreatedAt); err != nil {
			return fmt.Errorf("scan relational provider verification: %w", err)
		}
		if err := decodeJSON(checks, &verification.Checks); err != nil {
			return fmt.Errorf("decode relational provider verification checks: %w", err)
		}
		state.ProviderVerifications[verification.ID] = verification
		*loaded = true
	}
	if err := providerRows.Err(); err != nil {
		return err
	}

	signingRows, err := s.pool.Query(ctx, `SELECT id, tenant_id, provider_id, subject_type, subject_id, payload_hash, signature_ref, result, checks, schema_version, created_at FROM signing_operations`)
	if err != nil {
		return fmt.Errorf("load relational signing operations: %w", err)
	}
	defer signingRows.Close()
	for signingRows.Next() {
		var operation domain.SigningOperation
		var signatureRef sql.NullString
		var checks []byte
		if err := signingRows.Scan(&operation.ID, &operation.TenantID, &operation.ProviderID, &operation.SubjectType, &operation.SubjectID, &operation.PayloadHash, &signatureRef, &operation.Result, &checks, &operation.SchemaVersion, &operation.CreatedAt); err != nil {
			return fmt.Errorf("scan relational signing operation: %w", err)
		}
		operation.SignatureRef = nullableSQLString(signatureRef)
		if err := decodeJSON(checks, &operation.Checks); err != nil {
			return fmt.Errorf("decode relational signing operation checks: %w", err)
		}
		state.SigningOperations[operation.ID] = operation
		*loaded = true
	}
	return signingRows.Err()
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
	if err := syncRiskBuildControlRows(ctx, tx, state); err != nil {
		return err
	}
	if err := syncSourceDeploymentLifecycleRows(ctx, tx, state); err != nil {
		return err
	}
	if err := syncIncidentSecurityGovernanceRows(ctx, tx, state); err != nil {
		return err
	}
	if err := syncIntegrityProviderRows(ctx, tx, state); err != nil {
		return err
	}
	if err := syncPackageReportRetentionRows(ctx, tx, state); err != nil {
		return err
	}
	if err := syncFutureExtensionRows(ctx, tx, state); err != nil {
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

func syncRiskBuildControlRows(ctx context.Context, tx pgx.Tx, state app.PersistedState) error {
	for _, collector := range state.Collectors {
		if collector.ID == "" || collector.TenantID == "" || collector.APIKeyID == "" {
			continue
		}
		allowedScopes, err := json.Marshal(collector.AllowedScopes)
		if err != nil {
			return fmt.Errorf("encode collector scopes: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO collectors (
				id, tenant_id, name, type, version, api_key_id, status,
				allowed_scopes, last_seen_at, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				version = EXCLUDED.version,
				api_key_id = EXCLUDED.api_key_id,
				status = EXCLUDED.status,
				allowed_scopes = EXCLUDED.allowed_scopes,
				last_seen_at = EXCLUDED.last_seen_at,
				schema_version = EXCLUDED.schema_version
		`, collector.ID, collector.TenantID, collector.Name, collector.Type, collector.Version, collector.APIKeyID, collector.Status, allowedScopes, nullableTime(collector.LastSeenAt), collector.SchemaVersion, nonZeroTime(collector.CreatedAt)); err != nil {
			return fmt.Errorf("upsert collector row: %w", err)
		}
	}
	for _, build := range state.BuildRuns {
		if build.ID == "" || build.TenantID == "" || build.ProjectID == "" || build.ReleaseID == "" {
			continue
		}
		sourceIdentity, err := json.Marshal(build.SourceIdentity)
		if err != nil {
			return fmt.Errorf("encode build source identity: %w", err)
		}
		outputs, err := json.Marshal(build.Outputs)
		if err != nil {
			return fmt.Errorf("encode build outputs: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO build_runs (
				id, tenant_id, project_id, release_id, collector_id, provider,
				commit_sha, repository, workflow_ref, run_id, run_attempt,
				job_id, actor, ref, oidc_subject, status, started_at,
				finished_at, parameters_hash, environment_hash, source_identity,
				outputs, schema_version, created_at
			)
			VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, $10, $11,
				$12, $13, $14, $15, $16, $17,
				$18, $19, $20, $21,
				$22, $23, $24
			)
			ON CONFLICT (id) DO UPDATE SET
				status = EXCLUDED.status,
				finished_at = EXCLUDED.finished_at,
				parameters_hash = EXCLUDED.parameters_hash,
				environment_hash = EXCLUDED.environment_hash,
				source_identity = EXCLUDED.source_identity,
				outputs = EXCLUDED.outputs
		`, build.ID, build.TenantID, build.ProjectID, build.ReleaseID, nullableString(build.CollectorID), build.Provider,
			build.CommitSHA, nullableString(build.Repository), nullableString(build.WorkflowRef), nullableString(build.RunID), nullableInt(build.RunAttempt),
			nullableString(build.JobID), nullableString(build.Actor), nullableString(build.Ref), nullableString(build.OIDCSubject), build.Status, nonZeroTime(build.StartedAt),
			nullableTime(build.FinishedAt), nullableString(build.ParametersHash), nullableString(build.EnvironmentHash), sourceIdentity,
			outputs, build.SchemaVersion, nonZeroTime(build.CreatedAt)); err != nil {
			return fmt.Errorf("upsert build run row: %w", err)
		}
	}
	for _, attestation := range state.BuildAttestations {
		if attestation.ID == "" || attestation.TenantID == "" || attestation.BuildID == "" || attestation.EvidenceID == "" {
			continue
		}
		subjectDigests, err := json.Marshal(attestation.SubjectDigests)
		if err != nil {
			return fmt.Errorf("encode attestation subject digests: %w", err)
		}
		if _, err := tx.Exec(ctx, `
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
			ON CONFLICT (id) DO UPDATE SET
				payload_ref = EXCLUDED.payload_ref,
				payload_hash = EXCLUDED.payload_hash,
				payload_size = EXCLUDED.payload_size,
				predicate_type = EXCLUDED.predicate_type,
				subject_digests = EXCLUDED.subject_digests,
				builder_id = EXCLUDED.builder_id,
				build_type = EXCLUDED.build_type,
				materials_count = EXCLUDED.materials_count,
				signature_count = EXCLUDED.signature_count,
				verification_status = EXCLUDED.verification_status
		`, attestation.ID, attestation.TenantID, attestation.BuildID, attestation.EvidenceID, nullableString(attestation.PayloadRef), attestation.PayloadHash,
			attestation.PayloadSize, attestation.PayloadType, attestation.PredicateType, subjectDigests,
			nullableString(attestation.BuilderID), nullableString(attestation.BuildType), attestation.MaterialsCount, attestation.SignatureCount,
			attestation.VerificationStatus, attestation.SchemaVersion, nonZeroTime(attestation.CreatedAt)); err != nil {
			return fmt.Errorf("upsert build attestation row: %w", err)
		}
	}
	for _, document := range state.VEXDocuments {
		if document.ID == "" || document.TenantID == "" || document.EvidenceID == "" {
			continue
		}
		statusSummary, err := json.Marshal(document.StatusSummary)
		if err != nil {
			return fmt.Errorf("encode vex status summary: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO vex_documents (
				id, tenant_id, evidence_id, release_id, artifact_id, format,
				author, version, statement_count, status_summary,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (id) DO UPDATE SET
				statement_count = EXCLUDED.statement_count,
				status_summary = EXCLUDED.status_summary
		`, document.ID, document.TenantID, document.EvidenceID, nullableString(document.ReleaseID), nullableString(document.ArtifactID), document.Format,
			document.Author, nullableString(document.Version), document.StatementCount, statusSummary,
			document.SchemaVersion, nonZeroTime(document.CreatedAt)); err != nil {
			return fmt.Errorf("upsert vex document row: %w", err)
		}
	}
	for _, decision := range state.Decisions {
		if decision.ID == "" || decision.TenantID == "" || decision.FindingID == "" || decision.ScanID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO vulnerability_decisions (
				id, tenant_id, finding_id, scan_id, release_id, vulnerability,
				component, status, justification, impact_statement, action_statement,
				source, evidence_id, vex_document_id, supersedes, superseded_by,
				approved_by, schema_version, created_at
			)
			VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, $10, $11,
				$12, $13, $14, $15, $16,
				$17, $18, $19
			)
			ON CONFLICT (id) DO UPDATE SET
				superseded_by = EXCLUDED.superseded_by,
				approved_by = EXCLUDED.approved_by
		`, decision.ID, decision.TenantID, decision.FindingID, decision.ScanID, nullableString(decision.ReleaseID), decision.Vulnerability,
			nullableString(decision.Component), decision.Status, decision.Justification, nullableString(decision.ImpactStatement), nullableString(decision.ActionStatement),
			decision.Source, nullableString(decision.EvidenceID), nullableString(decision.VEXDocumentID), nullableString(decision.Supersedes), nullableString(decision.SupersededBy),
			nullableString(decision.ApprovedBy), decision.SchemaVersion, nonZeroTime(decision.CreatedAt)); err != nil {
			return fmt.Errorf("upsert vulnerability decision row: %w", err)
		}
	}
	for _, exception := range state.Exceptions {
		if exception.ID == "" || exception.TenantID == "" || exception.ReleaseID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO exceptions (
				id, tenant_id, release_id, finding_id, control_id, reason,
				owner, expires_at, approved, approved_by, approved_at, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (id) DO UPDATE SET
				approved = EXCLUDED.approved,
				approved_by = EXCLUDED.approved_by,
				approved_at = EXCLUDED.approved_at
		`, exception.ID, exception.TenantID, exception.ReleaseID, nullableString(exception.FindingID), nullableString(exception.ControlID), exception.Reason,
			exception.Owner, exception.ExpiresAt, exception.Approved, nullableString(exception.ApprovedBy), nullableTime(exception.ApprovedAt), nonZeroTime(exception.CreatedAt)); err != nil {
			return fmt.Errorf("upsert exception row: %w", err)
		}
	}
	for _, framework := range state.ControlFrameworks {
		if framework.ID == "" || framework.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO control_frameworks (
				id, tenant_id, name, slug, version, description,
				status, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET
				description = EXCLUDED.description,
				status = EXCLUDED.status,
				schema_version = EXCLUDED.schema_version
		`, framework.ID, framework.TenantID, framework.Name, framework.Slug, framework.Version, nullableString(framework.Description),
			framework.Status, framework.SchemaVersion, nonZeroTime(framework.CreatedAt)); err != nil {
			return fmt.Errorf("upsert control framework row: %w", err)
		}
	}
	for _, control := range state.SecurityControls {
		if control.ID == "" || control.TenantID == "" || control.FrameworkID == "" {
			continue
		}
		requirements, err := json.Marshal(control.EvidenceRequirements)
		if err != nil {
			return fmt.Errorf("encode control requirements: %w", err)
		}
		applicability, err := json.Marshal(control.Applicability)
		if err != nil {
			return fmt.Errorf("encode control applicability: %w", err)
		}
		limitations, err := json.Marshal(control.Limitations)
		if err != nil {
			return fmt.Errorf("encode control limitations: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO security_controls (
				id, tenant_id, framework_id, code, title, objective,
				evidence_requirements, applicability, limitations,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (id) DO UPDATE SET
				title = EXCLUDED.title,
				objective = EXCLUDED.objective,
				evidence_requirements = EXCLUDED.evidence_requirements,
				applicability = EXCLUDED.applicability,
				limitations = EXCLUDED.limitations,
				schema_version = EXCLUDED.schema_version
		`, control.ID, control.TenantID, control.FrameworkID, control.Code, control.Title, control.Objective,
			requirements, applicability, limitations, control.SchemaVersion, nonZeroTime(control.CreatedAt)); err != nil {
			return fmt.Errorf("upsert security control row: %w", err)
		}
	}
	for _, evidence := range state.ControlEvidence {
		if evidence.ID == "" || evidence.TenantID == "" || evidence.ControlID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO control_evidence (
				id, tenant_id, control_id, evidence_type, subject_type,
				subject_id, product_id, release_id, confidence, notes,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (id) DO UPDATE SET
				confidence = EXCLUDED.confidence,
				notes = EXCLUDED.notes,
				schema_version = EXCLUDED.schema_version
		`, evidence.ID, evidence.TenantID, evidence.ControlID, evidence.EvidenceType, evidence.SubjectType,
			evidence.SubjectID, nullableString(evidence.ProductID), nullableString(evidence.ReleaseID), evidence.Confidence, nullableString(evidence.Notes),
			evidence.SchemaVersion, nonZeroTime(evidence.CreatedAt)); err != nil {
			return fmt.Errorf("upsert control evidence row: %w", err)
		}
	}
	return nil
}

func syncSourceDeploymentLifecycleRows(ctx context.Context, tx pgx.Tx, state app.PersistedState) error {
	for _, event := range state.EvidenceLifecycle {
		if event.ID == "" || event.TenantID == "" || event.EvidenceID == "" {
			continue
		}
		details, err := json.Marshal(event.Details)
		if err != nil {
			return fmt.Errorf("encode evidence lifecycle details: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO evidence_lifecycle_events (
				id, tenant_id, evidence_id, action, reason, details,
				replacement_id, actor_id, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO NOTHING
		`, event.ID, event.TenantID, event.EvidenceID, event.Action, event.Reason, details,
			nullableString(event.ReplacementID), event.ActorID, event.SchemaVersion, nonZeroTime(event.CreatedAt)); err != nil {
			return fmt.Errorf("insert evidence lifecycle row: %w", err)
		}
	}
	for _, candidate := range state.ReleaseCandidates {
		if candidate.ID == "" || candidate.TenantID == "" || candidate.ReleaseID == "" {
			continue
		}
		document, err := json.Marshal(candidate)
		if err != nil {
			return fmt.Errorf("encode release candidate document: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO release_candidates (
				id, tenant_id, release_id, name, state, snapshot_hash,
				document, schema_version, created_at, promoted_at, rejected_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (id) DO UPDATE SET
				state = EXCLUDED.state,
				document = EXCLUDED.document,
				promoted_at = EXCLUDED.promoted_at,
				rejected_at = EXCLUDED.rejected_at
		`, candidate.ID, candidate.TenantID, candidate.ReleaseID, candidate.Name, candidate.State, candidate.SnapshotHash,
			document, candidate.SchemaVersion, nonZeroTime(candidate.CreatedAt), nullableTime(candidate.PromotedAt), nullableTime(candidate.RejectedAt)); err != nil {
			return fmt.Errorf("upsert release candidate row: %w", err)
		}
	}
	for _, image := range state.ContainerImages {
		if image.ID == "" || image.TenantID == "" || image.Repository == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO container_images (
				id, tenant_id, artifact_id, repository, tag, digest,
				platform, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET
				tag = EXCLUDED.tag,
				platform = EXCLUDED.platform
		`, image.ID, image.TenantID, nullableString(image.ArtifactID), image.Repository, nullableString(image.Tag), image.Digest,
			nullableString(image.Platform), image.SchemaVersion, nonZeroTime(image.CreatedAt)); err != nil {
			return fmt.Errorf("upsert container image row: %w", err)
		}
	}
	for _, signature := range state.ArtifactSignatures {
		if signature.ID == "" || signature.TenantID == "" || signature.ArtifactID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO artifact_signatures (
				id, tenant_id, artifact_id, subject_digest, algorithm, key_id,
				signature, payload_ref, payload_hash, verification_status,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (id) DO UPDATE SET
				payload_ref = EXCLUDED.payload_ref,
				payload_hash = EXCLUDED.payload_hash,
				verification_status = EXCLUDED.verification_status
		`, signature.ID, signature.TenantID, signature.ArtifactID, signature.SubjectDigest, signature.Algorithm, nullableString(signature.KeyID),
			signature.Signature, nullableString(signature.PayloadRef), nullableString(signature.PayloadHash), signature.VerificationStatus,
			signature.SchemaVersion, nonZeroTime(signature.CreatedAt)); err != nil {
			return fmt.Errorf("upsert artifact signature row: %w", err)
		}
	}
	for _, repository := range state.Repositories {
		if repository.ID == "" || repository.TenantID == "" || repository.FullName == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO source_repositories (
				id, tenant_id, project_id, provider, full_name, clone_url,
				default_branch, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET
				clone_url = EXCLUDED.clone_url,
				default_branch = EXCLUDED.default_branch
		`, repository.ID, repository.TenantID, nullableString(repository.ProjectID), repository.Provider, repository.FullName, nullableString(repository.CloneURL),
			nullableString(repository.DefaultBranch), repository.SchemaVersion, nonZeroTime(repository.CreatedAt)); err != nil {
			return fmt.Errorf("upsert source repository row: %w", err)
		}
	}
	for _, commit := range state.Commits {
		if commit.ID == "" || commit.TenantID == "" || commit.RepositoryID == "" || commit.SHA == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO source_commits (
				id, tenant_id, repository_id, sha, author, message_hash,
				committed_at, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET message_hash = EXCLUDED.message_hash
		`, commit.ID, commit.TenantID, commit.RepositoryID, commit.SHA, nullableString(commit.Author), nullableString(commit.MessageHash),
			nonZeroTime(commit.CommittedAt), commit.SchemaVersion, nonZeroTime(commit.CreatedAt)); err != nil {
			return fmt.Errorf("upsert source commit row: %w", err)
		}
	}
	for _, branch := range state.Branches {
		if branch.ID == "" || branch.TenantID == "" || branch.RepositoryID == "" || branch.Name == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO source_branches (
				id, tenant_id, repository_id, name, head_commit_id, protected,
				protection_hash, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET
				head_commit_id = EXCLUDED.head_commit_id,
				protected = EXCLUDED.protected,
				protection_hash = EXCLUDED.protection_hash
		`, branch.ID, branch.TenantID, branch.RepositoryID, branch.Name, nullableString(branch.HeadCommitID), branch.Protected,
			nullableString(branch.ProtectionHash), branch.SchemaVersion, nonZeroTime(branch.CreatedAt)); err != nil {
			return fmt.Errorf("upsert source branch row: %w", err)
		}
	}
	for _, pr := range state.PullRequests {
		if pr.ID == "" || pr.TenantID == "" || pr.RepositoryID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO pull_requests (
				id, tenant_id, repository_id, provider, provider_id, title,
				state, source_branch, target_branch, head_commit_id,
				review_decision, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			ON CONFLICT (id) DO UPDATE SET
				state = EXCLUDED.state,
				head_commit_id = EXCLUDED.head_commit_id,
				review_decision = EXCLUDED.review_decision
		`, pr.ID, pr.TenantID, pr.RepositoryID, pr.Provider, pr.ProviderID, pr.Title,
			pr.State, nullableString(pr.SourceBranch), nullableString(pr.TargetBranch), nullableString(pr.HeadCommitID),
			nullableString(pr.ReviewDecision), pr.SchemaVersion, nonZeroTime(pr.CreatedAt)); err != nil {
			return fmt.Errorf("upsert pull request row: %w", err)
		}
	}
	for _, environment := range state.Environments {
		if environment.ID == "" || environment.TenantID == "" || environment.ProductID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO deployment_environments (
				id, tenant_id, product_id, name, kind, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind
		`, environment.ID, environment.TenantID, environment.ProductID, environment.Name, environment.Kind, environment.SchemaVersion, nonZeroTime(environment.CreatedAt)); err != nil {
			return fmt.Errorf("upsert deployment environment row: %w", err)
		}
	}
	for _, deployment := range state.Deployments {
		if deployment.ID == "" || deployment.TenantID == "" || deployment.EnvironmentID == "" || deployment.ReleaseID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO deployment_events (
				id, tenant_id, environment_id, release_id, artifact_ids,
				status, started_at, finished_at, rollback_of, evidence_id,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (id) DO UPDATE SET
				status = EXCLUDED.status,
				finished_at = EXCLUDED.finished_at
		`, deployment.ID, deployment.TenantID, deployment.EnvironmentID, deployment.ReleaseID, deployment.ArtifactIDs,
			deployment.Status, nonZeroTime(deployment.StartedAt), nullableTime(deployment.FinishedAt), nullableString(deployment.RollbackOf), nullableString(deployment.EvidenceID),
			deployment.SchemaVersion, nonZeroTime(deployment.CreatedAt)); err != nil {
			return fmt.Errorf("upsert deployment event row: %w", err)
		}
	}
	return nil
}

func syncIncidentSecurityGovernanceRows(ctx context.Context, tx pgx.Tx, state app.PersistedState) error {
	for _, incident := range state.Incidents {
		if incident.ID == "" || incident.TenantID == "" || incident.ProductID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO incidents (
				id, tenant_id, product_id, release_id, title, severity, status,
				opened_at, closed_at, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (id) DO UPDATE SET
				status = EXCLUDED.status,
				closed_at = EXCLUDED.closed_at
		`, incident.ID, incident.TenantID, incident.ProductID, nullableString(incident.ReleaseID), incident.Title, incident.Severity, incident.Status,
			nonZeroTime(incident.OpenedAt), nullableTime(incident.ClosedAt), incident.SchemaVersion, nonZeroTime(incident.CreatedAt)); err != nil {
			return fmt.Errorf("upsert incident row: %w", err)
		}
	}
	for _, event := range state.TimelineEvents {
		if event.ID == "" || event.TenantID == "" || event.IncidentID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO incident_timeline_events (
				id, tenant_id, incident_id, event_type, summary, evidence_id,
				occurred_at, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO NOTHING
		`, event.ID, event.TenantID, event.IncidentID, event.EventType, event.Summary, nullableString(event.EvidenceID),
			nonZeroTime(event.OccurredAt), event.SchemaVersion, nonZeroTime(event.CreatedAt)); err != nil {
			return fmt.Errorf("insert incident timeline row: %w", err)
		}
	}
	for _, receiver := range state.IncidentWebhookReceivers {
		if receiver.ID == "" || receiver.TenantID == "" || receiver.IncidentID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO incident_webhook_receivers (
				id, tenant_id, incident_id, name, provider, public_key, status,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status
		`, receiver.ID, receiver.TenantID, receiver.IncidentID, receiver.Name, receiver.Provider, receiver.PublicKey, receiver.Status, receiver.SchemaVersion, nonZeroTime(receiver.CreatedAt)); err != nil {
			return fmt.Errorf("upsert incident webhook receiver row: %w", err)
		}
	}
	for _, event := range state.IncidentWebhookEvents {
		if event.ID == "" || event.TenantID == "" || event.ReceiverID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO incident_webhook_events (
				id, tenant_id, receiver_id, incident_id, provider, event_id,
				payload_hash, signature_hash, timeline_event_id, result,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (id) DO UPDATE SET result = EXCLUDED.result, timeline_event_id = EXCLUDED.timeline_event_id
		`, event.ID, event.TenantID, event.ReceiverID, event.IncidentID, event.Provider, event.EventID,
			event.PayloadHash, event.SignatureHash, nullableString(event.TimelineEventID), event.Result, event.SchemaVersion, nonZeroTime(event.CreatedAt)); err != nil {
			return fmt.Errorf("upsert incident webhook event row: %w", err)
		}
	}
	for _, task := range state.RemediationTasks {
		if task.ID == "" || task.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO remediation_tasks (
				id, tenant_id, incident_id, release_id, title, owner, status,
				due_at, evidence_id, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, evidence_id = EXCLUDED.evidence_id
		`, task.ID, task.TenantID, nullableString(task.IncidentID), nullableString(task.ReleaseID), task.Title, task.Owner, task.Status,
			nullableTime(task.DueAt), nullableString(task.EvidenceID), task.SchemaVersion, nonZeroTime(task.CreatedAt)); err != nil {
			return fmt.Errorf("upsert remediation task row: %w", err)
		}
	}
	for _, scan := range state.SecurityScans {
		if scan.ID == "" || scan.TenantID == "" || scan.EvidenceID == "" {
			continue
		}
		summary, err := json.Marshal(scan.Summary)
		if err != nil {
			return fmt.Errorf("encode security scan summary: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO security_scans (
				id, tenant_id, product_id, release_id, artifact_id, category,
				format, scanner, target_ref, evidence_id, payload_ref,
				payload_hash, finding_count, summary, redacted, quarantined,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
			ON CONFLICT (id) DO UPDATE SET
				finding_count = EXCLUDED.finding_count,
				summary = EXCLUDED.summary,
				redacted = EXCLUDED.redacted,
				quarantined = EXCLUDED.quarantined
		`, scan.ID, scan.TenantID, nullableString(scan.ProductID), nullableString(scan.ReleaseID), nullableString(scan.ArtifactID), scan.Category,
			scan.Format, scan.Scanner, scan.TargetRef, scan.EvidenceID, nullableString(scan.PayloadRef),
			scan.PayloadHash, scan.FindingCount, summary, scan.Redacted, scan.Quarantined,
			scan.SchemaVersion, nonZeroTime(scan.CreatedAt)); err != nil {
			return fmt.Errorf("upsert security scan row: %w", err)
		}
	}
	for _, document := range state.ManualSecurityDocs {
		if document.ID == "" || document.TenantID == "" || document.EvidenceID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO manual_security_documents (
				id, tenant_id, product_id, release_id, document_type, title,
				sensitivity, evidence_id, payload_ref, payload_hash,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (id) DO UPDATE SET sensitivity = EXCLUDED.sensitivity
		`, document.ID, document.TenantID, nullableString(document.ProductID), nullableString(document.ReleaseID), document.DocumentType, document.Title,
			document.Sensitivity, document.EvidenceID, nullableString(document.PayloadRef), document.PayloadHash, document.SchemaVersion, nonZeroTime(document.CreatedAt)); err != nil {
			return fmt.Errorf("upsert manual security document row: %w", err)
		}
	}
	for _, diff := range state.SBOMDiffs {
		if diff.ID == "" || diff.TenantID == "" || diff.BaseSBOMID == "" || diff.TargetSBOMID == "" {
			continue
		}
		document, err := json.Marshal(diff)
		if err != nil {
			return fmt.Errorf("encode sbom diff document: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO sbom_diffs (
				id, tenant_id, base_sbom_id, target_sbom_id, release_id,
				document, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (id) DO UPDATE SET document = EXCLUDED.document
		`, diff.ID, diff.TenantID, diff.BaseSBOMID, diff.TargetSBOMID, nullableString(diff.ReleaseID),
			document, diff.SchemaVersion, nonZeroTime(diff.CreatedAt)); err != nil {
			return fmt.Errorf("upsert sbom diff row: %w", err)
		}
	}
	for _, change := range state.DependencyChanges {
		if change.ID == "" || change.TenantID == "" || change.SBOMDiffID == "" {
			continue
		}
		component, err := json.Marshal(change.Component)
		if err != nil {
			return fmt.Errorf("encode dependency component: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO dependency_changes (
				id, tenant_id, sbom_diff_id, change_type, component,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET component = EXCLUDED.component
		`, change.ID, change.TenantID, change.SBOMDiffID, change.ChangeType, component, change.SchemaVersion, nonZeroTime(change.CreatedAt)); err != nil {
			return fmt.Errorf("upsert dependency change row: %w", err)
		}
	}
	for _, record := range state.VulnerabilityWorkflow {
		if record.ID == "" || record.TenantID == "" || record.FindingID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO vulnerability_workflow_records (
				id, tenant_id, finding_id, release_id, action, reason,
				actor_id, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO NOTHING
		`, record.ID, record.TenantID, record.FindingID, nullableString(record.ReleaseID), record.Action, record.Reason, record.ActorID, record.SchemaVersion, nonZeroTime(record.CreatedAt)); err != nil {
			return fmt.Errorf("insert vulnerability workflow row: %w", err)
		}
	}
	for _, diff := range state.ContractDiffs {
		if diff.ID == "" || diff.TenantID == "" || diff.BaseContractID == "" || diff.TargetContractID == "" {
			continue
		}
		document, err := json.Marshal(diff)
		if err != nil {
			return fmt.Errorf("encode contract diff document: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO contract_diffs (
				id, tenant_id, base_contract_id, target_contract_id, product_id,
				release_id, result, document, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET result = EXCLUDED.result, document = EXCLUDED.document
		`, diff.ID, diff.TenantID, diff.BaseContractID, diff.TargetContractID, diff.ProductID,
			nullableString(diff.ReleaseID), diff.Result, document, diff.SchemaVersion, nonZeroTime(diff.CreatedAt)); err != nil {
			return fmt.Errorf("upsert contract diff row: %w", err)
		}
	}
	for _, policy := range state.CustomPolicies {
		if policy.ID == "" || policy.TenantID == "" {
			continue
		}
		rules, err := json.Marshal(policy.Rules)
		if err != nil {
			return fmt.Errorf("encode custom policy rules: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO custom_policies (
				id, tenant_id, name, version, description, rules,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (id) DO UPDATE SET description = EXCLUDED.description, rules = EXCLUDED.rules
		`, policy.ID, policy.TenantID, policy.Name, policy.Version, nullableString(policy.Description), rules, policy.SchemaVersion, nonZeroTime(policy.CreatedAt)); err != nil {
			return fmt.Errorf("upsert custom policy row: %w", err)
		}
	}
	for _, evaluation := range state.CustomPolicyEvaluations {
		if evaluation.ID == "" || evaluation.TenantID == "" || evaluation.PolicyID == "" {
			continue
		}
		checks, err := json.Marshal(evaluation.Checks)
		if err != nil {
			return fmt.Errorf("encode custom policy checks: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO custom_policy_evaluations (
				id, tenant_id, policy_id, release_id, result, checks,
				input_hash, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET result = EXCLUDED.result, checks = EXCLUDED.checks
		`, evaluation.ID, evaluation.TenantID, evaluation.PolicyID, evaluation.ReleaseID, evaluation.Result, checks, evaluation.InputHash, evaluation.SchemaVersion, nonZeroTime(evaluation.CreatedAt)); err != nil {
			return fmt.Errorf("upsert custom policy evaluation row: %w", err)
		}
	}
	for _, waiver := range state.Waivers {
		if waiver.ID == "" || waiver.TenantID == "" || waiver.ScopeID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO waivers (
				id, tenant_id, scope_type, scope_id, control_id, policy_id,
				owner, risk, reason, expires_at, approved, approved_by,
				approved_at, supersedes, superseded_by, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
			ON CONFLICT (id) DO UPDATE SET
				approved = EXCLUDED.approved,
				approved_by = EXCLUDED.approved_by,
				approved_at = EXCLUDED.approved_at,
				superseded_by = EXCLUDED.superseded_by
		`, waiver.ID, waiver.TenantID, waiver.ScopeType, waiver.ScopeID, nullableString(waiver.ControlID), nullableString(waiver.PolicyID),
			waiver.Owner, waiver.Risk, waiver.Reason, waiver.ExpiresAt, waiver.Approved, nullableString(waiver.ApprovedBy),
			nullableTime(waiver.ApprovedAt), nullableString(waiver.Supersedes), nullableString(waiver.SupersededBy), waiver.SchemaVersion, nonZeroTime(waiver.CreatedAt)); err != nil {
			return fmt.Errorf("upsert waiver row: %w", err)
		}
	}
	for _, approval := range state.Approvals {
		if approval.ID == "" || approval.TenantID == "" || approval.SubjectID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO approval_records (
				id, tenant_id, subject_type, subject_id, decision, reason,
				approver_id, evidence_id, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO NOTHING
		`, approval.ID, approval.TenantID, approval.SubjectType, approval.SubjectID, approval.Decision, approval.Reason,
			approval.ApproverID, nullableString(approval.EvidenceID), approval.SchemaVersion, nonZeroTime(approval.CreatedAt)); err != nil {
			return fmt.Errorf("insert approval row: %w", err)
		}
	}
	for _, root := range state.DSSETrustRoots {
		if root.ID == "" || root.TenantID == "" || root.KeyID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO dsse_trust_roots (
				id, tenant_id, name, key_id, algorithm, public_key, status,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, public_key = EXCLUDED.public_key
		`, root.ID, root.TenantID, root.Name, root.KeyID, root.Algorithm, root.PublicKey, root.Status, root.SchemaVersion, nonZeroTime(root.CreatedAt)); err != nil {
			return fmt.Errorf("upsert dsse trust root row: %w", err)
		}
	}
	return nil
}

func syncIntegrityProviderRows(ctx context.Context, tx pgx.Tx, state app.PersistedState) error {
	for _, release := range state.CollectorReleases {
		if release.ID == "" || release.TenantID == "" || release.CollectorID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO collector_releases (
				id, tenant_id, collector_id, version, artifact_digest,
				signature_id, sbom_id, scan_id, pinned, verification_status,
				health_status, limitations, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			ON CONFLICT (id) DO UPDATE SET
				pinned = EXCLUDED.pinned,
				verification_status = EXCLUDED.verification_status,
				health_status = EXCLUDED.health_status,
				limitations = EXCLUDED.limitations,
				schema_version = EXCLUDED.schema_version
		`, release.ID, release.TenantID, release.CollectorID, release.Version, release.ArtifactDigest,
			nullableString(release.SignatureID), nullableString(release.SBOMID), nullableString(release.ScanID),
			release.Pinned, release.VerificationStatus, release.HealthStatus, release.Limitations,
			release.SchemaVersion, nonZeroTime(release.CreatedAt)); err != nil {
			return fmt.Errorf("upsert collector release row: %w", err)
		}
	}
	for _, verification := range state.CosignVerifications {
		if verification.ID == "" || verification.TenantID == "" || verification.ArtifactSignatureID == "" {
			continue
		}
		checks, err := json.Marshal(verification.Checks)
		if err != nil {
			return fmt.Errorf("encode cosign checks: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO cosign_verifications (
				id, tenant_id, artifact_id, container_image_id,
				artifact_signature_id, subject_digest, rekor_uuid, rekor_log_index,
				certificate_identity, certificate_issuer, result, checks,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			ON CONFLICT (id) DO UPDATE SET result = EXCLUDED.result, checks = EXCLUDED.checks, schema_version = EXCLUDED.schema_version
		`, verification.ID, verification.TenantID, nullableString(verification.ArtifactID), nullableString(verification.ContainerImageID),
			verification.ArtifactSignatureID, verification.SubjectDigest, nullableString(verification.RekorUUID),
			nullableString(verification.RekorLogIndex), nullableString(verification.CertificateIdentity),
			nullableString(verification.CertificateIssuer), verification.Result, checks, verification.SchemaVersion,
			nonZeroTime(verification.CreatedAt)); err != nil {
			return fmt.Errorf("upsert cosign verification row: %w", err)
		}
	}
	for _, provider := range state.SigningProviders {
		if provider.ID == "" || provider.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO signing_providers (
				id, tenant_id, name, type, status, key_ref, encrypted,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, key_ref = EXCLUDED.key_ref, encrypted = EXCLUDED.encrypted, schema_version = EXCLUDED.schema_version
		`, provider.ID, provider.TenantID, provider.Name, provider.Type, provider.Status, provider.KeyRef, provider.Encrypted, provider.SchemaVersion, nonZeroTime(provider.CreatedAt)); err != nil {
			return fmt.Errorf("upsert signing provider row: %w", err)
		}
	}
	for _, batch := range state.MerkleBatches {
		if batch.ID == "" || batch.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO merkle_batches (
				id, tenant_id, from_sequence, to_sequence, entry_count,
				leaf_hashes, root_hash, signature_refs, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET signature_refs = EXCLUDED.signature_refs, schema_version = EXCLUDED.schema_version
		`, batch.ID, batch.TenantID, batch.FromSequence, batch.ToSequence, batch.EntryCount, batch.LeafHashes, batch.RootHash, batch.SignatureRefs, batch.SchemaVersion, nonZeroTime(batch.CreatedAt)); err != nil {
			return fmt.Errorf("upsert merkle batch row: %w", err)
		}
	}
	for _, checkpoint := range state.TransparencyCheckpoints {
		if checkpoint.ID == "" || checkpoint.TenantID == "" || checkpoint.BatchID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO transparency_checkpoints (
				id, tenant_id, batch_id, provider, external_url, external_id,
				timestamp_hash, state, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, external_url = EXCLUDED.external_url, external_id = EXCLUDED.external_id, schema_version = EXCLUDED.schema_version
		`, checkpoint.ID, checkpoint.TenantID, checkpoint.BatchID, checkpoint.Provider, nullableString(checkpoint.ExternalURL), nullableString(checkpoint.ExternalID), checkpoint.TimestampHash, checkpoint.State, checkpoint.SchemaVersion, nonZeroTime(checkpoint.CreatedAt)); err != nil {
			return fmt.Errorf("upsert transparency checkpoint row: %w", err)
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

func syncFutureExtensionRows(ctx context.Context, tx pgx.Tx, state app.PersistedState) error {
	for _, collector := range state.CommercialCollectors {
		if collector.ID == "" || collector.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO commercial_collectors (
				id, tenant_id, name, provider, version, manifest_hash,
				allowed_scopes, status, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET
				allowed_scopes = EXCLUDED.allowed_scopes,
				status = EXCLUDED.status,
				schema_version = EXCLUDED.schema_version
		`, collector.ID, collector.TenantID, collector.Name, collector.Provider, collector.Version, collector.ManifestHash, collector.AllowedScopes, collector.Status, collector.SchemaVersion, nonZeroTime(collector.CreatedAt)); err != nil {
			return fmt.Errorf("upsert commercial collector row: %w", err)
		}
	}
	for _, summary := range state.EvidenceSummaries {
		if summary.ID == "" || summary.TenantID == "" {
			continue
		}
		citations, err := json.Marshal(summary.Citations)
		if err != nil {
			return fmt.Errorf("encode evidence summary citations: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO evidence_summaries (
				id, tenant_id, subject_type, subject_id, evidence_ids, summary,
				citations, assumptions, limitations, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (id) DO UPDATE SET summary = EXCLUDED.summary, citations = EXCLUDED.citations, assumptions = EXCLUDED.assumptions, limitations = EXCLUDED.limitations, schema_version = EXCLUDED.schema_version
		`, summary.ID, summary.TenantID, summary.SubjectType, summary.SubjectID, summary.EvidenceIDs, summary.Summary, citations, summary.Assumptions, summary.Limitations, summary.SchemaVersion, nonZeroTime(summary.CreatedAt)); err != nil {
			return fmt.Errorf("upsert evidence summary row: %w", err)
		}
	}
	for _, draft := range state.QuestionnaireDrafts {
		if draft.ID == "" || draft.TenantID == "" {
			continue
		}
		responses, err := json.Marshal(draft.Responses)
		if err != nil {
			return fmt.Errorf("encode questionnaire draft responses: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO questionnaire_drafts (
				id, tenant_id, template_id, product_id, release_id, responses,
				manifest_hash, limitations, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET responses = EXCLUDED.responses, manifest_hash = EXCLUDED.manifest_hash, limitations = EXCLUDED.limitations, schema_version = EXCLUDED.schema_version
		`, draft.ID, draft.TenantID, draft.TemplateID, nullableString(draft.ProductID), nullableString(draft.ReleaseID), responses, draft.ManifestHash, draft.Limitations, draft.SchemaVersion, nonZeroTime(draft.CreatedAt)); err != nil {
			return fmt.Errorf("upsert questionnaire draft row: %w", err)
		}
	}
	for _, graph := range state.GraphSnapshots {
		if graph.ID == "" || graph.TenantID == "" {
			continue
		}
		nodes, err := json.Marshal(graph.Nodes)
		if err != nil {
			return fmt.Errorf("encode graph nodes: %w", err)
		}
		edges, err := json.Marshal(graph.Edges)
		if err != nil {
			return fmt.Errorf("encode graph edges: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO evidence_graph_snapshots (
				id, tenant_id, product_id, release_id, nodes, edges,
				graph_hash, limitations, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET nodes = EXCLUDED.nodes, edges = EXCLUDED.edges, graph_hash = EXCLUDED.graph_hash, limitations = EXCLUDED.limitations, schema_version = EXCLUDED.schema_version
		`, graph.ID, graph.TenantID, nullableString(graph.ProductID), nullableString(graph.ReleaseID), nodes, edges, graph.GraphHash, graph.Limitations, graph.SchemaVersion, nonZeroTime(graph.CreatedAt)); err != nil {
			return fmt.Errorf("upsert graph snapshot row: %w", err)
		}
	}
	for _, profile := range state.SaaSProfiles {
		if profile.ID == "" || profile.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO saas_edition_profiles (
				id, tenant_id, name, region, admin_tenant_id, isolation_model,
				status, config_hash, limitations, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, config_hash = EXCLUDED.config_hash, limitations = EXCLUDED.limitations, schema_version = EXCLUDED.schema_version
		`, profile.ID, profile.TenantID, profile.Name, profile.Region, profile.AdminTenantID, profile.IsolationModel, profile.Status, profile.ConfigHash, profile.Limitations, profile.SchemaVersion, nonZeroTime(profile.CreatedAt)); err != nil {
			return fmt.Errorf("upsert saas profile row: %w", err)
		}
	}
	for _, log := range state.PublicTransparencyLogs {
		if log.ID == "" || log.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO public_transparency_logs (
				id, tenant_id, name, endpoint, public_key, state,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, schema_version = EXCLUDED.schema_version
		`, log.ID, log.TenantID, log.Name, log.Endpoint, log.PublicKey, log.State, log.SchemaVersion, nonZeroTime(log.CreatedAt)); err != nil {
			return fmt.Errorf("upsert public transparency log row: %w", err)
		}
	}
	for _, entry := range state.PublicTransparencyItems {
		if entry.ID == "" || entry.TenantID == "" {
			continue
		}
		checks, err := json.Marshal(entry.VerificationChecks)
		if err != nil {
			return fmt.Errorf("encode public transparency checks: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO public_transparency_log_entries (
				id, tenant_id, log_id, checkpoint_id, merkle_batch_id,
				external_id, entry_hash, inclusion_root_hash,
				inclusion_proof_hash, inclusion_verified_at, verification_checks,
				verification_limitations, state, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
			ON CONFLICT (id) DO UPDATE SET
				inclusion_root_hash = EXCLUDED.inclusion_root_hash,
				inclusion_proof_hash = EXCLUDED.inclusion_proof_hash,
				inclusion_verified_at = EXCLUDED.inclusion_verified_at,
				verification_checks = EXCLUDED.verification_checks,
				verification_limitations = EXCLUDED.verification_limitations,
				state = EXCLUDED.state,
				schema_version = EXCLUDED.schema_version
		`, entry.ID, entry.TenantID, entry.LogID, entry.CheckpointID, entry.MerkleBatchID, entry.ExternalID, entry.EntryHash,
			nullableString(entry.InclusionRootHash), nullableString(entry.InclusionProofHash), nullableTime(entry.InclusionVerifiedAt),
			checks, entry.VerificationLimitations, entry.State, entry.SchemaVersion, nonZeroTime(entry.CreatedAt)); err != nil {
			return fmt.Errorf("upsert public transparency entry row: %w", err)
		}
	}
	for _, collector := range state.MarketplaceCollectors {
		if collector.ID == "" || collector.TenantID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO marketplace_collectors (
				id, tenant_id, name, provider, version, publisher,
				manifest_hash, signature_id, sbom_id, scan_id, state,
				limitations, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, limitations = EXCLUDED.limitations, schema_version = EXCLUDED.schema_version
		`, collector.ID, collector.TenantID, collector.Name, collector.Provider, collector.Version, collector.Publisher, collector.ManifestHash,
			nullableString(collector.SignatureID), nullableString(collector.SBOMID), nullableString(collector.ScanID), collector.State,
			collector.Limitations, collector.SchemaVersion, nonZeroTime(collector.CreatedAt)); err != nil {
			return fmt.Errorf("upsert marketplace collector row: %w", err)
		}
	}
	for _, verification := range state.ProviderVerifications {
		if verification.ID == "" || verification.TenantID == "" {
			continue
		}
		checks, err := json.Marshal(verification.Checks)
		if err != nil {
			return fmt.Errorf("encode provider verification checks: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO provider_verifications (
				id, tenant_id, provider_type, provider_id, subject, result,
				checks, limitations, schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (id) DO UPDATE SET result = EXCLUDED.result, checks = EXCLUDED.checks, limitations = EXCLUDED.limitations, schema_version = EXCLUDED.schema_version
		`, verification.ID, verification.TenantID, verification.ProviderType, verification.ProviderID, verification.Subject, verification.Result, checks, verification.Limitations, verification.SchemaVersion, nonZeroTime(verification.CreatedAt)); err != nil {
			return fmt.Errorf("upsert provider verification row: %w", err)
		}
	}
	for _, operation := range state.SigningOperations {
		if operation.ID == "" || operation.TenantID == "" {
			continue
		}
		checks, err := json.Marshal(operation.Checks)
		if err != nil {
			return fmt.Errorf("encode signing operation checks: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO signing_operations (
				id, tenant_id, provider_id, subject_type, subject_id,
				payload_hash, signature_ref, result, checks,
				schema_version, created_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (id) DO UPDATE SET signature_ref = EXCLUDED.signature_ref, result = EXCLUDED.result, checks = EXCLUDED.checks, schema_version = EXCLUDED.schema_version
		`, operation.ID, operation.TenantID, operation.ProviderID, operation.SubjectType, operation.SubjectID, operation.PayloadHash, nullableString(operation.SignatureRef), operation.Result, checks, operation.SchemaVersion, nonZeroTime(operation.CreatedAt)); err != nil {
			return fmt.Errorf("upsert signing operation row: %w", err)
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

func nullableInt(value int) any {
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

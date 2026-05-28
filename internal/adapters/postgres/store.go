package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/app"
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
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit save ledger state transaction: %w", err)
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

func nullableTime(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return value.UTC()
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

package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

type CreateOrganizationInput struct {
	Name string
	Slug string
}

type CreateUserInput struct {
	OrganizationID string
	Email          string
	DisplayName    string
}

type CreateRoleBindingInput struct {
	SubjectType  string
	SubjectID    string
	Role         string
	ResourceType string
	ResourceID   string
}

type CreateSSOProviderInput struct {
	Name                    string
	Type                    string
	Issuer                  string
	ClientID                string
	GroupsClaim             string
	RoleMapping             map[string]string
	JWKS                    map[string]any
	SAMLSigningCertificates []string
}

type LinkSSOIdentityInput struct {
	UserID     string
	ProviderID string
	Subject    string
	Email      string
	Verified   bool
}

type ExchangeSSOCredentialInput struct {
	ProviderID    string
	Subject       string
	IDToken       string
	SAMLAssertion string
	ExpiresAt     time.Time
}

type CreateLegalHoldInput struct {
	ScopeType string
	ScopeID   string
	Reason    string
	Owner     string
}

type CreateRetentionOverrideInput struct {
	ScopeType      string
	ScopeID        string
	RetentionUntil time.Time
	Reason         string
	Owner          string
}

type CreateCommercialCollectorInput struct {
	Name          string
	Provider      string
	Version       string
	ManifestHash  string
	AllowedScopes []string
}

func (l *Ledger) InstanceAdminSnapshot(ctx context.Context, actor domain.Actor) (domain.InstanceAdminSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.InstanceAdminSnapshot{}, err
	}
	if err := require(actor, ScopeInstanceAdmin); err != nil {
		return domain.InstanceAdminSnapshot{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return domain.InstanceAdminSnapshot{ReportType: "instance_admin_snapshot", TenantCount: len(l.tenants), ResourceCounts: map[string]int{"tenants": len(l.tenants), "users": len(l.users), "collectors": len(l.collectors), "evidence": len(l.evidence)}, Limitations: []string{"Instance admin diagnostics expose operational counts only and not raw evidence payloads or secrets."}, GeneratedAt: l.now()}, nil
}

func (l *Ledger) CreateLegalHold(ctx context.Context, actor domain.Actor, in CreateLegalHoldInput) (domain.LegalHold, error) {
	if err := ctx.Err(); err != nil {
		return domain.LegalHold{}, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return domain.LegalHold{}, err
	}
	normalized, normalizeErr := operationsapp.NormalizeRetentionMarkerInput(operationsapp.RetentionMarkerInput{ScopeType: in.ScopeType, ScopeID: in.ScopeID, Reason: in.Reason, Owner: in.Owner})
	if normalizeErr != nil {
		return domain.LegalHold{}, ErrValidation
	}
	in = CreateLegalHoldInput(normalized)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureRetentionScopeLocked(actor.TenantID, in.ScopeType, in.ScopeID); err != nil {
		return domain.LegalHold{}, err
	}
	hold := domain.LegalHold{ID: newID("lh"), TenantID: actor.TenantID, ScopeType: in.ScopeType, ScopeID: in.ScopeID, Reason: in.Reason, Owner: in.Owner, SchemaVersion: domain.LegalHoldSchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Governance.InsertLegalHold(ctx, hold); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(hold.CreatedAt, actor.TenantID, "legal_hold.created", in.ScopeType, in.ScopeID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.LegalHold{}, err
		}
		l.legalHolds[hold.ID] = hold
		l.publishCommittedAuditEntryLocked(entry)
		return hold, nil
	}
	l.legalHolds[hold.ID] = hold
	_, _ = l.appendChainLocked(actor.TenantID, "legal_hold.created", in.ScopeType, in.ScopeID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.LegalHold{}, err
	}
	return hold, nil
}

func (l *Ledger) CreateRetentionOverride(ctx context.Context, actor domain.Actor, in CreateRetentionOverrideInput) (domain.RetentionOverride, error) {
	if err := ctx.Err(); err != nil {
		return domain.RetentionOverride{}, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return domain.RetentionOverride{}, err
	}
	normalized, normalizeErr := operationsapp.NormalizeRetentionOverrideInput(operationsapp.RetentionOverrideInput{RetentionMarkerInput: operationsapp.RetentionMarkerInput{ScopeType: in.ScopeType, ScopeID: in.ScopeID, Reason: in.Reason, Owner: in.Owner}, RetentionUntil: in.RetentionUntil})
	if normalizeErr != nil || !normalized.RetentionUntil.After(l.now()) {
		return domain.RetentionOverride{}, ErrValidation
	}
	in = CreateRetentionOverrideInput{ScopeType: normalized.ScopeType, ScopeID: normalized.ScopeID, Reason: normalized.Reason, Owner: normalized.Owner, RetentionUntil: normalized.RetentionUntil}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureRetentionScopeLocked(actor.TenantID, in.ScopeType, in.ScopeID); err != nil {
		return domain.RetentionOverride{}, err
	}
	override := domain.RetentionOverride{ID: newID("ro"), TenantID: actor.TenantID, ScopeType: in.ScopeType, ScopeID: in.ScopeID, RetentionUntil: in.RetentionUntil.UTC(), Reason: in.Reason, Owner: in.Owner, SchemaVersion: domain.RetentionOverrideSchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Governance.InsertRetentionOverride(ctx, override); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(override.CreatedAt, actor.TenantID, "retention_override.created", in.ScopeType, in.ScopeID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.RetentionOverride{}, err
		}
		l.retentionOverrides[override.ID] = override
		l.publishCommittedAuditEntryLocked(entry)
		return override, nil
	}
	l.retentionOverrides[override.ID] = override
	_, _ = l.appendChainLocked(actor.TenantID, "retention_override.created", in.ScopeType, in.ScopeID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.RetentionOverride{}, err
	}
	return override, nil
}

func (l *Ledger) RetentionReport(ctx context.Context, actor domain.Actor, scopeType, scopeID string) (domain.RetentionReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.RetentionReport{}, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return domain.RetentionReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	holds := []domain.LegalHold{}
	for _, hold := range l.legalHolds {
		if hold.TenantID == actor.TenantID && (scopeType == "" || (hold.ScopeType == scopeType && hold.ScopeID == scopeID)) {
			holds = append(holds, hold)
		}
	}
	overrides := []domain.RetentionOverride{}
	for _, override := range l.retentionOverrides {
		if override.TenantID == actor.TenantID && (scopeType == "" || (override.ScopeType == scopeType && override.ScopeID == scopeID)) {
			overrides = append(overrides, override)
		}
	}
	return domain.RetentionReport{ReportType: "retention", ScopeType: scopeType, ScopeID: scopeID, LegalHolds: holds, RetentionOverrides: overrides, Limitations: []string{"Retention reports describe Evydence records and do not replace external storage lifecycle verification."}, GeneratedAt: l.now()}, nil
}

func (l *Ledger) CreateCommercialCollectorDefinition(ctx context.Context, actor domain.Actor, in CreateCommercialCollectorInput) (domain.CommercialCollectorDefinition, error) {
	if err := ctx.Err(); err != nil {
		return domain.CommercialCollectorDefinition{}, err
	}
	if err := require(actor, ScopeCollectorAdmin); err != nil {
		return domain.CommercialCollectorDefinition{}, err
	}
	in.Name, in.Provider, in.Version = strings.TrimSpace(in.Name), strings.TrimSpace(in.Provider), strings.TrimSpace(in.Version)
	if in.Name == "" || in.Provider == "" || in.Version == "" || !validDigest(in.ManifestHash) || !validCollectorScopes(in.AllowedScopes) {
		return domain.CommercialCollectorDefinition{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, existing := range l.commercialCollectors {
		if existing.TenantID == actor.TenantID && existing.Name == in.Name && existing.Provider == in.Provider && existing.Version == in.Version {
			return domain.CommercialCollectorDefinition{}, ErrConflict
		}
	}
	def := domain.CommercialCollectorDefinition{ID: newID("ccol"), TenantID: actor.TenantID, Name: in.Name, Provider: in.Provider, Version: in.Version, ManifestHash: in.ManifestHash, AllowedScopes: sortedStrings(in.AllowedScopes), Status: "available", SchemaVersion: domain.CommercialCollectorVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Enterprise.InsertCommercialCollectorDefinition(ctx, def); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(def.CreatedAt, actor.TenantID, "commercial_collector.created", "commercial_collector", def.ID, actorType(actor), actorID(actor), in.ManifestHash, ""))
			return err
		}); err != nil {
			return domain.CommercialCollectorDefinition{}, err
		}
		l.commercialCollectors[def.ID] = def
		l.publishCommittedAuditEntryLocked(entry)
		return def, nil
	}
	l.commercialCollectors[def.ID] = def
	_, _ = l.appendChainLocked(actor.TenantID, "commercial_collector.created", "commercial_collector", def.ID, actorType(actor), actorID(actor), in.ManifestHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CommercialCollectorDefinition{}, err
	}
	return def, nil
}

func (l *Ledger) ListCommercialCollectorDefinitions(ctx context.Context, actor domain.Actor) ([]domain.CommercialCollectorDefinition, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeCollectorRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeResourceLocked(actor, ScopeCollectorRead, resourceRefs{}); err != nil {
		return nil, err
	}
	out := []domain.CommercialCollectorDefinition{}
	for _, def := range l.commercialCollectors {
		if def.TenantID == actor.TenantID {
			out = append(out, def)
		}
	}
	return out, nil
}

func (l *Ledger) ensureRoleSubjectLocked(tenantID, subjectType, subjectID string) error {
	switch subjectType {
	case "user":
		user, ok := l.users[subjectID]
		if !ok || user.TenantID != tenantID {
			return ErrNotFound
		}
	case "collector":
		collector, ok := l.collectors[subjectID]
		if !ok || collector.TenantID != tenantID {
			return ErrNotFound
		}
	default:
		return ErrValidation
	}
	return nil
}

func (l *Ledger) ensureRetentionScopeLocked(tenantID, scopeType, scopeID string) error {
	switch scopeType {
	case "tenant":
		if tenant, ok := l.tenants[scopeID]; !ok || tenant.ID != tenantID {
			return ErrNotFound
		}
	case "product", "project", "release":
		return l.ensureScopeLocked(tenantID, ternary(scopeType == "product", scopeID, ""), ternary(scopeType == "project", scopeID, ""), ternary(scopeType == "release", scopeID, ""))
	case "evidence":
		item, ok := l.evidence[scopeID]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	default:
		return ErrValidation
	}
	return nil
}

func (l *Ledger) ensureRoleResourceLocked(tenantID, resourceType, resourceID string) error {
	switch resourceType {
	case "":
		if resourceID != "" {
			return ErrValidation
		}
	case "tenant":
		if resourceID == "" {
			return nil
		}
		tenant, ok := l.tenants[resourceID]
		if !ok || tenant.ID != tenantID {
			return ErrNotFound
		}
	case "product":
		product, ok := l.products[resourceID]
		if resourceID == "" || !ok || product.TenantID != tenantID {
			return ErrNotFound
		}
	case "project":
		project, ok := l.projects[resourceID]
		if resourceID == "" || !ok || project.TenantID != tenantID {
			return ErrNotFound
		}
	case "release":
		release, ok := l.releases[resourceID]
		if resourceID == "" || !ok || release.TenantID != tenantID {
			return ErrNotFound
		}
	case "customer_security_package":
		pkg, ok := l.customerPackages[resourceID]
		if resourceID == "" || !ok || pkg.TenantID != tenantID {
			return ErrNotFound
		}
	case "evidence_bundle":
		bundle, ok := l.evidenceBundles[resourceID]
		if resourceID == "" || !ok || bundle.TenantID != tenantID {
			return ErrNotFound
		}
	default:
		return ErrValidation
	}
	return nil
}

func validRoleSubject(value string) bool {
	return value == "user" || value == "collector"
}

func validRole(value string) bool {
	switch value {
	case "tenant_admin", "security_engineer", "release_manager", "customer_verifier", "collector":
		return true
	default:
		return false
	}
}

func (l *Ledger) resourceGrantsForUserLocked(userID string) []domain.ResourceGrant {
	grants := []domain.ResourceGrant{}
	for _, binding := range l.roleBindings {
		if binding.SubjectType != "user" || binding.SubjectID != userID {
			continue
		}
		scopes := scopesForRole(binding.Role)
		if len(scopes) == 0 {
			continue
		}
		grants = append(grants, domain.ResourceGrant{
			Role:         binding.Role,
			ResourceType: binding.ResourceType,
			ResourceID:   binding.ResourceID,
			Scopes:       scopes,
		})
	}
	return grants
}

func (l *Ledger) resourceGrantsForSSOSessionLocked(session domain.SSOSession) []domain.ResourceGrant {
	provider, ok := l.ssoProviders[session.ProviderID]
	if !ok || provider.TenantID != session.TenantID {
		return nil
	}
	return resourceGrantsForProviderGroups(provider, session.Groups)
}

func resourceGrantsForProviderGroups(provider domain.SSOProvider, groups []string) []domain.ResourceGrant {
	return identityapp.ProviderGroupGrants(ssoProviderToIdentityContext(provider), groups)
}

func scopesFromResourceGrants(grants []domain.ResourceGrant) []string {
	scopes := map[string]struct{}{}
	for _, grant := range grants {
		for _, scope := range grant.Scopes {
			scopes[scope] = struct{}{}
		}
	}
	out := make([]string, 0, len(scopes))
	for scope := range scopes {
		out = append(out, scope)
	}
	return sortedStrings(out)
}

type resourceRefs struct {
	ProductID          string
	ProjectID          string
	ReleaseID          string
	ArtifactID         string
	BuildID            string
	DeploymentID       string
	EnvironmentID      string
	IncidentID         string
	SecurityScanID     string
	SourceRepositoryID string
	CustomerPackageID  string
	EvidenceBundleID   string
}

func refsForEvidence(item domain.EvidenceItem) resourceRefs {
	return resourceRefs{
		ProductID: item.ProductID, ProjectID: item.ProjectID, ReleaseID: item.ReleaseID,
		BuildID: item.BuildID, DeploymentID: item.DeploymentID,
	}
}

func (l *Ledger) authorizeResourceLocked(actor domain.Actor, scope string, refs resourceRefs) error {
	if l.resourceAllowedLocked(actor, scope, refs) {
		return nil
	}
	return ErrForbidden
}

func (l *Ledger) resourceAllowedLocked(actor domain.Actor, scope string, refs resourceRefs) bool {
	if !humanSessionActor(actor) {
		return true
	}
	for _, grant := range actor.ResourceGrants {
		if !grantHasScope(grant, scope) {
			continue
		}
		if l.grantCoversResourceLocked(actor.TenantID, grant, refs) {
			return true
		}
	}
	return false
}

func humanSessionActor(actor domain.Actor) bool {
	return actor.UserID != "" && actor.KeyID == "" && actor.CollectorID == ""
}

func grantHasScope(grant domain.ResourceGrant, scope string) bool {
	for _, got := range grant.Scopes {
		if got == "*" || got == scope || got == ScopeAdmin {
			return true
		}
	}
	return false
}

func (l *Ledger) grantCoversResourceLocked(tenantID string, grant domain.ResourceGrant, refs resourceRefs) bool {
	switch grant.ResourceType {
	case "", "tenant":
		return grant.ResourceID == "" || grant.ResourceID == tenantID
	case "product":
		return grant.ResourceID != "" && l.productCoversRefsLocked(tenantID, grant.ResourceID, refs)
	case "project":
		return grant.ResourceID != "" && l.projectCoversRefsLocked(tenantID, grant.ResourceID, refs)
	case "release":
		return grant.ResourceID != "" && l.releaseCoversRefsLocked(tenantID, grant.ResourceID, refs)
	case "customer_security_package":
		return refs.CustomerPackageID != "" && refs.CustomerPackageID == grant.ResourceID
	case "evidence_bundle":
		return refs.EvidenceBundleID != "" && refs.EvidenceBundleID == grant.ResourceID
	default:
		return false
	}
}

func (l *Ledger) productCoversRefsLocked(tenantID, productID string, refs resourceRefs) bool {
	if refs == (resourceRefs{}) {
		return false
	}
	if refs.ProductID != "" && refs.ProductID != productID {
		return false
	}
	if refs.ProjectID != "" {
		project, ok := l.projects[refs.ProjectID]
		if !ok || project.TenantID != tenantID || project.ProductID != productID {
			return false
		}
	}
	if refs.SourceRepositoryID != "" {
		repo, ok := l.repositories[refs.SourceRepositoryID]
		if !ok || repo.TenantID != tenantID {
			return false
		}
		if repo.ProjectID == "" {
			return false
		}
		project, ok := l.projects[repo.ProjectID]
		if !ok || project.TenantID != tenantID || project.ProductID != productID {
			return false
		}
	}
	if refs.ReleaseID != "" {
		release, ok := l.releases[refs.ReleaseID]
		if !ok || release.TenantID != tenantID || release.ProductID != productID {
			return false
		}
	}
	if refs.BuildID != "" {
		build, ok := l.buildRuns[refs.BuildID]
		if !ok || build.TenantID != tenantID {
			return false
		}
		if build.ReleaseID != "" {
			release, ok := l.releases[build.ReleaseID]
			if !ok || release.TenantID != tenantID || release.ProductID != productID {
				return false
			}
		}
		if build.ProjectID != "" {
			project, ok := l.projects[build.ProjectID]
			if !ok || project.TenantID != tenantID || project.ProductID != productID {
				return false
			}
		}
	}
	if refs.EnvironmentID != "" {
		env, ok := l.environments[refs.EnvironmentID]
		if !ok || env.TenantID != tenantID || env.ProductID != productID {
			return false
		}
	}
	if refs.DeploymentID != "" {
		deployment, ok := l.deployments[refs.DeploymentID]
		if !ok || deployment.TenantID != tenantID {
			return false
		}
		release, ok := l.releases[deployment.ReleaseID]
		if !ok || release.TenantID != tenantID || release.ProductID != productID {
			return false
		}
	}
	if refs.IncidentID != "" {
		incident, ok := l.incidents[refs.IncidentID]
		if !ok || incident.TenantID != tenantID || incident.ProductID != productID {
			return false
		}
	}
	if refs.SecurityScanID != "" {
		scan, ok := l.securityScans[refs.SecurityScanID]
		if !ok || scan.TenantID != tenantID {
			return false
		}
		if scan.ProductID != "" && scan.ProductID != productID {
			return false
		}
		if scan.ReleaseID != "" {
			release, ok := l.releases[scan.ReleaseID]
			if !ok || release.TenantID != tenantID || release.ProductID != productID {
				return false
			}
		}
	}
	if refs.ArtifactID != "" && !l.artifactCoversProductLocked(tenantID, refs.ArtifactID, productID) {
		return false
	}
	if refs.CustomerPackageID != "" {
		pkg, ok := l.customerPackages[refs.CustomerPackageID]
		if !ok || pkg.TenantID != tenantID || pkg.ProductID != productID {
			return false
		}
	}
	if refs.EvidenceBundleID != "" {
		bundle, ok := l.evidenceBundles[refs.EvidenceBundleID]
		if !ok || bundle.TenantID != tenantID {
			return false
		}
		if bundle.ReleaseID != "" {
			release, ok := l.releases[bundle.ReleaseID]
			if !ok || release.TenantID != tenantID || release.ProductID != productID {
				return false
			}
		}
	}
	return true
}

func (l *Ledger) projectCoversRefsLocked(tenantID, projectID string, refs resourceRefs) bool {
	if refs.ProjectID != "" {
		project, ok := l.projects[refs.ProjectID]
		return ok && project.TenantID == tenantID && project.ID == projectID
	}
	if refs.SourceRepositoryID != "" {
		repo, ok := l.repositories[refs.SourceRepositoryID]
		return ok && repo.TenantID == tenantID && repo.ProjectID == projectID
	}
	if refs.BuildID != "" {
		build, ok := l.buildRuns[refs.BuildID]
		return ok && build.TenantID == tenantID && build.ProjectID == projectID
	}
	if refs.ArtifactID != "" {
		return l.artifactCoversProjectLocked(tenantID, refs.ArtifactID, projectID)
	}
	return false
}

func (l *Ledger) releaseCoversRefsLocked(tenantID, releaseID string, refs resourceRefs) bool {
	if refs.ReleaseID != "" {
		release, ok := l.releases[refs.ReleaseID]
		return ok && release.TenantID == tenantID && release.ID == releaseID
	}
	if refs.CustomerPackageID != "" {
		pkg, ok := l.customerPackages[refs.CustomerPackageID]
		return ok && pkg.TenantID == tenantID && pkg.ReleaseID == releaseID
	}
	if refs.EvidenceBundleID != "" {
		bundle, ok := l.evidenceBundles[refs.EvidenceBundleID]
		return ok && bundle.TenantID == tenantID && bundle.ReleaseID == releaseID
	}
	if refs.BuildID != "" {
		build, ok := l.buildRuns[refs.BuildID]
		return ok && build.TenantID == tenantID && build.ReleaseID == releaseID
	}
	if refs.DeploymentID != "" {
		deployment, ok := l.deployments[refs.DeploymentID]
		return ok && deployment.TenantID == tenantID && deployment.ReleaseID == releaseID
	}
	if refs.IncidentID != "" {
		incident, ok := l.incidents[refs.IncidentID]
		return ok && incident.TenantID == tenantID && incident.ReleaseID == releaseID
	}
	if refs.SecurityScanID != "" {
		scan, ok := l.securityScans[refs.SecurityScanID]
		return ok && scan.TenantID == tenantID && scan.ReleaseID == releaseID
	}
	if refs.ArtifactID != "" && l.artifactCoversReleaseLocked(tenantID, refs.ArtifactID, releaseID) {
		return true
	}
	return false
}

func (l *Ledger) artifactCoversProductLocked(tenantID, artifactID, productID string) bool {
	for _, item := range l.evidence {
		if item.TenantID == tenantID && item.ProductID == productID && evidenceReferencesArtifact(item, artifactID) {
			return true
		}
	}
	for _, build := range l.buildRuns {
		if build.TenantID != tenantID {
			continue
		}
		for _, output := range build.Outputs {
			if output.ArtifactID != artifactID {
				continue
			}
			release, ok := l.releases[build.ReleaseID]
			if ok && release.TenantID == tenantID && release.ProductID == productID {
				return true
			}
		}
	}
	return false
}

func (l *Ledger) artifactCoversProjectLocked(tenantID, artifactID, projectID string) bool {
	for _, item := range l.evidence {
		if item.TenantID == tenantID && item.ProjectID == projectID && evidenceReferencesArtifact(item, artifactID) {
			return true
		}
	}
	for _, build := range l.buildRuns {
		if build.TenantID != tenantID || build.ProjectID != projectID {
			continue
		}
		for _, output := range build.Outputs {
			if output.ArtifactID == artifactID {
				return true
			}
		}
	}
	return false
}

func (l *Ledger) artifactCoversReleaseLocked(tenantID, artifactID, releaseID string) bool {
	for _, item := range l.evidence {
		if item.TenantID == tenantID && item.ReleaseID == releaseID && evidenceReferencesArtifact(item, artifactID) {
			return true
		}
	}
	for _, build := range l.buildRuns {
		if build.TenantID != tenantID || build.ReleaseID != releaseID {
			continue
		}
		for _, output := range build.Outputs {
			if output.ArtifactID == artifactID {
				return true
			}
		}
	}
	return false
}

func evidenceReferencesArtifact(item domain.EvidenceItem, artifactID string) bool {
	for _, ref := range item.SubjectRefs {
		if ref.Type == "artifact" && ref.ID == artifactID {
			return true
		}
	}
	return false
}

func scopesForRole(role string) []string {
	return identityapp.RoleScopes(role)
}

func oidcGroupsFromVerifiedToken(provider domain.SSOProvider, token string) []string {
	claimName := strings.TrimSpace(provider.GroupsClaim)
	if claimName == "" || token == "" || provider.Type != "oidc" {
		return nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil
	}
	return sortedStrings(stringClaimValues(claims[claimName]))
}

func stringClaimValues(value any) []string {
	seen := map[string]struct{}{}
	out := []string{}
	add := func(raw string) {
		item := strings.TrimSpace(raw)
		if item == "" {
			return
		}
		if _, ok := seen[item]; ok {
			return
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	switch got := value.(type) {
	case string:
		add(got)
	case []any:
		for _, item := range got {
			if text, ok := item.(string); ok {
				add(text)
			}
		}
	}
	return out
}

func validSSOType(value string) bool {
	return value == "oidc" || value == "saml"
}

func normalizeJWKS(jwks map[string]any) (map[string]any, error) {
	value, err := (identityapp.PublicTrustMaterialValidator{}).NormalizeJWKS(jwks)
	return value, fromIdentityContextError(err)
}

func normalizeSAMLSigningCertificates(certs []string) ([]string, error) {
	value, err := (identityapp.PublicTrustMaterialValidator{}).NormalizeSAMLSigningCertificates(certs)
	return value, fromIdentityContextError(err)
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range in {
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func ternary(ok bool, a, b string) string {
	if ok {
		return a
	}
	return b
}

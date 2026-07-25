package app

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

// MemoryUnitOfWorkFactory provides deterministic transaction semantics for
// application tests and local-only adapters. It deliberately models focused
// repositories instead of routing command tests through PersistedState.
type MemoryUnitOfWorkFactory struct {
	mu      sync.Mutex
	version uint64
	state   MemoryUnitOfWorkSnapshot
}

// MemoryUnitOfWorkSnapshot is a detached view of committed repository state.
// It is intended for deterministic tests and must not be used as a production
// persistence contract.
type MemoryUnitOfWorkSnapshot struct {
	Tenants               map[string]domain.Tenant
	APIKeys               map[string]domain.APIKey
	Collectors            map[string]domain.Collector
	Organizations         map[string]domain.Organization
	Users                 map[string]domain.HumanUser
	RoleBindings          map[string]domain.RoleBinding
	SSOProviders          map[string]domain.SSOProvider
	IdentityLinks         map[string]domain.UserIdentityLink
	ProviderVerifications map[string]domain.ProviderVerification
	SSOSessions           map[string]domain.SSOSession
	CustomerPortalAccess  map[string]domain.CustomerPortalAccess
	Products              map[string]domain.Product
	Projects              map[string]domain.Project
	Releases              map[string]domain.Release
	Artifacts             map[string]domain.Artifact
	Evidence              map[string]domain.EvidenceItem
	EvidenceLifecycle     map[string]domain.EvidenceLifecycleEvent
	SBOMs                 map[string]domain.SBOM
	VulnerabilityScans    map[string]domain.VulnerabilityScan
	OpenAPIContracts      map[string]domain.OpenAPIContract
	VEXDocuments          map[string]domain.VEXDocument
	VEXImportReports      map[string]domain.VEXImportReport
	ReleaseCandidates     map[string]domain.ReleaseCandidate
	Decisions             map[string]domain.VulnerabilityDecision
	Exceptions            map[string]domain.Exception
	BuildRuns             map[string]domain.BuildRun
	BuildAttestations     map[string]domain.BuildAttestation
	CollectorReleases     map[string]domain.CollectorRelease
	ControlFrameworks     map[string]domain.ControlFramework
	SecurityControls      map[string]domain.SecurityControl
	ControlEvidence       map[string]domain.ControlEvidence
	Waivers               map[string]domain.Waiver
	Approvals             map[string]domain.ApprovalRecord
	RedactionProfiles     map[string]domain.RedactionProfile
	LegalHolds            map[string]domain.LegalHold
	RetentionOverrides    map[string]domain.RetentionOverride
	AuditEntries          map[string][]domain.AuditChainEntry
	Idempotency           map[IdempotencyRecordKey]IdempotencyRecord
	OutboxJobs            map[string]OutboxJob
	ReleaseBundles        map[string]domain.ReleaseBundle
	SigningKeys           map[string]domain.SigningKey
	Signatures            map[string]domain.Signature
	VerificationResults   map[string]domain.VerificationResult
}

func NewMemoryUnitOfWorkFactory() *MemoryUnitOfWorkFactory {
	return &MemoryUnitOfWorkFactory{state: emptyMemoryUnitOfWorkSnapshot()}
}

func (f *MemoryUnitOfWorkFactory) BeginUnitOfWork(ctx context.Context) (UnitOfWork, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state, err := cloneMemoryUnitOfWorkSnapshot(f.state)
	if err != nil {
		return nil, err
	}
	return &memoryUnitOfWork{factory: f, version: f.version, state: state}, nil
}

func (f *MemoryUnitOfWorkFactory) Snapshot() (MemoryUnitOfWorkSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cloneMemoryUnitOfWorkSnapshot(f.state)
}

type memoryUnitOfWork struct {
	factory *MemoryUnitOfWorkFactory
	version uint64

	mu     sync.Mutex
	state  MemoryUnitOfWorkSnapshot
	closed bool
}

func (u *memoryUnitOfWork) Repositories() Repositories {
	return Repositories{
		Identity:       memoryIdentityRepository{uow: u},
		ReleaseCatalog: memoryReleaseCatalogRepository{uow: u},
		Evidence:       memoryEvidenceRepository{uow: u},
		Decisions:      memoryDecisionRepository{uow: u},
		Audit:          memoryAuditRepository{uow: u},
		Idempotency:    memoryIdempotencyRepository{uow: u},
		Outbox:         memoryOutboxRepository{uow: u},
		Controls:       memoryControlRepository{uow: u},
		Governance:     memoryGovernanceRepository{uow: u},
		Builds:         memoryBuildRepository{uow: u},
		Packages:       memoryPackageRepository{uow: u},
		Signatures:     memorySignatureRepository{uow: u},
		Verification:   memoryVerificationRepository{uow: u},
	}
}

func (u *memoryUnitOfWork) Commit(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return ErrConflict
	}
	state, err := cloneMemoryUnitOfWorkSnapshot(u.state)
	if err != nil {
		return err
	}
	u.factory.mu.Lock()
	defer u.factory.mu.Unlock()
	if u.factory.version != u.version {
		u.closed = true
		return ErrConflict
	}
	u.factory.state = state
	u.factory.version++
	u.closed = true
	return nil
}

func (u *memoryUnitOfWork) Rollback(context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return ErrConflict
	}
	u.closed = true
	return nil
}

func (u *memoryUnitOfWork) mutate(ctx context.Context, mutate func(*MemoryUnitOfWorkSnapshot) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return ErrConflict
	}
	return mutate(&u.state)
}

func (u *memoryUnitOfWork) appendAudit(ctx context.Context, entry domain.AuditChainEntry) (domain.AuditChainEntry, error) {
	if err := ctx.Err(); err != nil {
		return domain.AuditChainEntry{}, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return domain.AuditChainEntry{}, ErrConflict
	}
	if err := requireMemoryTenant(u.state, entry.TenantID); err != nil {
		return domain.AuditChainEntry{}, err
	}
	if entry.ID == "" || entry.EntryType == "" || entry.SubjectType == "" || entry.SubjectID == "" || entry.ActorType == "" || entry.ActorID == "" || entry.OccurredAt.IsZero() {
		return domain.AuditChainEntry{}, ErrValidation
	}
	entries := u.state.AuditEntries[entry.TenantID]
	for _, existing := range entries {
		if existing.ID == entry.ID {
			return domain.AuditChainEntry{}, ErrConflict
		}
	}
	entry.Sequence = int64(len(entries) + 1)
	entry.PreviousEntryHash = ""
	if len(entries) > 0 {
		entry.PreviousEntryHash = entries[len(entries)-1].EntryHash
	}
	if entry.SchemaVersion == "" {
		entry.SchemaVersion = domain.AuditChainEntrySchemaVersion
	}
	if err := RehashAuditChainEntry(&entry); err != nil {
		return domain.AuditChainEntry{}, err
	}
	cloned, err := cloneMemoryJSON(entry)
	if err != nil {
		return domain.AuditChainEntry{}, err
	}
	u.state.AuditEntries[entry.TenantID] = append(entries, cloned)
	return cloned, nil
}

type memoryIdentityRepository struct{ uow *memoryUnitOfWork }

func (r memoryIdentityRepository) InsertTenant(ctx context.Context, tenant domain.Tenant) error {
	cloned, err := cloneMemoryJSON(tenant)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if cloned.ID == "" || cloned.Name == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.Tenants[cloned.ID]; exists {
			return ErrConflict
		}
		state.Tenants[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) InsertAPIKey(ctx context.Context, key domain.APIKey) error {
	cloned := cloneMemoryAPIKey(key)
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.Name == "" || cloned.Prefix == "" || cloned.Hash == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.APIKeys[cloned.ID]; exists {
			return ErrConflict
		}
		state.APIKeys[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) UpdateAPIKeyLastUsed(ctx context.Context, key domain.APIKey) error {
	cloned := cloneMemoryAPIKey(key)
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		stored, ok := state.APIKeys[cloned.ID]
		if !ok || stored.TenantID != cloned.TenantID || stored.Prefix != cloned.Prefix || stored.Hash != cloned.Hash || stored.RevokedAt != nil || cloned.LastUsedAt == nil {
			return ErrConflict
		}
		state.APIKeys[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) UpdateCollectorLastSeen(ctx context.Context, collector domain.Collector) error {
	cloned, err := cloneMemoryJSON(collector)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		stored, ok := state.Collectors[cloned.ID]
		if !ok || stored.TenantID != cloned.TenantID || stored.APIKeyID != cloned.APIKeyID || cloned.LastSeenAt == nil {
			return ErrConflict
		}
		state.Collectors[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) InsertOrganization(ctx context.Context, organization domain.Organization) error {
	cloned, err := cloneMemoryJSON(organization)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.Name == "" || cloned.Slug == "" || cloned.Status == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.Organizations[cloned.ID]; exists {
			return ErrConflict
		}
		for _, existing := range state.Organizations {
			if existing.TenantID == cloned.TenantID && existing.Slug == cloned.Slug {
				return ErrConflict
			}
		}
		state.Organizations[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) InsertHumanUser(ctx context.Context, user domain.HumanUser) error {
	cloned, err := cloneMemoryJSON(user)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.Email == "" || cloned.DisplayName == "" || cloned.Status == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(cloned.OrganizationID, cloned.TenantID, state.Organizations) {
			return ErrNotFound
		}
		if _, exists := state.Users[cloned.ID]; exists {
			return ErrConflict
		}
		for _, existing := range state.Users {
			if existing.TenantID == cloned.TenantID && existing.Email == cloned.Email {
				return ErrConflict
			}
		}
		state.Users[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) DeactivateHumanUser(ctx context.Context, user domain.HumanUser) error {
	cloned, err := cloneMemoryJSON(user)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		stored, ok := state.Users[cloned.ID]
		if !ok || stored.TenantID != cloned.TenantID || stored.Status != "active" || cloned.Status != "deactivated" || cloned.DeactivatedAt == nil {
			return ErrConflict
		}
		state.Users[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) InsertRoleBinding(ctx context.Context, binding domain.RoleBinding) error {
	cloned, err := cloneMemoryJSON(binding)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || !validRoleSubject(cloned.SubjectType) || cloned.SubjectID == "" || !validRole(cloned.Role) || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryRoleSubjectBelongsToTenant(*state, cloned.TenantID, cloned.SubjectType, cloned.SubjectID) || !memoryRoleResourceBelongsToTenant(*state, cloned.TenantID, cloned.ResourceType, cloned.ResourceID) {
			return ErrNotFound
		}
		if _, exists := state.RoleBindings[cloned.ID]; exists {
			return ErrConflict
		}
		state.RoleBindings[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) InsertSSOProvider(ctx context.Context, provider domain.SSOProvider) error {
	cloned, err := cloneMemoryJSON(provider)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.Name == "" || !validSSOType(cloned.Type) || cloned.Issuer == "" || cloned.ClientID == "" || cloned.Status == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.SSOProviders[cloned.ID]; exists {
			return ErrConflict
		}
		state.SSOProviders[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) UpdateSSOProviderTrustMaterial(ctx context.Context, provider domain.SSOProvider) error {
	cloned, err := cloneMemoryJSON(provider)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		stored, ok := state.SSOProviders[cloned.ID]
		if !ok || stored.TenantID != cloned.TenantID || stored.Type != cloned.Type || cloned.TrustMaterialUpdatedAt == nil {
			return ErrConflict
		}
		state.SSOProviders[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) InsertUserIdentityLink(ctx context.Context, link domain.UserIdentityLink) error {
	cloned, err := cloneMemoryJSON(link)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.Subject == "" || cloned.Email == "" || !cloned.Verified || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(cloned.UserID, cloned.TenantID, state.Users) || !memoryResourceBelongsToTenant(cloned.ProviderID, cloned.TenantID, state.SSOProviders) {
			return ErrNotFound
		}
		for _, existing := range state.IdentityLinks {
			if existing.TenantID == cloned.TenantID && existing.ProviderID == cloned.ProviderID && existing.Subject == cloned.Subject {
				return ErrConflict
			}
		}
		if _, exists := state.IdentityLinks[cloned.ID]; exists {
			return ErrConflict
		}
		state.IdentityLinks[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) InsertProviderVerification(ctx context.Context, verification domain.ProviderVerification) error {
	cloned, err := cloneMemoryJSON(verification)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.ProviderType == "" || cloned.ProviderID == "" || cloned.Subject == "" || cloned.Result == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(cloned.ProviderID, cloned.TenantID, state.SSOProviders) {
			return ErrNotFound
		}
		if _, exists := state.ProviderVerifications[cloned.ID]; exists {
			return ErrConflict
		}
		state.ProviderVerifications[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) InsertSSOSession(ctx context.Context, session domain.SSOSession) error {
	cloned := cloneMemorySSOSession(session)
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.Prefix == "" || cloned.Hash == "" || cloned.ExpiresAt.IsZero() || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		user, userExists := state.Users[cloned.UserID]
		if !userExists || user.TenantID != cloned.TenantID || user.Status != "active" || !memoryResourceBelongsToTenant(cloned.ProviderID, cloned.TenantID, state.SSOProviders) {
			return ErrNotFound
		}
		if _, exists := state.SSOSessions[cloned.ID]; exists {
			return ErrConflict
		}
		state.SSOSessions[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) ValidateActiveSSOSession(ctx context.Context, session domain.SSOSession, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if session.ID == "" || session.TenantID == "" || session.UserID == "" || session.ProviderID == "" || session.Prefix == "" || session.Hash == "" || now.IsZero() {
		return ErrValidation
	}
	r.uow.mu.Lock()
	defer r.uow.mu.Unlock()
	stored, ok := r.uow.state.SSOSessions[session.ID]
	if !ok || stored.TenantID != session.TenantID || stored.UserID != session.UserID || stored.ProviderID != session.ProviderID || stored.Prefix != session.Prefix || !secretHashEqual(stored.Hash, session.Hash) || stored.RevokedAt != nil || !stored.ExpiresAt.After(now) {
		return ErrUnauthorized
	}
	user, ok := r.uow.state.Users[stored.UserID]
	if !ok || user.TenantID != stored.TenantID || user.Status != "active" {
		return ErrUnauthorized
	}
	return nil
}

func (r memoryIdentityRepository) RevokeSSOSession(ctx context.Context, session domain.SSOSession) error {
	cloned := cloneMemorySSOSession(session)
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		stored, ok := state.SSOSessions[cloned.ID]
		if !ok || stored.TenantID != cloned.TenantID || stored.UserID != cloned.UserID || stored.ProviderID != cloned.ProviderID || stored.Hash != cloned.Hash || stored.RevokedAt != nil || cloned.RevokedAt == nil {
			return ErrConflict
		}
		state.SSOSessions[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) InsertCustomerPortalAccess(ctx context.Context, access domain.CustomerPortalAccess) error {
	cloned := cloneMemoryCustomerPortalAccess(access)
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.PackageID == "" || cloned.CustomerName == "" || cloned.Prefix == "" || cloned.Hash == "" || cloned.ExpiresAt.IsZero() || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.CustomerPortalAccess[cloned.ID]; exists {
			return ErrConflict
		}
		state.CustomerPortalAccess[cloned.ID] = cloned
		return nil
	})
}

func (r memoryIdentityRepository) UpdateCustomerPortalAccess(ctx context.Context, previous, current domain.CustomerPortalAccess) error {
	clonedPrevious := cloneMemoryCustomerPortalAccess(previous)
	clonedCurrent := cloneMemoryCustomerPortalAccess(current)
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, clonedCurrent.TenantID); err != nil {
			return err
		}
		stored, ok := state.CustomerPortalAccess[clonedCurrent.ID]
		if !ok || stored.TenantID != clonedCurrent.TenantID || clonedPrevious.ID != clonedCurrent.ID || stored.AccessCount != clonedPrevious.AccessCount || stored.FailedAccessCount != clonedPrevious.FailedAccessCount || (stored.RevokedAt == nil) != (clonedPrevious.RevokedAt == nil) {
			return ErrConflict
		}
		state.CustomerPortalAccess[clonedCurrent.ID] = clonedCurrent
		return nil
	})
}

func memoryRoleSubjectBelongsToTenant(state MemoryUnitOfWorkSnapshot, tenantID, subjectType, subjectID string) bool {
	switch subjectType {
	case "user":
		return memoryResourceBelongsToTenant(subjectID, tenantID, state.Users)
	case "collector":
		return memoryResourceBelongsToTenant(subjectID, tenantID, state.Collectors)
	default:
		return false
	}
}

func memoryRoleResourceBelongsToTenant(state MemoryUnitOfWorkSnapshot, tenantID, resourceType, resourceID string) bool {
	switch resourceType {
	case "":
		return resourceID == ""
	case "tenant":
		return resourceID == "" || resourceID == tenantID
	case "product":
		return memoryResourceBelongsToTenant(resourceID, tenantID, state.Products)
	case "project":
		return memoryResourceBelongsToTenant(resourceID, tenantID, state.Projects)
	case "release":
		return memoryResourceBelongsToTenant(resourceID, tenantID, state.Releases)
	default:
		return false
	}
}

func memoryRetentionScopeBelongsToTenant(state MemoryUnitOfWorkSnapshot, tenantID, scopeType, scopeID string) bool {
	switch scopeType {
	case "tenant":
		_, ok := state.Tenants[scopeID]
		return ok && scopeID == tenantID
	case "product":
		return memoryResourceBelongsToTenant(scopeID, tenantID, state.Products)
	case "project":
		return memoryResourceBelongsToTenant(scopeID, tenantID, state.Projects)
	case "release":
		return memoryResourceBelongsToTenant(scopeID, tenantID, state.Releases)
	case "evidence":
		return memoryResourceBelongsToTenant(scopeID, tenantID, state.Evidence)
	default:
		return false
	}
}

type memoryReleaseCatalogRepository struct{ uow *memoryUnitOfWork }

func (r memoryReleaseCatalogRepository) InsertProduct(ctx context.Context, product domain.Product) error {
	cloned, err := cloneMemoryJSON(product)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.Name == "" || cloned.Slug == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.Products[cloned.ID]; exists {
			return ErrConflict
		}
		for _, existing := range state.Products {
			if existing.TenantID == cloned.TenantID && existing.Slug == cloned.Slug {
				return ErrConflict
			}
		}
		state.Products[cloned.ID] = cloned
		return nil
	})
}

func (r memoryReleaseCatalogRepository) InsertProject(ctx context.Context, project domain.Project) error {
	cloned, err := cloneMemoryJSON(project)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		product, ok := state.Products[cloned.ProductID]
		if !ok || product.TenantID != cloned.TenantID {
			return ErrNotFound
		}
		if cloned.ID == "" || cloned.Name == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.Projects[cloned.ID]; exists {
			return ErrConflict
		}
		state.Projects[cloned.ID] = cloned
		return nil
	})
}

func (r memoryReleaseCatalogRepository) InsertRelease(ctx context.Context, release domain.Release) error {
	cloned, err := cloneMemoryJSON(release)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		product, ok := state.Products[cloned.ProductID]
		if !ok || product.TenantID != cloned.TenantID {
			return ErrNotFound
		}
		if cloned.ID == "" || cloned.Version == "" || cloned.State == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.Releases[cloned.ID]; exists {
			return ErrConflict
		}
		for _, existing := range state.Releases {
			if existing.TenantID == cloned.TenantID && existing.ProductID == cloned.ProductID && existing.Version == cloned.Version {
				return ErrConflict
			}
		}
		state.Releases[cloned.ID] = cloned
		return nil
	})
}

func (r memoryReleaseCatalogRepository) UpdateReleaseState(ctx context.Context, release domain.Release, expectedState string) error {
	cloned, err := cloneMemoryJSON(release)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.ProductID == "" || cloned.State == "" || expectedState == "" {
			return ErrValidation
		}
		stored, ok := state.Releases[cloned.ID]
		if !ok || stored.TenantID != cloned.TenantID || stored.ProductID != cloned.ProductID {
			return ErrNotFound
		}
		if stored.State != expectedState {
			return ErrConflict
		}
		state.Releases[cloned.ID] = cloned
		return nil
	})
}

func (r memoryReleaseCatalogRepository) InsertArtifact(ctx context.Context, artifact domain.Artifact) error {
	cloned, err := cloneMemoryJSON(artifact)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.Name == "" || cloned.MediaType == "" || cloned.Digest == "" || cloned.Size < 0 || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.Artifacts[cloned.ID]; exists {
			return ErrConflict
		}
		for _, existing := range state.Artifacts {
			if existing.TenantID == cloned.TenantID && existing.Digest == cloned.Digest {
				return ErrConflict
			}
		}
		state.Artifacts[cloned.ID] = cloned
		return nil
	})
}

func (r memoryReleaseCatalogRepository) InsertReleaseCandidate(ctx context.Context, candidate domain.ReleaseCandidate) error {
	cloned, err := cloneMemoryJSON(candidate)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.ReleaseID == "" || cloned.Name == "" || cloned.State == "" || cloned.SnapshotHash == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(cloned.ReleaseID, cloned.TenantID, state.Releases) {
			return ErrNotFound
		}
		if _, exists := state.ReleaseCandidates[cloned.ID]; exists {
			return ErrConflict
		}
		state.ReleaseCandidates[cloned.ID] = cloned
		return nil
	})
}

func (r memoryReleaseCatalogRepository) UpdateReleaseCandidateState(ctx context.Context, candidate domain.ReleaseCandidate, expectedState string) error {
	cloned, err := cloneMemoryJSON(candidate)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		stored, ok := state.ReleaseCandidates[cloned.ID]
		if !ok || stored.TenantID != cloned.TenantID || stored.ReleaseID != cloned.ReleaseID {
			return ErrNotFound
		}
		if expectedState == "" || stored.State != expectedState {
			return ErrConflict
		}
		state.ReleaseCandidates[cloned.ID] = cloned
		return nil
	})
}

type memoryEvidenceRepository struct{ uow *memoryUnitOfWork }

func (r memoryEvidenceRepository) InsertEvidence(ctx context.Context, evidence domain.EvidenceItem) error {
	cloned, err := cloneMemoryJSON(evidence)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if !memoryResourceBelongsToTenant(cloned.ProductID, cloned.TenantID, state.Products) || !memoryResourceBelongsToTenant(cloned.ProjectID, cloned.TenantID, state.Projects) || !memoryResourceBelongsToTenant(cloned.ReleaseID, cloned.TenantID, state.Releases) {
			return ErrNotFound
		}
		if cloned.ID == "" || cloned.Type == "" || cloned.Title == "" || cloned.PayloadHash == "" || cloned.CanonicalHash == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.Evidence[cloned.ID]; exists {
			return ErrConflict
		}
		state.Evidence[cloned.ID] = cloned
		return nil
	})
}

func (r memoryEvidenceRepository) UpdateEvidenceLinks(ctx context.Context, evidence domain.EvidenceItem) error {
	cloned, err := cloneMemoryJSON(evidence)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		stored, ok := state.Evidence[cloned.ID]
		if !ok || stored.TenantID != cloned.TenantID {
			return ErrNotFound
		}
		if !memoryResourceBelongsToTenant(cloned.ProductID, cloned.TenantID, state.Products) || !memoryResourceBelongsToTenant(cloned.ReleaseID, cloned.TenantID, state.Releases) {
			return ErrNotFound
		}
		state.Evidence[cloned.ID] = cloned
		return nil
	})
}

func (r memoryEvidenceRepository) RecordSupersession(ctx context.Context, superseded, replacement domain.EvidenceItem) error {
	clonedSuperseded, err := cloneMemoryJSON(superseded)
	if err != nil {
		return err
	}
	clonedReplacement, err := cloneMemoryJSON(replacement)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, clonedSuperseded.TenantID); err != nil {
			return err
		}
		if clonedSuperseded.TenantID != clonedReplacement.TenantID || clonedSuperseded.ID == "" || clonedReplacement.ID == "" || clonedSuperseded.SupersededBy != clonedReplacement.ID || clonedReplacement.Supersedes != clonedSuperseded.ID {
			return ErrValidation
		}
		storedSuperseded, ok := state.Evidence[clonedSuperseded.ID]
		if !ok || storedSuperseded.TenantID != clonedSuperseded.TenantID {
			return ErrNotFound
		}
		storedReplacement, ok := state.Evidence[clonedReplacement.ID]
		if !ok || storedReplacement.TenantID != clonedSuperseded.TenantID {
			return ErrNotFound
		}
		if storedSuperseded.SupersededBy != "" || storedReplacement.Supersedes != "" {
			return ErrConflict
		}
		state.Evidence[clonedSuperseded.ID] = clonedSuperseded
		state.Evidence[clonedReplacement.ID] = clonedReplacement
		return nil
	})
}

func (r memoryEvidenceRepository) AppendLifecycle(ctx context.Context, event domain.EvidenceLifecycleEvent) error {
	cloned, err := cloneMemoryJSON(event)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		evidence, ok := state.Evidence[cloned.EvidenceID]
		if !ok || evidence.TenantID != cloned.TenantID {
			return ErrNotFound
		}
		if cloned.ID == "" || cloned.Action == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.EvidenceLifecycle[cloned.ID]; exists {
			return ErrConflict
		}
		state.EvidenceLifecycle[cloned.ID] = cloned
		return nil
	})
}

func (r memoryEvidenceRepository) InsertSBOM(ctx context.Context, sbom domain.SBOM) error {
	cloned, err := cloneMemoryJSON(sbom)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.EvidenceID == "" || cloned.Format == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(cloned.EvidenceID, cloned.TenantID, state.Evidence) || !memoryResourceBelongsToTenant(cloned.ReleaseID, cloned.TenantID, state.Releases) || !memoryResourceBelongsToTenant(cloned.ArtifactID, cloned.TenantID, state.Artifacts) {
			return ErrNotFound
		}
		if _, exists := state.SBOMs[cloned.ID]; exists {
			return ErrConflict
		}
		state.SBOMs[cloned.ID] = cloned
		return nil
	})
}

func (r memoryEvidenceRepository) InsertVulnerabilityScan(ctx context.Context, scan domain.VulnerabilityScan) error {
	cloned, err := cloneMemoryJSON(scan)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.EvidenceID == "" || cloned.Scanner == "" || cloned.TargetRef == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(cloned.EvidenceID, cloned.TenantID, state.Evidence) || !memoryResourceBelongsToTenant(cloned.ReleaseID, cloned.TenantID, state.Releases) {
			return ErrNotFound
		}
		if _, exists := state.VulnerabilityScans[cloned.ID]; exists {
			return ErrConflict
		}
		state.VulnerabilityScans[cloned.ID] = cloned
		return nil
	})
}

func (r memoryEvidenceRepository) InsertOpenAPIContract(ctx context.Context, contract domain.OpenAPIContract) error {
	cloned, err := cloneMemoryJSON(contract)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.ProductID == "" || cloned.EvidenceID == "" || cloned.Version == "" || cloned.Hash == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(cloned.ProductID, cloned.TenantID, state.Products) || !memoryResourceBelongsToTenant(cloned.ReleaseID, cloned.TenantID, state.Releases) || !memoryResourceBelongsToTenant(cloned.EvidenceID, cloned.TenantID, state.Evidence) {
			return ErrNotFound
		}
		if _, exists := state.OpenAPIContracts[cloned.ID]; exists {
			return ErrConflict
		}
		state.OpenAPIContracts[cloned.ID] = cloned
		return nil
	})
}

func (r memoryEvidenceRepository) InsertVEXDocument(ctx context.Context, document domain.VEXDocument) error {
	cloned, err := cloneMemoryJSON(document)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.EvidenceID == "" || cloned.ReleaseID == "" || cloned.Format == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(cloned.EvidenceID, cloned.TenantID, state.Evidence) || !memoryResourceBelongsToTenant(cloned.ReleaseID, cloned.TenantID, state.Releases) || !memoryResourceBelongsToTenant(cloned.ArtifactID, cloned.TenantID, state.Artifacts) {
			return ErrNotFound
		}
		if _, exists := state.VEXDocuments[cloned.ID]; exists {
			return ErrConflict
		}
		state.VEXDocuments[cloned.ID] = cloned
		return nil
	})
}

func (r memoryEvidenceRepository) InsertVEXImportReport(ctx context.Context, report domain.VEXImportReport) error {
	cloned, err := cloneMemoryJSON(report)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.VEXDocumentID == "" || cloned.EvidenceID == "" || cloned.ParserVersion == "" || cloned.Status == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() || cloned.UpdatedAt.IsZero() {
			return ErrValidation
		}
		vex, ok := state.VEXDocuments[cloned.VEXDocumentID]
		if !ok || vex.TenantID != cloned.TenantID || !memoryResourceBelongsToTenant(cloned.EvidenceID, cloned.TenantID, state.Evidence) || !memoryResourceBelongsToTenant(cloned.ReleaseID, cloned.TenantID, state.Releases) || !memoryResourceBelongsToTenant(cloned.ArtifactID, cloned.TenantID, state.Artifacts) {
			return ErrNotFound
		}
		if _, exists := state.VEXImportReports[cloned.ID]; exists {
			return ErrConflict
		}
		state.VEXImportReports[cloned.ID] = cloned
		return nil
	})
}

type memoryDecisionRepository struct{ uow *memoryUnitOfWork }

func (r memoryDecisionRepository) InsertVulnerabilityDecision(ctx context.Context, decision domain.VulnerabilityDecision) error {
	cloned, err := cloneMemoryJSON(decision)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if !memoryResourceBelongsToTenant(cloned.ReleaseID, cloned.TenantID, state.Releases) || !memoryResourceBelongsToTenant(cloned.EvidenceID, cloned.TenantID, state.Evidence) {
			return ErrNotFound
		}
		if cloned.ID == "" || cloned.FindingID == "" || cloned.ScanID == "" || cloned.Vulnerability == "" || cloned.Status == "" || cloned.Justification == "" || cloned.Source == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.Decisions[cloned.ID]; exists {
			return ErrConflict
		}
		state.Decisions[cloned.ID] = cloned
		return nil
	})
}

func (r memoryDecisionRepository) SupersedeAndInsert(ctx context.Context, decision domain.VulnerabilityDecision, superseded []domain.VulnerabilityDecision) error {
	clonedDecision, err := cloneMemoryJSON(decision)
	if err != nil {
		return err
	}
	clonedSuperseded, err := cloneMemoryJSON(superseded)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, clonedDecision.TenantID); err != nil {
			return err
		}
		if clonedDecision.ID == "" || clonedDecision.FindingID == "" || clonedDecision.ScanID == "" || clonedDecision.Vulnerability == "" || clonedDecision.Status == "" || clonedDecision.Justification == "" || clonedDecision.Source == "" || clonedDecision.SchemaVersion == "" || clonedDecision.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(clonedDecision.ReleaseID, clonedDecision.TenantID, state.Releases) || !memoryResourceBelongsToTenant(clonedDecision.EvidenceID, clonedDecision.TenantID, state.Evidence) {
			return ErrNotFound
		}
		scan, ok := state.VulnerabilityScans[clonedDecision.ScanID]
		if !ok || scan.TenantID != clonedDecision.TenantID {
			return ErrNotFound
		}
		if _, exists := state.Decisions[clonedDecision.ID]; exists {
			return ErrConflict
		}
		for _, prior := range clonedSuperseded {
			stored, ok := state.Decisions[prior.ID]
			if !ok || stored.TenantID != clonedDecision.TenantID || stored.SupersededBy != "" || prior.SupersededBy != clonedDecision.ID {
				return ErrConflict
			}
		}
		for _, prior := range clonedSuperseded {
			state.Decisions[prior.ID] = prior
		}
		state.Decisions[clonedDecision.ID] = clonedDecision
		return nil
	})
}

func (r memoryDecisionRepository) InsertException(ctx context.Context, exception domain.Exception) error {
	cloned, err := cloneMemoryJSON(exception)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.ReleaseID == "" || cloned.Reason == "" || cloned.Owner == "" || !cloned.ExpiresAt.After(cloned.CreatedAt) || cloned.CreatedAt.IsZero() || cloned.Approved || cloned.ApprovedBy != "" || cloned.ApprovedAt != nil {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(cloned.ReleaseID, cloned.TenantID, state.Releases) {
			return ErrNotFound
		}
		if cloned.ControlID != "" && !memoryResourceBelongsToTenant(cloned.ControlID, cloned.TenantID, state.SecurityControls) {
			return ErrNotFound
		}
		if _, exists := state.Exceptions[cloned.ID]; exists {
			return ErrConflict
		}
		state.Exceptions[cloned.ID] = cloned
		return nil
	})
}

func (r memoryDecisionRepository) ApproveException(ctx context.Context, exception domain.Exception) error {
	cloned, err := cloneMemoryJSON(exception)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		stored, ok := state.Exceptions[cloned.ID]
		if !ok || stored.TenantID != cloned.TenantID {
			return ErrNotFound
		}
		if stored.Approved || !cloned.Approved || cloned.ApprovedBy == "" || cloned.ApprovedAt == nil || !cloned.ExpiresAt.After(*cloned.ApprovedAt) {
			return ErrConflict
		}
		state.Exceptions[cloned.ID] = cloned
		return nil
	})
}

type memoryAuditRepository struct{ uow *memoryUnitOfWork }

func (r memoryAuditRepository) Append(ctx context.Context, entry domain.AuditChainEntry) (domain.AuditChainEntry, error) {
	return r.uow.appendAudit(ctx, entry)
}

type memoryIdempotencyRepository struct{ uow *memoryUnitOfWork }

func (r memoryIdempotencyRepository) Insert(ctx context.Context, key IdempotencyRecordKey, record IdempotencyRecord) error {
	cloned, err := cloneMemoryIdempotencyRecord(record)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, key.TenantID); err != nil {
			return err
		}
		if key.ActorID == "" || key.Method == "" || key.Path == "" || key.IdempotencyKey == "" || cloned.RequestHash == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.Idempotency[key]; exists {
			return ErrConflict
		}
		state.Idempotency[key] = cloned
		return nil
	})
}

type memoryOutboxRepository struct{ uow *memoryUnitOfWork }

func (r memoryOutboxRepository) Enqueue(ctx context.Context, job OutboxJob) error {
	cloned, err := cloneMemoryJSON(job)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.Kind == "" || cloned.SubjectType == "" || cloned.SubjectID == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.OutboxJobs[cloned.ID]; exists {
			return ErrConflict
		}
		state.OutboxJobs[cloned.ID] = cloned
		return nil
	})
}

type memoryControlRepository struct{ uow *memoryUnitOfWork }

func (r memoryControlRepository) InsertControlFramework(ctx context.Context, framework domain.ControlFramework) error {
	cloned, err := cloneMemoryJSON(framework)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.Name == "" || cloned.Slug == "" || cloned.Version == "" || cloned.Status == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.ControlFrameworks[cloned.ID]; exists {
			return ErrConflict
		}
		for _, existing := range state.ControlFrameworks {
			if existing.TenantID == cloned.TenantID && existing.Slug == cloned.Slug && existing.Version == cloned.Version {
				return ErrConflict
			}
		}
		state.ControlFrameworks[cloned.ID] = cloned
		return nil
	})
}

func (r memoryControlRepository) InsertSecurityControl(ctx context.Context, control domain.SecurityControl) error {
	cloned, err := cloneMemoryJSON(control)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.FrameworkID == "" || cloned.Code == "" || cloned.Title == "" || cloned.Objective == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		framework, ok := state.ControlFrameworks[cloned.FrameworkID]
		if !ok || framework.TenantID != cloned.TenantID {
			return ErrNotFound
		}
		if _, exists := state.SecurityControls[cloned.ID]; exists {
			return ErrConflict
		}
		for _, existing := range state.SecurityControls {
			if existing.TenantID == cloned.TenantID && existing.FrameworkID == cloned.FrameworkID && existing.Code == cloned.Code {
				return ErrConflict
			}
		}
		state.SecurityControls[cloned.ID] = cloned
		return nil
	})
}

func (r memoryControlRepository) InsertControlEvidence(ctx context.Context, evidence domain.ControlEvidence) error {
	cloned, err := cloneMemoryJSON(evidence)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.ControlID == "" || cloned.EvidenceType == "" || cloned.SubjectType == "" || cloned.SubjectID == "" || cloned.Confidence == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		control, ok := state.SecurityControls[cloned.ControlID]
		if !ok || control.TenantID != cloned.TenantID {
			return ErrNotFound
		}
		if _, exists := state.ControlEvidence[cloned.ID]; exists {
			return ErrConflict
		}
		for _, existing := range state.ControlEvidence {
			if existing.TenantID == cloned.TenantID && existing.ControlID == cloned.ControlID && existing.EvidenceType == cloned.EvidenceType && existing.SubjectType == cloned.SubjectType && existing.SubjectID == cloned.SubjectID && existing.ProductID == cloned.ProductID && existing.ReleaseID == cloned.ReleaseID {
				return ErrConflict
			}
		}
		state.ControlEvidence[cloned.ID] = cloned
		return nil
	})
}

type memoryGovernanceRepository struct{ uow *memoryUnitOfWork }

func (r memoryGovernanceRepository) InsertWaiver(ctx context.Context, waiver domain.Waiver) error {
	cloned, err := cloneMemoryJSON(waiver)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.ScopeType == "" || cloned.ScopeID == "" || cloned.Owner == "" || cloned.Risk == "" || cloned.Reason == "" || !cloned.ExpiresAt.After(cloned.CreatedAt) || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if cloned.ControlID != "" && !memoryResourceBelongsToTenant(cloned.ControlID, cloned.TenantID, state.SecurityControls) {
			return ErrNotFound
		}
		if _, exists := state.Waivers[cloned.ID]; exists {
			return ErrConflict
		}
		if cloned.Supersedes != "" {
			previous, ok := state.Waivers[cloned.Supersedes]
			if !ok || previous.TenantID != cloned.TenantID {
				return ErrNotFound
			}
			if previous.SupersededBy != "" {
				return ErrConflict
			}
			previous.SupersededBy = cloned.ID
			state.Waivers[previous.ID] = previous
		}
		state.Waivers[cloned.ID] = cloned
		return nil
	})
}

func (r memoryGovernanceRepository) ApproveWaiver(ctx context.Context, waiver domain.Waiver) error {
	cloned, err := cloneMemoryJSON(waiver)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		stored, ok := state.Waivers[cloned.ID]
		if !ok || stored.TenantID != cloned.TenantID {
			return ErrNotFound
		}
		if stored.Approved || !cloned.Approved || cloned.ApprovedAt == nil || cloned.ApprovedBy == "" || !cloned.ExpiresAt.After(*cloned.ApprovedAt) {
			return ErrConflict
		}
		state.Waivers[cloned.ID] = cloned
		return nil
	})
}

func (r memoryGovernanceRepository) InsertApprovalRecord(ctx context.Context, approval domain.ApprovalRecord) error {
	cloned, err := cloneMemoryJSON(approval)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.SubjectType == "" || cloned.SubjectID == "" || cloned.Decision == "" || cloned.Reason == "" || cloned.ApproverID == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if cloned.EvidenceID != "" && !memoryResourceBelongsToTenant(cloned.EvidenceID, cloned.TenantID, state.Evidence) {
			return ErrNotFound
		}
		if _, exists := state.Approvals[cloned.ID]; exists {
			return ErrConflict
		}
		state.Approvals[cloned.ID] = cloned
		return nil
	})
}

func (r memoryGovernanceRepository) InsertRedactionProfile(ctx context.Context, profile domain.RedactionProfile) error {
	cloned, err := cloneMemoryJSON(profile)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.Name == "" || len(cloned.AllowedTypes) == 0 || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.RedactionProfiles[cloned.ID]; exists {
			return ErrConflict
		}
		state.RedactionProfiles[cloned.ID] = cloned
		return nil
	})
}

func (r memoryGovernanceRepository) InsertLegalHold(ctx context.Context, hold domain.LegalHold) error {
	cloned, err := cloneMemoryJSON(hold)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.ScopeType == "" || cloned.ScopeID == "" || cloned.Reason == "" || cloned.Owner == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() || cloned.ReleasedAt != nil {
			return ErrValidation
		}
		if !memoryRetentionScopeBelongsToTenant(*state, cloned.TenantID, cloned.ScopeType, cloned.ScopeID) {
			return ErrNotFound
		}
		if _, exists := state.LegalHolds[cloned.ID]; exists {
			return ErrConflict
		}
		state.LegalHolds[cloned.ID] = cloned
		return nil
	})
}

func (r memoryGovernanceRepository) InsertRetentionOverride(ctx context.Context, override domain.RetentionOverride) error {
	cloned, err := cloneMemoryJSON(override)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.ScopeType == "" || cloned.ScopeID == "" || !cloned.RetentionUntil.After(cloned.CreatedAt) || cloned.Reason == "" || cloned.Owner == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryRetentionScopeBelongsToTenant(*state, cloned.TenantID, cloned.ScopeType, cloned.ScopeID) {
			return ErrNotFound
		}
		if _, exists := state.RetentionOverrides[cloned.ID]; exists {
			return ErrConflict
		}
		state.RetentionOverrides[cloned.ID] = cloned
		return nil
	})
}

type memoryBuildRepository struct{ uow *memoryUnitOfWork }

func (r memoryBuildRepository) InsertCollector(ctx context.Context, collector domain.Collector) error {
	cloned, err := cloneMemoryJSON(collector)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.Name == "" || cloned.Type == "" || cloned.Version == "" || cloned.APIKeyID == "" || cloned.Status == "" || len(cloned.AllowedScopes) == 0 || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(cloned.APIKeyID, cloned.TenantID, state.APIKeys) {
			return ErrNotFound
		}
		if _, exists := state.Collectors[cloned.ID]; exists {
			return ErrConflict
		}
		for _, existing := range state.Collectors {
			if existing.TenantID == cloned.TenantID && existing.Name == cloned.Name {
				return ErrConflict
			}
		}
		state.Collectors[cloned.ID] = cloned
		return nil
	})
}

func (r memoryBuildRepository) InsertCollectorRelease(ctx context.Context, release domain.CollectorRelease) error {
	cloned, err := cloneMemoryJSON(release)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.CollectorID == "" || cloned.Version == "" || cloned.ArtifactDigest == "" || cloned.VerificationStatus == "" || cloned.HealthStatus == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(cloned.CollectorID, cloned.TenantID, state.Collectors) {
			return ErrNotFound
		}
		if cloned.SBOMID != "" && !memoryResourceBelongsToTenant(cloned.SBOMID, cloned.TenantID, state.SBOMs) {
			return ErrNotFound
		}
		if cloned.ScanID != "" && !memoryResourceBelongsToTenant(cloned.ScanID, cloned.TenantID, state.VulnerabilityScans) {
			return ErrNotFound
		}
		if _, exists := state.CollectorReleases[cloned.ID]; exists {
			return ErrConflict
		}
		if cloned.Pinned {
			for id, existing := range state.CollectorReleases {
				if existing.TenantID == cloned.TenantID && existing.CollectorID == cloned.CollectorID && existing.Pinned {
					existing.Pinned = false
					state.CollectorReleases[id] = existing
				}
			}
		}
		state.CollectorReleases[cloned.ID] = cloned
		return nil
	})
}

func (r memoryBuildRepository) InsertBuildRun(ctx context.Context, build domain.BuildRun) error {
	cloned, err := cloneMemoryJSON(build)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.ProjectID == "" || cloned.ReleaseID == "" || cloned.Provider == "" || cloned.CommitSHA == "" || cloned.Status == "" || cloned.StartedAt.IsZero() || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(cloned.ProjectID, cloned.TenantID, state.Projects) || !memoryResourceBelongsToTenant(cloned.ReleaseID, cloned.TenantID, state.Releases) {
			return ErrNotFound
		}
		if cloned.CollectorID != "" && !memoryResourceBelongsToTenant(cloned.CollectorID, cloned.TenantID, state.Collectors) {
			return ErrNotFound
		}
		for _, output := range cloned.Outputs {
			if output.Digest == "" {
				return ErrValidation
			}
			if output.ArtifactID == "" {
				continue
			}
			artifact, ok := state.Artifacts[output.ArtifactID]
			if !ok || artifact.TenantID != cloned.TenantID || artifact.Digest != output.Digest {
				return ErrNotFound
			}
		}
		if _, exists := state.BuildRuns[cloned.ID]; exists {
			return ErrConflict
		}
		state.BuildRuns[cloned.ID] = cloned
		return nil
	})
}

func (r memoryBuildRepository) InsertBuildAttestation(ctx context.Context, attestation domain.BuildAttestation) error {
	cloned, err := cloneMemoryJSON(attestation)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.BuildID == "" || cloned.EvidenceID == "" || cloned.PayloadHash == "" || cloned.PayloadSize < 0 || cloned.VerificationStatus == "" || cloned.SchemaVersion == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if !memoryResourceBelongsToTenant(cloned.BuildID, cloned.TenantID, state.BuildRuns) {
			return ErrNotFound
		}
		evidence, ok := state.Evidence[cloned.EvidenceID]
		if !ok || evidence.TenantID != cloned.TenantID {
			return ErrNotFound
		}
		if evidence.BuildID != cloned.BuildID {
			return ErrValidation
		}
		if _, exists := state.BuildAttestations[cloned.ID]; exists {
			return ErrConflict
		}
		state.BuildAttestations[cloned.ID] = cloned
		return nil
	})
}

type memoryPackageRepository struct{ uow *memoryUnitOfWork }

func (r memoryPackageRepository) InsertReleaseBundle(ctx context.Context, bundle domain.ReleaseBundle) error {
	cloned, err := cloneMemoryJSON(bundle)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if !memoryResourceBelongsToTenant(cloned.ReleaseID, cloned.TenantID, state.Releases) {
			return ErrNotFound
		}
		if cloned.ID == "" || cloned.State == "" || cloned.ManifestHash == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.ReleaseBundles[cloned.ID]; exists {
			return ErrConflict
		}
		state.ReleaseBundles[cloned.ID] = cloned
		return nil
	})
}

type memorySignatureRepository struct{ uow *memoryUnitOfWork }

func (r memorySignatureRepository) InsertSigningKey(ctx context.Context, key domain.SigningKey) error {
	cloned := cloneMemorySigningKey(key)
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.KID == "" || cloned.Algorithm == "" || cloned.Status == "" || cloned.PublicKey == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.SigningKeys[cloned.ID]; exists {
			return ErrConflict
		}
		state.SigningKeys[cloned.ID] = cloned
		return nil
	})
}

func (r memorySignatureRepository) InsertSignature(ctx context.Context, signature domain.Signature) error {
	cloned, err := cloneMemoryJSON(signature)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		key, ok := state.SigningKeys[cloned.KeyID]
		if !ok || key.TenantID != cloned.TenantID {
			return ErrNotFound
		}
		if cloned.ID == "" || cloned.SubjectType == "" || cloned.SubjectID == "" || cloned.Algorithm == "" || cloned.Value == "" || cloned.CreatedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.Signatures[cloned.ID]; exists {
			return ErrConflict
		}
		state.Signatures[cloned.ID] = cloned
		return nil
	})
}

type memoryVerificationRepository struct{ uow *memoryUnitOfWork }

func (r memoryVerificationRepository) InsertVerificationResult(ctx context.Context, result domain.VerificationResult) error {
	cloned, err := cloneMemoryJSON(result)
	if err != nil {
		return err
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, cloned.TenantID); err != nil {
			return err
		}
		if cloned.ID == "" || cloned.SubjectType == "" || cloned.SubjectID == "" || cloned.Result == "" || cloned.VerifiedAt.IsZero() {
			return ErrValidation
		}
		if _, exists := state.VerificationResults[cloned.ID]; exists {
			return ErrConflict
		}
		state.VerificationResults[cloned.ID] = cloned
		return nil
	})
}

func emptyMemoryUnitOfWorkSnapshot() MemoryUnitOfWorkSnapshot {
	return MemoryUnitOfWorkSnapshot{
		Tenants:               map[string]domain.Tenant{},
		APIKeys:               map[string]domain.APIKey{},
		Collectors:            map[string]domain.Collector{},
		Organizations:         map[string]domain.Organization{},
		Users:                 map[string]domain.HumanUser{},
		RoleBindings:          map[string]domain.RoleBinding{},
		SSOProviders:          map[string]domain.SSOProvider{},
		IdentityLinks:         map[string]domain.UserIdentityLink{},
		ProviderVerifications: map[string]domain.ProviderVerification{},
		SSOSessions:           map[string]domain.SSOSession{},
		CustomerPortalAccess:  map[string]domain.CustomerPortalAccess{},
		Products:              map[string]domain.Product{},
		Projects:              map[string]domain.Project{},
		Releases:              map[string]domain.Release{},
		Artifacts:             map[string]domain.Artifact{},
		Evidence:              map[string]domain.EvidenceItem{},
		EvidenceLifecycle:     map[string]domain.EvidenceLifecycleEvent{},
		SBOMs:                 map[string]domain.SBOM{},
		VulnerabilityScans:    map[string]domain.VulnerabilityScan{},
		OpenAPIContracts:      map[string]domain.OpenAPIContract{},
		VEXDocuments:          map[string]domain.VEXDocument{},
		VEXImportReports:      map[string]domain.VEXImportReport{},
		ReleaseCandidates:     map[string]domain.ReleaseCandidate{},
		Decisions:             map[string]domain.VulnerabilityDecision{},
		Exceptions:            map[string]domain.Exception{},
		BuildRuns:             map[string]domain.BuildRun{},
		BuildAttestations:     map[string]domain.BuildAttestation{},
		CollectorReleases:     map[string]domain.CollectorRelease{},
		ControlFrameworks:     map[string]domain.ControlFramework{},
		SecurityControls:      map[string]domain.SecurityControl{},
		ControlEvidence:       map[string]domain.ControlEvidence{},
		Waivers:               map[string]domain.Waiver{},
		Approvals:             map[string]domain.ApprovalRecord{},
		RedactionProfiles:     map[string]domain.RedactionProfile{},
		LegalHolds:            map[string]domain.LegalHold{},
		RetentionOverrides:    map[string]domain.RetentionOverride{},
		AuditEntries:          map[string][]domain.AuditChainEntry{},
		Idempotency:           map[IdempotencyRecordKey]IdempotencyRecord{},
		OutboxJobs:            map[string]OutboxJob{},
		ReleaseBundles:        map[string]domain.ReleaseBundle{},
		SigningKeys:           map[string]domain.SigningKey{},
		Signatures:            map[string]domain.Signature{},
		VerificationResults:   map[string]domain.VerificationResult{},
	}
}

func cloneMemoryUnitOfWorkSnapshot(snapshot MemoryUnitOfWorkSnapshot) (MemoryUnitOfWorkSnapshot, error) {
	cloned := emptyMemoryUnitOfWorkSnapshot()
	var err error
	if cloned.Tenants, err = cloneMemoryMap(snapshot.Tenants); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	cloned.APIKeys = make(map[string]domain.APIKey, len(snapshot.APIKeys))
	for id, key := range snapshot.APIKeys {
		cloned.APIKeys[id] = cloneMemoryAPIKey(key)
	}
	if cloned.Collectors, err = cloneMemoryMap(snapshot.Collectors); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.Organizations, err = cloneMemoryMap(snapshot.Organizations); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.Users, err = cloneMemoryMap(snapshot.Users); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.RoleBindings, err = cloneMemoryMap(snapshot.RoleBindings); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.SSOProviders, err = cloneMemoryMap(snapshot.SSOProviders); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.IdentityLinks, err = cloneMemoryMap(snapshot.IdentityLinks); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.ProviderVerifications, err = cloneMemoryMap(snapshot.ProviderVerifications); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	cloned.SSOSessions = make(map[string]domain.SSOSession, len(snapshot.SSOSessions))
	for id, session := range snapshot.SSOSessions {
		cloned.SSOSessions[id] = cloneMemorySSOSession(session)
	}
	cloned.CustomerPortalAccess = make(map[string]domain.CustomerPortalAccess, len(snapshot.CustomerPortalAccess))
	for id, access := range snapshot.CustomerPortalAccess {
		cloned.CustomerPortalAccess[id] = cloneMemoryCustomerPortalAccess(access)
	}
	if cloned.Products, err = cloneMemoryMap(snapshot.Products); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.Projects, err = cloneMemoryMap(snapshot.Projects); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.Releases, err = cloneMemoryMap(snapshot.Releases); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.Artifacts, err = cloneMemoryMap(snapshot.Artifacts); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.Evidence, err = cloneMemoryMap(snapshot.Evidence); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.EvidenceLifecycle, err = cloneMemoryMap(snapshot.EvidenceLifecycle); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.SBOMs, err = cloneMemoryMap(snapshot.SBOMs); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.VulnerabilityScans, err = cloneMemoryMap(snapshot.VulnerabilityScans); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.OpenAPIContracts, err = cloneMemoryMap(snapshot.OpenAPIContracts); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.VEXDocuments, err = cloneMemoryMap(snapshot.VEXDocuments); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.VEXImportReports, err = cloneMemoryMap(snapshot.VEXImportReports); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.ReleaseCandidates, err = cloneMemoryMap(snapshot.ReleaseCandidates); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.Decisions, err = cloneMemoryMap(snapshot.Decisions); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.Exceptions, err = cloneMemoryMap(snapshot.Exceptions); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.BuildRuns, err = cloneMemoryMap(snapshot.BuildRuns); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.BuildAttestations, err = cloneMemoryMap(snapshot.BuildAttestations); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.CollectorReleases, err = cloneMemoryMap(snapshot.CollectorReleases); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.ControlFrameworks, err = cloneMemoryMap(snapshot.ControlFrameworks); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.SecurityControls, err = cloneMemoryMap(snapshot.SecurityControls); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.ControlEvidence, err = cloneMemoryMap(snapshot.ControlEvidence); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.Waivers, err = cloneMemoryMap(snapshot.Waivers); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.Approvals, err = cloneMemoryMap(snapshot.Approvals); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.RedactionProfiles, err = cloneMemoryMap(snapshot.RedactionProfiles); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.LegalHolds, err = cloneMemoryMap(snapshot.LegalHolds); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.RetentionOverrides, err = cloneMemoryMap(snapshot.RetentionOverrides); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.AuditEntries, err = cloneMemoryJSON(snapshot.AuditEntries); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	cloned.Idempotency = make(map[IdempotencyRecordKey]IdempotencyRecord, len(snapshot.Idempotency))
	for key, record := range snapshot.Idempotency {
		clonedRecord, err := cloneMemoryIdempotencyRecord(record)
		if err != nil {
			return MemoryUnitOfWorkSnapshot{}, err
		}
		cloned.Idempotency[key] = clonedRecord
	}
	if cloned.OutboxJobs, err = cloneMemoryMap(snapshot.OutboxJobs); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.ReleaseBundles, err = cloneMemoryMap(snapshot.ReleaseBundles); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	cloned.SigningKeys = make(map[string]domain.SigningKey, len(snapshot.SigningKeys))
	for id, key := range snapshot.SigningKeys {
		cloned.SigningKeys[id] = cloneMemorySigningKey(key)
	}
	if cloned.Signatures, err = cloneMemoryMap(snapshot.Signatures); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	if cloned.VerificationResults, err = cloneMemoryMap(snapshot.VerificationResults); err != nil {
		return MemoryUnitOfWorkSnapshot{}, err
	}
	return cloned, nil
}

func cloneMemoryMap[T any](input map[string]T) (map[string]T, error) {
	output := make(map[string]T, len(input))
	for key, value := range input {
		cloned, err := cloneMemoryJSON(value)
		if err != nil {
			return nil, err
		}
		output[key] = cloned
	}
	return output, nil
}

func cloneMemoryJSON[T any](value T) (T, error) {
	var cloned T
	body, err := json.Marshal(value)
	if err != nil {
		return cloned, err
	}
	if err := json.Unmarshal(body, &cloned); err != nil {
		return cloned, err
	}
	return cloned, nil
}

func cloneMemoryAPIKey(key domain.APIKey) domain.APIKey {
	cloned := key
	cloned.Scopes = append([]string(nil), key.Scopes...)
	return cloned
}

func cloneMemorySigningKey(key domain.SigningKey) domain.SigningKey {
	cloned := key
	cloned.Private = append([]byte(nil), key.Private...)
	return cloned
}

func cloneMemorySSOSession(session domain.SSOSession) domain.SSOSession {
	cloned := session
	cloned.Groups = append([]string(nil), session.Groups...)
	return cloned
}

func cloneMemoryCustomerPortalAccess(access domain.CustomerPortalAccess) domain.CustomerPortalAccess {
	return access
}

func cloneMemoryIdempotencyRecord(record IdempotencyRecord) (IdempotencyRecord, error) {
	cloned := record
	response, err := cloneMemoryJSON(record.Response)
	if err != nil {
		return IdempotencyRecord{}, err
	}
	cloned.Response = response
	return cloned, nil
}

func requireMemoryTenant(state MemoryUnitOfWorkSnapshot, tenantID string) error {
	if tenantID == "" {
		return ErrValidation
	}
	if _, ok := state.Tenants[tenantID]; !ok {
		return ErrNotFound
	}
	return nil
}

func memoryResourceBelongsToTenant[T interface{}](id, tenantID string, resources map[string]T) bool {
	if id == "" {
		return true
	}
	resource, ok := resources[id]
	if !ok {
		return false
	}
	return memoryResourceTenantID(resource) == tenantID
}

func memoryResourceTenantID(resource any) string {
	switch value := resource.(type) {
	case domain.Product:
		return value.TenantID
	case domain.Project:
		return value.TenantID
	case domain.Release:
		return value.TenantID
	case domain.Artifact:
		return value.TenantID
	case domain.EvidenceItem:
		return value.TenantID
	case domain.APIKey:
		return value.TenantID
	case domain.Organization:
		return value.TenantID
	case domain.HumanUser:
		return value.TenantID
	case domain.Collector:
		return value.TenantID
	case domain.BuildRun:
		return value.TenantID
	case domain.SSOProvider:
		return value.TenantID
	default:
		return ""
	}
}

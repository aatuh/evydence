package app

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func (l *Ledger) configureIdentityCommands() error {
	var discovery identityapp.OIDCDiscovery
	if l.oidc != nil {
		discovery = ledgerIdentityOIDCDiscovery{client: l.oidc}
	}
	service, err := identityapp.NewService(identityapp.Config{
		Reader: ledgerIdentityReader{ledger: l}, Transactions: ledgerIdentityTransactions{ledger: l},
		BootstrapTransactions: ledgerIdentityTransactions{ledger: l},
		Authorizer:            ledgerContextAuthorizer{ledger: l}, GrantPolicy: ledgerIdentityGrantPolicy{},
		Credentials: ledgerCredentialManager{ledger: l}, SessionCredentials: ledgerSessionCredentialManager{ledger: l},
		GrantTargets: ledgerIdentityGrantTargets{ledger: l}, SessionGrants: ledgerIdentitySessionGrants{},
		TrustMaterial: ledgerIdentityTrustMaterial{}, CanonicalHasher: ledgerIdentityCanonicalHasher{},
		OIDCDiscovery: discovery, CredentialVerifier: ledgerIdentityCredentialVerifier{}, VerificationPolicy: ledgerIdentityVerificationPolicy{},
		Clock: application.ClockFunc(l.now), IDs: application.IDGeneratorFunc(newID),
	})
	if err != nil {
		return err
	}
	l.identityCommands = service
	return nil
}

type ledgerIdentityGrantPolicy struct{}

func (ledgerIdentityGrantPolicy) AuthorizeScopes(actor identitydomain.Actor, scopes []string) error {
	return toIdentityContextError(requireGrantableScopes(actor, scopes))
}

type ledgerCredentialManager struct{ ledger *Ledger }

func (m ledgerCredentialManager) Generate() (identityapp.Credential, error) {
	secret := "evy_" + randomToken(32)
	return identityapp.Credential{Secret: secret, Prefix: secretPrefix(secret), Hash: m.ledger.hashSecret(secret)}, nil
}

func (m ledgerCredentialManager) Prefix(secret string) string { return secretPrefix(secret) }
func (m ledgerCredentialManager) Hash(secret string) string   { return m.ledger.hashSecret(secret) }
func (ledgerCredentialManager) Equal(stored, candidate string) bool {
	return secretHashEqual(stored, candidate)
}

type ledgerSessionCredentialManager struct{ ledger *Ledger }

func (m ledgerSessionCredentialManager) GenerateSession() (identityapp.Credential, error) {
	secret := "evysso_" + randomToken(32)
	return identityapp.Credential{Secret: secret, Prefix: secretPrefix(secret), Hash: m.ledger.hashSecret(secret)}, nil
}

type ledgerIdentityGrantTargets struct{ ledger *Ledger }

func (r ledgerIdentityGrantTargets) ValidateSubject(ctx context.Context, tenantID, subjectType, subjectID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return toIdentityContextError(r.ledger.ensureRoleSubjectLocked(tenantID, subjectType, subjectID))
}

func (r ledgerIdentityGrantTargets) ValidateResource(ctx context.Context, tenantID, resourceType, resourceID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return toIdentityContextError(r.ledger.ensureRoleResourceLocked(tenantID, resourceType, resourceID))
}

type ledgerIdentitySessionGrants struct{}

func (ledgerIdentitySessionGrants) GrantsForProviderGroups(provider identitydomain.SSOProvider, groups []string) []identitydomain.ResourceGrant {
	legacy := ssoProviderFromIdentityContext(provider)
	return cloneIdentityGrants(resourceGrantsForProviderGroups(legacy, groups))
}

type ledgerIdentityTrustMaterial struct{}

func (ledgerIdentityTrustMaterial) NormalizeJWKS(value map[string]any) (map[string]any, error) {
	result, err := normalizeJWKS(value)
	return result, toIdentityContextError(err)
}

func (ledgerIdentityTrustMaterial) NormalizeSAMLSigningCertificates(value []string) ([]string, error) {
	result, err := normalizeSAMLSigningCertificates(value)
	return result, toIdentityContextError(err)
}

type ledgerIdentityCanonicalHasher struct{}

func (ledgerIdentityCanonicalHasher) Hash(value any) (string, error) { return canonicalAnyHash(value) }

type ledgerIdentityOIDCDiscovery struct{ client OIDCDiscoveryClient }

func (d ledgerIdentityOIDCDiscovery) FetchOIDCTrustMaterial(ctx context.Context, request identityapp.OIDCDiscoveryRequest) (identityapp.OIDCDiscoveryResult, error) {
	result, err := d.client.FetchOIDCTrustMaterial(ctx, OIDCDiscoveryRequest{TenantID: request.TenantID, ProviderID: request.ProviderID, Issuer: request.Issuer})
	if err != nil {
		return identityapp.OIDCDiscoveryResult{}, err
	}
	return identityapp.OIDCDiscoveryResult{Issuer: result.Issuer, JWKS: cloneMap(result.JWKS)}, nil
}

type ledgerIdentityCredentialVerifier struct{}

func (ledgerIdentityCredentialVerifier) Verify(_ context.Context, request identityapp.CredentialVerificationRequest) (identityapp.CredentialVerificationResult, error) {
	provider := ssoProviderFromIdentityContext(request.Provider)
	var checks []domain.VerifyCheck
	var groups []string
	var err error
	switch provider.Type {
	case "oidc":
		checks, err = verifyOIDCIDToken(provider, request.Subject, request.IDToken, request.Now)
		if err == nil {
			groups = oidcGroupsFromVerifiedToken(provider, request.IDToken)
		}
	case "saml":
		checks, err = verifySAMLAssertion(provider, request.Subject, request.SAMLAssertion, request.Now)
	default:
		return identityapp.CredentialVerificationResult{}, identityapp.ErrValidation
	}
	return identityapp.CredentialVerificationResult{Checks: verificationChecksToIdentityContext(checks), Groups: append([]string(nil), groups...)}, err
}

type ledgerIdentityVerificationPolicy struct{}

func (ledgerIdentityVerificationPolicy) Assess(record identitydomain.ProviderVerification, provider identitydomain.SSOProvider, tokenSupplied bool) identitydomain.ProviderVerification {
	legacy := providerVerificationFromIdentityContext(record)
	reassessProviderVerification(&legacy, ssoProviderFromIdentityContext(provider), tokenSupplied)
	return providerVerificationToIdentityContext(legacy)
}

func (ledgerIdentityVerificationPolicy) ReturnsFailure(result string) bool {
	return verificationReturnsFailure(result)
}

type ledgerIdentityReader struct{ ledger *Ledger }

func (r ledgerIdentityReader) HasTenants(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return len(r.ledger.tenants) > 0, nil
}

func (r ledgerIdentityReader) ListAPIKeys(ctx context.Context, tenantID string) ([]identitydomain.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	result := make([]identitydomain.APIKey, 0)
	for _, key := range r.ledger.apiKeys {
		if key.TenantID == tenantID {
			result = append(result, apiKeyToIdentityContext(key))
		}
	}
	return result, nil
}

func (r ledgerIdentityReader) APIKeysByPrefix(ctx context.Context, prefix string) ([]identitydomain.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	result := make([]identitydomain.APIKey, 0)
	for _, key := range r.ledger.apiKeys {
		if key.Prefix == prefix {
			result = append(result, apiKeyToIdentityContext(key))
		}
	}
	return result, nil
}

func (r ledgerIdentityReader) SessionsByPrefix(ctx context.Context, prefix string) ([]identitydomain.SSOSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	result := make([]identitydomain.SSOSession, 0)
	for _, session := range r.ledger.ssoSessions {
		if session.Prefix == prefix {
			result = append(result, ssoSessionToIdentityContext(session))
		}
	}
	return result, nil
}

func (r ledgerIdentityReader) CollectorByAPIKey(ctx context.Context, tenantID, keyID string) (identityapp.CollectorBinding, bool, error) {
	if err := ctx.Err(); err != nil {
		return identityapp.CollectorBinding{}, false, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	for _, collector := range r.ledger.collectors {
		if collector.TenantID == tenantID && collector.APIKeyID == keyID {
			return identityapp.CollectorBinding{ID: collector.ID, TenantID: collector.TenantID, APIKeyID: collector.APIKeyID}, true, nil
		}
	}
	return identityapp.CollectorBinding{}, false, nil
}

func (r ledgerIdentityReader) SessionIdentity(ctx context.Context, session identitydomain.SSOSession) (identityapp.SessionIdentity, error) {
	if err := ctx.Err(); err != nil {
		return identityapp.SessionIdentity{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	user, ok := r.ledger.users[session.UserID]
	if !ok || user.TenantID != session.TenantID {
		return identityapp.SessionIdentity{}, identityapp.ErrNotFound
	}
	legacySession := ssoSessionFromIdentityContext(session)
	grants := append(r.ledger.resourceGrantsForUserLocked(user.ID), r.ledger.resourceGrantsForSSOSessionLocked(legacySession)...)
	return identityapp.SessionIdentity{User: humanUserToIdentityContext(user), Grants: cloneIdentityGrants(grants)}, nil
}

func (r ledgerIdentityReader) OrganizationBySlug(ctx context.Context, tenantID, slug string) (identitydomain.Organization, bool, error) {
	if err := ctx.Err(); err != nil {
		return identitydomain.Organization{}, false, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	for _, organization := range r.ledger.organizations {
		if organization.TenantID == tenantID && organization.Slug == slug {
			return organizationToIdentityContext(organization), true, nil
		}
	}
	return identitydomain.Organization{}, false, nil
}

func (r ledgerIdentityReader) Organization(ctx context.Context, tenantID, id string) (identitydomain.Organization, error) {
	if err := ctx.Err(); err != nil {
		return identitydomain.Organization{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	organization, ok := r.ledger.organizations[id]
	if !ok || organization.TenantID != tenantID {
		return identitydomain.Organization{}, identityapp.ErrNotFound
	}
	return organizationToIdentityContext(organization), nil
}

func (r ledgerIdentityReader) UserByEmail(ctx context.Context, tenantID, email string) (identitydomain.HumanUser, bool, error) {
	if err := ctx.Err(); err != nil {
		return identitydomain.HumanUser{}, false, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	for _, user := range r.ledger.users {
		if user.TenantID == tenantID && user.Email == email {
			return humanUserToIdentityContext(user), true, nil
		}
	}
	return identitydomain.HumanUser{}, false, nil
}

func (r ledgerIdentityReader) User(ctx context.Context, tenantID, id string) (identitydomain.HumanUser, error) {
	if err := ctx.Err(); err != nil {
		return identitydomain.HumanUser{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	user, ok := r.ledger.users[id]
	if !ok || user.TenantID != tenantID {
		return identitydomain.HumanUser{}, identityapp.ErrNotFound
	}
	return humanUserToIdentityContext(user), nil
}

func (r ledgerIdentityReader) ListRoleBindings(ctx context.Context, tenantID string) ([]identitydomain.RoleBinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	result := make([]identitydomain.RoleBinding, 0)
	for _, binding := range r.ledger.roleBindings {
		if binding.TenantID == tenantID {
			result = append(result, roleBindingToIdentityContext(binding))
		}
	}
	return result, nil
}

func (r ledgerIdentityReader) SSOProvider(ctx context.Context, tenantID, id string) (identitydomain.SSOProvider, error) {
	if err := ctx.Err(); err != nil {
		return identitydomain.SSOProvider{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	provider, ok := r.ledger.ssoProviders[id]
	if !ok || provider.TenantID != tenantID {
		return identitydomain.SSOProvider{}, identityapp.ErrNotFound
	}
	return ssoProviderToIdentityContext(provider), nil
}

func (r ledgerIdentityReader) SSOProviderByID(ctx context.Context, id string) (identitydomain.SSOProvider, error) {
	if err := ctx.Err(); err != nil {
		return identitydomain.SSOProvider{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	provider, ok := r.ledger.ssoProviders[id]
	if !ok {
		return identitydomain.SSOProvider{}, identityapp.ErrNotFound
	}
	return ssoProviderToIdentityContext(provider), nil
}

func (r ledgerIdentityReader) IdentityLink(ctx context.Context, tenantID, providerID, subject string) (identitydomain.UserIdentityLink, bool, error) {
	if err := ctx.Err(); err != nil {
		return identitydomain.UserIdentityLink{}, false, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	for _, link := range r.ledger.identityLinks {
		if link.TenantID == tenantID && link.ProviderID == providerID && link.Subject == subject {
			return userIdentityLinkToIdentityContext(link), true, nil
		}
	}
	return identitydomain.UserIdentityLink{}, false, nil
}

func (r ledgerIdentityReader) SSOSession(ctx context.Context, tenantID, id string) (identitydomain.SSOSession, error) {
	if err := ctx.Err(); err != nil {
		return identitydomain.SSOSession{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	session, ok := r.ledger.ssoSessions[id]
	if !ok || session.TenantID != tenantID {
		return identitydomain.SSOSession{}, identityapp.ErrNotFound
	}
	return ssoSessionToIdentityContext(session), nil
}

func (r ledgerIdentityReader) UserGrants(ctx context.Context, tenantID, userID string) ([]identitydomain.ResourceGrant, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	user, ok := r.ledger.users[userID]
	if !ok || user.TenantID != tenantID {
		return nil, identityapp.ErrNotFound
	}
	return cloneIdentityGrants(r.ledger.resourceGrantsForUserLocked(userID)), nil
}

type ledgerIdentityTransactions struct{ ledger *Ledger }

func (r ledgerIdentityTransactions) Execute(ctx context.Context, command identityapp.TransactionCommand) error {
	return r.execute(ctx, func(ctx context.Context, tx *ledgerIdentityTransaction) error {
		return command(ctx, tx)
	})
}

func (r ledgerIdentityTransactions) ExecuteBootstrap(ctx context.Context, command identityapp.BootstrapTransactionCommand) error {
	return r.execute(ctx, func(ctx context.Context, tx *ledgerIdentityTransaction) error {
		return command(ctx, tx)
	})
}

func (r ledgerIdentityTransactions) execute(ctx context.Context, command func(context.Context, *ledgerIdentityTransaction) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l := r.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	tx := newLedgerIdentityTransaction(l)
	if l.unitOfWork != nil {
		err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repositories Repositories) error {
			tx.repositories = &repositories
			return command(ctx, tx)
		})
		if err != nil {
			return toIdentityContextError(err)
		}
		tx.publish()
		return nil
	}
	if err := command(ctx, tx); err != nil {
		return err
	}
	return tx.commitCompatibility(ctx)
}

type ledgerIdentityTransaction struct {
	ledger                *Ledger
	repositories          *Repositories
	tenants               map[string]domain.Tenant
	apiKeys               map[string]domain.APIKey
	signingKeys           map[string]domain.SigningKey
	collectors            map[string]domain.Collector
	organizations         map[string]domain.Organization
	users                 map[string]domain.HumanUser
	roleBindings          map[string]domain.RoleBinding
	ssoProviders          map[string]domain.SSOProvider
	identityLinks         map[string]domain.UserIdentityLink
	providerVerifications map[string]domain.ProviderVerification
	ssoSessions           map[string]domain.SSOSession
	audit                 []domain.AuditChainEntry
}

func newLedgerIdentityTransaction(ledger *Ledger) *ledgerIdentityTransaction {
	return &ledgerIdentityTransaction{
		ledger: ledger, tenants: map[string]domain.Tenant{}, apiKeys: map[string]domain.APIKey{},
		signingKeys: map[string]domain.SigningKey{}, collectors: map[string]domain.Collector{},
		organizations: map[string]domain.Organization{}, users: map[string]domain.HumanUser{},
		roleBindings: map[string]domain.RoleBinding{}, ssoProviders: map[string]domain.SSOProvider{},
		identityLinks: map[string]domain.UserIdentityLink{}, providerVerifications: map[string]domain.ProviderVerification{},
		ssoSessions: map[string]domain.SSOSession{},
	}
}

func (t *ledgerIdentityTransaction) Identity() identityapp.Repository { return t }
func (t *ledgerIdentityTransaction) Audit() application.AuditAppender { return t }

func (t *ledgerIdentityTransaction) InsertTenant(ctx context.Context, tenant identitydomain.Tenant) error {
	legacy := tenantFromIdentityContext(tenant)
	if _, exists := t.ledger.tenants[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	if _, exists := t.tenants[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Identity.InsertTenant(ctx, legacy); err != nil {
			return toIdentityContextError(err)
		}
	}
	t.tenants[legacy.ID] = legacy
	return nil
}

// InsertInitialSigningKey is one of EVY-903's three temporary compatibility
// exceptions to the one-owner transaction rule. BootstrapTenant calls it
// through the narrower BootstrapTransaction capability so tenant, credential,
// key, and audit remain atomic. EVY-904 removes this bridge when
// verification/signing owns bootstrap.
func (t *ledgerIdentityTransaction) InsertInitialSigningKey(ctx context.Context, tenant identitydomain.Tenant) error {
	legacyTenant := tenantFromIdentityContext(tenant)
	pending, ok := t.tenants[legacyTenant.ID]
	if !ok || !reflect.DeepEqual(pending, legacyTenant) {
		return identityapp.ErrConflict
	}
	key, err := t.ledger.newSigningKey(legacyTenant.ID)
	if err != nil {
		return err
	}
	if t.repositories != nil {
		if err := t.repositories.Signatures.InsertSigningKey(ctx, key); err != nil {
			return toIdentityContextError(err)
		}
	}
	t.signingKeys[key.ID] = key
	return nil
}

func (t *ledgerIdentityTransaction) InsertAPIKey(ctx context.Context, key identitydomain.APIKey) error {
	legacy := apiKeyFromIdentityContext(key)
	if t.repositories != nil {
		if err := t.repositories.Identity.InsertAPIKey(ctx, legacy); err != nil {
			return toIdentityContextError(err)
		}
	}
	t.apiKeys[legacy.ID] = legacy
	return nil
}

func (t *ledgerIdentityTransaction) UpdateAPIKeyActivity(ctx context.Context, key identitydomain.APIKey, activity identityapp.CollectorActivity) error {
	legacyKey := apiKeyFromIdentityContext(key)
	stored, ok := t.ledger.apiKeys[legacyKey.ID]
	if !ok || legacyKey.LastUsedAt == nil || stored.TenantID != legacyKey.TenantID || stored.Prefix != legacyKey.Prefix || !secretHashEqual(stored.Hash, legacyKey.Hash) || stored.RevokedAt != nil || (stored.ExpiresAt != nil && !stored.ExpiresAt.After(legacyKey.LastUsedAt.UTC())) {
		return identityapp.ErrUnauthorized
	}
	lastUsedAt := legacyKey.LastUsedAt.UTC()
	if stored.LastUsedAt != nil && stored.LastUsedAt.UTC().After(lastUsedAt) {
		lastUsedAt = stored.LastUsedAt.UTC()
	}
	legacyKey = stored
	legacyKey.LastUsedAt = &lastUsedAt
	var collector domain.Collector
	if activity.ID != "" {
		if activity.TenantID != legacyKey.TenantID || activity.LastSeenAt.IsZero() {
			return identityapp.ErrUnauthorized
		}
		collector, ok = t.ledger.collectors[activity.ID]
		if !ok || collector.TenantID != activity.TenantID || collector.APIKeyID != legacyKey.ID {
			return identityapp.ErrUnauthorized
		}
		lastSeenAt := activity.LastSeenAt.UTC()
		if collector.LastSeenAt != nil && collector.LastSeenAt.UTC().After(lastSeenAt) {
			lastSeenAt = collector.LastSeenAt.UTC()
		}
		collector.LastSeenAt = &lastSeenAt
	}
	if t.repositories != nil {
		if err := t.repositories.Identity.UpdateAPIKeyLastUsed(ctx, legacyKey); err != nil {
			return toIdentityContextError(err)
		}
		if activity.ID != "" {
			if err := t.repositories.Identity.UpdateCollectorLastSeen(ctx, collector); err != nil {
				return toIdentityContextError(err)
			}
		}
	}
	t.apiKeys[legacyKey.ID] = legacyKey
	if activity.ID != "" {
		t.collectors[collector.ID] = collector
	}
	return nil
}

func (t *ledgerIdentityTransaction) ValidateActiveSession(ctx context.Context, session identitydomain.SSOSession, now time.Time) error {
	legacy := ssoSessionFromIdentityContext(session)
	stored, ok := t.ledger.ssoSessions[legacy.ID]
	if !ok || stored.TenantID != legacy.TenantID || stored.UserID != legacy.UserID || stored.ProviderID != legacy.ProviderID || stored.Prefix != legacy.Prefix || !secretHashEqual(stored.Hash, legacy.Hash) || stored.RevokedAt != nil || !stored.ExpiresAt.After(now) {
		return identityapp.ErrUnauthorized
	}
	user, ok := t.ledger.users[stored.UserID]
	if !ok || user.TenantID != stored.TenantID || user.Status != "active" {
		return identityapp.ErrUnauthorized
	}
	if t.repositories != nil {
		if err := t.repositories.Identity.ValidateActiveSSOSession(ctx, legacy, now); err != nil {
			return identityapp.ErrUnauthorized
		}
	}
	return nil
}

func (t *ledgerIdentityTransaction) InsertOrganization(ctx context.Context, organization identitydomain.Organization) error {
	legacy := organizationFromIdentityContext(organization)
	if _, exists := t.ledger.organizations[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	if _, exists := t.organizations[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	for _, existing := range t.ledger.organizations {
		if existing.TenantID == legacy.TenantID && existing.Slug == legacy.Slug {
			return identityapp.ErrConflict
		}
	}
	for _, existing := range t.organizations {
		if existing.TenantID == legacy.TenantID && existing.Slug == legacy.Slug {
			return identityapp.ErrConflict
		}
	}
	if t.repositories != nil {
		if err := t.repositories.Identity.InsertOrganization(ctx, legacy); err != nil {
			return toIdentityContextError(err)
		}
	}
	t.organizations[legacy.ID] = legacy
	return nil
}

func (t *ledgerIdentityTransaction) InsertHumanUser(ctx context.Context, user identitydomain.HumanUser) error {
	legacy := humanUserFromIdentityContext(user)
	if _, exists := t.ledger.users[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	if _, exists := t.users[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	if legacy.OrganizationID != "" {
		organization, ok := t.organizations[legacy.OrganizationID]
		if !ok {
			organization, ok = t.ledger.organizations[legacy.OrganizationID]
		}
		if !ok || organization.TenantID != legacy.TenantID {
			return identityapp.ErrNotFound
		}
	}
	for _, existing := range t.ledger.users {
		if existing.TenantID == legacy.TenantID && existing.Email == legacy.Email {
			return identityapp.ErrConflict
		}
	}
	for _, existing := range t.users {
		if existing.TenantID == legacy.TenantID && existing.Email == legacy.Email {
			return identityapp.ErrConflict
		}
	}
	if t.repositories != nil {
		if err := t.repositories.Identity.InsertHumanUser(ctx, legacy); err != nil {
			return toIdentityContextError(err)
		}
	}
	t.users[legacy.ID] = legacy
	return nil
}

func (t *ledgerIdentityTransaction) DeactivateHumanUser(ctx context.Context, user identitydomain.HumanUser) error {
	legacy := humanUserFromIdentityContext(user)
	stored, ok := t.users[legacy.ID]
	if !ok {
		stored, ok = t.ledger.users[legacy.ID]
	}
	if !ok || stored.TenantID != legacy.TenantID {
		return identityapp.ErrNotFound
	}
	if stored.Status != "active" || legacy.Status != "deactivated" || legacy.DeactivatedAt == nil {
		return identityapp.ErrConflict
	}
	if stored.Email != legacy.Email || stored.OrganizationID != legacy.OrganizationID {
		return identityapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Identity.DeactivateHumanUser(ctx, legacy); err != nil {
			return toIdentityContextError(err)
		}
	}
	t.users[legacy.ID] = legacy
	return nil
}

func (t *ledgerIdentityTransaction) InsertRoleBinding(ctx context.Context, binding identitydomain.RoleBinding) error {
	legacy := roleBindingFromIdentityContext(binding)
	if _, exists := t.ledger.roleBindings[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	if _, exists := t.roleBindings[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	if err := t.ledger.ensureRoleSubjectLocked(legacy.TenantID, legacy.SubjectType, legacy.SubjectID); err != nil {
		return toIdentityContextError(err)
	}
	if err := t.ledger.ensureRoleResourceLocked(legacy.TenantID, legacy.ResourceType, legacy.ResourceID); err != nil {
		return toIdentityContextError(err)
	}
	if t.repositories != nil {
		if err := t.repositories.Identity.InsertRoleBinding(ctx, legacy); err != nil {
			return toIdentityContextError(err)
		}
	}
	t.roleBindings[legacy.ID] = legacy
	return nil
}

func (t *ledgerIdentityTransaction) InsertSSOProvider(ctx context.Context, provider identitydomain.SSOProvider) error {
	legacy := ssoProviderFromIdentityContext(provider)
	if _, exists := t.ledger.ssoProviders[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	if _, exists := t.ssoProviders[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Identity.InsertSSOProvider(ctx, legacy); err != nil {
			return toIdentityContextError(err)
		}
	}
	t.ssoProviders[legacy.ID] = legacy
	return nil
}

func (t *ledgerIdentityTransaction) CompareAndSwapSSOProviderTrustMaterial(ctx context.Context, expected, provider identitydomain.SSOProvider) error {
	legacyExpected := ssoProviderFromIdentityContext(expected)
	legacy := ssoProviderFromIdentityContext(provider)
	stored, ok := t.ssoProviders[legacy.ID]
	if !ok {
		stored, ok = t.ledger.ssoProviders[legacy.ID]
	}
	if !ok || stored.TenantID != legacy.TenantID {
		return identityapp.ErrNotFound
	}
	if !sameSSOProviderTrustState(stored, legacyExpected) || legacyExpected.ID != legacy.ID || legacyExpected.TenantID != legacy.TenantID || legacyExpected.Type != legacy.Type || legacyExpected.Issuer != legacy.Issuer || legacyExpected.ClientID != legacy.ClientID || legacyExpected.Status != legacy.Status {
		return identityapp.ErrConflict
	}
	if legacy.TrustMaterialUpdatedAt == nil {
		return identityapp.ErrValidation
	}
	if t.repositories != nil {
		if err := t.repositories.Identity.CompareAndSwapSSOProviderTrustMaterial(ctx, legacyExpected, legacy); err != nil {
			return toIdentityContextError(err)
		}
	}
	t.ssoProviders[legacy.ID] = legacy
	return nil
}

func sameSSOProviderTrustState(left, right domain.SSOProvider) bool {
	return left.ID == right.ID &&
		left.TenantID == right.TenantID &&
		left.Type == right.Type &&
		left.Issuer == right.Issuer &&
		left.ClientID == right.ClientID &&
		left.Status == right.Status &&
		reflect.DeepEqual(left.JWKS, right.JWKS) &&
		reflect.DeepEqual(left.SAMLSigningCertificates, right.SAMLSigningCertificates) &&
		equalOptionalTime(left.TrustMaterialUpdatedAt, right.TrustMaterialUpdatedAt)
}

func equalOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func (t *ledgerIdentityTransaction) InsertUserIdentityLink(ctx context.Context, link identitydomain.UserIdentityLink) error {
	legacy := userIdentityLinkFromIdentityContext(link)
	if _, exists := t.ledger.identityLinks[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	if _, exists := t.identityLinks[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	user, ok := t.users[legacy.UserID]
	if !ok {
		user, ok = t.ledger.users[legacy.UserID]
	}
	if !ok || user.TenantID != legacy.TenantID || user.Email != legacy.Email {
		return identityapp.ErrNotFound
	}
	provider, ok := t.ssoProviders[legacy.ProviderID]
	if !ok {
		provider, ok = t.ledger.ssoProviders[legacy.ProviderID]
	}
	if !ok || provider.TenantID != legacy.TenantID {
		return identityapp.ErrNotFound
	}
	for _, existing := range t.ledger.identityLinks {
		if existing.TenantID == legacy.TenantID && existing.ProviderID == legacy.ProviderID && existing.Subject == legacy.Subject {
			return identityapp.ErrConflict
		}
	}
	for _, existing := range t.identityLinks {
		if existing.TenantID == legacy.TenantID && existing.ProviderID == legacy.ProviderID && existing.Subject == legacy.Subject {
			return identityapp.ErrConflict
		}
	}
	if t.repositories != nil {
		if err := t.repositories.Identity.InsertUserIdentityLink(ctx, legacy); err != nil {
			return toIdentityContextError(err)
		}
	}
	t.identityLinks[legacy.ID] = legacy
	return nil
}

func (t *ledgerIdentityTransaction) ValidateSSOExchangeState(ctx context.Context, snapshot identityapp.SSOExchangeSnapshot) error {
	if t.repositories != nil {
		if err := t.repositories.Identity.ValidateSSOExchangeState(ctx, SSOExchangeSnapshot{
			Provider:          ssoProviderFromIdentityContext(snapshot.Provider),
			Subject:           snapshot.Subject,
			IdentityLink:      userIdentityLinkFromIdentityContext(snapshot.IdentityLink),
			IdentityLinkFound: snapshot.IdentityLinkFound,
			User:              humanUserFromIdentityContext(snapshot.User),
			UserLoaded:        snapshot.UserLoaded,
			UserFound:         snapshot.UserFound,
			UserGrants:        identityGrantsFromContext(snapshot.UserGrants),
			UserGrantsLoaded:  snapshot.UserGrantsLoaded,
		}); err != nil {
			return toIdentityContextError(err)
		}
	}
	provider, ok := t.ledger.ssoProviders[snapshot.Provider.ID]
	if !ok || !reflect.DeepEqual(ssoProviderToIdentityContext(provider), snapshot.Provider) {
		return identityapp.ErrConflict
	}
	var currentLink domain.UserIdentityLink
	currentLinkFound := false
	for _, candidate := range t.ledger.identityLinks {
		if candidate.TenantID == snapshot.Provider.TenantID && candidate.ProviderID == snapshot.Provider.ID && candidate.Subject == snapshot.Subject {
			currentLink = candidate
			currentLinkFound = true
			break
		}
	}
	if currentLinkFound != snapshot.IdentityLinkFound {
		return identityapp.ErrConflict
	}
	if currentLinkFound && !reflect.DeepEqual(userIdentityLinkToIdentityContext(currentLink), snapshot.IdentityLink) {
		return identityapp.ErrConflict
	}
	if snapshot.UserLoaded {
		if !snapshot.IdentityLinkFound {
			return identityapp.ErrConflict
		}
		user, exists := t.ledger.users[snapshot.IdentityLink.UserID]
		if exists != snapshot.UserFound {
			return identityapp.ErrConflict
		}
		if snapshot.UserFound && (snapshot.User.ID != snapshot.IdentityLink.UserID || !reflect.DeepEqual(humanUserToIdentityContext(user), snapshot.User)) {
			return identityapp.ErrConflict
		}
	}
	if snapshot.UserGrantsLoaded {
		if !reflect.DeepEqual(identityGrantSet(t.ledger.resourceGrantsForUserLocked(snapshot.User.ID)), identityContextGrantSet(snapshot.UserGrants)) {
			return identityapp.ErrConflict
		}
	}
	return nil
}

func (t *ledgerIdentityTransaction) InsertProviderVerification(ctx context.Context, verification identitydomain.ProviderVerification) error {
	legacy := providerVerificationFromIdentityContext(verification)
	if _, exists := t.ledger.providerVerifications[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	if _, exists := t.providerVerifications[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	provider, ok := t.ssoProviders[legacy.ProviderID]
	if !ok {
		provider, ok = t.ledger.ssoProviders[legacy.ProviderID]
	}
	if !ok || provider.TenantID != legacy.TenantID || provider.Type != legacy.ProviderType {
		return identityapp.ErrNotFound
	}
	if t.repositories != nil {
		if err := t.repositories.Identity.InsertProviderVerification(ctx, legacy); err != nil {
			return toIdentityContextError(err)
		}
	}
	t.providerVerifications[legacy.ID] = legacy
	return nil
}

func (t *ledgerIdentityTransaction) InsertSSOSession(ctx context.Context, session identitydomain.SSOSession) error {
	legacy := ssoSessionFromIdentityContext(session)
	if _, exists := t.ledger.ssoSessions[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	if _, exists := t.ssoSessions[legacy.ID]; exists {
		return identityapp.ErrConflict
	}
	user, ok := t.users[legacy.UserID]
	if !ok {
		user, ok = t.ledger.users[legacy.UserID]
	}
	if !ok || user.TenantID != legacy.TenantID || user.Status != "active" {
		return identityapp.ErrNotFound
	}
	provider, ok := t.ssoProviders[legacy.ProviderID]
	if !ok {
		provider, ok = t.ledger.ssoProviders[legacy.ProviderID]
	}
	if !ok || provider.TenantID != legacy.TenantID {
		return identityapp.ErrNotFound
	}
	if t.repositories != nil {
		if err := t.repositories.Identity.InsertSSOSession(ctx, legacy); err != nil {
			return toIdentityContextError(err)
		}
	}
	t.ssoSessions[legacy.ID] = legacy
	return nil
}

func (t *ledgerIdentityTransaction) RevokeSSOSession(ctx context.Context, session identitydomain.SSOSession) error {
	legacy := ssoSessionFromIdentityContext(session)
	stored, ok := t.ssoSessions[legacy.ID]
	if !ok {
		stored, ok = t.ledger.ssoSessions[legacy.ID]
	}
	if !ok || stored.TenantID != legacy.TenantID {
		return identityapp.ErrNotFound
	}
	if stored.UserID != legacy.UserID || stored.ProviderID != legacy.ProviderID || stored.Prefix != legacy.Prefix || stored.Hash != legacy.Hash {
		return identityapp.ErrConflict
	}
	if stored.RevokedAt != nil || legacy.RevokedAt == nil {
		return identityapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Identity.RevokeSSOSession(ctx, legacy); err != nil {
			return toIdentityContextError(err)
		}
	}
	t.ssoSessions[legacy.ID] = legacy
	return nil
}

func (t *ledgerIdentityTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	entry := domain.AuditChainEntry{
		ID: event.ID, TenantID: event.TenantID, EntryType: event.EntryType, SubjectType: event.SubjectType,
		SubjectID: event.SubjectID, ActorType: event.ActorType, ActorID: event.ActorID, OccurredAt: event.OccurredAt,
		PayloadHash: event.PayloadHash, SignatureRef: event.SignatureRef, SchemaVersion: domain.AuditChainEntrySchemaVersion,
	}
	if t.repositories != nil {
		committed, err := t.repositories.Audit.Append(ctx, entry)
		if err != nil {
			return application.AuditReceipt{}, toIdentityContextError(err)
		}
		entry = committed
	} else if err := t.completeCompatibilityAudit(&entry); err != nil {
		return application.AuditReceipt{}, toIdentityContextError(err)
	}
	t.audit = append(t.audit, entry)
	return application.AuditReceipt{ID: entry.ID}, nil
}

func (t *ledgerIdentityTransaction) completeCompatibilityAudit(entry *domain.AuditChainEntry) error {
	entries := t.ledger.chain[entry.TenantID]
	for _, pending := range t.audit {
		if pending.TenantID == entry.TenantID {
			entries = append(entries, pending)
		}
	}
	entry.Sequence = int64(len(entries) + 1)
	if len(entries) > 0 {
		entry.PreviousEntryHash = entries[len(entries)-1].EntryHash
	}
	return RehashAuditChainEntry(entry)
}

func (t *ledgerIdentityTransaction) publish() {
	for id, tenant := range t.tenants {
		t.ledger.tenants[id] = tenant
	}
	for id, key := range t.apiKeys {
		t.ledger.apiKeys[id] = key
	}
	for id, key := range t.signingKeys {
		t.ledger.signingKeys[id] = key
	}
	for id, collector := range t.collectors {
		t.ledger.collectors[id] = collector
	}
	for id, organization := range t.organizations {
		t.ledger.organizations[id] = organization
	}
	for id, user := range t.users {
		t.ledger.users[id] = user
	}
	for id, binding := range t.roleBindings {
		t.ledger.roleBindings[id] = binding
	}
	for id, provider := range t.ssoProviders {
		t.ledger.ssoProviders[id] = provider
	}
	for id, link := range t.identityLinks {
		t.ledger.identityLinks[id] = link
	}
	for id, verification := range t.providerVerifications {
		t.ledger.providerVerifications[id] = verification
	}
	for id, session := range t.ssoSessions {
		t.ledger.ssoSessions[id] = session
	}
	for _, entry := range t.audit {
		t.ledger.publishCommittedAuditEntryLocked(entry)
	}
}

func (t *ledgerIdentityTransaction) commitCompatibility(ctx context.Context) error {
	tenants := cloneTenantMap(t.ledger.tenants)
	keys := cloneAPIKeyMap(t.ledger.apiKeys)
	signingKeys := cloneSigningKeyMap(t.ledger.signingKeys)
	collectors := cloneCollectorMap(t.ledger.collectors)
	organizations := cloneOrganizationMap(t.ledger.organizations)
	users := cloneHumanUserMap(t.ledger.users)
	bindings := cloneRoleBindingMap(t.ledger.roleBindings)
	providers := cloneSSOProviderMap(t.ledger.ssoProviders)
	links := cloneUserIdentityLinkMap(t.ledger.identityLinks)
	verifications := cloneProviderVerificationMap(t.ledger.providerVerifications)
	sessions := cloneSSOSessionMap(t.ledger.ssoSessions)
	chain := cloneAuditChainMap(t.ledger.chain)
	t.publish()
	persist := t.ledger.persistCriticalStateLocked
	if len(t.organizations) > 0 || len(t.users) > 0 || len(t.roleBindings) > 0 || len(t.ssoProviders) > 0 || len(t.identityLinks) > 0 {
		persist = t.ledger.persistLocked
	}
	if err := persist(ctx); err != nil {
		t.ledger.tenants = tenants
		t.ledger.apiKeys = keys
		t.ledger.signingKeys = signingKeys
		t.ledger.collectors = collectors
		t.ledger.organizations = organizations
		t.ledger.users = users
		t.ledger.roleBindings = bindings
		t.ledger.ssoProviders = providers
		t.ledger.identityLinks = links
		t.ledger.providerVerifications = verifications
		t.ledger.ssoSessions = sessions
		t.ledger.chain = chain
		return toIdentityContextError(err)
	}
	return nil
}

func tenantToIdentityContext(value domain.Tenant) identitydomain.Tenant {
	return identitydomain.Tenant{ID: value.ID, Name: value.Name, CreatedAt: value.CreatedAt}
}

func tenantFromIdentityContext(value identitydomain.Tenant) domain.Tenant {
	return domain.Tenant{ID: value.ID, Name: value.Name, CreatedAt: value.CreatedAt}
}

func apiKeyToIdentityContext(value domain.APIKey) identitydomain.APIKey {
	return identitydomain.APIKey{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Prefix: value.Prefix, Scopes: append([]string(nil), value.Scopes...),
		CreatedAt: value.CreatedAt, ExpiresAt: cloneTimePtr(value.ExpiresAt), RevokedAt: cloneTimePtr(value.RevokedAt),
		LastUsedAt: cloneTimePtr(value.LastUsedAt), Hash: value.Hash,
	}
}

func apiKeyFromIdentityContext(value identitydomain.APIKey) domain.APIKey {
	return domain.APIKey{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Prefix: value.Prefix, Scopes: append([]string(nil), value.Scopes...),
		CreatedAt: value.CreatedAt, ExpiresAt: cloneTimePtr(value.ExpiresAt), RevokedAt: cloneTimePtr(value.RevokedAt),
		LastUsedAt: cloneTimePtr(value.LastUsedAt), Hash: value.Hash,
	}
}

func organizationToIdentityContext(value domain.Organization) identitydomain.Organization {
	return identitydomain.Organization{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Slug: value.Slug,
		Status: value.Status, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func organizationFromIdentityContext(value identitydomain.Organization) domain.Organization {
	return domain.Organization{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Slug: value.Slug,
		Status: value.Status, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func humanUserFromIdentityContext(value identitydomain.HumanUser) domain.HumanUser {
	return domain.HumanUser{
		ID: value.ID, TenantID: value.TenantID, OrganizationID: value.OrganizationID, Email: value.Email,
		DisplayName: value.DisplayName, Status: value.Status, DeactivatedAt: cloneTimePtr(value.DeactivatedAt),
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func roleBindingToIdentityContext(value domain.RoleBinding) identitydomain.RoleBinding {
	return identitydomain.RoleBinding{
		ID: value.ID, TenantID: value.TenantID, SubjectType: value.SubjectType, SubjectID: value.SubjectID,
		Role: value.Role, ResourceType: value.ResourceType, ResourceID: value.ResourceID,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func roleBindingFromIdentityContext(value identitydomain.RoleBinding) domain.RoleBinding {
	return domain.RoleBinding{
		ID: value.ID, TenantID: value.TenantID, SubjectType: value.SubjectType, SubjectID: value.SubjectID,
		Role: value.Role, ResourceType: value.ResourceType, ResourceID: value.ResourceID,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func ssoProviderToIdentityContext(value domain.SSOProvider) identitydomain.SSOProvider {
	return identitydomain.SSOProvider{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Type: value.Type, Issuer: value.Issuer,
		ClientID: value.ClientID, GroupsClaim: value.GroupsClaim, RoleMapping: cloneStringMap(value.RoleMapping),
		JWKS: cloneIdentityAnyMap(value.JWKS), SAMLSigningCertificates: append([]string(nil), value.SAMLSigningCertificates...),
		TrustMaterialUpdatedAt: cloneTimePtr(value.TrustMaterialUpdatedAt), Status: value.Status,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func ssoProviderFromIdentityContext(value identitydomain.SSOProvider) domain.SSOProvider {
	return domain.SSOProvider{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Type: value.Type, Issuer: value.Issuer,
		ClientID: value.ClientID, GroupsClaim: value.GroupsClaim, RoleMapping: cloneStringMap(value.RoleMapping),
		JWKS: cloneIdentityAnyMap(value.JWKS), SAMLSigningCertificates: append([]string(nil), value.SAMLSigningCertificates...),
		TrustMaterialUpdatedAt: cloneTimePtr(value.TrustMaterialUpdatedAt), Status: value.Status,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func userIdentityLinkToIdentityContext(value domain.UserIdentityLink) identitydomain.UserIdentityLink {
	return identitydomain.UserIdentityLink{
		ID: value.ID, TenantID: value.TenantID, UserID: value.UserID, ProviderID: value.ProviderID,
		Subject: value.Subject, Email: value.Email, Verified: value.Verified,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func userIdentityLinkFromIdentityContext(value identitydomain.UserIdentityLink) domain.UserIdentityLink {
	return domain.UserIdentityLink{
		ID: value.ID, TenantID: value.TenantID, UserID: value.UserID, ProviderID: value.ProviderID,
		Subject: value.Subject, Email: value.Email, Verified: value.Verified,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func verificationChecksToIdentityContext(values []domain.VerifyCheck) []identitydomain.VerificationCheck {
	result := make([]identitydomain.VerificationCheck, 0, len(values))
	for _, value := range values {
		result = append(result, identitydomain.VerificationCheck{Name: value.Name, Result: value.Result, Detail: value.Detail})
	}
	return result
}

func verificationChecksFromIdentityContext(values []identitydomain.VerificationCheck) []domain.VerifyCheck {
	result := make([]domain.VerifyCheck, 0, len(values))
	for _, value := range values {
		result = append(result, domain.VerifyCheck{Name: value.Name, Result: value.Result, Detail: value.Detail})
	}
	return result
}

func providerVerificationToIdentityContext(value domain.ProviderVerification) identitydomain.ProviderVerification {
	return identitydomain.ProviderVerification{
		ID: value.ID, TenantID: value.TenantID, ProviderType: value.ProviderType, ProviderID: value.ProviderID,
		Subject: value.Subject, Result: value.Result, Checks: verificationChecksToIdentityContext(value.Checks),
		Profile: identitydomain.VerificationProfileSnapshot{
			ID: value.Profile.ID, Version: value.Profile.Version,
			RequiredChecks: append([]string(nil), value.Profile.RequiredChecks...),
			TrustMaterial:  append([]string(nil), value.Profile.TrustMaterial...), IdentityPolicy: value.Profile.IdentityPolicy,
			TransparencyProof: value.Profile.TransparencyProof, PayloadScope: value.Profile.PayloadScope,
			PayloadDigest: value.Profile.PayloadDigest, Limitations: append([]string(nil), value.Profile.Limitations...),
		},
		Limitations: append([]string(nil), value.Limitations...), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func providerVerificationFromIdentityContext(value identitydomain.ProviderVerification) domain.ProviderVerification {
	return domain.ProviderVerification{
		ID: value.ID, TenantID: value.TenantID, ProviderType: value.ProviderType, ProviderID: value.ProviderID,
		Subject: value.Subject, Result: value.Result, Checks: verificationChecksFromIdentityContext(value.Checks),
		Profile: domain.VerificationProfile{
			ID: value.Profile.ID, Version: value.Profile.Version,
			RequiredChecks: append([]string(nil), value.Profile.RequiredChecks...),
			TrustMaterial:  append([]string(nil), value.Profile.TrustMaterial...), IdentityPolicy: value.Profile.IdentityPolicy,
			TransparencyProof: value.Profile.TransparencyProof, PayloadScope: value.Profile.PayloadScope,
			PayloadDigest: value.Profile.PayloadDigest, Limitations: append([]string(nil), value.Profile.Limitations...),
		},
		Limitations: append([]string(nil), value.Limitations...), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func ssoSessionToIdentityContext(value domain.SSOSession) identitydomain.SSOSession {
	return identitydomain.SSOSession{
		ID: value.ID, TenantID: value.TenantID, UserID: value.UserID, ProviderID: value.ProviderID, Prefix: value.Prefix,
		Groups: append([]string(nil), value.Groups...), ExpiresAt: value.ExpiresAt, RevokedAt: cloneTimePtr(value.RevokedAt),
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt, Hash: value.Hash,
	}
}

func ssoSessionFromIdentityContext(value identitydomain.SSOSession) domain.SSOSession {
	return domain.SSOSession{
		ID: value.ID, TenantID: value.TenantID, UserID: value.UserID, ProviderID: value.ProviderID, Prefix: value.Prefix,
		Groups: append([]string(nil), value.Groups...), ExpiresAt: value.ExpiresAt, RevokedAt: cloneTimePtr(value.RevokedAt),
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt, Hash: value.Hash,
	}
}

func humanUserToIdentityContext(value domain.HumanUser) identitydomain.HumanUser {
	return identitydomain.HumanUser{
		ID: value.ID, TenantID: value.TenantID, OrganizationID: value.OrganizationID, Email: value.Email, DisplayName: value.DisplayName,
		Status: value.Status, DeactivatedAt: cloneTimePtr(value.DeactivatedAt), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func cloneIdentityGrants(values []domain.ResourceGrant) []identitydomain.ResourceGrant {
	result := make([]identitydomain.ResourceGrant, 0, len(values))
	for _, value := range values {
		result = append(result, identitydomain.ResourceGrant{Role: value.Role, ResourceType: value.ResourceType, ResourceID: value.ResourceID, Scopes: append([]string(nil), value.Scopes...)})
	}
	return result
}

func identityGrantsFromContext(values []identitydomain.ResourceGrant) []domain.ResourceGrant {
	result := make([]domain.ResourceGrant, 0, len(values))
	for _, value := range values {
		result = append(result, domain.ResourceGrant{
			Role: value.Role, ResourceType: value.ResourceType, ResourceID: value.ResourceID,
			Scopes: append([]string(nil), value.Scopes...),
		})
	}
	return result
}

func toIdentityContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrValidation):
		return identityapp.ErrValidation
	case errors.Is(err, ErrUnauthorized):
		return identityapp.ErrUnauthorized
	case errors.Is(err, ErrForbidden):
		return identityapp.ErrForbidden
	case errors.Is(err, ErrNotFound):
		return identityapp.ErrNotFound
	case errors.Is(err, ErrConflict):
		return identityapp.ErrConflict
	case errors.Is(err, ErrVerificationFailed):
		return identityapp.ErrVerificationFailed
	default:
		return err
	}
}

func fromIdentityContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, identityapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, identityapp.ErrUnauthorized):
		return ErrUnauthorized
	case errors.Is(err, identityapp.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, identityapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, identityapp.ErrConflict):
		return ErrConflict
	case errors.Is(err, identityapp.ErrVerificationFailed):
		return ErrVerificationFailed
	default:
		return err
	}
}

func cloneAPIKeyMap(values map[string]domain.APIKey) map[string]domain.APIKey {
	result := make(map[string]domain.APIKey, len(values))
	for key, value := range values {
		result[key] = apiKeyFromIdentityContext(apiKeyToIdentityContext(value))
	}
	return result
}

func cloneTenantMap(values map[string]domain.Tenant) map[string]domain.Tenant {
	result := make(map[string]domain.Tenant, len(values))
	for key, value := range values {
		result[key] = tenantFromIdentityContext(tenantToIdentityContext(value))
	}
	return result
}

func cloneSigningKeyMap(values map[string]domain.SigningKey) map[string]domain.SigningKey {
	result := make(map[string]domain.SigningKey, len(values))
	for id, value := range values {
		value.Private = append([]byte(nil), value.Private...)
		value.ValidUntil = cloneTimePtr(value.ValidUntil)
		value.RevokedAt = cloneTimePtr(value.RevokedAt)
		value.CompromisedAt = cloneTimePtr(value.CompromisedAt)
		result[id] = value
	}
	return result
}

func cloneCollectorMap(values map[string]domain.Collector) map[string]domain.Collector {
	result := make(map[string]domain.Collector, len(values))
	for key, value := range values {
		value.AllowedScopes = append([]string(nil), value.AllowedScopes...)
		value.LastSeenAt = cloneTimePtr(value.LastSeenAt)
		result[key] = value
	}
	return result
}

func cloneOrganizationMap(values map[string]domain.Organization) map[string]domain.Organization {
	result := make(map[string]domain.Organization, len(values))
	for key, value := range values {
		result[key] = organizationFromIdentityContext(organizationToIdentityContext(value))
	}
	return result
}

func cloneHumanUserMap(values map[string]domain.HumanUser) map[string]domain.HumanUser {
	result := make(map[string]domain.HumanUser, len(values))
	for key, value := range values {
		result[key] = humanUserFromIdentityContext(humanUserToIdentityContext(value))
	}
	return result
}

func cloneRoleBindingMap(values map[string]domain.RoleBinding) map[string]domain.RoleBinding {
	result := make(map[string]domain.RoleBinding, len(values))
	for key, value := range values {
		result[key] = roleBindingFromIdentityContext(roleBindingToIdentityContext(value))
	}
	return result
}

func cloneSSOProviderMap(values map[string]domain.SSOProvider) map[string]domain.SSOProvider {
	result := make(map[string]domain.SSOProvider, len(values))
	for key, value := range values {
		result[key] = ssoProviderFromIdentityContext(ssoProviderToIdentityContext(value))
	}
	return result
}

func cloneUserIdentityLinkMap(values map[string]domain.UserIdentityLink) map[string]domain.UserIdentityLink {
	result := make(map[string]domain.UserIdentityLink, len(values))
	for key, value := range values {
		result[key] = userIdentityLinkFromIdentityContext(userIdentityLinkToIdentityContext(value))
	}
	return result
}

func cloneProviderVerificationMap(values map[string]domain.ProviderVerification) map[string]domain.ProviderVerification {
	result := make(map[string]domain.ProviderVerification, len(values))
	for key, value := range values {
		result[key] = providerVerificationFromIdentityContext(providerVerificationToIdentityContext(value))
	}
	return result
}

func cloneSSOSessionMap(values map[string]domain.SSOSession) map[string]domain.SSOSession {
	result := make(map[string]domain.SSOSession, len(values))
	for key, value := range values {
		result[key] = ssoSessionFromIdentityContext(ssoSessionToIdentityContext(value))
	}
	return result
}

func cloneIdentityAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]any, len(values))
	for key, value := range values {
		result[key] = cloneIdentityAny(value)
	}
	return result
}

func cloneIdentityAny(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneIdentityAnyMap(typed)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = cloneIdentityAny(item)
		}
		return result
	case []string:
		return append([]string(nil), typed...)
	default:
		return typed
	}
}

func identityGrantSet(values []domain.ResourceGrant) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[identityGrantKey(value.Role, value.ResourceType, value.ResourceID, value.Scopes)] = struct{}{}
	}
	return result
}

func identityContextGrantSet(values []identitydomain.ResourceGrant) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[identityGrantKey(value.Role, value.ResourceType, value.ResourceID, value.Scopes)] = struct{}{}
	}
	return result
}

func identityGrantKey(role, resourceType, resourceID string, scopes []string) string {
	sortedScopes := append([]string(nil), scopes...)
	sort.Strings(sortedScopes)
	return strings.Join([]string{role, resourceType, resourceID, strings.Join(sortedScopes, "\x00")}, "\x01")
}

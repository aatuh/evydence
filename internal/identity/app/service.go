// Package app owns identity credential command and authentication orchestration.
package app

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const (
	ScopeAdmin         = "admin"
	ScopeIdentityAdmin = "identity:admin"
)

var (
	ErrValidation         = errors.New("validation failed")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = application.ErrForbidden
	ErrNotFound           = errors.New("not found")
	ErrConflict           = errors.New("conflict")
	ErrVerificationFailed = errors.New("verification failed")
)

type Credential struct {
	Secret string
	Prefix string
	Hash   string
}

type CredentialManager interface {
	Generate() (Credential, error)
	Prefix(string) string
	Hash(string) string
	Equal(string, string) bool
}

// SessionCredentialManager issues an SSO-session credential with the
// session-specific public prefix. Hashing and comparison remain on
// CredentialManager so authentication uses one secret-verification boundary.
type SessionCredentialManager interface {
	GenerateSession() (Credential, error)
}

type GrantPolicy interface {
	AuthorizeScopes(identitydomain.Actor, []string) error
}

type CollectorBinding struct {
	ID       string
	TenantID string
	APIKeyID string
}

type CollectorActivity struct {
	ID         string
	TenantID   string
	LastSeenAt time.Time
}

type SessionIdentity struct {
	User   identitydomain.HumanUser
	Grants []identitydomain.ResourceGrant
}

type Reader interface {
	HasTenants(context.Context) (bool, error)
	ListAPIKeys(context.Context, string) ([]identitydomain.APIKey, error)
	APIKeysByPrefix(context.Context, string) ([]identitydomain.APIKey, error)
	SessionsByPrefix(context.Context, string) ([]identitydomain.SSOSession, error)
	CollectorByAPIKey(context.Context, string, string) (CollectorBinding, bool, error)
	SessionIdentity(context.Context, identitydomain.SSOSession) (SessionIdentity, error)
	OrganizationBySlug(context.Context, string, string) (identitydomain.Organization, bool, error)
	Organization(context.Context, string, string) (identitydomain.Organization, error)
	UserByEmail(context.Context, string, string) (identitydomain.HumanUser, bool, error)
	User(context.Context, string, string) (identitydomain.HumanUser, error)
	ListRoleBindings(context.Context, string) ([]identitydomain.RoleBinding, error)
	SSOProvider(context.Context, string, string) (identitydomain.SSOProvider, error)
	SSOProviderByID(context.Context, string) (identitydomain.SSOProvider, error)
	IdentityLink(context.Context, string, string, string) (identitydomain.UserIdentityLink, bool, error)
	SSOSession(context.Context, string, string) (identitydomain.SSOSession, error)
	UserGrants(context.Context, string, string) ([]identitydomain.ResourceGrant, error)
}

type Repository interface {
	InsertTenant(context.Context, identitydomain.Tenant) error
	InsertAPIKey(context.Context, identitydomain.APIKey) error
	UpdateAPIKeyActivity(context.Context, identitydomain.APIKey, CollectorActivity) error
	ValidateActiveSession(context.Context, identitydomain.SSOSession, time.Time) error
	InsertOrganization(context.Context, identitydomain.Organization) error
	InsertHumanUser(context.Context, identitydomain.HumanUser) error
	DeactivateHumanUser(context.Context, identitydomain.HumanUser) error
	InsertRoleBinding(context.Context, identitydomain.RoleBinding) error
	InsertSSOProvider(context.Context, identitydomain.SSOProvider) error
	CompareAndSwapSSOProviderTrustMaterial(context.Context, identitydomain.SSOProvider, identitydomain.SSOProvider) error
	InsertUserIdentityLink(context.Context, identitydomain.UserIdentityLink) error
	ValidateSSOExchangeState(context.Context, SSOExchangeSnapshot) error
	InsertProviderVerification(context.Context, identitydomain.ProviderVerification) error
	InsertSSOSession(context.Context, identitydomain.SSOSession) error
	RevokeSSOSession(context.Context, identitydomain.SSOSession) error
}

type Transaction interface {
	Identity() Repository
	Audit() application.AuditAppender
}

type TransactionCommand func(context.Context, Transaction) error

type TransactionRunner interface {
	Execute(context.Context, TransactionCommand) error
}

// BootstrapTransaction is the temporary composition compatibility boundary
// for creating the first verification/signing key in the same durable unit of
// work as a tenant and its first API credential. Only BootstrapTenant receives
// this capability; ordinary identity commands cannot write signing state. The
// boundary is removed when verification/signing bootstrap moves in EVY-904.
type BootstrapTransaction interface {
	Transaction
	InsertInitialSigningKey(context.Context, identitydomain.Tenant) error
}

type BootstrapTransactionCommand func(context.Context, BootstrapTransaction) error

type BootstrapTransactionRunner interface {
	ExecuteBootstrap(context.Context, BootstrapTransactionCommand) error
}

type Config struct {
	Reader                Reader
	Transactions          TransactionRunner
	BootstrapTransactions BootstrapTransactionRunner
	Authorizer            application.Authorizer
	GrantPolicy           GrantPolicy
	Credentials           CredentialManager
	SessionCredentials    SessionCredentialManager
	GrantTargets          GrantTargetResolver
	SessionGrants         SessionGrantPolicy
	TrustMaterial         TrustMaterialValidator
	CanonicalHasher       CanonicalHasher
	OIDCDiscovery         OIDCDiscovery
	CredentialVerifier    CredentialVerifier
	VerificationPolicy    ProviderVerificationPolicy
	Clock                 application.Clock
	IDs                   application.IDGenerator
}

type Service struct {
	reader                Reader
	transactions          TransactionRunner
	bootstrapTransactions BootstrapTransactionRunner
	authorizer            application.Authorizer
	grantPolicy           GrantPolicy
	credentials           CredentialManager
	sessionCredentials    SessionCredentialManager
	grantTargets          GrantTargetResolver
	sessionGrants         SessionGrantPolicy
	trustMaterial         TrustMaterialValidator
	canonicalHasher       CanonicalHasher
	oidcDiscovery         OIDCDiscovery
	credentialVerifier    CredentialVerifier
	verificationPolicy    ProviderVerificationPolicy
	clock                 application.Clock
	ids                   application.IDGenerator
}

func NewService(config Config) (*Service, error) {
	if config.Reader == nil || config.Transactions == nil || config.BootstrapTransactions == nil || config.Authorizer == nil || config.GrantPolicy == nil || config.Credentials == nil || config.SessionCredentials == nil || config.GrantTargets == nil || config.SessionGrants == nil || config.TrustMaterial == nil || config.CanonicalHasher == nil || config.CredentialVerifier == nil || config.VerificationPolicy == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &Service{
		reader: config.Reader, transactions: config.Transactions, bootstrapTransactions: config.BootstrapTransactions, authorizer: config.Authorizer,
		grantPolicy: config.GrantPolicy, credentials: config.Credentials, sessionCredentials: config.SessionCredentials,
		grantTargets: config.GrantTargets, sessionGrants: config.SessionGrants, trustMaterial: config.TrustMaterial,
		canonicalHasher: config.CanonicalHasher, oidcDiscovery: config.OIDCDiscovery,
		credentialVerifier: config.CredentialVerifier, verificationPolicy: config.VerificationPolicy,
		clock: config.Clock, ids: config.IDs,
	}, nil
}

func (s *Service) HasTenants(ctx context.Context) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	return s.reader.HasTenants(ctx)
}

type BootstrapTenantInput struct {
	TenantName string
	APIKeyName string
	Scopes     []string
}

// BootstrapTenant owns validation and all identity writes for first-tenant
// creation. Its runner preserves the legacy all-or-nothing bootstrap contract
// while EVY-904 moves initial signing-key creation to its owning context.
func (s *Service) BootstrapTenant(ctx context.Context, input BootstrapTenantInput) (identitydomain.Tenant, identitydomain.APIKey, string, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.Tenant{}, identitydomain.APIKey{}, "", err
	}
	input.TenantName = strings.TrimSpace(input.TenantName)
	input.APIKeyName = strings.TrimSpace(input.APIKeyName)
	if input.TenantName == "" || input.APIKeyName == "" {
		return identitydomain.Tenant{}, identitydomain.APIKey{}, "", ErrValidation
	}
	if len(input.Scopes) == 0 {
		input.Scopes = []string{"*"}
	}
	input.Scopes = sortedStrings(input.Scopes)
	credential, err := s.credentials.Generate()
	if err != nil || strings.TrimSpace(credential.Secret) == "" || strings.TrimSpace(credential.Prefix) == "" || strings.TrimSpace(credential.Hash) == "" {
		if err != nil {
			return identitydomain.Tenant{}, identitydomain.APIKey{}, "", err
		}
		return identitydomain.Tenant{}, identitydomain.APIKey{}, "", ErrValidation
	}
	now := s.clock.Now().UTC()
	tenant := identitydomain.Tenant{ID: s.ids.NewID("ten"), Name: input.TenantName, CreatedAt: now}
	key := identitydomain.APIKey{
		ID: s.ids.NewID("key"), TenantID: tenant.ID, Name: input.APIKeyName, Prefix: credential.Prefix,
		Scopes: append([]string(nil), input.Scopes...), CreatedAt: now, Hash: credential.Hash,
	}
	err = s.bootstrapTransactions.ExecuteBootstrap(ctx, func(ctx context.Context, tx BootstrapTransaction) error {
		if err := tx.Identity().InsertTenant(ctx, tenant); err != nil {
			return err
		}
		if err := tx.Identity().InsertAPIKey(ctx, key); err != nil {
			return err
		}
		if err := tx.InsertInitialSigningKey(ctx, tenant); err != nil {
			return err
		}
		_, err := tx.Audit().AppendAudit(ctx, application.AuditEvent{
			ID: s.ids.NewID("ace"), TenantID: tenant.ID, EntryType: "tenant.created", SubjectType: "tenant", SubjectID: tenant.ID,
			ActorType: "system", ActorID: "bootstrap", OccurredAt: now,
		})
		return err
	})
	if err != nil {
		return identitydomain.Tenant{}, identitydomain.APIKey{}, "", err
	}
	public := cloneAPIKey(key)
	public.Hash = ""
	return tenant, public, credential.Secret, nil
}

type CreateAPIKeyInput struct {
	Name      string
	Scopes    []string
	ExpiresAt *time.Time
}

func (s *Service) CreateAPIKey(ctx context.Context, actor identitydomain.Actor, input CreateAPIKeyInput) (identitydomain.APIKey, string, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.APIKey{}, "", err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeAdmin, ScopeOnly: true, TenantWide: true}); err != nil {
		return identitydomain.APIKey{}, "", err
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Scopes = sortedStrings(input.Scopes)
	if input.Name == "" || len(input.Scopes) == 0 {
		return identitydomain.APIKey{}, "", ErrValidation
	}
	if err := s.grantPolicy.AuthorizeScopes(actor, input.Scopes); err != nil {
		return identitydomain.APIKey{}, "", err
	}
	credential, err := s.credentials.Generate()
	if err != nil || strings.TrimSpace(credential.Secret) == "" || strings.TrimSpace(credential.Prefix) == "" || strings.TrimSpace(credential.Hash) == "" {
		if err != nil {
			return identitydomain.APIKey{}, "", err
		}
		return identitydomain.APIKey{}, "", ErrValidation
	}
	now := s.clock.Now().UTC()
	key := identitydomain.APIKey{
		ID: s.ids.NewID("key"), TenantID: actor.TenantID, Name: input.Name, Prefix: credential.Prefix,
		Scopes: append([]string(nil), input.Scopes...), CreatedAt: now, ExpiresAt: cloneTime(input.ExpiresAt), Hash: credential.Hash,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Identity().InsertAPIKey(ctx, key); err != nil {
			return err
		}
		_, err := tx.Audit().AppendAudit(ctx, application.AuditEvent{
			ID: s.ids.NewID("ace"), TenantID: actor.TenantID, EntryType: "api_key.created", SubjectType: "api_key", SubjectID: key.ID,
			ActorType: actorType(actor), ActorID: actorID(actor), OccurredAt: now,
		})
		return err
	})
	if err != nil {
		return identitydomain.APIKey{}, "", err
	}
	public := cloneAPIKey(key)
	public.Hash = ""
	return public, credential.Secret, nil
}

func (s *Service) ListAPIKeys(ctx context.Context, actor identitydomain.Actor) ([]identitydomain.APIKey, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeAdmin, ScopeOnly: true, TenantWide: true}); err != nil {
		return nil, err
	}
	keys, err := s.reader.ListAPIKeys(ctx, actor.TenantID)
	if err != nil {
		return nil, err
	}
	result := make([]identitydomain.APIKey, 0, len(keys))
	for _, key := range keys {
		if key.TenantID != actor.TenantID {
			continue
		}
		key = cloneAPIKey(key)
		key.Hash = ""
		result = append(result, key)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (s *Service) Authenticate(ctx context.Context, secret string) (identitydomain.Actor, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.Actor{}, err
	}
	secret = strings.TrimSpace(strings.TrimPrefix(secret, "Bearer "))
	if secret == "" {
		return identitydomain.Actor{}, ErrUnauthorized
	}
	prefix := s.credentials.Prefix(secret)
	hash := s.credentials.Hash(secret)
	keys, err := s.reader.APIKeysByPrefix(ctx, prefix)
	if err != nil {
		return identitydomain.Actor{}, authenticationError(ctx)
	}
	for _, key := range keys {
		if key.Prefix != prefix || !s.credentials.Equal(key.Hash, hash) || key.RevokedAt != nil {
			continue
		}
		now := s.clock.Now().UTC()
		if key.ExpiresAt != nil && !key.ExpiresAt.After(now) {
			return identitydomain.Actor{}, ErrUnauthorized
		}
		updated := cloneAPIKey(key)
		lastUsedAt := now
		if key.LastUsedAt != nil && key.LastUsedAt.UTC().After(lastUsedAt) {
			lastUsedAt = key.LastUsedAt.UTC()
		}
		updated.LastUsedAt = &lastUsedAt
		collector := CollectorActivity{}
		binding, found, err := s.reader.CollectorByAPIKey(ctx, key.TenantID, key.ID)
		if err != nil {
			return identitydomain.Actor{}, authenticationError(ctx)
		}
		if found {
			if binding.TenantID != key.TenantID || binding.APIKeyID != key.ID {
				return identitydomain.Actor{}, ErrUnauthorized
			}
			collector = CollectorActivity{ID: binding.ID, TenantID: binding.TenantID, LastSeenAt: now}
		}
		if err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
			return tx.Identity().UpdateAPIKeyActivity(ctx, updated, collector)
		}); err != nil {
			return identitydomain.Actor{}, authenticationError(ctx)
		}
		return identitydomain.Actor{TenantID: key.TenantID, KeyID: key.ID, Name: key.Name, Scopes: append([]string(nil), key.Scopes...), CollectorID: collector.ID}, nil
	}
	sessions, err := s.reader.SessionsByPrefix(ctx, prefix)
	if err != nil {
		return identitydomain.Actor{}, authenticationError(ctx)
	}
	for _, session := range sessions {
		now := s.clock.Now().UTC()
		if session.Prefix != prefix || !s.credentials.Equal(session.Hash, hash) || session.RevokedAt != nil || !session.ExpiresAt.After(now) {
			continue
		}
		identity, err := s.reader.SessionIdentity(ctx, session)
		if err != nil {
			return identitydomain.Actor{}, authenticationError(ctx)
		}
		if identity.User.TenantID != session.TenantID || identity.User.ID != session.UserID || identity.User.Status != "active" {
			return identitydomain.Actor{}, ErrUnauthorized
		}
		if err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
			return tx.Identity().ValidateActiveSession(ctx, session, now)
		}); err != nil {
			return identitydomain.Actor{}, authenticationError(ctx)
		}
		grants := cloneGrants(identity.Grants)
		scopes := scopesFromGrants(grants)
		if len(scopes) == 0 {
			return identitydomain.Actor{}, ErrForbidden
		}
		return identitydomain.Actor{
			TenantID: identity.User.TenantID, UserID: identity.User.ID, SessionID: session.ID, Name: identity.User.Email,
			Scopes: scopes, ResourceGrants: grants,
		}, nil
	}
	return identitydomain.Actor{}, ErrUnauthorized
}

func authenticationError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnauthorized
}

func scopesFromGrants(grants []identitydomain.ResourceGrant) []string {
	set := map[string]struct{}{}
	for _, grant := range grants {
		for _, scope := range grant.Scopes {
			if scope = strings.TrimSpace(scope); scope != "" {
				set[scope] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(set))
	for scope := range set {
		result = append(result, scope)
	}
	sort.Strings(result)
	return result
}

func cloneAPIKey(value identitydomain.APIKey) identitydomain.APIKey {
	value.Scopes = append([]string(nil), value.Scopes...)
	value.ExpiresAt = cloneTime(value.ExpiresAt)
	value.RevokedAt = cloneTime(value.RevokedAt)
	value.LastUsedAt = cloneTime(value.LastUsedAt)
	return value
}

func cloneGrants(values []identitydomain.ResourceGrant) []identitydomain.ResourceGrant {
	result := make([]identitydomain.ResourceGrant, 0, len(values))
	for _, value := range values {
		value.Scopes = append([]string(nil), value.Scopes...)
		result = append(result, value)
	}
	return result
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	for index := range result {
		result[index] = strings.TrimSpace(result[index])
	}
	sort.Strings(result)
	return result
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrValidation
	}
	return ctx.Err()
}

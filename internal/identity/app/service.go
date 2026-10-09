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

type Config struct {
	Reader             Reader
	Transactions       TransactionRunner
	Authorizer         application.Authorizer
	GrantPolicy        GrantPolicy
	Credentials        CredentialManager
	SessionCredentials SessionCredentialManager
	GrantTargets       GrantTargetResolver
	SessionGrants      SessionGrantPolicy
	TrustMaterial      TrustMaterialValidator
	CanonicalHasher    CanonicalHasher
	OIDCDiscovery      OIDCDiscovery
	CredentialVerifier CredentialVerifier
	VerificationPolicy ProviderVerificationPolicy
	Clock              application.Clock
	IDs                application.IDGenerator
}

type Service struct {
	authenticator      *Authenticator
	reader             Reader
	transactions       TransactionRunner
	authorizer         application.Authorizer
	grantPolicy        GrantPolicy
	credentials        CredentialManager
	sessionCredentials SessionCredentialManager
	grantTargets       GrantTargetResolver
	trustMaterial      TrustMaterialValidator
	canonicalHasher    CanonicalHasher
	oidcDiscovery      OIDCDiscovery
	exchange           *SSOExchangeCommands
	clock              application.Clock
	ids                application.IDGenerator
}

func NewService(config Config) (*Service, error) {
	if config.Reader == nil || config.Transactions == nil || config.Authorizer == nil || config.GrantPolicy == nil || config.Credentials == nil || config.SessionCredentials == nil || config.GrantTargets == nil || config.SessionGrants == nil || config.TrustMaterial == nil || config.CanonicalHasher == nil || config.CredentialVerifier == nil || config.VerificationPolicy == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	authenticator, err := NewAuthenticator(AuthenticationConfig{
		Reader: config.Reader, Activity: transactionAuthenticationActivity{transactions: config.Transactions},
		Credentials: config.Credentials, Clock: config.Clock,
	})
	if err != nil {
		return nil, err
	}
	exchange, err := NewSSOExchangeCommands(SSOExchangeCommandConfig{
		Reader: config.Reader, Transactions: serviceSSOExchangeTransactions{transactions: config.Transactions},
		Credentials: config.SessionCredentials, Verifier: config.CredentialVerifier,
		VerificationPolicy: config.VerificationPolicy, SessionGrants: config.SessionGrants,
		Clock: config.Clock, IDs: config.IDs,
	})
	if err != nil {
		return nil, err
	}
	return &Service{
		authenticator: authenticator,
		reader:        config.Reader, transactions: config.Transactions, authorizer: config.Authorizer,
		grantPolicy: config.GrantPolicy, credentials: config.Credentials, sessionCredentials: config.SessionCredentials,
		grantTargets: config.GrantTargets, trustMaterial: config.TrustMaterial,
		canonicalHasher: config.CanonicalHasher, oidcDiscovery: config.OIDCDiscovery,
		exchange: exchange,
		clock:    config.Clock, ids: config.IDs,
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

// PreparedTenantBootstrap is sensitive composition-layer state. Secret and the
// API-key hash must be retained only until CommitTenantBootstrap succeeds; only
// PublicResult may cross the public API boundary.
type PreparedTenantBootstrap struct {
	Tenant identitydomain.Tenant
	APIKey identitydomain.APIKey
	Secret string
}

// PublicResult returns the bootstrap response without the stored credential
// hash. Callers must invoke it only after the shared bootstrap transaction has
// committed successfully.
func (p PreparedTenantBootstrap) PublicResult() (identitydomain.Tenant, identitydomain.APIKey, string) {
	tenant := p.Tenant
	key := cloneAPIKey(p.APIKey)
	key.Hash = ""
	return tenant, key, p.Secret
}

// PrepareTenantBootstrap validates and prepares only Identity-owned state. It
// does not persist anything; the composition layer combines it with the
// Verification-owned initial signing key in one shared transaction.
func (s *Service) PrepareTenantBootstrap(ctx context.Context, input BootstrapTenantInput) (PreparedTenantBootstrap, error) {
	return (&TenantBootstrapCommands{TenantBootstrapConfig{Credentials: s.credentials, Clock: s.clock, IDs: s.ids}}).PrepareTenantBootstrap(ctx, input)
}

// CommitTenantBootstrap writes only Identity-owned bootstrap records and their
// audit entry into a transaction supplied by the composition layer.
func (s *Service) CommitTenantBootstrap(ctx context.Context, tx Transaction, prepared PreparedTenantBootstrap) error {
	if tx == nil {
		return ErrValidation
	}
	return (&TenantBootstrapCommands{TenantBootstrapConfig{Credentials: s.credentials, Clock: s.clock, IDs: s.ids}}).CommitTenantBootstrap(ctx, serviceTenantBootstrapTransaction{tx}, prepared)
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
	input, err := normalizeAPIKeyCreateInput(input)
	if err != nil {
		return identitydomain.APIKey{}, "", err
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
	return s.authenticator.Authenticate(ctx, secret)
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

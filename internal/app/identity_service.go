package app

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type identityService struct {
	ledger *Ledger
}

func (l *Ledger) identityService() identityService {
	return identityService{ledger: l}
}

func (s identityService) HasTenants() bool {
	l := s.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.tenants) > 0
}

func (s identityService) BootstrapTenant(ctx context.Context, name, keyName string, scopes []string) (domain.Tenant, domain.APIKey, string, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	name = strings.TrimSpace(name)
	keyName = strings.TrimSpace(keyName)
	if name == "" || keyName == "" {
		return domain.Tenant{}, domain.APIKey{}, "", ErrValidation
	}
	if len(scopes) == 0 {
		scopes = []string{"*"}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	tenant := domain.Tenant{ID: newID("ten"), Name: name, CreatedAt: now}
	l.tenants[tenant.ID] = tenant
	key, secret, err := l.createAPIKeyLocked(tenant.ID, keyName, scopes, nil)
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	if _, err := l.rotateSigningKeyLocked(tenant.ID, "bootstrap"); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	_, _ = l.appendChainLocked(tenant.ID, "tenant.created", "tenant", tenant.ID, "system", "bootstrap", "", "")
	if err := l.persistCriticalLocked(ctx, l.criticalMutationLocked()); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	return tenant, key, secret, nil
}

func (s identityService) Authenticate(ctx context.Context, secret string) (domain.Actor, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.Actor{}, err
	}
	secret = strings.TrimSpace(strings.TrimPrefix(secret, "Bearer "))
	if secret == "" {
		return domain.Actor{}, ErrUnauthorized
	}
	prefix := secretPrefix(secret)
	hash := l.hashSecret(secret)
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, key := range l.apiKeys {
		if key.Prefix != prefix || !secretHashEqual(key.Hash, hash) || key.RevokedAt != nil {
			continue
		}
		if key.ExpiresAt != nil && !key.ExpiresAt.After(l.now()) {
			return domain.Actor{}, ErrUnauthorized
		}
		now := l.now()
		key.LastUsedAt = &now
		l.apiKeys[id] = key
		collectorID := ""
		for collectorMapID, collector := range l.collectors {
			if collector.TenantID == key.TenantID && collector.APIKeyID == key.ID {
				collectorID = collector.ID
				collector.LastSeenAt = &now
				l.collectors[collectorMapID] = collector
				break
			}
		}
		_ = l.persistCriticalLocked(ctx, l.criticalMutationLocked())
		return domain.Actor{TenantID: key.TenantID, KeyID: key.ID, Name: key.Name, Scopes: append([]string(nil), key.Scopes...), CollectorID: collectorID}, nil
	}
	for id, session := range l.ssoSessions {
		if session.Prefix != prefix || !secretHashEqual(session.Hash, hash) || session.RevokedAt != nil || !session.ExpiresAt.After(l.now()) {
			continue
		}
		user, ok := l.users[session.UserID]
		if !ok || user.TenantID != session.TenantID || user.Status != "active" {
			return domain.Actor{}, ErrUnauthorized
		}
		grants := append(l.resourceGrantsForUserLocked(user.ID), l.resourceGrantsForSSOSessionLocked(session)...)
		scopes := scopesFromResourceGrants(grants)
		if len(scopes) == 0 {
			return domain.Actor{}, ErrForbidden
		}
		l.ssoSessions[id] = session
		_ = l.persistCriticalLocked(ctx, l.criticalMutationLocked())
		return domain.Actor{TenantID: user.TenantID, UserID: user.ID, SessionID: session.ID, Name: user.Email, Scopes: scopes, ResourceGrants: grants}, nil
	}
	return domain.Actor{}, ErrUnauthorized
}

func (s identityService) CreateAPIKey(ctx context.Context, actor domain.Actor, name string, scopes []string, expiresAt *time.Time) (domain.APIKey, string, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.APIKey{}, "", err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return domain.APIKey{}, "", err
	}
	if strings.TrimSpace(name) == "" || len(scopes) == 0 {
		return domain.APIKey{}, "", ErrValidation
	}
	if err := requireGrantableScopes(actor, scopes); err != nil {
		return domain.APIKey{}, "", err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, secret, err := l.createAPIKeyLocked(actor.TenantID, name, scopes, expiresAt)
	if err != nil {
		return domain.APIKey{}, "", err
	}
	_, _ = l.appendChainLocked(actor.TenantID, "api_key.created", "api_key", key.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistCriticalLocked(ctx, l.criticalMutationLocked()); err != nil {
		return domain.APIKey{}, "", err
	}
	return key, secret, nil
}

func (s identityService) ListAPIKeys(ctx context.Context, actor domain.Actor) ([]domain.APIKey, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.APIKey{}
	for _, key := range l.apiKeys {
		if key.TenantID == actor.TenantID {
			key.Hash = ""
			out = append(out, key)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (l *Ledger) CreateOrganization(ctx context.Context, actor domain.Actor, in CreateOrganizationInput) (domain.Organization, error) {
	return l.identityService().CreateOrganization(ctx, actor, in)
}

func (l *Ledger) CreateUser(ctx context.Context, actor domain.Actor, in CreateUserInput) (domain.HumanUser, error) {
	return l.identityService().CreateUser(ctx, actor, in)
}

func (l *Ledger) DeactivateUser(ctx context.Context, actor domain.Actor, id string) (domain.HumanUser, error) {
	return l.identityService().DeactivateUser(ctx, actor, id)
}

func (l *Ledger) CreateRoleBinding(ctx context.Context, actor domain.Actor, in CreateRoleBindingInput) (domain.RoleBinding, error) {
	return l.identityService().CreateRoleBinding(ctx, actor, in)
}

func (l *Ledger) ListRoleBindings(ctx context.Context, actor domain.Actor) ([]domain.RoleBinding, error) {
	return l.identityService().ListRoleBindings(ctx, actor)
}

func (l *Ledger) CreateSSOProvider(ctx context.Context, actor domain.Actor, in CreateSSOProviderInput) (domain.SSOProvider, error) {
	return l.identityService().CreateSSOProvider(ctx, actor, in)
}

func (l *Ledger) UpdateSSOProviderTrustMaterial(ctx context.Context, actor domain.Actor, id string, in UpdateSSOProviderTrustMaterialInput) (domain.SSOProvider, error) {
	return l.identityService().UpdateSSOProviderTrustMaterial(ctx, actor, id, in)
}

func (l *Ledger) RefreshSSOProviderOIDCTrustMaterial(ctx context.Context, actor domain.Actor, id string) (domain.SSOProvider, error) {
	return l.identityService().RefreshSSOProviderOIDCTrustMaterial(ctx, actor, id)
}

func (l *Ledger) LinkSSOIdentity(ctx context.Context, actor domain.Actor, in LinkSSOIdentityInput) (domain.UserIdentityLink, error) {
	return l.identityService().LinkSSOIdentity(ctx, actor, in)
}

func (l *Ledger) CreateSSOSession(ctx context.Context, actor domain.Actor, in CreateSSOSessionInput) (domain.SSOSession, string, error) {
	return l.identityService().CreateSSOSession(ctx, actor, in)
}

func (l *Ledger) ExchangeSSOCredential(ctx context.Context, in ExchangeSSOCredentialInput) (domain.ProviderVerification, domain.SSOSession, string, error) {
	return l.identityService().ExchangeSSOCredential(ctx, in)
}

func (l *Ledger) RevokeSSOSession(ctx context.Context, actor domain.Actor, id string) (domain.SSOSession, error) {
	return l.identityService().RevokeSSOSession(ctx, actor, id)
}

func (l *Ledger) RevokeCurrentSSOSession(ctx context.Context, actor domain.Actor) (domain.SSOSession, error) {
	return l.identityService().RevokeCurrentSSOSession(ctx, actor)
}

func (l *Ledger) CreateCustomerPortalAccess(ctx context.Context, actor domain.Actor, in CreateCustomerPortalAccessInput) (domain.CustomerPortalAccess, string, error) {
	return l.identityService().CreateCustomerPortalAccess(ctx, actor, in)
}

func (l *Ledger) AccessCustomerPortalPackage(ctx context.Context, token string) (domain.CustomerSecurityPackage, error) {
	return l.identityService().AccessCustomerPortalPackage(ctx, token)
}

func (l *Ledger) AccessCustomerPortalPackageWithAcceptance(ctx context.Context, token string, in CustomerPortalAcceptanceInput) (domain.CustomerSecurityPackage, error) {
	return l.identityService().AccessCustomerPortalPackageWithAcceptance(ctx, token, in)
}

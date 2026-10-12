package app

import (
	"context"
	"slices"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// AuthenticationReader is the narrow credential lookup and grant projection
// boundary. Production adapters can satisfy it without loading tenant state.
type AuthenticationReader interface {
	APIKeysByPrefix(context.Context, string) ([]identitydomain.APIKey, error)
	SessionsByPrefix(context.Context, string) ([]identitydomain.SSOSession, error)
	CollectorByAPIKey(context.Context, string, string) (CollectorBinding, bool, error)
	SessionIdentity(context.Context, identitydomain.SSOSession) (SessionIdentity, error)
}

type AuthenticationCredentials interface {
	Prefix(string) string
	Hash(string) string
	Equal(string, string) bool
}

// AuthenticationActivity makes credential-use updates and session revalidation
// explicit. An adapter must commit key and collector activity atomically.
type AuthenticationActivity interface {
	RecordAPIKeyUse(context.Context, identitydomain.APIKey, CollectorActivity) error
	ValidateActiveSession(context.Context, identitydomain.SSOSession, SessionIdentity, application.Clock) (time.Time, error)
}

type AuthenticationConfig struct {
	Reader      AuthenticationReader
	Activity    AuthenticationActivity
	Credentials AuthenticationCredentials
	Clock       application.Clock
}

// Authenticator verifies API keys and SSO sessions and validates their
// activity/revocation transaction before returning an actor.
type Authenticator struct {
	reader      AuthenticationReader
	activity    AuthenticationActivity
	credentials AuthenticationCredentials
	clock       application.Clock
}

func NewAuthenticator(config AuthenticationConfig) (*Authenticator, error) {
	if config.Reader == nil || config.Activity == nil || config.Credentials == nil || config.Clock == nil {
		return nil, ErrValidation
	}
	return &Authenticator{reader: config.Reader, activity: config.Activity, credentials: config.Credentials, clock: config.Clock}, nil
}

type transactionAuthenticationActivity struct{ transactions TransactionRunner }

func (a transactionAuthenticationActivity) RecordAPIKeyUse(ctx context.Context, key identitydomain.APIKey, collector CollectorActivity) error {
	return a.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return tx.Identity().UpdateAPIKeyActivity(ctx, key, collector)
	})
}

func (a transactionAuthenticationActivity) ValidateActiveSession(ctx context.Context, session identitydomain.SSOSession, identity SessionIdentity, clock application.Clock) (time.Time, error) {
	var used time.Time
	err := a.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		var err error
		used, err = tx.Identity().ValidateActiveSession(ctx, session, identity, clock)
		return err
	})
	if err != nil {
		return time.Time{}, err
	}
	return used, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, secret string) (identitydomain.Actor, error) {
	if a == nil {
		return identitydomain.Actor{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return identitydomain.Actor{}, err
	}
	secret = strings.TrimSpace(strings.TrimPrefix(secret, "Bearer "))
	if secret == "" {
		return identitydomain.Actor{}, ErrUnauthorized
	}
	prefix := a.credentials.Prefix(secret)
	hash := a.credentials.Hash(secret)
	keys, err := a.reader.APIKeysByPrefix(ctx, prefix)
	if err != nil {
		return identitydomain.Actor{}, authenticationError(ctx)
	}
	for _, key := range keys {
		if key.Prefix != prefix || !a.credentials.Equal(key.Hash, hash) || key.RevokedAt != nil {
			continue
		}
		now := a.clock.Now().UTC()
		if key.ExpiresAt != nil && !key.ExpiresAt.After(now) {
			return identitydomain.Actor{}, ErrUnauthorized
		}
		updated := cloneAPIKey(key)
		// Preserve an empty JSON array versus null in the admission snapshot.
		// The actor's published inert-scope semantics remain unchanged.
		updated.Scopes = slices.Clone(key.Scopes)
		lastUsedAt := now
		if key.LastUsedAt != nil && key.LastUsedAt.UTC().After(lastUsedAt) {
			lastUsedAt = key.LastUsedAt.UTC()
		}
		updated.LastUsedAt = &lastUsedAt
		collector := CollectorActivity{}
		actor := identitydomain.Actor{TenantID: key.TenantID, KeyID: key.ID, Name: key.Name, Scopes: append([]string(nil), key.Scopes...)}
		binding, found, err := a.reader.CollectorByAPIKey(ctx, key.TenantID, key.ID)
		if err != nil {
			return identitydomain.Actor{}, authenticationError(ctx)
		}
		if found {
			if err := authz.CheckCollectorCredentialBinding(actor, authz.CollectorCredentialBinding{ID: binding.ID, TenantID: binding.TenantID, APIKeyID: binding.APIKeyID, Status: binding.Status, AllowedScopes: binding.AllowedScopes}); err != nil {
				return identitydomain.Actor{}, ErrUnauthorized
			}
			collector = CollectorActivity{ID: binding.ID, TenantID: binding.TenantID, LastSeenAt: now, AllowedScopes: append([]string(nil), binding.AllowedScopes...)}
			actor.CollectorID = binding.ID
		}
		if err := a.activity.RecordAPIKeyUse(ctx, updated, collector); err != nil {
			return identitydomain.Actor{}, authenticationError(ctx)
		}
		if err := ctx.Err(); err != nil {
			return identitydomain.Actor{}, err
		}
		return actor, nil
	}
	sessions, err := a.reader.SessionsByPrefix(ctx, prefix)
	if err != nil {
		return identitydomain.Actor{}, authenticationError(ctx)
	}
	for _, session := range sessions {
		now := a.clock.Now().UTC()
		if session.Prefix != prefix || !a.credentials.Equal(session.Hash, hash) || !session.ActiveAt(now) {
			continue
		}
		identity, err := a.reader.SessionIdentity(ctx, session)
		if err != nil {
			return identitydomain.Actor{}, authenticationError(ctx)
		}
		if identity.User.TenantID != session.TenantID || identity.User.ID != session.UserID || identity.User.Status != "active" {
			return identitydomain.Actor{}, ErrUnauthorized
		}
		identity.User = cloneHumanUser(identity.User)
		grants := cloneGrants(identity.Grants)
		scopes := scopesFromGrants(grants)
		if len(scopes) == 0 {
			return identitydomain.Actor{}, ErrForbidden
		}
		identity.Grants = cloneGrants(grants)
		used, err := a.activity.ValidateActiveSession(ctx, cloneSSOSession(session), identity, a.clock)
		if err != nil {
			return identitydomain.Actor{}, authenticationError(ctx)
		}
		if err := ctx.Err(); err != nil {
			return identitydomain.Actor{}, err
		}
		session.LastUsedAt = &used
		if !session.ActiveAt(a.clock.Now().UTC()) {
			return identitydomain.Actor{}, ErrUnauthorized
		}
		return identitydomain.Actor{
			TenantID: identity.User.TenantID, UserID: identity.User.ID, SessionID: session.ID, Name: identity.User.Email,
			Scopes: scopes, ResourceGrants: grants,
		}, nil
	}
	return identitydomain.Actor{}, ErrUnauthorized
}

// SameSessionIdentity compares every coordinate that contributes to the actor.
// Admission adapters use it while holding the selected identity/grant rows.
func SameSessionIdentity(a, b SessionIdentity) bool {
	if a.User.ID != b.User.ID || a.User.TenantID != b.User.TenantID || a.User.Email != b.User.Email || a.User.Status != b.User.Status || len(a.Grants) != len(b.Grants) {
		return false
	}
	for i, grant := range a.Grants {
		other := b.Grants[i]
		if grant.Role != other.Role || grant.ResourceType != other.ResourceType || grant.ResourceID != other.ResourceID || !slices.Equal(grant.Scopes, other.Scopes) {
			return false
		}
	}
	return true
}

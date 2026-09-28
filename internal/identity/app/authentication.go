package app

import (
	"context"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
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
	ValidateActiveSession(context.Context, identitydomain.SSOSession, time.Time) error
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

func (a transactionAuthenticationActivity) ValidateActiveSession(ctx context.Context, session identitydomain.SSOSession, now time.Time) error {
	return a.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return tx.Identity().ValidateActiveSession(ctx, session, now)
	})
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
		lastUsedAt := now
		if key.LastUsedAt != nil && key.LastUsedAt.UTC().After(lastUsedAt) {
			lastUsedAt = key.LastUsedAt.UTC()
		}
		updated.LastUsedAt = &lastUsedAt
		collector := CollectorActivity{}
		binding, found, err := a.reader.CollectorByAPIKey(ctx, key.TenantID, key.ID)
		if err != nil {
			return identitydomain.Actor{}, authenticationError(ctx)
		}
		if found {
			if binding.TenantID != key.TenantID || binding.APIKeyID != key.ID {
				return identitydomain.Actor{}, ErrUnauthorized
			}
			collector = CollectorActivity{ID: binding.ID, TenantID: binding.TenantID, LastSeenAt: now}
		}
		if err := a.activity.RecordAPIKeyUse(ctx, updated, collector); err != nil {
			return identitydomain.Actor{}, authenticationError(ctx)
		}
		return identitydomain.Actor{TenantID: key.TenantID, KeyID: key.ID, Name: key.Name, Scopes: append([]string(nil), key.Scopes...), CollectorID: collector.ID}, nil
	}
	sessions, err := a.reader.SessionsByPrefix(ctx, prefix)
	if err != nil {
		return identitydomain.Actor{}, authenticationError(ctx)
	}
	for _, session := range sessions {
		now := a.clock.Now().UTC()
		if session.Prefix != prefix || !a.credentials.Equal(session.Hash, hash) || session.RevokedAt != nil || !session.ExpiresAt.After(now) {
			continue
		}
		identity, err := a.reader.SessionIdentity(ctx, session)
		if err != nil {
			return identitydomain.Actor{}, authenticationError(ctx)
		}
		if identity.User.TenantID != session.TenantID || identity.User.ID != session.UserID || identity.User.Status != "active" {
			return identitydomain.Actor{}, ErrUnauthorized
		}
		if err := a.activity.ValidateActiveSession(ctx, session, now); err != nil {
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

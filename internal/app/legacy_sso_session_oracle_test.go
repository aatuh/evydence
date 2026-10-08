package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

// Unchanged historical declarations retained only for package-local oracles.
// HTTP issuance, revocation and logout fixtures use focused Identity services.
type CreateSSOSessionInput struct {
	UserID     string
	ProviderID string
	ExpiresAt  time.Time
}

func (l *Ledger) CreateSSOSession(ctx context.Context, actor domain.Actor, in CreateSSOSessionInput) (domain.SSOSession, string, error) {
	session, secret, err := l.identityCommands.CreateSSOSession(ctx, actor, identityapp.CreateSSOSessionInput{
		UserID: in.UserID, ProviderID: in.ProviderID, ExpiresAt: in.ExpiresAt,
	})
	return ssoSessionFromIdentityContext(session), secret, fromIdentityContextError(err)
}

func (l *Ledger) RevokeSSOSession(ctx context.Context, actor domain.Actor, id string) (domain.SSOSession, error) {
	session, err := l.identityCommands.RevokeSSOSession(ctx, actor, id)
	return ssoSessionFromIdentityContext(session), fromIdentityContextError(err)
}

func (l *Ledger) RevokeCurrentSSOSession(ctx context.Context, actor domain.Actor) (domain.SSOSession, error) {
	session, err := l.identityCommands.RevokeCurrentSSOSession(ctx, actor)
	return ssoSessionFromIdentityContext(session), fromIdentityContextError(err)
}

package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

// Historical declarations retained unchanged for package-local regression
// oracles only. Production and HTTP fixtures use focused Identity commands.
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

func (l *Ledger) CreateSSOProvider(ctx context.Context, actor domain.Actor, in CreateSSOProviderInput) (domain.SSOProvider, error) {
	provider, err := l.identityCommands.CreateSSOProvider(ctx, actor, identityapp.CreateSSOProviderInput{
		Name: in.Name, Type: in.Type, Issuer: in.Issuer, ClientID: in.ClientID, GroupsClaim: in.GroupsClaim,
		RoleMapping: cloneStringMap(in.RoleMapping), JWKS: cloneIdentityAnyMap(in.JWKS),
		SAMLSigningCertificates: append([]string(nil), in.SAMLSigningCertificates...),
	})
	return ssoProviderFromIdentityContext(provider), fromIdentityContextError(err)
}

func (l *Ledger) LinkSSOIdentity(ctx context.Context, actor domain.Actor, in LinkSSOIdentityInput) (domain.UserIdentityLink, error) {
	link, err := l.identityCommands.LinkSSOIdentity(ctx, actor, identityapp.LinkSSOIdentityInput{
		UserID: in.UserID, ProviderID: in.ProviderID, Subject: in.Subject, Email: in.Email, Verified: in.Verified,
	})
	return userIdentityLinkFromIdentityContext(link), fromIdentityContextError(err)
}

func (l *Ledger) ExchangeSSOCredential(ctx context.Context, in ExchangeSSOCredentialInput) (domain.ProviderVerification, domain.SSOSession, string, error) {
	verification, session, secret, err := l.identityCommands.ExchangeSSOCredential(ctx, identityapp.ExchangeSSOCredentialInput{
		ProviderID: in.ProviderID, Subject: in.Subject, IDToken: in.IDToken,
		SAMLAssertion: in.SAMLAssertion, ExpiresAt: in.ExpiresAt,
	})
	return providerVerificationFromIdentityContext(verification), ssoSessionFromIdentityContext(session), secret, fromIdentityContextError(err)
}

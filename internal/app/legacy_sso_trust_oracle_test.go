package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

// These unchanged historical declarations exist only for package-local
// regression oracles. Production SSO trust commands belong to Identity.
type UpdateSSOProviderTrustMaterialInput struct {
	JWKS                    map[string]any
	SAMLSigningCertificates []string
}

func (l *Ledger) UpdateSSOProviderTrustMaterial(ctx context.Context, actor domain.Actor, id string, in UpdateSSOProviderTrustMaterialInput) (domain.SSOProvider, error) {
	provider, err := l.identityCommands.UpdateSSOProviderTrustMaterial(ctx, actor, id, identityapp.UpdateSSOProviderTrustMaterialInput{
		JWKS: cloneIdentityAnyMap(in.JWKS), SAMLSigningCertificates: append([]string(nil), in.SAMLSigningCertificates...),
	})
	return ssoProviderFromIdentityContext(provider), fromIdentityContextError(err)
}

func (l *Ledger) RefreshSSOProviderOIDCTrustMaterial(ctx context.Context, actor domain.Actor, id string) (domain.SSOProvider, error) {
	provider, err := l.identityCommands.RefreshSSOProviderOIDCTrustMaterial(ctx, actor, id)
	return ssoProviderFromIdentityContext(provider), fromIdentityContextError(err)
}

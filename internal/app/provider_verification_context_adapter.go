package app

import (
	"context"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

// IdentityProviderAPIValidator translates the existing network adapter DTOs.
// It owns no Ledger or state and can be bound directly by production wiring.
type IdentityProviderAPIValidator struct{ Client ProviderIdentityValidator }

func (v IdentityProviderAPIValidator) ValidateProviderIdentity(ctx context.Context, r identityapp.ProviderIdentityValidationRequest) (identityapp.ProviderIdentityValidationResult, error) {
	if v.Client == nil {
		return identityapp.ProviderIdentityValidationResult{}, identityapp.ErrValidation
	}
	result, err := v.Client.ValidateProviderIdentity(ctx, ProviderIdentityValidationRequest{TenantID: r.TenantID, ProviderID: r.ProviderID, ProviderType: r.ProviderType, Issuer: r.Issuer, Subject: r.Subject, GroupsClaim: r.GroupsClaim, AccessToken: r.AccessToken})
	return identityapp.ProviderIdentityValidationResult{Checks: verificationChecksToIdentityContext(result.Checks), Groups: append([]string(nil), result.Groups...), Limitations: append([]string(nil), result.Limitations...)}, err
}

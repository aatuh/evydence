package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
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

type localProviderVerificationReader struct{ ledgerIdentityReader }

func (r localProviderVerificationReader) ReadOwnedSSOProvider(ctx context.Context, tenant, id string) (identitydomain.SSOProvider, error) {
	return r.SSOProvider(ctx, tenant, id)
}

type localProviderVerificationTransactions struct{ ledgerIdentityTransactions }
type localProviderVerificationTransaction struct{ tx *ledgerIdentityTransaction }

func (t localProviderVerificationTransactions) ExecuteProviderVerification(ctx context.Context, fn func(context.Context, identityapp.ProviderVerificationTransaction) error) error {
	return t.execute(ctx, func(ctx context.Context, tx *ledgerIdentityTransaction) error {
		return fn(ctx, localProviderVerificationTransaction{tx})
	})
}
func (t localProviderVerificationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return identityapp.NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (t localProviderVerificationTransaction) ValidateSSOExchangeState(ctx context.Context, s identityapp.SSOExchangeSnapshot) error {
	return t.tx.ValidateSSOExchangeState(ctx, s)
}
func (t localProviderVerificationTransaction) InsertProviderVerification(ctx context.Context, v identitydomain.ProviderVerification) error {
	return t.tx.InsertProviderVerification(ctx, v)
}
func (t localProviderVerificationTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.AppendAudit(ctx, e)
}

func (l *Ledger) verifyProviderIdentity(ctx context.Context, a identitydomain.Actor, in identityapp.VerifyProviderIdentityInput) (identitydomain.ProviderVerification, error) {
	var live identityapp.ProviderIdentityValidator
	if l.providerAPI != nil {
		live = IdentityProviderAPIValidator{Client: l.providerAPI}
	}
	s, err := identityapp.NewProviderVerificationCommands(identityapp.ProviderVerificationCommandConfig{Reader: localProviderVerificationReader{ledgerIdentityReader{l}}, Transactions: localProviderVerificationTransactions{ledgerIdentityTransactions{l}}, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Verifier: LocalSSOCredentialVerifier{}, LiveProvider: live, VerificationPolicy: LocalSSOVerificationPolicy{}, Clock: application.ClockFunc(l.now), IDs: application.IDGeneratorFunc(newID)})
	if err != nil {
		return identitydomain.ProviderVerification{}, err
	}
	return s.VerifyProviderIdentity(ctx, a, in)
}

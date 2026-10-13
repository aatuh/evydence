package app

import (
	"context"
	"testing"
	"time"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Only focused memory operational repositories own local SAML state. No
// binding, request or assertion maps are added to the retired Ledger oracle.
type ledgerSAMLProofReader struct{ ledger *Ledger }

func (r ledgerSAMLProofReader) SAMLProviderBindingByID(ctx context.Context, id string) (identitydomain.SAMLProviderBinding, error) {
	var out identitydomain.SAMLProviderBinding
	err := r.ledger.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
		reader, ok := repos.Identity.(identityapp.SAMLRequestProviderReader)
		if !ok {
			return ErrValidation
		}
		var err error
		out, err = reader.SAMLProviderBindingByID(ctx, id)
		return err
	})
	return out, toIdentityContextError(err)
}
func (r ledgerSAMLProofReader) ReadSAMLAuthenticationRequest(ctx context.Context, tenant, provider, id string) (identitydomain.SAMLAuthenticationRequest, error) {
	var out identitydomain.SAMLAuthenticationRequest
	err := r.ledger.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
		reader, ok := repos.Identity.(identityapp.SAMLAuthenticationRequestReader)
		if !ok {
			return ErrValidation
		}
		var err error
		out, err = reader.ReadSAMLAuthenticationRequest(ctx, tenant, provider, id)
		return err
	})
	return out, toIdentityContextError(err)
}
func seedOracleSAMLRequest(t *testing.T, l *Ledger, provider identitydomain.SSOProvider) (identitydomain.SAMLAuthenticationRequest, string) {
	t.Helper()
	credentials, err := identityapp.NewHMACAuthenticationCredentials(string(l.pepper))
	if err != nil {
		t.Fatal(err)
	}
	state, err := credentials.GenerateLoginState()
	if err != nil {
		t.Fatal(err)
	}
	now := l.now().UTC().Truncate(time.Microsecond)
	binding := identitydomain.SAMLProviderBinding{TenantID: provider.TenantID, ProviderID: provider.ID, Provider: provider, Recipient: "https://sp.example.test/consume", NameIDFormat: identitydomain.SAMLNameIDUnspecified, SchemaVersion: identitydomain.SAMLProviderBindingSchemaVersion, UpdatedAt: now}
	fp, err := identityapp.SAMLProviderTrustFingerprint(binding)
	if err != nil {
		t.Fatal(err)
	}
	r := identitydomain.SAMLAuthenticationRequest{ID: newID("samlreq"), TenantID: provider.TenantID, ProviderID: provider.ID, Delivery: "api", Issuer: provider.Issuer, Audience: provider.ClientID, Recipient: binding.Recipient, NameIDFormat: binding.NameIDFormat, TrustFingerprint: fp, StateHash: state.Hash, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), SchemaVersion: identitydomain.SAMLAuthenticationRequestSchemaVersion}
	err = l.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, repos Repositories) error {
		writer, ok := repos.Identity.(interface {
			UpsertSAMLProviderBinding(context.Context, identitydomain.SAMLProviderBinding) error
			InsertSAMLAuthenticationRequest(context.Context, identitydomain.SAMLAuthenticationRequest, time.Time) error
		})
		if !ok {
			return ErrValidation
		}
		if err := writer.UpsertSAMLProviderBinding(ctx, binding); err != nil {
			return err
		}
		return writer.InsertSAMLAuthenticationRequest(ctx, r, now)
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, state.Secret
}

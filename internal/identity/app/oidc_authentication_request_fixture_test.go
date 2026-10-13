package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Service regressions use the same random secret/hash profile as production;
// only the local cryptographic verifier remains a test double in these cases.
func (f *identityServiceFixture) boundExchangeInput(t *testing.T, in ExchangeSSOCredentialInput) ExchangeSSOCredentialInput {
	t.Helper()
	var provider identitydomain.SSOProvider
	for _, p := range f.reader.providers {
		if p.ID == strings.TrimSpace(in.ProviderID) {
			provider = p
			break
		}
	}
	if provider.ID == "" || provider.Type != "oidc" {
		return in
	}
	credentials, err := NewHMACAuthenticationCredentials("test-proof-pepper")
	if err != nil {
		t.Fatal(err)
	}
	state, err := credentials.GenerateLoginState()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := credentials.GenerateLoginNonce()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := OIDCProviderTrustFingerprint(provider)
	if err != nil {
		t.Fatal(err)
	}
	request := identitydomain.OIDCAuthenticationRequest{ID: "request", TenantID: provider.TenantID, ProviderID: provider.ID, Delivery: "api", StateHash: state.Hash, NonceHash: nonce.Hash, TrustFingerprint: fingerprint, CreatedAt: f.now, ExpiresAt: f.now.Add(5 * time.Minute), SchemaVersion: identitydomain.OIDCAuthenticationRequestSchemaVersion}
	f.transactions.state.oidcRequests[request.ID] = request
	f.reader.oidcRequests = func() map[string]identitydomain.OIDCAuthenticationRequest { return f.transactions.state.oidcRequests }
	f.service.exchange.config.ProofCredentials = credentials
	f.verifier.result.Nonce, f.verifier.result.IssuedAt, f.verifier.result.ExpiresAt = nonce.Secret, f.now, f.now.Add(time.Hour)
	in.AuthenticationRequestID, in.StateSecret = request.ID, state.Secret
	return in
}
func (f *fakeIdentityReader) ReadOIDCAuthenticationRequest(_ context.Context, tenant, provider, id string) (identitydomain.OIDCAuthenticationRequest, error) {
	if f.oidcRequests == nil {
		return identitydomain.OIDCAuthenticationRequest{}, ErrNotFound
	}
	v, ok := f.oidcRequests()[id]
	if !ok || v.TenantID != tenant || v.ProviderID != provider {
		return identitydomain.OIDCAuthenticationRequest{}, ErrNotFound
	}
	if v.ConsumedAt != nil {
		at := *v.ConsumedAt
		v.ConsumedAt = &at
	}
	return v, nil
}
func (f fakeIdentityRepository) ConsumeOIDCAuthenticationRequest(_ context.Context, v identitydomain.OIDCAuthenticationRequest, clock application.Clock) (time.Time, error) {
	current, ok := f.state.oidcRequests[v.ID]
	at := clock.Now().UTC()
	if !ok || current.TenantID != v.TenantID || current.ProviderID != v.ProviderID || current.StateHash != v.StateHash || current.NonceHash != v.NonceHash || !current.PendingAt(at) {
		return time.Time{}, ErrUnauthorized
	}
	current.ConsumedAt = &at
	f.state.oidcRequests[v.ID] = current
	return at, nil
}

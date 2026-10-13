package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SAMLExchangeReader interface {
	SAMLRequestProviderReader
	SAMLAuthenticationRequestReader
}

func (s *SSOExchangeCommands) boundSAMLRequest(ctx context.Context, p identitydomain.SSOProvider, in ExchangeSSOCredentialInput, now time.Time) (identitydomain.SAMLAuthenticationRequest, error) {
	return boundSAMLAuthenticationRequest(ctx, s.config.SAMLAuthentication, s.config.ProofCredentials, p, in, now)
}

func boundSAMLAuthenticationRequest(ctx context.Context, reader SAMLExchangeReader, credentials AuthenticationCredentials, p identitydomain.SSOProvider, in ExchangeSSOCredentialInput, now time.Time) (identitydomain.SAMLAuthenticationRequest, error) {
	id := strings.TrimSpace(in.AuthenticationRequestID)
	if reader == nil || credentials == nil || !identitydomain.ValidSAMLID(id) || len(in.StateSecret) != len("evylogin_")+43 || !strings.HasPrefix(in.StateSecret, "evylogin_") || !validIssuedLoginCredential(Credential{Secret: in.StateSecret, Prefix: in.StateSecret[:12], Hash: credentials.Hash(in.StateSecret)}, "evylogin_") {
		return identitydomain.SAMLAuthenticationRequest{}, ErrUnauthorized
	}
	delivery := in.Delivery
	if delivery == "" {
		delivery = "api"
	}
	if delivery != "api" && delivery != "browser" {
		return identitydomain.SAMLAuthenticationRequest{}, ErrValidation
	}
	b, err := reader.SAMLProviderBindingByID(ctx, p.ID)
	if err != nil {
		return identitydomain.SAMLAuthenticationRequest{}, authenticationError(ctx)
	}
	if b.TenantID != p.TenantID || b.ProviderID != p.ID || !ValidSAMLProviderBinding(b) {
		return identitydomain.SAMLAuthenticationRequest{}, ErrUnauthorized
	}
	// The separate public provider lookup and binding read must represent the
	// same trust revision; the consumer will lock and revalidate again at commit.
	current := cloneSAMLProviderBinding(b)
	current.Provider = cloneSSOProvider(p)
	fingerprint, err := SAMLProviderTrustFingerprint(current)
	if err != nil {
		return identitydomain.SAMLAuthenticationRequest{}, ErrUnauthorized
	}
	bindingFingerprint, err := SAMLProviderTrustFingerprint(b)
	if err != nil || bindingFingerprint != fingerprint {
		return identitydomain.SAMLAuthenticationRequest{}, ErrUnauthorized
	}
	r, err := reader.ReadSAMLAuthenticationRequest(ctx, p.TenantID, p.ID, id)
	if err != nil {
		return identitydomain.SAMLAuthenticationRequest{}, authenticationError(ctx)
	}
	if r.ID != id || r.TenantID != p.TenantID || r.ProviderID != p.ID || r.Delivery != delivery || r.Issuer != p.Issuer || r.Audience != p.ClientID || r.Recipient != b.Recipient || r.NameIDFormat != b.NameIDFormat || r.TrustFingerprint != fingerprint || !r.PendingAt(now) || !credentials.Equal(r.StateHash, credentials.Hash(in.StateSecret)) {
		return identitydomain.SAMLAuthenticationRequest{}, ErrUnauthorized
	}
	return r, nil
}

func verifiedSAMLAssertionUse(r identitydomain.SAMLAuthenticationRequest, v CredentialVerificationResult, now time.Time) (identitydomain.SAMLAssertionUse, error) {
	var empty identitydomain.SAMLAssertionUse
	if v.SAMLInResponseTo != r.ID || v.SAMLRecipient != r.Recipient || !identitydomain.ValidSAMLID(v.SAMLAssertionID) || v.IssuedAt.Before(r.CreatedAt.Add(-time.Minute)) {
		return empty, ErrUnauthorized
	}
	if !v.SessionExpiresAt.IsZero() && (!validAPIKeyTime(v.SessionExpiresAt) || !v.SessionExpiresAt.After(now)) {
		return empty, ErrUnauthorized
	}
	passed := make(map[string]bool, len(v.Checks))
	for _, c := range v.Checks {
		if c.Result != "passed" {
			return empty, ErrUnauthorized
		}
		passed[c.Name] = true
	}
	for _, name := range []string{"saml_assertion_signature", "issuer", "audience", "subject", "saml_assertion_time", "saml_recipient", "saml_response_correlation"} {
		if !passed[name] {
			return empty, ErrUnauthorized
		}
	}
	hash, err := SAMLAssertionFingerprint(r, v.SAMLAssertionID)
	if err != nil {
		return empty, ErrUnauthorized
	}
	proof := identitydomain.SAMLAssertionUse{AssertionHash: hash, IssuedAt: v.IssuedAt, ExpiresAt: v.ExpiresAt}
	if !proof.ValidAt(now) {
		return empty, ErrUnauthorized
	}
	return proof, nil
}

func samlExchangeProofFresh(s SSOExchangeSnapshot, now time.Time) bool {
	return s.SAMLAuthenticationRequest != nil && s.SAMLAssertionUse != nil && s.SAMLAuthenticationRequest.PendingAt(now) && s.SAMLAssertionUse.ValidAt(now)
}

// The explicit local Service composes narrow capabilities dynamically; the
// general Reader/Repository contracts do not grow with this protocol.
type serviceSAMLExchangeReader struct{ reader Reader }

func (r serviceSAMLExchangeReader) SAMLProviderBindingByID(ctx context.Context, id string) (identitydomain.SAMLProviderBinding, error) {
	reader, ok := r.reader.(SAMLRequestProviderReader)
	if !ok {
		return identitydomain.SAMLProviderBinding{}, ErrValidation
	}
	return reader.SAMLProviderBindingByID(ctx, id)
}
func (r serviceSAMLExchangeReader) ReadSAMLAuthenticationRequest(ctx context.Context, tenant, provider, id string) (identitydomain.SAMLAuthenticationRequest, error) {
	reader, ok := r.reader.(SAMLAuthenticationRequestReader)
	if !ok {
		return identitydomain.SAMLAuthenticationRequest{}, ErrValidation
	}
	return reader.ReadSAMLAuthenticationRequest(ctx, tenant, provider, id)
}
func (t serviceSSOExchangeTransaction) ConsumeSAMLAuthenticationRequest(ctx context.Context, r identitydomain.SAMLAuthenticationRequest, p identitydomain.SAMLAssertionUse, c application.Clock) (time.Time, error) {
	consumer, ok := t.identity.(SAMLAuthenticationRequestConsumer)
	if !ok {
		return time.Time{}, ErrValidation
	}
	return consumer.ConsumeSAMLAuthenticationRequest(ctx, r, p, c)
}

package app

import (
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/identity/saml"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestSAMLRejectsHistoricalCustomSignatureAndUnsignedBindings(t *testing.T) {
	key, certificate := samlTestCertificate(t)
	provider := domain.SSOProvider{
		ID: "provider", TenantID: "tenant", Type: "saml",
		Issuer: "https://saml-idp.example.test", ClientID: "saml-client",
		SAMLSigningCertificates: []string{certificate},
	}
	assertion := signedTestSAMLAssertion(t, key, provider.Issuer, provider.ClientID, "subject", fixedNow().Add(-time.Minute), fixedNow().Add(time.Hour))
	for _, tc := range []struct {
		name string
		edit func(string) string
	}{
		{"historical custom signature", func(value string) string { return value }},
		{"unsigned assertion ID", func(value string) string {
			return strings.Replace(value, `ID="assertion-1"`, `ID="attacker-selected-assertion"`, 1)
		}},
		{"unsigned recipient", func(value string) string {
			return strings.Replace(value, "</Subject>", `<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData Recipient="https://foreign.example.test/consume" NotOnOrAfter="`+fixedNow().Add(time.Hour).Format(time.RFC3339)+`"/></SubjectConfirmation></Subject>`, 1)
		}},
		{"unsigned response correlation", func(value string) string {
			return strings.Replace(value, "</Subject>", `<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="foreign-login-request" NotOnOrAfter="`+fixedNow().Add(time.Hour).Format(time.RFC3339)+`"/></SubjectConfirmation></Subject>`, 1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := (LocalSSOCredentialVerifier{SAML: saml.Verifier{}}).Verify(t.Context(), identityapp.CredentialVerificationRequest{Provider: identitydomain.SSOProvider(provider), Subject: "subject", SAMLAssertion: tc.edit(assertion), SAMLRequestID: "request", SAMLRecipient: "https://sp.example.test/consume", Now: fixedNow()}); err == nil {
				t.Fatal("custom signature or unsigned SAML binding retained credential authority")
			}
		})
	}
}

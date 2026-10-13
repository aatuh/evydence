package app

import (
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestSAMLBoundAssuranceProfileRequiresCryptographicAndRequestChecks(t *testing.T) {
	names := []string{"saml_assertion_signature", "issuer", "audience", "subject", "saml_assertion_time", "saml_recipient", "saml_response_correlation", "saml_request_state_binding", "verified_identity_link"}
	provider := identitydomain.SSOProvider{Type: "saml"}
	for omitted := -1; omitted < len(names); omitted++ {
		v := identitydomain.ProviderVerification{}
		for i, name := range names {
			if i != omitted {
				v.Checks = append(v.Checks, identitydomain.VerificationCheck{Name: name, Result: "passed"})
			}
		}
		got := (LocalSSOVerificationPolicy{}).Assess(v, provider, true)
		if omitted == 7 { // Absence of the state-binding check must not select the bound profile.
			if got.Profile.ID == "provider-identity-saml-bound.v1" {
				t.Fatal("unbound SAML mislabeled as bound proof")
			}
			continue
		}
		if got.Profile.ID != "provider-identity-saml-bound.v1" || got.Profile.PayloadScope != "server-owned authentication state, signed SAML assertion claims and verified tenant identity link" {
			t.Fatal("SAML binding profile missing or ambiguous", got.Profile.ID)
		}
		if omitted < 0 && got.Result != "passed" {
			t.Fatal("complete verified SAML profile did not pass")
		}
		if omitted >= 0 && got.Result == "passed" {
			t.Fatal("missing SAML proof check became authority", names[omitted])
		}
	}
}

package app

import (
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestOIDCAssuranceProfilePinsCryptographyAndBoundLoginSemantics(t *testing.T) {
	provider := domain.SSOProvider{Type: "oidc"}
	checks := []domain.VerifyCheck{}
	for _, name := range []string{"id_token_signature", "issuer", "audience", "authorized_party", "subject", "token_time", "nonce_state_binding"} {
		checks = append(checks, domain.VerifyCheck{Name: name, Result: "passed"})
	}
	p := providerVerificationProfile(provider, true, checks, nil)
	if p.ID != "provider-identity-oidc-bound.v1" || domain.AggregateVerificationState(p, checks) != domain.VerificationStatePassed {
		t.Fatal("bound OIDC assurance does not identify the proof semantics", p.ID)
	}
	missingSignature := checks[1:]
	p = providerVerificationProfile(provider, true, missingSignature, nil)
	if domain.AggregateVerificationState(p, missingSignature) == domain.VerificationStatePassed {
		t.Fatal("missing cryptographic evidence passed a bound-login profile")
	}
	unbound := checks[:len(checks)-1]
	p = providerVerificationProfile(provider, true, unbound, nil)
	if p.ID != "provider-identity-oidc.v2" {
		t.Fatal("strict token assessment borrowed historical OIDC semantics", p.ID)
	}
	p = providerVerificationProfile(provider, false, nil, nil)
	if p.ID != "provider-identity-oidc.v1" || domain.AggregateVerificationState(p, nil) == domain.VerificationStatePassed {
		t.Fatal("metadata-only assessment acquired credential authority")
	}
}

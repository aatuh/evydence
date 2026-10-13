package app

import (
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

func assuranceProfile(id string, requiredChecks, trustMaterial []string, identityPolicy, transparencyProof, payloadScope, payloadDigest string, limitations []string) domain.VerificationProfile {
	return domain.NormalizeVerificationProfile(domain.VerificationProfile{
		ID:                id,
		Version:           domain.VerificationProfileSchemaVersion,
		RequiredChecks:    requiredChecks,
		TrustMaterial:     trustMaterial,
		IdentityPolicy:    identityPolicy,
		TransparencyProof: transparencyProof,
		PayloadScope:      payloadScope,
		PayloadDigest:     payloadDigest,
		Limitations:       limitations,
	})
}

func requiredCheckNames(checks []domain.VerifyCheck) []string {
	set := map[string]struct{}{}
	for _, check := range checks {
		if check.Name != "" {
			set[check.Name] = struct{}{}
		}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func verificationReturnsFailure(result string) bool {
	return result == string(domain.VerificationStateFailed) || result == string(domain.VerificationStateError)
}

func providerVerificationProfile(provider domain.SSOProvider, tokenSupplied bool, checks []domain.VerifyCheck, limitations []string) domain.VerificationProfile {
	required := requiredCheckNames(checks)
	id := "provider-identity-" + provider.Type + ".v1"
	payloadScope := "provider credential claims and verified identity link"
	localOIDCProof := false
	for _, check := range checks {
		localOIDCProof = localOIDCProof || strings.HasPrefix(check.Name, "id_token_") || check.Name == "token_time" || check.Name == "nonce_state_binding"
	}
	if provider.Type == "oidc" && tokenSupplied && localOIDCProof {
		id = "provider-identity-oidc.v2"
		required = append(required, "id_token_signature", "issuer", "audience", "authorized_party", "subject", "token_time")
		for _, check := range checks {
			if check.Name == "nonce_state_binding" {
				id = "provider-identity-oidc-bound.v1"
				required = append(required, "nonce_state_binding")
				payloadScope = "server-owned authentication state, provider credential claims and verified tenant identity link"
			}
		}
	}
	if !tokenSupplied {
		required = append(required, "provider_credential_signature")
	}
	if provider.Type == "saml" && tokenSupplied {
		for _, check := range checks {
			if check.Name == "saml_request_state_binding" {
				id = "provider-identity-saml-bound.v1"
				required = append(required, "saml_assertion_signature", "issuer", "audience", "subject", "saml_assertion_time", "saml_recipient", "saml_response_correlation", "saml_request_state_binding", "verified_identity_link")
				payloadScope = "server-owned authentication state, signed SAML assertion claims and verified tenant identity link"
			}
		}
	}
	trustMaterial := []string{"configured " + provider.Type + " provider metadata"}
	switch provider.Type {
	case "oidc":
		trustMaterial = append(trustMaterial, "configured OIDC JWKS")
	case "saml":
		trustMaterial = append(trustMaterial, "configured SAML signing certificates")
	}
	return assuranceProfile(id, required, trustMaterial, "provider subject must match a verified tenant identity link", "not_evaluated", payloadScope, "", limitations)
}

func reassessProviderVerification(record *domain.ProviderVerification, provider domain.SSOProvider, tokenSupplied bool) {
	profile := providerVerificationProfile(provider, tokenSupplied, record.Checks, record.Limitations)
	record.Profile = profile
	record.Result = string(domain.AggregateVerificationState(profile, record.Checks))
}

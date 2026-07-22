package app

import (
	"sort"
	"time"

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

func verificationResult(id, tenantID, subjectType, subjectID string, checks []domain.VerifyCheck, profile domain.VerificationProfile, at time.Time) domain.VerificationResult {
	profile = domain.NormalizeVerificationProfile(profile)
	return domain.VerificationResult{
		ID:            id,
		TenantID:      tenantID,
		SubjectType:   subjectType,
		SubjectID:     subjectID,
		Result:        string(domain.AggregateVerificationState(profile, checks)),
		Checks:        append([]domain.VerifyCheck(nil), checks...),
		Profile:       profile,
		Limitations:   append([]string(nil), profile.Limitations...),
		SchemaVersion: domain.VerificationResultSchemaVersion,
		VerifiedAt:    at,
	}
}

func verificationReturnsFailure(result string) bool {
	return result == string(domain.VerificationStateFailed) || result == string(domain.VerificationStateError)
}

func providerVerificationProfile(provider domain.SSOProvider, tokenSupplied bool, checks []domain.VerifyCheck, limitations []string) domain.VerificationProfile {
	required := requiredCheckNames(checks)
	if !tokenSupplied {
		required = append(required, "provider_credential_signature")
	}
	trustMaterial := []string{"configured " + provider.Type + " provider metadata"}
	switch provider.Type {
	case "oidc":
		trustMaterial = append(trustMaterial, "configured OIDC JWKS")
	case "saml":
		trustMaterial = append(trustMaterial, "configured SAML signing certificates")
	}
	return assuranceProfile("provider-identity-"+provider.Type+".v1", required, trustMaterial, "provider subject must match a verified tenant identity link", "not_evaluated", "provider credential claims and verified identity link", "", limitations)
}

func reassessProviderVerification(record *domain.ProviderVerification, provider domain.SSOProvider, tokenSupplied bool) {
	profile := providerVerificationProfile(provider, tokenSupplied, record.Checks, record.Limitations)
	record.Profile = profile
	record.Result = string(domain.AggregateVerificationState(profile, record.Checks))
}

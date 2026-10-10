package app

import (
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Detached profile translation remains a stateless runtime dependency.
func verificationProfileFromContext(value verificationdomain.VerificationProfile) domain.VerificationProfile {
	return domain.VerificationProfile{
		ID: value.ID, Version: value.Version, RequiredChecks: append([]string(nil), value.RequiredChecks...),
		TrustMaterial: append([]string(nil), value.TrustMaterial...), IdentityPolicy: value.IdentityPolicy,
		TransparencyProof: value.TransparencyProof, PayloadScope: value.PayloadScope, PayloadDigest: value.PayloadDigest,
		Limitations: append([]string(nil), value.Limitations...),
	}
}

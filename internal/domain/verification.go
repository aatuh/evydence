package domain

import verificationdomain "github.com/aatuh/evydence/internal/verification/domain"

type VerificationState string

// VerificationProfile records the exact scope and required checks of an
// assurance decision. It contains identifiers and digests, never raw payloads
// or trust secrets.
type VerificationProfile struct {
	ID                string   `json:"id"`
	Version           string   `json:"version"`
	RequiredChecks    []string `json:"required_checks"`
	TrustMaterial     []string `json:"trust_material,omitempty"`
	IdentityPolicy    string   `json:"identity_policy,omitempty"`
	TransparencyProof string   `json:"transparency_proof,omitempty"`
	PayloadScope      string   `json:"payload_scope,omitempty"`
	PayloadDigest     string   `json:"payload_digest,omitempty"`
	Limitations       []string `json:"limitations"`
}

func NormalizeVerificationProfile(profile VerificationProfile) VerificationProfile {
	return verificationProfileFromContext(
		verificationdomain.NormalizeVerificationProfile(verificationProfileToContext(profile)),
	)
}

// AggregateVerificationState only returns passed when every profile-required
// check is present and passed. This intentionally keeps incomplete, warning,
// and skipped assurance evidence out of the passed state.
func AggregateVerificationState(profile VerificationProfile, checks []VerifyCheck) VerificationState {
	state := verificationdomain.AggregateVerificationState(
		verificationProfileToContext(profile),
		verificationChecksToContext(checks),
	)
	return VerificationState(state.String())
}

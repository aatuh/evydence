package domain

import (
	"sort"
	"strings"
)

const (
	VerificationResultSchemaVersion  = "verification-result.v2.0.0"
	VerificationProfileSchemaVersion = "verification-profile.v1.0.0"
)

type VerificationState string

const (
	VerificationStatePassed      VerificationState = "passed"
	VerificationStateFailed      VerificationState = "failed"
	VerificationStateNotVerified VerificationState = "not_verified"
	VerificationStateLimited     VerificationState = "limited"
	VerificationStateSkipped     VerificationState = "skipped"
	VerificationStateError       VerificationState = "error"
)

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
	profile.ID = strings.TrimSpace(profile.ID)
	profile.Version = strings.TrimSpace(profile.Version)
	if profile.Version == "" {
		profile.Version = VerificationProfileSchemaVersion
	}
	profile.RequiredChecks = normalizedStrings(profile.RequiredChecks)
	profile.TrustMaterial = normalizedStrings(profile.TrustMaterial)
	profile.IdentityPolicy = strings.TrimSpace(profile.IdentityPolicy)
	profile.TransparencyProof = strings.TrimSpace(profile.TransparencyProof)
	profile.PayloadScope = strings.TrimSpace(profile.PayloadScope)
	profile.PayloadDigest = strings.TrimSpace(profile.PayloadDigest)
	profile.Limitations = normalizedStrings(profile.Limitations)
	return profile
}

// AggregateVerificationState only returns passed when every profile-required
// check is present and passed. This intentionally keeps incomplete, warning,
// and skipped assurance evidence out of the passed state.
func AggregateVerificationState(profile VerificationProfile, checks []VerifyCheck) VerificationState {
	profile = NormalizeVerificationProfile(profile)
	if profile.ID == "" || len(profile.RequiredChecks) == 0 {
		return VerificationStateNotVerified
	}

	results := map[string][]string{}
	for _, check := range checks {
		name := strings.TrimSpace(check.Name)
		if name == "" {
			continue
		}
		result := strings.TrimSpace(check.Result)
		results[name] = append(results[name], result)
	}
	if len(results) == 0 {
		return VerificationStateNotVerified
	}

	allSkipped := true
	limited := false
	failed := false
	hadError := false
	for _, required := range profile.RequiredChecks {
		values := results[required]
		if len(values) == 0 {
			limited = true
			allSkipped = false
			continue
		}
		for _, value := range values {
			switch value {
			case string(VerificationStateError):
				hadError = true
			case string(VerificationStateFailed):
				failed = true
			case string(VerificationStateSkipped):
				continue
			case string(VerificationStatePassed):
				allSkipped = false
			default:
				limited = true
				allSkipped = false
			}
		}
	}
	if hadError {
		return VerificationStateError
	}
	if failed {
		return VerificationStateFailed
	}
	if limited {
		return VerificationStateLimited
	}
	if allSkipped {
		return VerificationStateSkipped
	}
	for _, required := range profile.RequiredChecks {
		for _, value := range results[required] {
			if value != string(VerificationStatePassed) {
				return VerificationStateLimited
			}
		}
	}
	return VerificationStatePassed
}

func normalizedStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

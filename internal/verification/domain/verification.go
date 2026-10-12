package domain

import (
	"sort"
	"strings"
	"time"
)

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

func AggregateVerificationState(profile VerificationProfile, checks []VerifyCheck) VerificationState {
	profile = NormalizeVerificationProfile(profile)
	if profile.ID == "" || len(profile.RequiredChecks) == 0 {
		state, _ := ParseVerificationState(VerificationStateNotVerified)
		return state
	}
	results := make(map[string][]string)
	for _, check := range checks {
		name := strings.TrimSpace(check.Name)
		if name != "" {
			results[name] = append(results[name], strings.TrimSpace(check.Result))
		}
	}
	if len(results) == 0 {
		state, _ := ParseVerificationState(VerificationStateNotVerified)
		return state
	}
	allSkipped, limited, failed, hadError := true, false, false, false
	for _, required := range profile.RequiredChecks {
		values := results[required]
		if len(values) == 0 {
			limited, allSkipped = true, false
			continue
		}
		for _, value := range values {
			switch value {
			case VerificationStateError:
				hadError = true
			case VerificationStateFailed:
				failed = true
			case VerificationStateSkipped:
			case VerificationStatePassed:
				allSkipped = false
			default:
				limited, allSkipped = true, false
			}
		}
	}
	value := VerificationStatePassed
	switch {
	case hadError:
		value = VerificationStateError
	case failed:
		value = VerificationStateFailed
	case limited:
		value = VerificationStateLimited
	case allSkipped:
		value = VerificationStateSkipped
	default:
		for _, required := range profile.RequiredChecks {
			for _, result := range results[required] {
				if result != VerificationStatePassed {
					value = VerificationStateLimited
				}
			}
		}
	}
	state, _ := ParseVerificationState(value)
	return state
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

func (key SigningKey) HistoricalValidityAt(signedAt, verificationTime time.Time) string {
	if signedAt.IsZero() || verificationTime.IsZero() || verificationTime.Before(signedAt) {
		return SigningKeyHistoricalValidityOutsideWindow
	}
	validFrom := key.ValidFrom
	if validFrom.IsZero() {
		validFrom = key.CreatedAt
	}
	if validFrom.IsZero() || signedAt.Before(validFrom) {
		return SigningKeyHistoricalValidityOutsideWindow
	}
	validUntil := key.ValidUntil
	if validUntil == nil && key.Status.String() == SigningKeyStatusRevoked && key.RevokedAt != nil && key.RevocationSemantics != SigningKeyRevocationCompromised {
		validUntil = key.RevokedAt
	}
	if validUntil != nil && signedAt.After(*validUntil) {
		return SigningKeyHistoricalValidityOutsideWindow
	}
	if key.RevocationSemantics == SigningKeyRevocationCompromised {
		switch key.HistoricalValidityPolicy {
		case SigningKeyHistoricalValidityInvalidateAll:
			return SigningKeyHistoricalValidityCompromised
		case SigningKeyHistoricalValidityInvalidateFromCompromise:
			compromisedAt := key.CompromisedAt
			if compromisedAt == nil {
				compromisedAt = key.RevokedAt
			}
			if compromisedAt != nil && !signedAt.Before(*compromisedAt) {
				return SigningKeyHistoricalValidityCompromised
			}
		}
	}
	return SigningKeyHistoricalValidityValid
}

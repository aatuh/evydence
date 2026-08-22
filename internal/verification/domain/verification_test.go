package domain

import (
	"reflect"
	"testing"
	"time"
)

func TestVerificationStateAndSigningKeyStatusValidation(t *testing.T) {
	for _, value := range []string{
		VerificationStatePassed,
		VerificationStateFailed,
		VerificationStateNotVerified,
		VerificationStateLimited,
		VerificationStateSkipped,
		VerificationStateError,
	} {
		state, err := ParseVerificationState(" " + value + " ")
		if err != nil || state.String() != value || state.IsZero() {
			t.Fatalf("ParseVerificationState(%q)=(%q, %v)", value, state.String(), err)
		}
	}
	if _, err := ParseVerificationState("unknown"); err == nil {
		t.Fatal("unknown verification state was accepted")
	}
	if !(VerificationState{}).IsZero() {
		t.Fatal("zero verification state was not reported")
	}

	for _, value := range []string{SigningKeyStatusActive, SigningKeyStatusRetiring, SigningKeyStatusRevoked, SigningKeyStatusLegacyUnspecifiedValue} {
		status, err := ParseSigningKeyStatus(" " + value + " ")
		if err != nil || status.String() != value || status.IsZero() {
			t.Fatalf("ParseSigningKeyStatus(%q)=(%q, %v)", value, status.String(), err)
		}
	}
	if _, err := ParseSigningKeyStatus("unknown"); err == nil {
		t.Fatal("unknown signing-key status was accepted")
	}
	if !(SigningKeyStatus{}).IsZero() {
		t.Fatal("zero signing-key status was not reported")
	}
}

func TestNormalizeVerificationProfileCopiesSortsAndDefaults(t *testing.T) {
	input := VerificationProfile{
		ID:             " profile ",
		RequiredChecks: []string{" signature ", "digest", "signature", ""},
		TrustMaterial:  []string{" root-b ", "root-a"},
		IdentityPolicy: " identity ",
		Limitations:    []string{" offline ", "offline"},
	}
	got := NormalizeVerificationProfile(input)
	if got.ID != "profile" || got.Version != VerificationProfileSchemaVersion || got.IdentityPolicy != "identity" {
		t.Fatalf("profile scalar normalization failed: %#v", got)
	}
	if !reflect.DeepEqual(got.RequiredChecks, []string{"digest", "signature"}) ||
		!reflect.DeepEqual(got.TrustMaterial, []string{"root-a", "root-b"}) ||
		!reflect.DeepEqual(got.Limitations, []string{"offline"}) {
		t.Fatalf("profile list normalization failed: %#v", got)
	}
	input.RequiredChecks[0] = "changed"
	if got.RequiredChecks[0] == "changed" {
		t.Fatal("normalization aliased caller-owned slices")
	}
	if normalized := NormalizeVerificationProfile(VerificationProfile{ID: "empty"}); normalized.RequiredChecks != nil {
		t.Fatalf("empty normalized list=%#v, want nil", normalized.RequiredChecks)
	}
}

func TestAggregateVerificationStatePrecedence(t *testing.T) {
	profile := VerificationProfile{ID: "profile", RequiredChecks: []string{"signature", "digest"}}
	tests := []struct {
		name    string
		profile VerificationProfile
		checks  []VerifyCheck
		want    string
	}{
		{name: "missing profile", profile: VerificationProfile{}, want: VerificationStateNotVerified},
		{name: "no checks", profile: profile, want: VerificationStateNotVerified},
		{name: "passed", profile: profile, checks: []VerifyCheck{{Name: "signature", Result: "passed"}, {Name: "digest", Result: "passed"}}, want: VerificationStatePassed},
		{name: "error wins", profile: profile, checks: []VerifyCheck{{Name: "signature", Result: "failed"}, {Name: "digest", Result: "error"}}, want: VerificationStateError},
		{name: "failed", profile: profile, checks: []VerifyCheck{{Name: "signature", Result: "failed"}, {Name: "digest", Result: "passed"}}, want: VerificationStateFailed},
		{name: "missing required", profile: profile, checks: []VerifyCheck{{Name: "signature", Result: "passed"}}, want: VerificationStateLimited},
		{name: "all skipped", profile: profile, checks: []VerifyCheck{{Name: "signature", Result: "skipped"}, {Name: "digest", Result: "skipped"}}, want: VerificationStateSkipped},
		{name: "unknown required result", profile: profile, checks: []VerifyCheck{{Name: "signature", Result: "warning"}, {Name: "digest", Result: "passed"}}, want: VerificationStateLimited},
		{name: "blank check ignored", profile: profile, checks: []VerifyCheck{{Name: "", Result: "passed"}}, want: VerificationStateNotVerified},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := AggregateVerificationState(test.profile, test.checks).String(); got != test.want {
				t.Fatalf("AggregateVerificationState()=%q, want %q", got, test.want)
			}
		})
	}
}

func TestSigningKeyHistoricalValidityPolicies(t *testing.T) {
	now := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	active, _ := ParseSigningKeyStatus(SigningKeyStatusActive)
	revoked, _ := ParseSigningKeyStatus(SigningKeyStatusRevoked)
	validFrom := now.Add(-time.Hour)
	validUntil := now.Add(time.Hour)
	base := SigningKey{Status: active, ValidFrom: validFrom, ValidUntil: &validUntil, CreatedAt: validFrom}
	if got := base.HistoricalValidityAt(now, now.Add(time.Minute)); got != SigningKeyHistoricalValidityValid {
		t.Fatalf("valid key result=%q", got)
	}
	if got := base.HistoricalValidityAt(time.Time{}, now); got != SigningKeyHistoricalValidityOutsideWindow {
		t.Fatalf("zero signature time result=%q", got)
	}
	if got := base.HistoricalValidityAt(now, now.Add(-time.Minute)); got != SigningKeyHistoricalValidityOutsideWindow {
		t.Fatalf("verification before signature result=%q", got)
	}
	if got := (SigningKey{Status: active}).HistoricalValidityAt(now, now); got != SigningKeyHistoricalValidityOutsideWindow {
		t.Fatalf("missing validity origin result=%q", got)
	}
	if got := base.HistoricalValidityAt(validFrom.Add(-time.Minute), now); got != SigningKeyHistoricalValidityOutsideWindow {
		t.Fatalf("signature before validity result=%q", got)
	}
	expired := base
	expired.ValidUntil = &validFrom
	if got := expired.HistoricalValidityAt(now, now); got != SigningKeyHistoricalValidityOutsideWindow {
		t.Fatalf("signature after expiry result=%q", got)
	}
	ordinaryRevoked := base
	ordinaryRevoked.Status = revoked
	ordinaryRevoked.ValidUntil = nil
	ordinaryRevoked.RevocationSemantics = SigningKeyRevocationOrdinary
	revokedAt := now.Add(-time.Minute)
	ordinaryRevoked.RevokedAt = &revokedAt
	if got := ordinaryRevoked.HistoricalValidityAt(now, now); got != SigningKeyHistoricalValidityOutsideWindow {
		t.Fatalf("ordinary revocation result=%q", got)
	}

	compromised := base
	compromised.RevocationSemantics = SigningKeyRevocationCompromised
	compromised.HistoricalValidityPolicy = SigningKeyHistoricalValidityInvalidateAll
	if got := compromised.HistoricalValidityAt(now, now); got != SigningKeyHistoricalValidityCompromised {
		t.Fatalf("invalidate-all result=%q", got)
	}
	compromised.HistoricalValidityPolicy = SigningKeyHistoricalValidityInvalidateFromCompromise
	compromisedAt := now.Add(-time.Minute)
	compromised.CompromisedAt = &compromisedAt
	if got := compromised.HistoricalValidityAt(now, now); got != SigningKeyHistoricalValidityCompromised {
		t.Fatalf("post-compromise signature result=%q", got)
	}
	compromisedAt = now.Add(time.Minute)
	compromised.CompromisedAt = &compromisedAt
	if got := compromised.HistoricalValidityAt(now, now); got != SigningKeyHistoricalValidityValid {
		t.Fatalf("pre-compromise signature result=%q", got)
	}
	compromised.CompromisedAt = nil
	compromised.RevokedAt = &revokedAt
	if got := compromised.HistoricalValidityAt(now, now); got != SigningKeyHistoricalValidityCompromised {
		t.Fatalf("revocation fallback result=%q", got)
	}
}

func TestVerificationProfileDefinitionsAreDefensive(t *testing.T) {
	definitions := VerificationProfileDefinitions()
	if len(definitions) < 12 {
		t.Fatalf("profile definitions=%d, want complete registry", len(definitions))
	}
	definitions[0].RequiredChecks[0] = "changed"
	fresh, ok := VerificationProfileDefinitionFor(definitions[0].ID)
	if !ok || fresh.RequiredChecks[0] == "changed" {
		t.Fatalf("profile registry leaked mutable state: %#v", fresh)
	}
	if _, ok := VerificationProfileDefinitionFor("missing"); ok {
		t.Fatal("unknown profile definition was found")
	}
}

package domain

import (
	"slices"
	"testing"
)

func TestAggregateVerificationStateIsConservativeAndDeterministic(t *testing.T) {
	profile := VerificationProfile{
		ID:             "test.profile",
		Version:        VerificationProfileSchemaVersion,
		RequiredChecks: []string{"signature", "payload"},
	}
	cases := []struct {
		name   string
		checks []VerifyCheck
		want   VerificationState
	}{
		{name: "all required checks pass", checks: []VerifyCheck{{Name: "payload", Result: "passed"}, {Name: "signature", Result: "passed"}}, want: VerificationStatePassed},
		{name: "missing required check is limited", checks: []VerifyCheck{{Name: "signature", Result: "passed"}}, want: VerificationStateLimited},
		{name: "warning is limited", checks: []VerifyCheck{{Name: "signature", Result: "passed"}, {Name: "payload", Result: "warning"}}, want: VerificationStateLimited},
		{name: "all skipped is skipped", checks: []VerifyCheck{{Name: "signature", Result: "skipped"}, {Name: "payload", Result: "skipped"}}, want: VerificationStateSkipped},
		{name: "failed takes precedence", checks: []VerifyCheck{{Name: "signature", Result: "failed"}, {Name: "payload", Result: "passed"}}, want: VerificationStateFailed},
		{name: "failed takes precedence over a missing check", checks: []VerifyCheck{{Name: "signature", Result: "failed"}}, want: VerificationStateFailed},
		{name: "error takes precedence", checks: []VerifyCheck{{Name: "signature", Result: "error"}, {Name: "payload", Result: "passed"}}, want: VerificationStateError},
		{name: "error takes precedence over a missing check", checks: []VerifyCheck{{Name: "signature", Result: "error"}}, want: VerificationStateError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AggregateVerificationState(profile, tc.checks); got != tc.want {
				t.Fatalf("AggregateVerificationState() = %q, want %q", got, tc.want)
			}
		})
	}

	if got := AggregateVerificationState(VerificationProfile{}, []VerifyCheck{{Name: "signature", Result: "passed"}}); got != VerificationStateNotVerified {
		t.Fatalf("unprofiled verification = %q, want %q", got, VerificationStateNotVerified)
	}
}

func TestNormalizeVerificationProfileSortsAndCopies(t *testing.T) {
	profile := VerificationProfile{
		ID:                "  profile  ",
		RequiredChecks:    []string{"signature", "payload", "signature", ""},
		TrustMaterial:     []string{"root-b", "root-a", "root-a", ""},
		Limitations:       []string{"  limited  ", "limited", ""},
		PayloadScope:      "  raw attestation bytes  ",
		IdentityPolicy:    "  subject-bound  ",
		TransparencyProof: "  verified  ",
	}

	normalized := NormalizeVerificationProfile(profile)
	if normalized.ID != "profile" || normalized.Version != VerificationProfileSchemaVersion {
		t.Fatalf("normalized identity = %#v", normalized)
	}
	if got, want := normalized.RequiredChecks, []string{"payload", "signature"}; !sameStrings(got, want) {
		t.Fatalf("required checks = %#v, want %#v", got, want)
	}
	if got, want := normalized.TrustMaterial, []string{"root-a", "root-b"}; !sameStrings(got, want) {
		t.Fatalf("trust material = %#v, want %#v", got, want)
	}
	if got, want := normalized.Limitations, []string{"limited"}; !sameStrings(got, want) {
		t.Fatalf("limitations = %#v, want %#v", got, want)
	}
	if normalized.PayloadScope != "raw attestation bytes" || normalized.IdentityPolicy != "subject-bound" || normalized.TransparencyProof != "verified" {
		t.Fatalf("normalized scalar fields = %#v", normalized)
	}
	profile.RequiredChecks[0] = "mutated"
	if normalized.RequiredChecks[1] != "signature" {
		t.Fatalf("normalized profile aliases caller slices: %#v", normalized.RequiredChecks)
	}
}

func sameStrings(got, want []string) bool {
	return slices.Equal(got, want)
}

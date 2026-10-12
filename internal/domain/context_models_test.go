package domain_test

import (
	"reflect"
	"testing"
	"time"

	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestContextReleaseConstructorAndTransitionsRejectInvalidStates(t *testing.T) {
	now := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	if _, err := releasedomain.NewRelease("", "ten_1", "prod_1", "1.0.0", now); err == nil {
		t.Fatal("release constructor accepted an empty ID")
	}
	release, err := releasedomain.NewRelease("rel_1", "ten_1", "prod_1", "1.0.0", now)
	if err != nil {
		t.Fatalf("NewRelease: %v", err)
	}
	if release.State.String() != releasedomain.ReleaseStateDraftValue || release.Revision != 1 {
		t.Fatalf("new release state=%q revision=%d", release.State.String(), release.Revision)
	}
	if _, err := release.Approve(now.Add(time.Minute)); err == nil {
		t.Fatal("draft release skipped the frozen transition")
	}
	frozen, err := release.Freeze(now.Add(time.Minute))
	if err != nil || frozen.State.String() != releasedomain.ReleaseStateFrozenValue || frozen.Revision != 2 {
		t.Fatalf("Freeze()=(%#v, %v)", frozen, err)
	}
	approved, err := frozen.Approve(now.Add(2 * time.Minute))
	if err != nil || approved.State.String() != releasedomain.ReleaseStateApprovedValue || approved.Revision != 3 {
		t.Fatalf("Approve()=(%#v, %v)", approved, err)
	}
	if _, err := approved.Freeze(now.Add(3 * time.Minute)); err == nil {
		t.Fatal("approved release transitioned backwards")
	}
}

func TestContextStableStateParsersRejectUnknownValues(t *testing.T) {
	tests := []struct {
		name  string
		parse func(string) error
	}{
		{"release", func(value string) error { _, err := releasedomain.ParseReleaseState(value); return err }},
		{"candidate", func(value string) error { _, err := releasedomain.ParseReleaseCandidateState(value); return err }},
		{"evidence lifecycle", func(value string) error { _, err := evidencedomain.ParseEvidenceLifecycleState(value); return err }},
		{"decision", func(value string) error { _, err := riskdomain.ParseDecisionStatus(value); return err }},
		{"bundle", func(value string) error { _, err := packagedomain.ParseBundleState(value); return err }},
		{"verification", func(value string) error { _, err := verificationdomain.ParseVerificationState(value); return err }},
		{"signing key", func(value string) error { _, err := verificationdomain.ParseSigningKeyStatus(value); return err }},
		{"incident", func(value string) error { _, err := operationsdomain.ParseIncidentStatus(value); return err }},
		{"collector", func(value string) error { _, err := integrationdomain.ParseCollectorStatus(value); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.parse("unknown"); err == nil {
				t.Fatal("unknown state was accepted")
			}
		})
	}
}

func TestContextIdentityAndEvidenceConstructorsNormalizeDefensively(t *testing.T) {
	actor, err := identitydomain.NewActor(" ten_1 ", []string{"evidence:read", " evidence:read ", "release:read"})
	if err != nil {
		t.Fatalf("NewActor: %v", err)
	}
	if actor.TenantID != "ten_1" || !reflect.DeepEqual(actor.Scopes, []string{"evidence:read", "release:read"}) {
		t.Fatalf("actor was not normalized: %#v", actor)
	}
	if !actor.HasScope("evidence:read") || actor.HasScope("") {
		t.Fatalf("actor scope behavior is invalid: %#v", actor)
	}
	if _, err := identitydomain.NewActor("", nil); err == nil {
		t.Fatal("actor constructor accepted an empty tenant")
	}
	reference, err := evidencedomain.NewSubjectReference(" artifact ", " art_1 ", " sha256:abc ")
	if err != nil || reference.Type != "artifact" || reference.ID != "art_1" || reference.Digest != "sha256:abc" {
		t.Fatalf("NewSubjectReference()=(%#v, %v)", reference, err)
	}
}

func TestContextVerificationPolicyIsConservativeAndExcludesPrivateMaterial(t *testing.T) {
	profile := verificationdomain.VerificationProfile{ID: "profile", RequiredChecks: []string{"signature", "digest"}}
	checks := []verificationdomain.VerifyCheck{
		{Name: "signature", Result: verificationdomain.VerificationStatePassed},
		{Name: "digest", Result: verificationdomain.VerificationStateError},
	}
	if state := verificationdomain.AggregateVerificationState(profile, checks); state.String() != verificationdomain.VerificationStateError {
		t.Fatalf("aggregate state=%q, want error", state.String())
	}
	if _, ok := reflect.TypeOf(verificationdomain.SigningKey{}).FieldByName("Private"); ok {
		t.Fatal("context signing-key metadata exposes private key material")
	}
	definitions := verificationdomain.VerificationProfileDefinitions()
	if len(definitions) < 12 {
		t.Fatalf("verification profile definitions=%d, want complete registry", len(definitions))
	}
	definitions[0].RequiredChecks[0] = "mutated"
	fresh, ok := verificationdomain.VerificationProfileDefinitionFor(definitions[0].ID)
	if !ok || fresh.RequiredChecks[0] == "mutated" {
		t.Fatalf("verification context leaked mutable profile policy: %#v", fresh)
	}
}

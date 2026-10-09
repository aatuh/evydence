package domain

import "testing"

func TestBundleStateValidationAndTransitions(t *testing.T) {
	generated, err := ParseBundleState(" " + BundleStateGeneratedValue + " ")
	if err != nil || generated.String() != BundleStateGeneratedValue || generated.IsZero() {
		t.Fatalf("ParseBundleState(generated)=(%q, %v)", generated.String(), err)
	}
	published, _ := ParseBundleState(BundleStatePublishedValue)
	revoked, _ := ParseBundleState(BundleStateRevokedValue)
	if !generated.CanTransitionTo(published) || !generated.CanTransitionTo(revoked) || !published.CanTransitionTo(revoked) {
		t.Fatal("valid bundle transition was rejected")
	}
	if revoked.CanTransitionTo(generated) || published.CanTransitionTo(generated) {
		t.Fatal("invalid bundle transition was accepted")
	}
	if _, err := ParseBundleState("unknown"); err == nil {
		t.Fatal("unknown bundle state was accepted")
	}
	if !(BundleState{}).IsZero() {
		t.Fatal("zero bundle state was not reported")
	}
}

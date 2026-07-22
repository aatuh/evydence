package app

import (
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestNormalizeStateMapsLegacyRetentionClaimsConservatively(t *testing.T) {
	state := normalizeState(PersistedState{ObjectRetentionPolicies: map[string]domain.ObjectRetentionPolicy{
		"legacy": {ID: "legacy", Status: "verified", SchemaVersion: "object-retention-policy.v1.0.0"},
	}})
	policy := state.ObjectRetentionPolicies["legacy"]
	if policy.Status != "not_verified" || policy.SchemaVersion != domain.ObjectRetentionPolicyVersion || policy.MaxVerificationAgeHours != defaultRetentionVerificationAgeHours {
		t.Fatalf("legacy retention policy = %#v", policy)
	}
	if len(policy.VerificationLimitations) != 1 {
		t.Fatalf("legacy retention limitation = %#v", policy.VerificationLimitations)
	}
}

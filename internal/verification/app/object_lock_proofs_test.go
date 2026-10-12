package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestObjectLockProofsAreOrderedRedactedFreshAndDetached(t *testing.T) {
	now := time.Now().UTC()
	expired, future := now, now.Add(time.Hour)
	policies := []verificationdomain.ObjectRetentionPolicy{
		{ID: "z", Name: "Fresh", Status: "verified", VerificationExpiresAt: &future, VerificationChecks: []verificationdomain.VerifyCheck{{Name: "z", Result: "passed"}, {Name: "a", Result: "passed"}}, ObjectPrefix: "private-prefix", ObjectKey: "private-key", VerificationBucket: "private-bucket", CreatedAt: now},
		{ID: "a", Status: "verified", VerificationExpiresAt: &expired, CreatedAt: now},
		{ID: "b", Status: "configured", CreatedAt: now},
	}
	proofs := ObjectLockProofs(policies, now)
	if len(proofs) != 3 || proofs[0]["id"] != "a" || proofs[0]["status"] != "stale" || proofs[1]["status"] != "configured" || proofs[2]["status"] != "verified" {
		t.Fatalf("proofs=%#v", proofs)
	}
	checks := proofs[2]["verification_checks"].([]map[string]any)
	if checks[0]["name"] != "a" || proofs[2]["object_prefix_configured"] != true || proofs[2]["sample_object_key_configured"] != true {
		t.Fatal(proofs[2])
	}
	encoded, err := json.Marshal(proofs)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-prefix", "private-key", "private-bucket"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
	checks[0]["result"] = "tampered"
	if policies[0].VerificationChecks[0].Result != "passed" || policies[1].Status != "verified" || len(policies[1].VerificationChecks) != 0 {
		t.Fatal("renderer mutated source policies")
	}
	if len(ObjectLockProofs(nil, now)) != 0 {
		t.Fatal("empty policy set grew facts")
	}
}

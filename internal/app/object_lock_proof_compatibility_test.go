package app

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestObjectLockProofRendererMatchesLegacyManifest(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	expired, future := now.Add(-time.Hour), now.Add(time.Hour)
	hold := true
	policies := []domain.ObjectRetentionPolicy{
		{ID: "policy_z", TenantID: "tenant", Name: "Fresh", ObjectPrefix: "private/prefix", ObjectKey: "private/key", RequireLegalHold: true, Mode: "COMPLIANCE", RetentionDays: 30, Status: "verified", VerificationHash: "sha256:observation", VerifiedAt: &now, VerificationProvider: "minio", VerificationMode: "COMPLIANCE", VerificationRetentionDays: 30, VerificationLegalHold: &hold, VerificationObservedAt: &now, VerificationExpiresAt: &future, CreatedAt: now, VerificationChecks: []domain.VerifyCheck{{Name: "z", Result: "passed"}, {Name: "a", Result: "passed"}}, VerificationLimitations: []string{"provider scope"}},
		{ID: "policy_a", TenantID: "tenant", Name: "Stale", Status: "verified", VerificationExpiresAt: &expired, CreatedAt: now},
		{ID: "policy_missing_expiry", TenantID: "tenant", Name: "Unbounded", Status: "verified", CreatedAt: now},
	}
	ledger := &Ledger{now: func() time.Time { return now }, retentionPolicies: map[string]domain.ObjectRetentionPolicy{}}
	core := make([]verificationdomain.ObjectRetentionPolicy, 0, len(policies))
	for _, policy := range policies {
		ledger.retentionPolicies[policy.ID] = policy
		core = append(core, objectRetentionPolicyToVerificationContext(policy))
	}
	ledger.retentionPolicies["foreign"] = domain.ObjectRetentionPolicy{ID: "foreign", TenantID: "other"}
	legacy, err := json.Marshal(ledger.packageObjectLockProofsLocked("tenant"))
	if err != nil {
		t.Fatal(err)
	}
	golden, err := canonicalAnyHash(ledger.packageObjectLockProofsLocked("tenant"))
	if err != nil {
		t.Fatal(err)
	}
	if golden != "sha256:ea70f0c1f86252aa38ebd1f92f1f7817a85ca38d944f269bf547d120c7c15a91" {
		t.Fatalf("legacy proof hash changed: %s", golden)
	}
	actual, err := json.Marshal(verificationapp.ObjectLockProofs(core, now))
	if err != nil || string(actual) != string(legacy) {
		t.Fatalf("proof compatibility mismatch:\n%s\n%s\n%v", legacy, actual, err)
	}
}

package app

import (
	"sort"
	"time"

	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// ObjectLockProofs renders the existing package-safe retention observation
// metadata. It omits object paths and provider bucket names, preserves current
// verification limitations, and never upgrades configuration to provider proof.
// Callers must supply only policies owned by the requested tenant.
func ObjectLockProofs(policies []verificationdomain.ObjectRetentionPolicy, now time.Time) []map[string]any {
	proofs := make([]map[string]any, 0, len(policies))
	for _, stored := range policies {
		policy := currentRetentionPolicy(stored, now)
		checks := make([]map[string]any, 0, len(policy.VerificationChecks))
		for _, check := range policy.VerificationChecks {
			checks = append(checks, map[string]any{"name": check.Name, "result": check.Result, "detail": check.Detail})
		}
		sort.Slice(checks, func(i, j int) bool { return checks[i]["name"].(string) < checks[j]["name"].(string) })
		proof := map[string]any{
			"id": policy.ID, "name": policy.Name,
			"object_prefix_configured": policy.ObjectPrefix != "", "sample_object_key_configured": policy.ObjectKey != "",
			"require_legal_hold": policy.RequireLegalHold, "mode": policy.Mode, "retention_days": policy.RetentionDays,
			"status": policy.Status, "verification_hash": policy.VerificationHash,
			"verification_provider": policy.VerificationProvider, "verification_mode": policy.VerificationMode,
			"verification_retention_days": policy.VerificationRetentionDays,
			"verification_checks":         checks, "verification_limitations": append([]string(nil), policy.VerificationLimitations...),
			"created_at": policy.CreatedAt.UTC().Format(time.RFC3339),
			"limitations": []string{
				"Object-lock proof records show configured Evydence verification results for tenant object-storage settings only.",
				"They do not prove external WORM enforcement, IAM policy, lifecycle policy, backup behavior, or legal compliance.",
			},
		}
		if policy.VerifiedAt != nil {
			proof["verified_at"] = policy.VerifiedAt.UTC().Format(time.RFC3339)
		}
		if policy.VerificationObservedAt != nil {
			proof["verification_observed_at"] = policy.VerificationObservedAt.UTC().Format(time.RFC3339)
		}
		if policy.VerificationExpiresAt != nil {
			proof["verification_expires_at"] = policy.VerificationExpiresAt.UTC().Format(time.RFC3339)
		}
		if policy.VerificationLegalHold != nil {
			proof["verification_legal_hold"] = *policy.VerificationLegalHold
		}
		proofs = append(proofs, proof)
	}
	sort.Slice(proofs, func(i, j int) bool { return proofs[i]["id"].(string) < proofs[j]["id"].(string) })
	return proofs
}

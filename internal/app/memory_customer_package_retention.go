package app

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Tenant-wide public observation facts, after validating the package roots.
// Neither raw object paths nor provider buckets enter the projection. This
// typed fixture model cannot establish native SQL JSON-shape guarantees.
func readMemoryCustomerPackageRetention(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, product, release string, at time.Time, budget *memoryCustomerSnapshotBudget) ([]map[string]any, error) {
	if err := validateMemoryCustomerSnapshotRead(ctx, s, tenant, product, release, budget); err != nil {
		return nil, err
	}
	at = at.UTC()
	if at.IsZero() || at.Year() < 1 || at.Year() > 9999 {
		return nil, ErrValidation
	}
	working := *budget
	policies := []verificationdomain.ObjectRetentionPolicy{}
	details := 0
	for key, p := range s.ObjectRetentionPolicies {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if p.TenantID != tenant {
			continue
		}
		if p.ID != key || !memoryCustomerSnapshotID(key, false) || len(policies) == packageapp.MaxBundleSnapshotRows || p.RetentionDays < 0 || p.VerificationRetentionDays < 0 || len(p.VerificationChecks) > 4096-details || len(p.VerificationLimitations) > 4096-details-len(p.VerificationChecks) {
			return nil, ErrConflict
		}
		details += len(p.VerificationChecks) + len(p.VerificationLimitations)
		for _, value := range []struct {
			text  string
			limit int
		}{{p.Name, 4096}, {p.Mode, 64}, {p.Status, 64}, {p.VerificationHash, 1024}, {p.VerificationProvider, 64}, {p.VerificationMode, 64}} {
			if !memoryGovernanceText(value.text, value.limit) {
				return nil, ErrConflict
			}
		}
		checks := make([]map[string]any, 0, len(p.VerificationChecks))
		for _, c := range p.VerificationChecks {
			checks = append(checks, map[string]any{"name": c.Name, "result": c.Result, "detail": c.Detail})
		}
		row := map[string]any{"id": p.ID, "name": p.Name, "mode": p.Mode, "status": p.Status, "retention_days": p.RetentionDays, "verification_retention_days": p.VerificationRetentionDays, "verification_hash": p.VerificationHash, "verification_provider": p.VerificationProvider, "verification_mode": p.VerificationMode, "checks": checks, "limitations": p.VerificationLimitations}
		if err := memoryCustomerMetadataTimes(row, map[string]time.Time{"created_at": p.CreatedAt}, map[string]*time.Time{"verified_at": p.VerifiedAt, "observed_at": p.VerificationObservedAt, "expires_at": p.VerificationExpiresAt}); err != nil {
			return nil, err
		}
		if err := working.charge(row); err != nil {
			return nil, err
		}
		public := verificationdomain.ObjectRetentionPolicy{ID: p.ID, TenantID: tenant, Name: p.Name, RequireLegalHold: p.RequireLegalHold, Mode: p.Mode, RetentionDays: p.RetentionDays, Status: p.Status, VerificationHash: p.VerificationHash, VerificationProvider: p.VerificationProvider, VerificationMode: p.VerificationMode, VerificationRetentionDays: p.VerificationRetentionDays, VerificationLimitations: slices.Clone(p.VerificationLimitations), CreatedAt: p.CreatedAt.UTC(), VerifiedAt: cloneTimePtr(p.VerifiedAt), VerificationObservedAt: cloneTimePtr(p.VerificationObservedAt), VerificationExpiresAt: cloneTimePtr(p.VerificationExpiresAt)}
		if p.ObjectPrefix != "" {
			public.ObjectPrefix = "configured"
		}
		if p.ObjectKey != "" {
			public.ObjectKey = "configured"
		}
		if p.VerificationLegalHold != nil {
			hold := *p.VerificationLegalHold
			public.VerificationLegalHold = &hold
		}
		for _, c := range p.VerificationChecks {
			public.VerificationChecks = append(public.VerificationChecks, verificationdomain.VerifyCheck{Name: c.Name, Result: c.Result, Detail: c.Detail})
		}
		policies = append(policies, public)
	}
	proofs := verificationapp.ObjectLockProofs(policies, at)
	raw, err := json.Marshal(proofs)
	if err != nil {
		return nil, ErrConflict
	}
	output := *budget
	if err := output.chargeJSON(raw); err != nil {
		return nil, err
	}
	if output.remainingBytes < working.remainingBytes {
		working = output
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	*budget = working
	return proofs, nil
}

package app

import (
	"context"
	"encoding/json"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

var _ verificationapp.RetentionPolicyReader = memoryIntegrityRepository{}

// Current typed fixture policy reads, not SQL row locking or provider proof.
// Replay reads identity only, so changed/oversized observations cannot prevent
// an otherwise authorized replay of its original stored response.
func (r memoryIntegrityRepository) LockObjectRetentionPolicy(ctx context.Context, tenant, id string) error {
	if !memoryMembershipQueryText(id, 1024) {
		return ErrValidation
	}
	return memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.ObjectRetentionPolicies[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		return nil
	})
}

func (r memoryIntegrityRepository) GetObjectRetentionPolicyForUpdate(ctx context.Context, tenant, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	return r.ReadObjectRetentionPolicy(ctx, tenant, id)
}

func (r memoryIntegrityRepository) ReadObjectRetentionPolicy(ctx context.Context, tenant, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	var out verificationdomain.ObjectRetentionPolicy
	if !memoryMembershipQueryText(id, 1024) {
		return out, ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.ObjectRetentionPolicies[id]
		if !ok || v.TenantID != tenant {
			return ErrNotFound
		}
		if v.ID != id {
			return ErrConflict
		}
		// Even empty facts consume JSON structure. Check the minimum encoded
		// size before iterating or allocating a detached observation.
		remaining := verificationapp.MaxRetentionPolicyBytes
		if len(v.VerificationChecks) > remaining/len(`{"name":"","result":""}`) {
			return ErrConflict
		}
		remaining -= len(v.VerificationChecks) * len(`{"name":"","result":""}`)
		if len(v.VerificationLimitations) > remaining/2 {
			return ErrConflict
		}
		remaining -= len(v.VerificationLimitations) * 2
		consume := func(text string) bool {
			if !memoryGovernanceText(text, remaining) {
				return false
			}
			remaining -= len(text)
			return true
		}
		for _, text := range []string{v.ID, v.TenantID, v.Name, v.ObjectPrefix, v.ObjectKey, v.Mode, v.Status, v.VerificationHash, v.VerificationProvider, v.VerificationBucket, v.VerificationMode, v.SchemaVersion} {
			if !consume(text) {
				return ErrConflict
			}
		}
		for _, c := range v.VerificationChecks {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !consume(c.Name) || !consume(c.Result) || !consume(c.Detail) {
				return ErrConflict
			}
		}
		for _, text := range v.VerificationLimitations {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !consume(text) {
				return ErrConflict
			}
		}
		raw, err := json.Marshal(v)
		if err != nil || len(raw) > verificationapp.MaxRetentionPolicyBytes {
			return ErrConflict
		}
		out = domain.ObjectRetentionPolicyToContextModel(v)
		return ctx.Err()
	})
	if err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	return out, nil
}

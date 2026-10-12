package app

import (
	"context"
	"encoding/json"

	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

var _ verificationapp.BackupVerificationReader = memoryVerificationRepository{}

// Only fixture ownership is modeled. No state hash, consistency checks or
// restore observations are read by this replay guard.
func (r memoryVerificationRepository) LockBackupVerificationScope(ctx context.Context, tenant, id string) error {
	if !memoryMembershipQueryText(id, 1024) {
		return ErrValidation
	}
	return memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.BackupManifests[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		return nil
	})
}

// This current typed view selects recorded check facts only. It cannot prove
// SQL locking, durability, live backup contents or successful restoration.
func (r memoryVerificationRepository) ReadBackupVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.BackupVerificationSnapshot, error) {
	var out verificationapp.BackupVerificationSnapshot
	if subject.Type != "backup_manifest" || subject.Resources != (application.ResourceReferences{}) || !memoryMembershipQueryText(subject.ID, 1024) {
		return out, ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, subject.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.BackupManifests[subject.ID]
		if !ok || v.TenantID != subject.TenantID {
			return ErrNotFound
		}
		if v.ID != subject.ID || v.ConsistencyChecks == nil || len(v.ConsistencyChecks) > verificationapp.MaxBackupVerificationChecks || !memoryGovernanceText(v.StateHash, 1024) {
			return ErrConflict
		}
		remaining := verificationapp.MaxBackupVerificationBytes - len(v.StateHash) - 2
		checks := make([]verificationdomain.VerifyCheck, 0, len(v.ConsistencyChecks))
		for i, c := range v.ConsistencyChecks {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !memoryGovernanceText(c.Name, 128) || !memoryGovernanceText(c.Result, 64) || !memoryGovernanceText(c.Detail, 1024) {
				return ErrConflict
			}
			check := verificationdomain.VerifyCheck(c)
			raw, err := json.Marshal(check)
			separator := 0
			if i > 0 {
				separator = 1
			}
			if err != nil || len(raw)+separator > remaining {
				return ErrConflict
			}
			remaining -= len(raw) + separator
			checks = append(checks, check)
		}
		out = verificationapp.BackupVerificationSnapshot{Subject: subject, StateHash: v.StateHash, Checks: checks}
		return ctx.Err()
	})
	if err != nil {
		return verificationapp.BackupVerificationSnapshot{}, err
	}
	return out, nil
}

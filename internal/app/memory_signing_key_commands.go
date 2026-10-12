package app

import (
	"context"
	"sort"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

var _ verificationapp.SigningKeyScopeLocker = memorySignatureRepository{}

// Test-adapter capabilities read the current typed transaction view. They do
// not establish SQL row locks, transfer bounds, key custody or storage encryption.
func (r memorySignatureRepository) LockSigningKeyScope(ctx context.Context, tenant, raw string) error {
	id, err := verificationapp.NormalizeSigningKeyID(raw)
	if err != nil {
		return ErrValidation
	}
	return memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		key, ok := s.SigningKeys[id]
		if !ok || key.ID != id || key.TenantID != tenant {
			return ErrNotFound
		}
		return nil
	})
}

func (r memorySignatureRepository) GetSigningKeyForUpdate(ctx context.Context, tenant, raw string) (verificationdomain.SigningKey, error) {
	id, err := verificationapp.NormalizeSigningKeyID(raw)
	if err != nil {
		return verificationdomain.SigningKey{}, ErrValidation
	}
	var out verificationdomain.SigningKey
	err = memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		key, ok := s.SigningKeys[id]
		if !ok || key.TenantID != tenant {
			return ErrNotFound
		}
		if key.ID != id {
			return ErrConflict
		}
		var err error
		out, _, err = memorySigningAdminKey(key)
		return err
	})
	if err != nil {
		return verificationdomain.SigningKey{}, err
	}
	return out, nil
}

func (r memorySignatureRepository) ListLocalSigningKeysForUpdate(ctx context.Context, tenant string) ([]verificationdomain.SigningKey, error) {
	var out []verificationdomain.SigningKey
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		keys := make([]verificationdomain.SigningKey, 0)
		budget := 8 << 20
		for id, key := range s.SigningKeys {
			if err := ctx.Err(); err != nil {
				return err
			}
			if key.TenantID != tenant || key.Provider != "" && key.Provider != verificationdomain.SigningKeyDefaultProvider {
				continue
			}
			if key.ID != id || len(keys) == verificationapp.MaxSigningRotationKeys {
				return ErrConflict
			}
			v, size, err := memorySigningAdminKey(key)
			if err != nil || size > budget {
				return ErrConflict
			}
			budget -= size
			keys = append(keys, v)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
		out = keys
		return ctx.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func memorySigningAdminKey(key domain.SigningKey) (verificationdomain.SigningKey, int, error) {
	status, err := verificationdomain.ParseSigningKeyStatus(key.Status)
	if err != nil || key.ID == "" || key.TenantID == "" || key.KID == "" || key.Algorithm == "" || key.PublicKey == "" || key.Version < 1 || key.Version > 2147483647 || key.CreatedAt.IsZero() || key.ValidFrom.IsZero() {
		return verificationdomain.SigningKey{}, 0, ErrConflict
	}
	size := 0
	for _, field := range []struct {
		value string
		limit int
	}{
		{key.ID, 1024}, {key.TenantID, 1024}, {key.KID, 1024}, {key.Provider, 64},
		{key.Algorithm, 64}, {key.Status, 64}, {key.PublicKey, 16384}, {key.PublicKeyFingerprint, 1024},
		{key.RevocationReason, 4096}, {key.RevocationSemantics, 64}, {key.HistoricalValidityPolicy, 64},
	} {
		if !memoryGovernanceText(field.value, field.limit) {
			return verificationdomain.SigningKey{}, 0, ErrConflict
		}
		size += len(field.value)
	}
	// Private bytes are neither copied into the DTO nor inspected by this read.
	return verificationdomain.SigningKey{ID: key.ID, TenantID: key.TenantID, KID: key.KID, Version: key.Version, Provider: key.Provider, Algorithm: key.Algorithm, Status: status, PublicKey: key.PublicKey, PublicKeyFingerprint: key.PublicKeyFingerprint, ValidFrom: key.ValidFrom.UTC(), ValidUntil: cloneTimePtr(key.ValidUntil), CreatedAt: key.CreatedAt.UTC(), RevokedAt: cloneTimePtr(key.RevokedAt), RevocationReason: key.RevocationReason, RevocationSemantics: key.RevocationSemantics, HistoricalValidityPolicy: key.HistoricalValidityPolicy, CompromisedAt: cloneTimePtr(key.CompromisedAt)}, size, nil
}

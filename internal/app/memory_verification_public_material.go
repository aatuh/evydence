package app

import (
	"context"
	"encoding/json"
	"slices"

	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type memoryVerificationPublicMaterial struct {
	Signatures []verificationdomain.Signature
	Keys       []verificationdomain.SigningKey
}

// Common bounded public material for fixture verification snapshots. Callers
// discard partial construction on failure; no private key field is selected.
func readMemoryVerificationPublicMaterial(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant string, refs []string, budget *memoryCustomerSnapshotBudget, out *memoryVerificationPublicMaterial) error {
	seen := map[string]bool{}
	keys := map[string]bool{}
	ids := slices.Clone(refs)
	slices.Sort(ids)
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !memoryCustomerSnapshotID(id, false) || seen[id] {
			return ErrConflict
		}
		seen[id] = true
		v, ok := s.Signatures[id]
		if !ok || v.TenantID != tenant {
			continue
		}
		if v.ID != id {
			return ErrConflict
		}
		for _, field := range []struct {
			v string
			n int
		}{{v.ID, 1024}, {v.TenantID, 1024}, {v.SubjectType, 64}, {v.SubjectID, 1024}, {v.KeyID, 1024}, {v.Algorithm, 64}, {v.Value, 16384}} {
			if !memoryGovernanceText(field.v, field.n) {
				return ErrConflict
			}
		}
		public := verificationdomain.Signature(v)
		raw, err := json.Marshal(public)
		if err != nil {
			return ErrConflict
		}
		if err := budget.chargeJSON(raw); err != nil {
			return err
		}
		out.Signatures = append(out.Signatures, public)
		keys[v.KeyID] = true
	}
	keyIDs := make([]string, 0, len(keys))
	for id := range keys {
		keyIDs = append(keyIDs, id)
	}
	slices.Sort(keyIDs)
	for _, id := range keyIDs {
		if err := ctx.Err(); err != nil {
			return err
		}
		v, ok := s.SigningKeys[id]
		if !ok || v.TenantID != tenant {
			continue
		}
		if v.ID != id {
			return ErrConflict
		}
		for _, field := range []struct {
			v string
			n int
		}{{v.ID, 1024}, {v.TenantID, 1024}, {v.Algorithm, 64}, {v.PublicKey, 16384}, {v.Status, 64}, {v.RevocationSemantics, 64}, {v.HistoricalValidityPolicy, 64}} {
			if !memoryGovernanceText(field.v, field.n) {
				return ErrConflict
			}
		}
		status := v.Status
		if status == "" {
			status = verificationdomain.SigningKeyStatusLegacyUnspecifiedValue
		}
		parsed, err := verificationdomain.ParseSigningKeyStatus(status)
		if err != nil {
			return ErrConflict
		}
		public := verificationdomain.SigningKey{ID: v.ID, TenantID: v.TenantID, Algorithm: v.Algorithm, Status: parsed, PublicKey: v.PublicKey, CreatedAt: v.CreatedAt, ValidFrom: v.ValidFrom, ValidUntil: cloneTimePtr(v.ValidUntil), RevokedAt: cloneTimePtr(v.RevokedAt), CompromisedAt: cloneTimePtr(v.CompromisedAt), RevocationSemantics: v.RevocationSemantics, HistoricalValidityPolicy: v.HistoricalValidityPolicy}
		raw, err := json.Marshal(public)
		if err != nil {
			return ErrConflict
		}
		if err := budget.chargeJSON(raw); err != nil {
			return err
		}
		out.Keys = append(out.Keys, public)
	}
	return ctx.Err()
}

package app

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// Current transaction-owned facts for focused relationship commands. These
// test-backend reads do not model PostgreSQL row locking or transfer bounds.
func (r memoryEvidenceRepository) LockRelationshipTenant(ctx context.Context, tenant string) error {
	_, err := r.ResolveEvidenceCreationScope(ctx, tenant, application.ResourceReferences{})
	return err
}
func (r memoryEvidenceRepository) LockRelationshipEvidence(ctx context.Context, tenant, id string) (application.ResourceReferences, error) {
	return r.LockEvidenceBundleEvidence(ctx, tenant, id)
}
func (r memoryEvidenceRepository) LockRelationshipTarget(ctx context.Context, tenant, kind, id string) (application.ResourceReferences, error) {
	refs := application.ResourceReferences{}
	switch kind {
	case "product":
		refs.ProductID = id
	case "release":
		refs.ReleaseID = id
	default:
		return refs, ErrValidation
	}
	if !memoryMembershipQueryText(id, 1024) {
		return refs, ErrValidation
	}
	return r.ResolveEvidenceCreationScope(ctx, tenant, refs)
}
func (r memoryEvidenceRepository) ReadRelationshipEvidence(ctx context.Context, tenant, id string) (evidencedomain.EvidenceItem, error) {
	var out evidencedomain.EvidenceItem
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		if _, err := memoryBundleEvidenceCoordinates(s, tenant, id); err != nil {
			return err
		}
		remaining := verificationapp.MaxEvidenceVerificationBytes
		v, err := readMemoryEvidenceWithProvenance(ctx, s, s.Evidence[id], &remaining)
		if err != nil {
			return err
		}
		out = domain.EvidenceToContextModel(v)
		return nil
	})
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	return out, nil
}
func (r memoryEvidenceRepository) ReadRelationshipOrigins(ctx context.Context, tenant, id string) ([]evidencedomain.EvidenceLifecycleEvent, error) {
	var out []evidencedomain.EvidenceLifecycleEvent
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		if _, err := memoryBundleEvidenceCoordinates(s, tenant, id); err != nil {
			return err
		}
		remaining := 8 << 20
		out = make([]evidencedomain.EvidenceLifecycleEvent, 0)
		for key, e := range s.EvidenceLifecycle {
			origin, exists := e.Details[evidencedomain.LegacyCanonicalOriginDetailKey]
			if e.TenantID != tenant || e.EvidenceID != id || e.SchemaVersion != evidencedomain.EvidenceRelationshipLifecycleSchemaVersion || !exists {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			action, err := evidencedomain.ParseEvidenceLifecycleState(e.Action)
			if err != nil || !memoryMembershipQueryText(key, 1024) || e.ID != key || len(out) == 4096 {
				return ErrConflict
			}
			selected := domain.EvidenceLifecycleEvent{ID: e.ID, TenantID: tenant, EvidenceID: id, Action: e.Action, SchemaVersion: e.SchemaVersion, Details: map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: origin}}
			raw, err := json.Marshal(selected)
			if err != nil || len(raw) > remaining {
				return ErrConflict
			}
			remaining -= len(raw)
			detached, err := cloneMemoryEvidenceRecord(selected)
			if err != nil {
				return ErrConflict
			}
			out = append(out, evidencedomain.EvidenceLifecycleEvent{ID: e.ID, TenantID: tenant, EvidenceID: id, Action: action, SchemaVersion: e.SchemaVersion, Details: detached.Details})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return ctx.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ evidenceapp.RelationshipScopeTransaction = memoryEvidenceRepository{}

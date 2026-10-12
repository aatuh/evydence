package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

var _ verificationapp.EvidenceVerificationReader = memoryVerificationRepository{}

func (r memoryVerificationRepository) ResolveEvidenceVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	refs, err := memoryEvidenceRepository(r).LockEvidenceBundleEvidence(ctx, tenant, id)
	if err != nil {
		return verificationapp.SubjectReference{}, err
	}
	return verificationapp.SubjectReference{TenantID: tenant, Type: "evidence_item", ID: id, Resources: refs}, nil
}

// Current typed canonical facts and only relevant legacy origins, never raw
// objects. The shared selected-provenance reader retains one combined budget.
// Memory fixtures do not establish SQL locking, transfer bounds or durability.
func (r memoryVerificationRepository) ReadEvidenceVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.EvidenceVerificationSnapshot, error) {
	var out verificationapp.EvidenceVerificationSnapshot
	if subject.Type != "evidence_item" || !memoryMembershipQueryText(subject.ID, 1024) {
		return out, ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, subject.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryBundleEvidenceCoordinates(s, subject.TenantID, subject.ID)
		if err != nil {
			return err
		}
		if refs != subject.Resources {
			return ErrConflict
		}
		remaining := verificationapp.MaxEvidenceVerificationBytes
		item, err := readMemoryEvidenceWithProvenance(ctx, s, s.Evidence[subject.ID], &remaining)
		if err != nil {
			return err
		}
		var origins []evidencedomain.EvidenceLifecycleEvent
		if item.Canonicalization == evidencedomain.LegacyEvidenceCanonicalizationProfileVersion {
			ids := []string{}
			for id, event := range s.EvidenceLifecycle {
				if err := ctx.Err(); err != nil {
					return err
				}
				if event.TenantID != subject.TenantID || event.EvidenceID != subject.ID || event.SchemaVersion != evidencedomain.EvidenceRelationshipLifecycleSchemaVersion {
					continue
				}
				if _, exists := event.Details[evidencedomain.LegacyCanonicalOriginDetailKey]; !exists {
					continue
				}
				if event.ID != id || !memoryMembershipQueryText(id, 1024) || len(ids) == verificationapp.MaxEvidenceVerificationOrigins {
					return ErrConflict
				}
				ids = append(ids, id)
			}
			slices.Sort(ids)
			for _, id := range ids {
				if err := ctx.Err(); err != nil {
					return err
				}
				raw, err := memorySelectedEvidenceJSON(s.EvidenceLifecycle[id].Details[evidencedomain.LegacyCanonicalOriginDetailKey], &remaining)
				if err != nil {
					return err
				}
				decoder := json.NewDecoder(bytes.NewReader(raw))
				decoder.UseNumber()
				var origin any
				if err := decoder.Decode(&origin); err != nil {
					return ErrConflict
				}
				origins = append(origins, evidencedomain.EvidenceLifecycleEvent{TenantID: subject.TenantID, EvidenceID: subject.ID, SchemaVersion: evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, Details: map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: origin}})
			}
		}
		out = verificationapp.EvidenceVerificationSnapshot{Subject: subject, Item: domain.EvidenceToContextModel(item), Lifecycle: origins}
		return ctx.Err()
	})
	if err != nil {
		if errors.Is(err, evidencequery.ErrNotFound) {
			err = ErrNotFound
		} else if errors.Is(err, evidencequery.ErrConflict) || errors.Is(err, evidencequery.ErrValidation) {
			err = ErrConflict
		}
		return verificationapp.EvidenceVerificationSnapshot{}, err
	}
	return out, nil
}

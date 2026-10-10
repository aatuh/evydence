package app

import (
	"context"
	"errors"
	"slices"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

var _ verificationapp.DSSEVerificationReader = memoryVerificationRepository{}

// Current typed test-backend facts, not aggregate caches. Memory snapshots do
// not establish PostgreSQL locking, JSON shape, transfer bounds or durability.
func memoryDSSECoordinates(s *MemoryUnitOfWorkSnapshot, tenant, id string) (application.ResourceReferences, error) {
	a, ok := s.BuildAttestations[id]
	if !ok || a.ID != id || a.TenantID != tenant {
		return application.ResourceReferences{}, ErrNotFound
	}
	if !memoryMembershipQueryText(a.BuildID, 1024) || !memoryMembershipQueryText(a.EvidenceID, 1024) {
		return application.ResourceReferences{}, ErrConflict
	}
	refs, err := memoryBundleEvidenceCoordinates(s, tenant, a.EvidenceID)
	if err != nil {
		return application.ResourceReferences{}, err
	}
	if refs.BuildID != a.BuildID || refs.ProjectID == "" || refs.ReleaseID == "" {
		return application.ResourceReferences{}, ErrConflict
	}
	return refs, nil
}

func (r memoryVerificationRepository) ResolveDSSEVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	if !memoryMembershipQueryText(id, 1024) {
		return verificationapp.SubjectReference{}, ErrValidation
	}
	var out verificationapp.SubjectReference
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryDSSECoordinates(s, tenant, id)
		if err != nil {
			return err
		}
		out = verificationapp.SubjectReference{TenantID: tenant, Type: "build_attestation", ID: id, Resources: refs}
		return nil
	})
	if err != nil {
		return verificationapp.SubjectReference{}, err
	}
	return out, nil
}

func (r memoryVerificationRepository) ReadDSSEVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.DSSEVerificationSnapshot, error) {
	var out verificationapp.DSSEVerificationSnapshot
	if subject.Type != "build_attestation" || !memoryMembershipQueryText(subject.ID, 1024) {
		return out, ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, subject.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryDSSECoordinates(s, subject.TenantID, subject.ID)
		if err != nil {
			return err
		}
		if refs != subject.Resources {
			return ErrConflict
		}
		budget, records := verificationapp.MaxDSSEVerificationBytes, verificationapp.MaxDSSEVerificationRecords
		a := s.BuildAttestations[subject.ID]
		item := s.Evidence[a.EvidenceID]
		if !consumeMemoryDSSERecords(2+len(a.SubjectDigests)+len(item.SubjectRefs), &records) {
			return ErrConflict
		}
		if _, err := memorySelectedEvidenceJSON(a, &budget); err != nil {
			return err
		}
		item, err = readMemoryEvidenceWithProvenance(ctx, s, item, &budget)
		if err != nil {
			return err
		}
		if ValidateWorkerEvidenceRecord(item, a) != nil || a.PayloadRef != item.PayloadRef || a.PayloadHash != item.PayloadHash || a.PayloadSize != item.PayloadSize {
			return ErrConflict
		}
		payload, ok := s.ObjectPayloads[memoryObjectPayloadKey(subject.TenantID, a.PayloadHash)]
		if !ok {
			return ErrNotFound
		}
		if payload.TenantID != subject.TenantID || payload.Digest != a.PayloadHash || validateObjectPayload(payload) != nil || payload.Status != ObjectPayloadFinalized || payload.Size != a.PayloadSize || payload.Size < 1 || payload.Size > verificationapp.MaxDSSEPayloadBytes || a.PayloadRef != "object://"+payload.FinalKey || !ObjectMediaTypesMatch(payload.MediaType, item.PayloadMediaType) {
			return ErrConflict
		}
		// Select only lifecycle bindings, excluding private failure metadata.
		selected := ObjectPayload{TenantID: payload.TenantID, Digest: payload.Digest, Size: payload.Size, MediaType: payload.MediaType, StagingKey: payload.StagingKey, FinalKey: payload.FinalKey, Status: payload.Status, CreatedAt: payload.CreatedAt, UpdatedAt: payload.UpdatedAt}
		if _, err := memorySelectedEvidenceJSON(selected, &budget); err != nil {
			return err
		}
		out = verificationapp.DSSEVerificationSnapshot{Subject: subject, EvidenceID: a.EvidenceID, PayloadRef: a.PayloadRef, PayloadHash: a.PayloadHash, PayloadSize: a.PayloadSize, PayloadMediaType: payload.MediaType, PayloadFinalized: true}
		if err := readMemoryDSSEExpectedSubjects(ctx, s, &out, &budget, &records); err != nil {
			return err
		}
		ids := []string{}
		for id, root := range s.DSSETrustRoots {
			if err := ctx.Err(); err != nil {
				return err
			}
			if root.TenantID != subject.TenantID || root.Status != "active" {
				continue
			}
			if root.ID != id || !memoryMembershipQueryText(id, 1024) || len(ids) == records {
				return ErrConflict
			}
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			root := s.DSSETrustRoots[id]
			if !consumeMemoryDSSERecords(1+len(root.AllowedPredicateTypes)+len(root.ExpectedBuilderIDs)+len(root.RequiredClaims), &records) {
				return ErrConflict
			}
			if _, err := memorySelectedEvidenceJSON(root, &budget); err != nil {
				return err
			}
			owned := domain.DSSETrustRootToContextModel(root)
			if verificationapp.ValidDSSETrustRoot(owned) {
				owned.AllowedPredicateTypes = slices.Clone(owned.AllowedPredicateTypes)
				owned.ExpectedBuilderIDs = slices.Clone(owned.ExpectedBuilderIDs)
				owned.RequiredClaims = slices.Clone(owned.RequiredClaims)
				out.Roots = append(out.Roots, owned)
			}
		}
		return ctx.Err()
	})
	if err != nil {
		if errors.Is(err, evidencequery.ErrConflict) || errors.Is(err, evidencequery.ErrValidation) {
			err = ErrConflict
		}
		return verificationapp.DSSEVerificationSnapshot{}, err
	}
	return out, nil
}

func consumeMemoryDSSERecords(n int, remaining *int) bool {
	if n < 0 || n > *remaining {
		return false
	}
	*remaining -= n
	return true
}

func readMemoryDSSEExpectedSubjects(ctx context.Context, s *MemoryUnitOfWorkSnapshot, out *verificationapp.DSSEVerificationSnapshot, budget, records *int) error {
	outputs := s.BuildRuns[out.Subject.Resources.BuildID].Outputs
	if !consumeMemoryDSSERecords(len(outputs), records) {
		return ErrConflict
	}
	if _, err := memorySelectedEvidenceJSON(outputs, budget); err != nil {
		return err
	}
	artifacts := map[string]string{}
	for _, output := range outputs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !memoryMembershipQueryText(output.ArtifactID, 1024) || ValidateCanonicalObjectDigest(output.Digest) != nil {
			return ErrConflict
		}
		if _, seen := artifacts[output.ArtifactID]; seen {
			continue
		}
		a, found := s.Artifacts[output.ArtifactID]
		if !found || a.TenantID != out.Subject.TenantID {
			continue
		}
		if a.ID != output.ArtifactID || !memoryMembershipQueryText(a.Digest, 1024) || !consumeMemoryDSSERecords(1, records) || len(a.ID)+len(a.Digest) > *budget {
			return ErrConflict
		}
		*budget -= len(a.ID) + len(a.Digest)
		artifacts[a.ID] = a.Digest
	}
	wanted := map[string]bool{}
	for _, output := range outputs {
		if artifacts[output.ArtifactID] == output.Digest {
			wanted[output.ArtifactID] = true
		}
	}
	if len(wanted) == 0 {
		return ctx.Err()
	}
	linked := map[string]bool{}
	for id, e := range s.Evidence {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.TenantID != out.Subject.TenantID || e.ReleaseID != out.Subject.Resources.ReleaseID {
			continue
		}
		relevant := false
		for _, ref := range e.SubjectRefs {
			if ref.Type == "artifact" && wanted[ref.ID] {
				relevant = true
				break
			}
		}
		if !relevant {
			continue
		}
		if e.ID != id || !consumeMemoryDSSERecords(1+len(e.SubjectRefs), records) {
			return ErrConflict
		}
		if _, err := memorySelectedEvidenceJSON(e.SubjectRefs, budget); err != nil {
			return err
		}
		for _, ref := range e.SubjectRefs {
			if ref.Type == "artifact" && wanted[ref.ID] {
				linked[ref.ID] = true
			}
		}
	}
	for _, output := range outputs {
		if linked[output.ArtifactID] && artifacts[output.ArtifactID] == output.Digest {
			out.ExpectedSubjectDigests = append(out.ExpectedSubjectDigests, output.Digest)
		}
	}
	slices.Sort(out.ExpectedSubjectDigests)
	return ctx.Err()
}

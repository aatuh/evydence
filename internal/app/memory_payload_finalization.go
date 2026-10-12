package app

import (
	"context"
	"time"
)

// Focused lifecycle support for typed test-backend fixtures. The caller must
// verify finalized object bytes before this metadata transition; this is not
// evidence of provider storage, PostgreSQL locks or durable worker execution.
func (r memoryObjectPayloadRepository) GetObjectPayload(ctx context.Context, tenant, digest string) (ObjectPayload, error) {
	var out ObjectPayload
	if ValidateCanonicalObjectDigest(digest) != nil {
		return out, ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		p, ok := s.ObjectPayloads[memoryObjectPayloadKey(tenant, digest)]
		if !ok || p.TenantID != tenant || p.Digest != digest {
			return ErrNotFound
		}
		if validateObjectPayload(p) != nil {
			return ErrConflict
		}
		var err error
		out, err = cloneMemoryJSON(p)
		return err
	})
	if err != nil {
		return ObjectPayload{}, err
	}
	return out, nil
}

func (r memoryObjectPayloadRepository) MarkObjectPayloadFinalized(ctx context.Context, requested ObjectPayload) error {
	if validateObjectPayload(requested) != nil {
		return ErrValidation
	}
	return memoryIdentityRepository(r).membershipRead(ctx, requested.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		key := memoryObjectPayloadKey(requested.TenantID, requested.Digest)
		p, ok := s.ObjectPayloads[key]
		if !ok || p.TenantID != requested.TenantID || p.Digest != requested.Digest {
			return ErrNotFound
		}
		if validateObjectPayload(p) != nil || p.Size != requested.Size || p.StagingKey != requested.StagingKey || p.FinalKey != requested.FinalKey || !ObjectMediaTypesMatch(p.MediaType, requested.MediaType) || !p.CreatedAt.Equal(requested.CreatedAt) {
			return ErrConflict
		}
		if p.Status == ObjectPayloadFinalized {
			return nil
		}
		if p.Status != ObjectPayloadStaged && p.Status != ObjectPayloadFailed {
			return ErrConflict
		}
		at := time.Now().UTC()
		p.Status, p.UpdatedAt, p.FinalizedAt = ObjectPayloadFinalized, at, &at
		p.FailureCode, p.FailedAt = "", nil
		s.ObjectPayloads[key] = p
		return nil
	})
}

package app

import (
	"context"
)

// stagePayload writes raw bytes to a deterministic tenant staging key. When a
// command uses a unit of work, the caller must persist the returned metadata
// with persistStagedObjectPayload in that same transaction before exposing a
// domain record. Legacy in-memory paths finalize immediately because they do
// not have a transactional payload repository.
func (l *Ledger) stagePayload(ctx context.Context, tenantID, mediaType, digest string, raw []byte) (ObjectPayload, error) {
	source := BytesPayloadSource(raw)
	if source.Digest != digest {
		return ObjectPayload{}, ErrValidation
	}
	return l.stagePayloadSource(ctx, tenantID, mediaType, source)
}

// stagePayloadSource stages a repeatable payload source after its transport
// has streamed, counted, and hashed it. The object-store adapter performs its
// own digest and byte-count verification before staged metadata is trusted.
func (l *Ledger) stagePayloadSource(ctx context.Context, tenantID, mediaType string, source PayloadSource) (ObjectPayload, error) {
	if err := ctx.Err(); err != nil {
		return ObjectPayload{}, err
	}
	if err := validatePayloadSource(source, EvidenceDocumentLimit); err != nil {
		return ObjectPayload{}, err
	}
	if l.objects == nil {
		return ObjectPayload{}, nil
	}
	stager, ok := l.objects.(PayloadObjectStore)
	if !ok {
		return ObjectPayload{}, ErrConflict
	}
	payload, err := StageObjectPayload(ctx, stager, tenantID, mediaType, source, l.now())
	if err != nil {
		return ObjectPayload{}, err
	}
	if l.unitOfWork != nil {
		return payload, nil
	}
	object, err := stager.FinalizePayload(ctx, payload)
	if err != nil {
		return ObjectPayload{}, err
	}
	if err := verifyFinalizedPayloadObject(payload, object); err != nil {
		return ObjectPayload{}, err
	}
	now := l.now().UTC()
	payload.Status = ObjectPayloadFinalized
	payload.UpdatedAt = now
	payload.FinalizedAt = &now
	return payload, nil
}

// persistStagedObjectPayload couples staged metadata and the finalization job
// to the surrounding domain transaction. The job uses a stable logical key so
// repeated command delivery cannot create competing finalizers.
func (l *Ledger) persistStagedObjectPayload(ctx context.Context, repos Repositories, payload ObjectPayload) error {
	if !payload.managed() {
		return nil
	}
	if err := validateObjectPayload(payload); err != nil {
		return err
	}
	if err := repos.Payloads.RecordStagedObjectPayload(ctx, payload); err != nil {
		return err
	}
	return repos.Outbox.Enqueue(ctx, l.newOutboxJob(payload.TenantID, "finalize_payload", "object_payload", payload.Digest, map[string]any{
		"payload_digest":    payload.Digest,
		"payload_lifecycle": PayloadLifecycleVersion,
	}))
}

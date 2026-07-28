package app

import (
	"context"
	"errors"
	"strings"
	"time"
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
	payload, err := newStagedObjectPayload(tenantID, mediaType, source.Digest, l.now())
	if err != nil {
		return ObjectPayload{}, err
	}
	reader, err := source.Open()
	if err != nil {
		return ObjectPayload{}, err
	}
	defer reader.Close()
	payload, err = stager.StagePayload(ctx, payload, reader)
	if err != nil {
		return ObjectPayload{}, err
	}
	if payload.Size != source.Size || payload.Digest != source.Digest || payload.Status != ObjectPayloadStaged {
		return ObjectPayload{}, ErrValidation
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

func newStagedObjectPayload(tenantID, mediaType, digest string, now time.Time) (ObjectPayload, error) {
	tenantID = strings.TrimSpace(tenantID)
	mediaType = strings.TrimSpace(mediaType)
	if tenantID == "" || !validDigest(digest) {
		return ObjectPayload{}, ErrValidation
	}
	digestPart := strings.TrimPrefix(digest, "sha256:")
	prefix := "tenants/" + tenantID + "/"
	now = now.UTC()
	return ObjectPayload{
		TenantID:   tenantID,
		Digest:     digest,
		MediaType:  mediaType,
		StagingKey: prefix + "staging/sha256/" + digestPart,
		FinalKey:   prefix + "payloads/sha256/" + digestPart,
		Status:     ObjectPayloadStaged,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

func (p ObjectPayload) Reference() string {
	if strings.TrimSpace(p.FinalKey) == "" {
		return ""
	}
	return "object://" + p.FinalKey
}

func (p ObjectPayload) managed() bool {
	return p.Status == ObjectPayloadStaged && p.TenantID != "" && p.Digest != "" && p.StagingKey != "" && p.FinalKey != ""
}

func (p ObjectPayload) present() bool {
	return p.TenantID != "" || p.Digest != "" || p.Size != 0 || p.MediaType != "" || p.StagingKey != "" || p.FinalKey != "" || p.Status != "" || p.FailureCode != "" || !p.CreatedAt.IsZero() || !p.UpdatedAt.IsZero() || p.FinalizedAt != nil || p.FailedAt != nil || p.OrphanedAt != nil
}

func validateObjectPayload(payload ObjectPayload) error {
	prefix := "tenants/" + strings.TrimSpace(payload.TenantID) + "/"
	if strings.TrimSpace(payload.TenantID) == "" || !validDigest(payload.Digest) || payload.Size < 0 ||
		!strings.HasPrefix(payload.StagingKey, prefix) || !strings.HasPrefix(payload.FinalKey, prefix) ||
		payload.CreatedAt.IsZero() || payload.UpdatedAt.IsZero() {
		return ErrValidation
	}
	switch payload.Status {
	case ObjectPayloadStaged, ObjectPayloadFinalized, ObjectPayloadFailed, ObjectPayloadOrphaned:
		return nil
	default:
		return ErrValidation
	}
}

// ValidateObjectPayloadForRepository keeps adapter validation aligned with the
// application lifecycle invariant without exposing any storage implementation
// to the application layer.
func ValidateObjectPayloadForRepository(payload ObjectPayload) error {
	return validateObjectPayload(payload)
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

// addPayloadLifecycle records that a worker must verify durable finalization
// before reading a payload object. Legacy jobs intentionally omit this marker
// and retain their historical behavior until separately migrated.
func addPayloadLifecycle(payload map[string]any, staged ObjectPayload) map[string]any {
	if !staged.managed() {
		return payload
	}
	payload["payload_lifecycle"] = PayloadLifecycleVersion
	payload["payload_digest"] = staged.Digest
	return payload
}

// FinalizeStagedObjectPayload makes finalization repeatable after crashes. A
// copy that completed before the database transition is verified and accepted
// on the next attempt. Missing staged and final objects become discoverable
// orphaned metadata rather than silently trusted state.
func FinalizeStagedObjectPayload(ctx context.Context, lifecycle ObjectPayloadLifecycleStore, objects PayloadObjectStore, tenantID, digest string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if lifecycle == nil || objects == nil || strings.TrimSpace(tenantID) == "" || !validDigest(digest) {
		return ErrValidation
	}
	payload, err := lifecycle.GetObjectPayload(ctx, strings.TrimSpace(tenantID), digest)
	if err != nil {
		return err
	}
	if err := validateObjectPayload(payload); err != nil {
		return err
	}
	if payload.Status == ObjectPayloadOrphaned {
		return ErrNotFound
	}
	if payload.Status == ObjectPayloadFinalized {
		object, err := objects.Get(ctx, payload.FinalKey)
		if err != nil {
			_ = lifecycle.MarkObjectPayloadOrphaned(ctx, payload)
			return err
		}
		return verifyFinalizedPayloadObject(payload, object)
	}
	object, err := objects.FinalizePayload(ctx, payload)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = lifecycle.MarkObjectPayloadOrphaned(ctx, payload)
			return err
		}
		_ = lifecycle.MarkObjectPayloadFailed(ctx, payload, "finalization_failed")
		return err
	}
	if err := verifyFinalizedPayloadObject(payload, object); err != nil {
		_ = lifecycle.MarkObjectPayloadFailed(ctx, payload, "finalization_verification_failed")
		return err
	}
	return lifecycle.MarkObjectPayloadFinalized(ctx, payload)
}

func RequireFinalizedObjectPayload(ctx context.Context, lifecycle ObjectPayloadLifecycleStore, tenantID, digest, finalKey string) error {
	if lifecycle == nil || strings.TrimSpace(tenantID) == "" || !validDigest(digest) || strings.TrimSpace(finalKey) == "" {
		return ErrValidation
	}
	payload, err := lifecycle.GetObjectPayload(ctx, tenantID, digest)
	if err != nil {
		return err
	}
	if payload.Status != ObjectPayloadFinalized || payload.FinalKey != finalKey {
		return ErrConflict
	}
	return nil
}

func verifyFinalizedPayloadObject(payload ObjectPayload, object Object) error {
	if object.TenantID != payload.TenantID || object.Key != payload.FinalKey || object.Digest != payload.Digest || int64(len(object.Bytes)) != payload.Size {
		return ErrValidation
	}
	return nil
}

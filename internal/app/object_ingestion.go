package app

import (
	"context"
	"errors"
	"strings"
	"time"
)

// StageObjectPayload is the shared, Ledger-independent staging boundary. It
// verifies the returned metadata against the requested identity; persistence
// and finalization remain the caller's transactional responsibility.
func StageObjectPayload(ctx context.Context, objects PayloadObjectStore, tenantID, mediaType string, source PayloadSource, at time.Time) (ObjectPayload, error) {
	if ctx == nil {
		return ObjectPayload{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return ObjectPayload{}, err
	}
	if err := validatePayloadSource(source, EvidenceDocumentLimit); err != nil {
		return ObjectPayload{}, err
	}
	if objects == nil {
		return ObjectPayload{}, ErrConflict
	}
	expected, err := newStagedObjectPayload(tenantID, mediaType, source.Digest, at)
	if err != nil {
		return ObjectPayload{}, err
	}
	reader, err := source.Open()
	if err != nil {
		return ObjectPayload{}, err
	}
	if reader == nil {
		return ObjectPayload{}, ErrValidation
	}
	defer reader.Close()
	p, err := objects.StagePayload(ctx, expected, reader)
	if err != nil {
		return ObjectPayload{}, err
	}
	if validateObjectPayload(p) != nil || p.TenantID != expected.TenantID || p.Size != source.Size || p.Digest != expected.Digest || !ObjectMediaTypesMatch(expected.MediaType, p.MediaType) || p.StagingKey != expected.StagingKey || p.FinalKey != expected.FinalKey || p.Status != ObjectPayloadStaged || !p.CreatedAt.Equal(expected.CreatedAt) || p.FinalizedAt != nil || p.FailedAt != nil || p.OrphanedAt != nil || p.FailureCode != "" {
		return ObjectPayload{}, ErrValidation
	}
	return p, nil
}

func newStagedObjectPayload(tenantID, mediaType, digest string, now time.Time) (ObjectPayload, error) {
	tenantID = strings.TrimSpace(tenantID)
	mediaType = strings.TrimSpace(mediaType)
	stagingKey, finalKey, err := CanonicalObjectPayloadKeys(tenantID, digest)
	if err != nil || ValidateObjectMediaType(mediaType) != nil {
		return ObjectPayload{}, ErrValidation
	}
	now = now.UTC()
	return ObjectPayload{
		TenantID:   tenantID,
		Digest:     digest,
		MediaType:  mediaType,
		StagingKey: stagingKey,
		FinalKey:   finalKey,
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

func validateObjectPayload(payload ObjectPayload) error {
	stagingKey, finalKey, err := CanonicalObjectPayloadKeys(payload.TenantID, payload.Digest)
	if err != nil || ValidateObjectMediaType(payload.MediaType) != nil || payload.Size < 0 ||
		payload.StagingKey != stagingKey || payload.FinalKey != finalKey ||
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
	return VerifyObjectPayloadRead(payload, object, payload.FinalKey)
}

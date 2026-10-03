package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	defaultObjectReconciliationLimit            = 100
	maximumObjectReconciliationLimit            = 1_000
	defaultProviderInventoryReconciliationLimit = 1_000
	maximumProviderInventoryReconciliationLimit = 10_000
	minimumAbandonedStagingAge                  = time.Hour
	defaultDryRunAbandonedStagingAge            = 24 * time.Hour
	ObjectReconciliationReceiptSchemaVersion    = "object-reconciliation.v1"
)

// ObjectInventoryItem is provider metadata used only to report candidate
// provider objects without database ownership. It intentionally excludes raw
// object bytes and provider response details. Inventory pages are advisory:
// listing omissions are never used as proof that an expected object is gone.
type ObjectInventoryItem struct {
	TenantID  string
	Key       string
	Digest    string
	Size      int64
	CreatedAt time.Time
}

// ObjectInventoryPage uses numeric cursors so reconciliation receipts and
// operator output do not contain an object key or digest. Pages may repeat or
// omit provider objects as storage listings converge; callers must therefore
// treat them as reports, never deletion authority.
type ObjectInventoryPage struct {
	Objects    []ObjectInventoryItem
	NextCursor int
}

// ObjectInventoryStore lists tenant-prefixed provider metadata. It does not
// expose deletion because reconciliation must not delete provider data.
type ObjectInventoryStore interface {
	ListObjectInventory(context.Context, string, int, int) (ObjectInventoryPage, error)
}

type objectPayloadGetter interface {
	Get(context.Context, string) (Object, error)
}

// ObjectPayloadReconciliationStore is the database-authoritative side of a
// reconciliation run. All operations receive an explicit tenant ID; object
// ownership includes terminal lifecycle rows so an existing record cannot be
// reported as a provider orphan simply because it is quarantined.
type ObjectPayloadReconciliationStore interface {
	ListObjectPayloads(context.Context, string, int, int) ([]ObjectPayload, int, error)
	ObjectPayloadOwnsObject(context.Context, string, string) (bool, error)
	RecordObjectReconciliationReceipt(context.Context, ObjectReconciliationReceipt) error
}

// ObjectPayloadReconciliationAction is one lifecycle transition planned after
// object verification. Apply-mode stores must commit every action together
// with the receipt and audit entry so no cleanup mutation can exist without its
// durable evidence.
type ObjectPayloadReconciliationAction struct {
	Payload     ObjectPayload
	Status      ObjectPayloadStatus
	FailureCode string
}

// ObjectPayloadReconciliationApplyStore atomically applies lifecycle changes
// and records the corresponding receipt/audit evidence. Object-store reads are
// completed before this transaction begins; provider calls are never made
// while holding the database transaction.
type ObjectPayloadReconciliationApplyStore interface {
	ApplyObjectReconciliation(context.Context, ObjectReconciliationReceipt, []ObjectPayloadReconciliationAction) error
}

// ObjectReconciliationRequest bounds and resumes one tenant-only scan. Apply
// is deliberately opt-in; the zero value is a non-mutating dry run. Applying
// reconciliation requires an explicit abandoned-staging threshold even though
// this ticket does not delete any provider object.
type ObjectReconciliationRequest struct {
	TenantID               string
	MetadataCursor         int
	ProviderCursor         int
	Limit                  int
	ProviderInventoryLimit int
	Apply                  bool
	OrphanStagedAfter      time.Duration
	Now                    func() time.Time
}

// ObjectReconciliationReceipt records safe counters rather than object keys,
// digests, raw evidence, storage paths, or provider error text. It is safe to
// attach to an audit chain and to expose as an operator metric.
type ObjectReconciliationReceipt struct {
	ID                     string    `json:"id"`
	SchemaVersion          string    `json:"schema_version"`
	TenantID               string    `json:"tenant_id"`
	DryRun                 bool      `json:"dry_run"`
	MetadataCursor         int       `json:"metadata_cursor"`
	NextMetadataCursor     int       `json:"next_metadata_cursor,omitempty"`
	ProviderCursor         int       `json:"provider_cursor"`
	NextProviderCursor     int       `json:"next_provider_cursor,omitempty"`
	ScannedPayloads        int       `json:"scanned_payloads"`
	HealthyPayloads        int       `json:"healthy_payloads"`
	MissingFinalObjects    int       `json:"missing_final_objects"`
	MissingStagedObjects   int       `json:"missing_staged_objects"`
	DigestMismatches       int       `json:"digest_mismatches"`
	RecoveredFinalizations int       `json:"recovered_finalizations"`
	AbandonedStaging       int       `json:"abandoned_staging"`
	ProviderOrphans        int       `json:"provider_orphans"`
	QuarantinedPayloads    int       `json:"quarantined_payloads"`
	CreatedAt              time.Time `json:"created_at"`
}

// ObjectReconciliationMetrics is a tenant-safe aggregate over immutable run
// receipts. It intentionally contains counts only, never object identifiers.
type ObjectReconciliationMetrics struct {
	Runs                 int64
	ScannedPayloads      int64
	MissingFinalObjects  int64
	MissingStagedObjects int64
	DigestMismatches     int64
	ProviderOrphans      int64
	QuarantinedPayloads  int64
	LastRunAt            time.Time
}

// ObjectReconciliationMetricsStore supplies receipt-backed safe metrics to
// the API process without coupling the core ledger to PostgreSQL.
type ObjectReconciliationMetricsStore interface {
	ObjectReconciliationMetrics(context.Context, string) (ObjectReconciliationMetrics, error)
}

// ReconcileObjectPayloads verifies database metadata by direct object reads.
// Provider inventory is only used to report candidate unowned objects. A
// missing item from ListObjectInventory never changes lifecycle state, so
// eventual-consistency or provider list failures cannot cause data deletion or
// a false quarantine. Apply mode plans lifecycle mutations during the scan and
// commits all of them with the receipt/audit evidence only after every object
// read succeeds. It never deletes raw storage objects.
func ReconcileObjectPayloads(ctx context.Context, lifecycle ObjectPayloadLifecycleStore, metadata ObjectPayloadReconciliationStore, objects objectPayloadGetter, request ObjectReconciliationRequest) (ObjectReconciliationReceipt, error) {
	request, now, err := normalizeObjectReconciliationRequest(request)
	if err != nil {
		return ObjectReconciliationReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return ObjectReconciliationReceipt{}, err
	}
	if lifecycle == nil || metadata == nil || objects == nil {
		return ObjectReconciliationReceipt{}, ErrValidation
	}
	payloads, nextMetadataCursor, err := metadata.ListObjectPayloads(ctx, request.TenantID, request.MetadataCursor, request.Limit)
	if err != nil {
		return ObjectReconciliationReceipt{}, errors.New("payload reconciliation metadata lookup failed")
	}
	receipt := ObjectReconciliationReceipt{
		ID:                 newObjectReconciliationReceiptID(),
		SchemaVersion:      ObjectReconciliationReceiptSchemaVersion,
		TenantID:           request.TenantID,
		DryRun:             !request.Apply,
		MetadataCursor:     request.MetadataCursor,
		NextMetadataCursor: nextMetadataCursor,
		ProviderCursor:     request.ProviderCursor,
		CreatedAt:          now,
	}
	actions := make([]ObjectPayloadReconciliationAction, 0)
	for _, payload := range payloads {
		if err := ctx.Err(); err != nil {
			return ObjectReconciliationReceipt{}, err
		}
		if err := validateObjectPayload(payload); err != nil || payload.TenantID != request.TenantID {
			return ObjectReconciliationReceipt{}, errors.New("payload reconciliation metadata is invalid")
		}
		receipt.ScannedPayloads++
		if err := reconcileOneObjectPayload(ctx, objects, payload, request, now, &receipt, &actions); err != nil {
			return ObjectReconciliationReceipt{}, err
		}
	}
	if inventory, ok := objects.(ObjectInventoryStore); ok && request.ProviderInventoryLimit > 0 {
		page, err := inventory.ListObjectInventory(ctx, request.TenantID, request.ProviderCursor, request.ProviderInventoryLimit)
		if err != nil {
			return ObjectReconciliationReceipt{}, errors.New("payload reconciliation provider inventory failed")
		}
		receipt.NextProviderCursor = page.NextCursor
		for _, item := range page.Objects {
			if err := ctx.Err(); err != nil {
				return ObjectReconciliationReceipt{}, err
			}
			if item.TenantID != request.TenantID || !strings.HasPrefix(item.Key, "tenants/"+request.TenantID+"/") {
				return ObjectReconciliationReceipt{}, errors.New("payload reconciliation provider inventory is invalid")
			}
			owned, err := metadata.ObjectPayloadOwnsObject(ctx, request.TenantID, item.Key)
			if err != nil {
				return ObjectReconciliationReceipt{}, errors.New("payload reconciliation ownership lookup failed")
			}
			if !owned {
				receipt.ProviderOrphans++
			}
		}
	}
	if request.Apply {
		applyStore, ok := metadata.(ObjectPayloadReconciliationApplyStore)
		if !ok {
			return ObjectReconciliationReceipt{}, errors.New("payload reconciliation atomic apply is unavailable")
		}
		if err := applyStore.ApplyObjectReconciliation(ctx, receipt, actions); err != nil {
			return ObjectReconciliationReceipt{}, errors.New("apply payload reconciliation failed")
		}
		return receipt, nil
	}
	if err := metadata.RecordObjectReconciliationReceipt(ctx, receipt); err != nil {
		return ObjectReconciliationReceipt{}, errors.New("record payload reconciliation receipt failed")
	}
	return receipt, nil
}

func normalizeObjectReconciliationRequest(request ObjectReconciliationRequest) (ObjectReconciliationRequest, time.Time, error) {
	request.TenantID = strings.TrimSpace(request.TenantID)
	if request.TenantID == "" || request.MetadataCursor < 0 || request.ProviderCursor < 0 {
		return ObjectReconciliationRequest{}, time.Time{}, ErrValidation
	}
	if request.Limit == 0 {
		request.Limit = defaultObjectReconciliationLimit
	}
	if request.Limit < 1 || request.Limit > maximumObjectReconciliationLimit {
		return ObjectReconciliationRequest{}, time.Time{}, ErrValidation
	}
	if request.ProviderInventoryLimit == 0 {
		request.ProviderInventoryLimit = defaultProviderInventoryReconciliationLimit
	}
	if request.ProviderInventoryLimit < 0 || request.ProviderInventoryLimit > maximumProviderInventoryReconciliationLimit {
		return ObjectReconciliationRequest{}, time.Time{}, ErrValidation
	}
	if request.Apply && request.OrphanStagedAfter < minimumAbandonedStagingAge {
		return ObjectReconciliationRequest{}, time.Time{}, ErrValidation
	}
	if !request.Apply && request.OrphanStagedAfter <= 0 {
		request.OrphanStagedAfter = defaultDryRunAbandonedStagingAge
	}
	now := time.Now().UTC()
	if request.Now != nil {
		now = request.Now().UTC()
	}
	if now.IsZero() {
		return ObjectReconciliationRequest{}, time.Time{}, ErrValidation
	}
	return request, now, nil
}

func reconcileOneObjectPayload(ctx context.Context, objects objectPayloadGetter, payload ObjectPayload, request ObjectReconciliationRequest, now time.Time, receipt *ObjectReconciliationReceipt, actions *[]ObjectPayloadReconciliationAction) error {
	switch payload.Status {
	case ObjectPayloadFinalized:
		state, err := reconciliationObjectState(ctx, objects, payload, payload.FinalKey)
		if err != nil {
			return err
		}
		switch state {
		case reconciliationObjectHealthy:
			receipt.HealthyPayloads++
		case reconciliationObjectMissing:
			receipt.MissingFinalObjects++
			planObjectPayloadQuarantine(payload, request.Apply, receipt, actions, false)
		case reconciliationObjectMismatch:
			receipt.DigestMismatches++
			planObjectPayloadQuarantine(payload, request.Apply, receipt, actions, true)
		}
	case ObjectPayloadStaged:
		finalState, err := reconciliationObjectState(ctx, objects, payload, payload.FinalKey)
		if err != nil {
			return err
		}
		switch finalState {
		case reconciliationObjectHealthy:
			receipt.RecoveredFinalizations++
			if request.Apply {
				*actions = append(*actions, ObjectPayloadReconciliationAction{Payload: payload, Status: ObjectPayloadFinalized})
			}
			return nil
		case reconciliationObjectMismatch:
			receipt.DigestMismatches++
			planObjectPayloadQuarantine(payload, request.Apply, receipt, actions, true)
			return nil
		}
		stagedState, err := reconciliationObjectState(ctx, objects, payload, payload.StagingKey)
		if err != nil {
			return err
		}
		switch stagedState {
		case reconciliationObjectHealthy:
			if !payload.CreatedAt.After(now.Add(-request.OrphanStagedAfter)) {
				receipt.AbandonedStaging++
				planObjectPayloadQuarantine(payload, request.Apply, receipt, actions, false)
				return nil
			}
			receipt.HealthyPayloads++
		case reconciliationObjectMissing:
			receipt.MissingStagedObjects++
			planObjectPayloadQuarantine(payload, request.Apply, receipt, actions, false)
		case reconciliationObjectMismatch:
			receipt.DigestMismatches++
			planObjectPayloadQuarantine(payload, request.Apply, receipt, actions, true)
		}
	case ObjectPayloadFailed, ObjectPayloadOrphaned:
		// Terminal states are already prevented from package and verification
		// reads. Their provider objects remain inventory-owned by database rows.
	default:
		return errors.New("payload reconciliation metadata is invalid")
	}
	return nil
}

type reconciliationObjectStatus uint8

const (
	reconciliationObjectHealthy reconciliationObjectStatus = iota
	reconciliationObjectMissing
	reconciliationObjectMismatch
)

func reconciliationObjectState(ctx context.Context, objects objectPayloadGetter, payload ObjectPayload, key string) (reconciliationObjectStatus, error) {
	object, err := objects.Get(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return reconciliationObjectMissing, nil
	}
	if err != nil {
		return 0, errors.New("payload reconciliation object lookup failed")
	}
	if !objectPayloadReadMatches(payload, object, key) {
		return reconciliationObjectMismatch, nil
	}
	return reconciliationObjectHealthy, nil
}

func objectPayloadReadMatches(payload ObjectPayload, object Object, key string) bool {
	return VerifyObjectPayloadRead(payload, object, key) == nil
}

func planObjectPayloadQuarantine(payload ObjectPayload, apply bool, receipt *ObjectReconciliationReceipt, actions *[]ObjectPayloadReconciliationAction, mismatch bool) {
	if !apply {
		return
	}
	action := ObjectPayloadReconciliationAction{Payload: payload, Status: ObjectPayloadOrphaned}
	if mismatch {
		action.Status = ObjectPayloadFailed
		action.FailureCode = "reconciliation_mismatch"
	}
	*actions = append(*actions, action)
	receipt.QuarantinedPayloads++
}

func newObjectReconciliationReceiptID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		// A receipt ID is a durable correlation key, not a secret. Time remains
		// sufficient to avoid panicking during a transient entropy failure.
		return fmt.Sprintf("rec_%d", time.Now().UTC().UnixNano())
	}
	return "rec_" + hex.EncodeToString(value[:])
}

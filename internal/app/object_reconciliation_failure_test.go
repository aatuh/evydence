package app

import (
	"context"
	"errors"
	"testing"
	"time"
)

type reconciliationFailureFixture struct {
	payloads     []ObjectPayload
	inventory    []ObjectInventoryItem
	objects      map[string]Object
	listErr      error
	inventoryErr error
	ownershipErr error
	receiptErr   error
	applyErr     error
	objectErr    error
	receiptCalls int
	applyCalls   int
}

func (f *reconciliationFailureFixture) Get(_ context.Context, key string) (Object, error) {
	if f.objectErr != nil {
		return Object{}, f.objectErr
	}
	object, ok := f.objects[key]
	if !ok {
		return Object{}, ErrNotFound
	}
	return object, nil
}

func (f *reconciliationFailureFixture) GetObjectPayload(context.Context, string, string) (ObjectPayload, error) {
	return ObjectPayload{}, ErrNotFound
}

func (f *reconciliationFailureFixture) MarkObjectPayloadFinalized(context.Context, ObjectPayload) error {
	return nil
}

func (f *reconciliationFailureFixture) MarkObjectPayloadFailed(context.Context, ObjectPayload, string) error {
	return nil
}

func (f *reconciliationFailureFixture) MarkObjectPayloadOrphaned(context.Context, ObjectPayload) error {
	return nil
}

func (f *reconciliationFailureFixture) ListObjectPayloads(context.Context, string, int, int) ([]ObjectPayload, int, error) {
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return append([]ObjectPayload(nil), f.payloads...), 0, nil
}

func (f *reconciliationFailureFixture) ObjectPayloadOwnsObject(context.Context, string, string) (bool, error) {
	if f.ownershipErr != nil {
		return false, f.ownershipErr
	}
	return false, nil
}

func (f *reconciliationFailureFixture) RecordObjectReconciliationReceipt(context.Context, ObjectReconciliationReceipt) error {
	f.receiptCalls++
	return f.receiptErr
}

func (f *reconciliationFailureFixture) ListObjectInventory(context.Context, string, int, int) (ObjectInventoryPage, error) {
	if f.inventoryErr != nil {
		return ObjectInventoryPage{}, f.inventoryErr
	}
	return ObjectInventoryPage{Objects: append([]ObjectInventoryItem(nil), f.inventory...)}, nil
}

func (f *reconciliationFailureFixture) ApplyObjectReconciliation(context.Context, ObjectReconciliationReceipt, []ObjectPayloadReconciliationAction) error {
	f.applyCalls++
	return f.applyErr
}

type reconciliationMetadataWithoutAtomicApply struct {
	fixture *reconciliationFailureFixture
}

func (f reconciliationMetadataWithoutAtomicApply) ListObjectPayloads(ctx context.Context, tenantID string, cursor, limit int) ([]ObjectPayload, int, error) {
	return f.fixture.ListObjectPayloads(ctx, tenantID, cursor, limit)
}

func (f reconciliationMetadataWithoutAtomicApply) ObjectPayloadOwnsObject(ctx context.Context, tenantID, key string) (bool, error) {
	return f.fixture.ObjectPayloadOwnsObject(ctx, tenantID, key)
}

func (f reconciliationMetadataWithoutAtomicApply) RecordObjectReconciliationReceipt(ctx context.Context, receipt ObjectReconciliationReceipt) error {
	return f.fixture.RecordObjectReconciliationReceipt(ctx, receipt)
}

func TestReconcileObjectPayloadsFailurePathsFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	payload := reconciledPayload("ten_failure", "payload", ObjectPayloadFinalized, now)
	providerItem := ObjectInventoryItem{
		TenantID: "ten_failure",
		Key:      "tenants/ten_failure/payloads/sha256/provider-only",
	}
	tests := []struct {
		name    string
		fixture *reconciliationFailureFixture
		request ObjectReconciliationRequest
	}{
		{
			name:    "metadata lookup failure",
			fixture: &reconciliationFailureFixture{listErr: errors.New("database unavailable")},
		},
		{
			name: "object lookup failure",
			fixture: &reconciliationFailureFixture{
				payloads:  []ObjectPayload{payload},
				objectErr: errors.New("provider unavailable"),
			},
		},
		{
			name:    "provider inventory failure",
			fixture: &reconciliationFailureFixture{inventoryErr: errors.New("list unavailable")},
		},
		{
			name: "ownership lookup failure",
			fixture: &reconciliationFailureFixture{
				inventory:    []ObjectInventoryItem{providerItem},
				ownershipErr: errors.New("ownership unavailable"),
			},
		},
		{
			name:    "receipt persistence failure",
			fixture: &reconciliationFailureFixture{receiptErr: errors.New("receipt unavailable")},
		},
		{
			name: "atomic apply failure",
			fixture: &reconciliationFailureFixture{
				payloads: []ObjectPayload{payload},
				applyErr: errors.New("commit unavailable"),
			},
			request: ObjectReconciliationRequest{Apply: true, OrphanStagedAfter: time.Hour},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := test.request
			request.TenantID = "ten_failure"
			request.Limit = 10
			request.ProviderInventoryLimit = 10
			request.Now = func() time.Time { return now }
			_, err := ReconcileObjectPayloads(t.Context(), test.fixture, test.fixture, test.fixture, request)
			if err == nil {
				t.Fatal("failure path returned success")
			}
		})
	}
}

func TestReconcileObjectPayloadsRequiresAtomicApplyStore(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	fixture := &reconciliationFailureFixture{}
	metadata := reconciliationMetadataWithoutAtomicApply{fixture: fixture}
	_, err := ReconcileObjectPayloads(t.Context(), fixture, metadata, fixture, ObjectReconciliationRequest{
		TenantID:          "ten_failure",
		Limit:             10,
		Apply:             true,
		OrphanStagedAfter: time.Hour,
		Now:               func() time.Time { return now },
	})
	if err == nil {
		t.Fatal("apply without atomic store was accepted")
	}
	if fixture.receiptCalls != 0 {
		t.Fatalf("non-atomic apply persisted %d receipts", fixture.receiptCalls)
	}
}

func TestNormalizeObjectReconciliationRequestRejectsUnsafeBounds(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	for _, request := range []ObjectReconciliationRequest{
		{TenantID: ""},
		{TenantID: "ten_bounds", MetadataCursor: -1},
		{TenantID: "ten_bounds", ProviderCursor: -1},
		{TenantID: "ten_bounds", Limit: maximumObjectReconciliationLimit + 1},
		{TenantID: "ten_bounds", ProviderInventoryLimit: maximumProviderInventoryReconciliationLimit + 1},
		{TenantID: "ten_bounds", Apply: true, OrphanStagedAfter: minimumAbandonedStagingAge - time.Nanosecond},
		{TenantID: "ten_bounds", Now: func() time.Time { return time.Time{} }},
	} {
		request.Now = chooseReconciliationNow(request.Now, now)
		if _, _, err := normalizeObjectReconciliationRequest(request); err == nil {
			t.Fatalf("unsafe request accepted: %#v", request)
		}
	}
}

func chooseReconciliationNow(current func() time.Time, fallback time.Time) func() time.Time {
	if current != nil {
		return current
	}
	return func() time.Time { return fallback }
}

func TestReconcileObjectPayloadsRejectsCanceledContextAndNilPorts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fixture := &reconciliationFailureFixture{}
	if _, err := ReconcileObjectPayloads(ctx, fixture, fixture, fixture, ObjectReconciliationRequest{TenantID: "ten_failure"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reconciliation err=%v, want canceled", err)
	}
	if _, err := ReconcileObjectPayloads(t.Context(), nil, fixture, fixture, ObjectReconciliationRequest{TenantID: "ten_failure"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil lifecycle err=%v, want validation", err)
	}
}

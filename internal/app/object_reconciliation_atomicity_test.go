package app

import (
	"context"
	"errors"
	"testing"
	"time"
)

func (f *reconciliationFixture) ApplyObjectReconciliation(
	ctx context.Context,
	receipt ObjectReconciliationReceipt,
	actions []ObjectPayloadReconciliationAction,
) error {
	copyPayloads := append([]ObjectPayload(nil), f.payloads...)
	copyFixture := &reconciliationFixture{payloads: copyPayloads}
	for _, action := range actions {
		var err error
		switch action.Status {
		case ObjectPayloadFinalized:
			err = copyFixture.MarkObjectPayloadFinalized(ctx, action.Payload)
		case ObjectPayloadFailed:
			err = copyFixture.MarkObjectPayloadFailed(ctx, action.Payload, action.FailureCode)
		case ObjectPayloadOrphaned:
			err = copyFixture.MarkObjectPayloadOrphaned(ctx, action.Payload)
		default:
			err = ErrValidation
		}
		if err != nil {
			return err
		}
	}
	f.payloads = copyFixture.payloads
	f.receipts = append(f.receipts, receipt)
	return nil
}

type failingReconciliationApplyFixture struct {
	*reconciliationFixture
	err error
}

func (f *failingReconciliationApplyFixture) ApplyObjectReconciliation(
	context.Context,
	ObjectReconciliationReceipt,
	[]ObjectPayloadReconciliationAction,
) error {
	return f.err
}

type crossTenantMetadataReconciliationFixture struct {
	*reconciliationFixture
	payload ObjectPayload
}

func (f *crossTenantMetadataReconciliationFixture) ListObjectPayloads(
	context.Context,
	string,
	int,
	int,
) ([]ObjectPayload, int, error) {
	return []ObjectPayload{f.payload}, 0, nil
}

type crossTenantInventoryReconciliationFixture struct {
	*reconciliationFixture
	item ObjectInventoryItem
}

func (f *crossTenantInventoryReconciliationFixture) ListObjectInventory(
	context.Context,
	string,
	int,
	int,
) (ObjectInventoryPage, error) {
	return ObjectInventoryPage{Objects: []ObjectInventoryItem{f.item}}, nil
}

func TestReconcileObjectPayloadsApplyFailureLeavesLifecycleAndReceiptUnchanged(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	missing := reconciledPayload("ten_atomic", "missing", ObjectPayloadFinalized, now)
	base := &reconciliationFixture{
		payloads: []ObjectPayload{missing},
		objects:  map[string]Object{},
	}
	fixture := &failingReconciliationApplyFixture{
		reconciliationFixture: base,
		err:                   errors.New("commit failed"),
	}

	_, err := ReconcileObjectPayloads(
		context.Background(),
		fixture,
		fixture,
		fixture,
		ObjectReconciliationRequest{
			TenantID:          missing.TenantID,
			Limit:             10,
			Apply:             true,
			OrphanStagedAfter: time.Hour,
			Now:               func() time.Time { return now },
		},
	)
	if err == nil {
		t.Fatal("apply failure was not returned")
	}
	if got := base.payloads[0].Status; got != ObjectPayloadFinalized {
		t.Fatalf("failed atomic apply published lifecycle status %q", got)
	}
	if len(base.receipts) != 0 {
		t.Fatalf("failed atomic apply published receipts: %#v", base.receipts)
	}
}

func TestReconcileObjectPayloadsRejectsCrossTenantMetadata(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	base := &reconciliationFixture{objects: map[string]Object{}}
	fixture := &crossTenantMetadataReconciliationFixture{
		reconciliationFixture: base,
		payload:               reconciledPayload("ten_other", "foreign", ObjectPayloadFinalized, now),
	}

	_, err := ReconcileObjectPayloads(
		context.Background(),
		fixture,
		fixture,
		fixture,
		ObjectReconciliationRequest{
			TenantID: "ten_expected",
			Limit:    10,
			Now:      func() time.Time { return now },
		},
	)
	if err == nil {
		t.Fatal("cross-tenant reconciliation metadata was accepted")
	}
	if len(base.receipts) != 0 {
		t.Fatalf("cross-tenant metadata produced receipt: %#v", base.receipts)
	}
}

func TestReconcileObjectPayloadsRejectsCrossTenantProviderInventory(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		item ObjectInventoryItem
	}{
		{
			name: "foreign tenant",
			item: ObjectInventoryItem{
				TenantID: "ten_other",
				Key:      "tenants/ten_other/payloads/sha256/foreign",
			},
		},
		{
			name: "foreign key prefix",
			item: ObjectInventoryItem{
				TenantID: "ten_expected",
				Key:      "tenants/ten_other/payloads/sha256/foreign",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := &reconciliationFixture{objects: map[string]Object{}}
			fixture := &crossTenantInventoryReconciliationFixture{
				reconciliationFixture: base,
				item:                  test.item,
			}
			_, err := ReconcileObjectPayloads(
				context.Background(),
				fixture,
				fixture,
				fixture,
				ObjectReconciliationRequest{
					TenantID:               "ten_expected",
					Limit:                  10,
					ProviderInventoryLimit: 10,
					Now:                    func() time.Time { return now },
				},
			)
			if err == nil {
				t.Fatal("cross-tenant provider inventory was accepted")
			}
			if len(base.receipts) != 0 {
				t.Fatalf("cross-tenant inventory produced receipt: %#v", base.receipts)
			}
		})
	}
}

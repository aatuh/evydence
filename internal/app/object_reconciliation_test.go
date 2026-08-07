package app

import (
	"context"
	"errors"
	"testing"
	"time"
)

type reconciliationFixture struct {
	payloads []ObjectPayload
	objects  map[string]Object
	listed   []ObjectInventoryItem
	receipts []ObjectReconciliationReceipt
}

type reconciliationMetricsFixture struct{ metrics ObjectReconciliationMetrics }

func (f reconciliationMetricsFixture) ObjectReconciliationMetrics(_ context.Context, _ string) (ObjectReconciliationMetrics, error) {
	return f.metrics, nil
}

func (f *reconciliationFixture) Get(_ context.Context, key string) (Object, error) {
	object, ok := f.objects[key]
	if !ok {
		return Object{}, ErrNotFound
	}
	return object, nil
}

func (f *reconciliationFixture) GetObjectPayload(_ context.Context, tenantID, digest string) (ObjectPayload, error) {
	for _, payload := range f.payloads {
		if payload.TenantID == tenantID && payload.Digest == digest {
			return payload, nil
		}
	}
	return ObjectPayload{}, ErrNotFound
}

func (f *reconciliationFixture) ListObjectPayloads(_ context.Context, tenantID string, cursor, limit int) ([]ObjectPayload, int, error) {
	if cursor < 0 || limit < 1 {
		return nil, 0, ErrValidation
	}
	items := make([]ObjectPayload, 0, limit)
	for _, payload := range f.payloads {
		if payload.TenantID == tenantID {
			items = append(items, payload)
		}
	}
	if cursor >= len(items) {
		return nil, 0, nil
	}
	end := cursor + limit
	if end >= len(items) {
		return append([]ObjectPayload(nil), items[cursor:]...), 0, nil
	}
	return append([]ObjectPayload(nil), items[cursor:end]...), end, nil
}

func (f *reconciliationFixture) ObjectPayloadOwnsObject(_ context.Context, tenantID, key string) (bool, error) {
	for _, payload := range f.payloads {
		if payload.TenantID == tenantID && (payload.StagingKey == key || payload.FinalKey == key) {
			return true, nil
		}
	}
	return false, nil
}

func (f *reconciliationFixture) MarkObjectPayloadFinalized(_ context.Context, target ObjectPayload) error {
	return f.update(target, func(payload *ObjectPayload) {
		payload.Status = ObjectPayloadFinalized
		payload.FailureCode = ""
	})
}

func (f *reconciliationFixture) MarkObjectPayloadFailed(_ context.Context, target ObjectPayload, code string) error {
	return f.update(target, func(payload *ObjectPayload) {
		payload.Status = ObjectPayloadFailed
		payload.FailureCode = code
	})
}

func (f *reconciliationFixture) MarkObjectPayloadOrphaned(_ context.Context, target ObjectPayload) error {
	return f.update(target, func(payload *ObjectPayload) {
		payload.Status = ObjectPayloadOrphaned
		payload.FailureCode = "object_missing"
	})
}

func (f *reconciliationFixture) update(target ObjectPayload, update func(*ObjectPayload)) error {
	for index := range f.payloads {
		payload := &f.payloads[index]
		if payload.TenantID == target.TenantID && payload.Digest == target.Digest && payload.FinalKey == target.FinalKey {
			update(payload)
			return nil
		}
	}
	return ErrNotFound
}

func (f *reconciliationFixture) RecordObjectReconciliationReceipt(_ context.Context, receipt ObjectReconciliationReceipt) error {
	f.receipts = append(f.receipts, receipt)
	return nil
}

func (f *reconciliationFixture) ListObjectInventory(_ context.Context, tenantID string, cursor, limit int) (ObjectInventoryPage, error) {
	if cursor < 0 || limit < 1 {
		return ObjectInventoryPage{}, ErrValidation
	}
	items := make([]ObjectInventoryItem, 0, limit)
	for _, item := range f.listed {
		if item.TenantID == tenantID {
			items = append(items, item)
		}
	}
	if cursor >= len(items) {
		return ObjectInventoryPage{}, nil
	}
	end := cursor + limit
	page := ObjectInventoryPage{}
	if end >= len(items) {
		page.Objects = append([]ObjectInventoryItem(nil), items[cursor:]...)
		return page, nil
	}
	page.Objects = append([]ObjectInventoryItem(nil), items[cursor:end]...)
	page.NextCursor = end
	return page, nil
}

func TestReconcileObjectPayloadsReportsWithoutMutatingAndDoesNotTrustListingForMissingObjects(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	good := reconciledPayload("ten_reconcile", "good", ObjectPayloadFinalized, now)
	missing := reconciledPayload("ten_reconcile", "missing", ObjectPayloadFinalized, now)
	mismatch := reconciledPayload("ten_reconcile", "mismatch", ObjectPayloadFinalized, now)
	staged := reconciledPayload("ten_reconcile", "staged", ObjectPayloadStaged, now.Add(-2*time.Hour))
	fixture := &reconciliationFixture{
		payloads: []ObjectPayload{good, missing, mismatch, staged},
		objects: map[string]Object{
			good.FinalKey:     reconciledObject(good, good.FinalKey, []byte("good")),
			mismatch.FinalKey: reconciledObject(mismatch, mismatch.FinalKey, []byte("not-the-declared-content")),
			staged.StagingKey: reconciledObject(staged, staged.StagingKey, []byte("staged")),
		},
		// The inventory omits the good object. Direct lookup remains authoritative
		// for missing-object decisions; a list omission cannot quarantine it.
		listed: []ObjectInventoryItem{
			{TenantID: "ten_reconcile", Key: "tenants/ten_reconcile/payloads/sha256/provider-only", CreatedAt: now},
		},
	}

	receipt, err := ReconcileObjectPayloads(ctx, fixture, fixture, fixture, ObjectReconciliationRequest{
		TenantID:               "ten_reconcile",
		Limit:                  20,
		ProviderInventoryLimit: 20,
		OrphanStagedAfter:      time.Hour,
		Now:                    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("reconcile object payloads: %v", err)
	}
	if !receipt.DryRun || receipt.ScannedPayloads != 4 || receipt.MissingFinalObjects != 1 || receipt.DigestMismatches != 1 || receipt.AbandonedStaging != 1 || receipt.ProviderOrphans != 1 {
		t.Fatalf("unexpected dry-run receipt: %#v", receipt)
	}
	if len(fixture.receipts) != 1 || !fixture.receipts[0].DryRun {
		t.Fatalf("dry run receipt was not persisted safely: %#v", fixture.receipts)
	}
	for _, payload := range fixture.payloads {
		if payload.Status != ObjectPayloadFinalized && payload.Status != ObjectPayloadStaged {
			t.Fatalf("dry run changed lifecycle state: %#v", fixture.payloads)
		}
	}
}

func TestReconcileObjectPayloadsAppliesSafeQuarantineAndRecovery(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	missing := reconciledPayload("ten_reconcile", "missing", ObjectPayloadFinalized, now)
	mismatch := reconciledPayload("ten_reconcile", "mismatch", ObjectPayloadFinalized, now)
	recoverable := reconciledPayload("ten_reconcile", "recoverable", ObjectPayloadStaged, now.Add(-2*time.Hour))
	abandoned := reconciledPayload("ten_reconcile", "abandoned", ObjectPayloadStaged, now.Add(-2*time.Hour))
	fixture := &reconciliationFixture{
		payloads: []ObjectPayload{missing, mismatch, recoverable, abandoned},
		objects: map[string]Object{
			mismatch.FinalKey:    reconciledObject(mismatch, mismatch.FinalKey, []byte("not-the-declared-content")),
			recoverable.FinalKey: reconciledObject(recoverable, recoverable.FinalKey, []byte("recoverable")),
			abandoned.StagingKey: reconciledObject(abandoned, abandoned.StagingKey, []byte("abandoned")),
		},
	}

	receipt, err := ReconcileObjectPayloads(ctx, fixture, fixture, fixture, ObjectReconciliationRequest{
		TenantID:          "ten_reconcile",
		Limit:             20,
		Apply:             true,
		OrphanStagedAfter: time.Hour,
		Now:               func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("apply reconciliation: %v", err)
	}
	if receipt.DryRun || receipt.QuarantinedPayloads != 3 || receipt.RecoveredFinalizations != 1 {
		t.Fatalf("unexpected apply receipt: %#v", receipt)
	}
	if got := fixture.payloads[0].Status; got != ObjectPayloadOrphaned {
		t.Fatalf("missing final status = %q, want orphaned", got)
	}
	if got := fixture.payloads[1].Status; got != ObjectPayloadFailed {
		t.Fatalf("digest mismatch status = %q, want failed", got)
	}
	if got := fixture.payloads[2].Status; got != ObjectPayloadFinalized {
		t.Fatalf("recoverable final status = %q, want finalized", got)
	}
	if got := fixture.payloads[3].Status; got != ObjectPayloadOrphaned {
		t.Fatalf("abandoned staging status = %q, want orphaned", got)
	}
	if err := RequireFinalizedObjectPayload(ctx, fixture, mismatch.TenantID, mismatch.Digest, mismatch.FinalKey); !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatched payload reader gate err = %v, want conflict", err)
	}
}

func TestReconcileObjectPayloadsRequiresExplicitThresholdForApply(t *testing.T) {
	fixture := &reconciliationFixture{}
	_, err := ReconcileObjectPayloads(context.Background(), fixture, fixture, fixture, ObjectReconciliationRequest{
		TenantID: "ten_reconcile",
		Apply:    true,
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("apply without abandoned-staging threshold err = %v, want validation", err)
	}
}

func TestLedgerMetricsExposeOnlySafeReconciliationCounters(t *testing.T) {
	ledger := NewLedger(Config{
		APIKeyPepper: "test-pepper",
		Now:          fixedNow,
		ReconciliationMetrics: reconciliationMetricsFixture{metrics: ObjectReconciliationMetrics{
			Runs:                2,
			ScannedPayloads:     14,
			MissingFinalObjects: 1,
			DigestMismatches:    1,
			ProviderOrphans:     3,
			QuarantinedPayloads: 2,
			LastRunAt:           fixedNow(),
		}},
	})
	_, _, secret, err := ledger.BootstrapTenant(context.Background(), "Reconciliation", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap metrics tenant: %v", err)
	}
	actor, err := ledger.Authenticate(context.Background(), secret)
	if err != nil {
		t.Fatalf("authenticate metrics tenant: %v", err)
	}
	metrics, err := ledger.Metrics(context.Background(), actor)
	if err != nil || metrics["object_reconciliation_runs"] != int64(2) || metrics["object_reconciliation_scanned_payloads"] != int64(14) || metrics["object_reconciliation_provider_orphans"] != int64(3) || metrics["object_reconciliation_quarantined_payloads"] != int64(2) {
		t.Fatalf("safe reconciliation metrics=%#v err=%v", metrics, err)
	}
}

func reconciledPayload(tenantID, content string, status ObjectPayloadStatus, createdAt time.Time) ObjectPayload {
	digest := hashBytes([]byte(content))
	return ObjectPayload{
		TenantID:   tenantID,
		Digest:     digest,
		Size:       int64(len(content)),
		MediaType:  "application/octet-stream",
		StagingKey: "tenants/" + tenantID + "/staging/sha256/" + digest[len("sha256:"):],
		FinalKey:   "tenants/" + tenantID + "/payloads/sha256/" + digest[len("sha256:"):],
		Status:     status,
		CreatedAt:  createdAt,
		UpdatedAt:  createdAt,
	}
}

func reconciledObject(payload ObjectPayload, key string, body []byte) Object {
	return Object{Key: key, TenantID: payload.TenantID, MediaType: payload.MediaType, Digest: payload.Digest, Bytes: body, CreatedAt: payload.CreatedAt}
}

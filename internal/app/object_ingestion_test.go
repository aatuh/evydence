package app

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

type payloadLifecycleFixture struct {
	payloads map[string]ObjectPayload
}

func (f *payloadLifecycleFixture) GetObjectPayload(_ context.Context, tenantID, digest string) (ObjectPayload, error) {
	payload, ok := f.payloads[memoryObjectPayloadKey(tenantID, digest)]
	if !ok {
		return ObjectPayload{}, ErrNotFound
	}
	return payload, nil
}

func (f *payloadLifecycleFixture) MarkObjectPayloadFinalized(ctx context.Context, payload ObjectPayload) error {
	stored, err := f.GetObjectPayload(ctx, payload.TenantID, payload.Digest)
	if err != nil || stored.FinalKey != payload.FinalKey || stored.Status == ObjectPayloadOrphaned {
		return ErrConflict
	}
	now := time.Now().UTC()
	stored.Status = ObjectPayloadFinalized
	stored.FailureCode = ""
	stored.UpdatedAt = now
	stored.FinalizedAt = &now
	stored.FailedAt = nil
	stored.OrphanedAt = nil
	f.payloads[memoryObjectPayloadKey(stored.TenantID, stored.Digest)] = stored
	return nil
}

func (f *payloadLifecycleFixture) MarkObjectPayloadFailed(ctx context.Context, payload ObjectPayload, failureCode string) error {
	stored, err := f.GetObjectPayload(ctx, payload.TenantID, payload.Digest)
	if err != nil || stored.FinalKey != payload.FinalKey || stored.Status == ObjectPayloadFinalized || stored.Status == ObjectPayloadOrphaned {
		return ErrConflict
	}
	now := time.Now().UTC()
	stored.Status = ObjectPayloadFailed
	stored.FailureCode = failureCode
	stored.UpdatedAt = now
	stored.FailedAt = &now
	f.payloads[memoryObjectPayloadKey(stored.TenantID, stored.Digest)] = stored
	return nil
}

func (f *payloadLifecycleFixture) MarkObjectPayloadOrphaned(ctx context.Context, payload ObjectPayload) error {
	stored, err := f.GetObjectPayload(ctx, payload.TenantID, payload.Digest)
	if err != nil || stored.FinalKey != payload.FinalKey {
		return ErrConflict
	}
	now := time.Now().UTC()
	stored.Status = ObjectPayloadOrphaned
	stored.FailureCode = "object_missing"
	stored.UpdatedAt = now
	stored.OrphanedAt = &now
	f.payloads[memoryObjectPayloadKey(stored.TenantID, stored.Digest)] = stored
	return nil
}

type flakyPayloadStore struct {
	*testObjectStore
	failures int
}

func (s *flakyPayloadStore) FinalizePayload(ctx context.Context, payload ObjectPayload) (Object, error) {
	if s.failures > 0 {
		s.failures--
		return Object{}, errors.New("temporary object storage failure")
	}
	return s.testObjectStore.FinalizePayload(ctx, payload)
}

func TestUploadSBOMPersistedStagingMetadataAndFinalizationJobAreAtomic(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	objects := newTestObjectStore()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	ledger.objects = objects
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatal(err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "payments", "application/json", sampleDigest("staged-payload-artifact"), 42)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api","version":"1.0.0"}]}`)
	if _, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, raw); err != nil {
		t.Fatalf("upload SBOM: %v", err)
	}

	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	digest := hashBytes(raw)
	payload, ok := snapshot.ObjectPayloads[memoryObjectPayloadKey(actor.TenantID, digest)]
	if !ok || payload.Status != ObjectPayloadStaged || payload.Size != int64(len(raw)) {
		t.Fatalf("staged payload metadata = %#v", payload)
	}
	if _, err := objects.Get(ctx, payload.StagingKey); err != nil {
		t.Fatalf("read staged payload: %v", err)
	}
	if _, err := objects.Get(ctx, payload.FinalKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("final payload before finalization err=%v, want not found", err)
	}

	var finalizer, parser OutboxJob
	for _, job := range snapshot.OutboxJobs {
		switch job.Kind {
		case "finalize_payload":
			finalizer = job
		case "parse_sbom":
			parser = job
		}
	}
	if finalizer.SubjectID != digest || parser.Payload["payload_lifecycle"] != PayloadLifecycleVersion || parser.Payload["payload_digest"] != digest {
		t.Fatalf("payload jobs finalizer=%#v parser=%#v", finalizer, parser)
	}
}

func TestCreateEvidenceRejectsMismatchedStagedPayloadBinding(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	payload, err := newStagedObjectPayload(actor.TenantID, "application/json", sampleDigest("payload-binding"), fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	payload.Size = 10
	if _, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{
		Type:             "build",
		Title:            "mismatched staged payload",
		PayloadRef:       "object://" + payload.FinalKey,
		PayloadHash:      payload.Digest,
		PayloadMediaType: "application/json",
		PayloadSize:      11,
		StagedPayload:    payload,
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("mismatched staged payload binding error=%v, want validation", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ObjectPayloads) != 0 || len(snapshot.Evidence) != 0 {
		t.Fatalf("rejected staged payload mutated durable state: payloads=%#v evidence=%#v", snapshot.ObjectPayloads, snapshot.Evidence)
	}
}

func TestUploadSBOMLeavesDiscoverableStagingObjectWhenTransactionFails(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	objects := newTestObjectStore()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, UnitOfWork: memory, ObjectStore: objects})
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatal(err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "payments", "application/json", sampleDigest("staged-rollback-artifact"), 42)
	if err != nil {
		t.Fatal(err)
	}
	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{
		inner: memory,
		decorate: func(repos Repositories) Repositories {
			repos.Evidence = failingEvidenceRepository{EvidenceRepository: repos.Evidence}
			return repos
		},
	}
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api"}]}`)
	if _, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, raw); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("upload SBOM error=%v, want injected transaction failure", err)
	}
	payload, err := newStagedObjectPayload(actor.TenantID, "application/vnd.cyclonedx+json", hashBytes(raw), fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objects.Get(ctx, payload.StagingKey); err != nil {
		t.Fatalf("staged upload should remain discoverable after database failure: %v", err)
	}
	if _, err := objects.Get(ctx, payload.FinalKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("database failure must not expose final payload: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snapshot.ObjectPayloads[memoryObjectPayloadKey(actor.TenantID, hashBytes(raw))]; ok {
		t.Fatal("rolled-back payload metadata was committed")
	}
}

func TestFinalizeStagedObjectPayloadRetriesSafelyAndGatesReaders(t *testing.T) {
	ctx := context.Background()
	raw := []byte("payload bytes")
	payload, err := newStagedObjectPayload("ten_payload", "application/octet-stream", hashBytes(raw), fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	objects := &flakyPayloadStore{testObjectStore: newTestObjectStore(), failures: 1}
	payload, err = objects.StagePayload(ctx, payload, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := &payloadLifecycleFixture{payloads: map[string]ObjectPayload{memoryObjectPayloadKey(payload.TenantID, payload.Digest): payload}}
	if err := RequireFinalizedObjectPayload(ctx, lifecycle, payload.TenantID, payload.Digest, payload.FinalKey); !errors.Is(err, ErrConflict) {
		t.Fatalf("staged payload read gate error=%v, want conflict", err)
	}
	if err := FinalizeStagedObjectPayload(ctx, lifecycle, objects, payload.TenantID, payload.Digest); err == nil {
		t.Fatal("expected first finalization attempt to fail")
	}
	failed, err := lifecycle.GetObjectPayload(ctx, payload.TenantID, payload.Digest)
	if err != nil || failed.Status != ObjectPayloadFailed || failed.FailureCode != "finalization_failed" {
		t.Fatalf("failed lifecycle metadata = %#v err=%v", failed, err)
	}
	if err := FinalizeStagedObjectPayload(ctx, lifecycle, objects, payload.TenantID, payload.Digest); err != nil {
		t.Fatalf("retry finalization: %v", err)
	}
	if err := FinalizeStagedObjectPayload(ctx, lifecycle, objects, payload.TenantID, payload.Digest); err != nil {
		t.Fatalf("repeated finalization after crash boundary: %v", err)
	}
	finalized, err := lifecycle.GetObjectPayload(ctx, payload.TenantID, payload.Digest)
	if err != nil || finalized.Status != ObjectPayloadFinalized || finalized.FinalizedAt == nil {
		t.Fatalf("finalized lifecycle metadata = %#v err=%v", finalized, err)
	}
	if err := RequireFinalizedObjectPayload(ctx, lifecycle, payload.TenantID, payload.Digest, payload.FinalKey); err != nil {
		t.Fatalf("finalized payload read gate: %v", err)
	}
	if err := RequireFinalizedObjectPayload(ctx, lifecycle, "ten_other", payload.Digest, payload.FinalKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant payload read gate error=%v, want not found", err)
	}
}

func TestFinalizeStagedObjectPayloadMarksMissingObjectsOrphaned(t *testing.T) {
	ctx := context.Background()
	payload, err := newStagedObjectPayload("ten_missing", "application/json", sampleDigest("missing-payload"), fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	payload.Size = 1
	for _, status := range []ObjectPayloadStatus{ObjectPayloadStaged, ObjectPayloadFinalized} {
		t.Run(string(status), func(t *testing.T) {
			current := payload
			current.Status = status
			lifecycle := &payloadLifecycleFixture{payloads: map[string]ObjectPayload{memoryObjectPayloadKey(current.TenantID, current.Digest): current}}
			if err := FinalizeStagedObjectPayload(ctx, lifecycle, newTestObjectStore(), current.TenantID, current.Digest); !errors.Is(err, ErrNotFound) {
				t.Fatalf("missing %s payload error=%v, want not found", status, err)
			}
			stored, err := lifecycle.GetObjectPayload(ctx, current.TenantID, current.Digest)
			if err != nil || stored.Status != ObjectPayloadOrphaned || stored.FailureCode != "object_missing" {
				t.Fatalf("orphaned %s payload=%#v err=%v", status, stored, err)
			}
		})
	}
}

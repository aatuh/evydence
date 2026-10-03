package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type recordingWorkerProjectionStore struct {
	mu         sync.Mutex
	projection WorkerProjection
	err        error
	tenantIDs  []string
}

func (s *recordingWorkerProjectionStore) LoadWorkerProjection(_ context.Context, tenantID string) (WorkerProjection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenantIDs = append(s.tenantIDs, tenantID)
	return s.projection, s.err
}

func (s *recordingWorkerProjectionStore) loadedTenantIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.tenantIDs...)
}

func TestWithIdempotencyCommandCloneRetainsWorkerProjectionStore(t *testing.T) {
	t.Run("release bundle fails closed when projection loading fails", func(t *testing.T) {
		ctx := context.Background()
		memory := NewMemoryUnitOfWorkFactory()
		ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
		product, err := ledger.CreateProduct(ctx, actor, "Projection product", "projection-product")
		if err != nil {
			t.Fatalf("CreateProduct: %v", err)
		}
		release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
		if err != nil {
			t.Fatalf("CreateRelease: %v", err)
		}

		projectionErr := errors.New("worker projection unavailable")
		projectionStore := &recordingWorkerProjectionStore{err: projectionErr}
		ledger.workerProjections = projectionStore

		_, _, err = ledger.WithIdempotency(ctx, actor, "POST", "/v1/release-bundles", "projection-bundle", []byte(`{"release_id":"`+release.ID+`"}`), func(commandCtx context.Context, commandLedger *Ledger) (int, any, error) {
			bundle, commandErr := commandLedger.CreateReleaseBundle(commandCtx, actor, release.ID)
			return 201, bundle, commandErr
		})
		if !errors.Is(err, projectionErr) {
			t.Fatalf("WithIdempotency error = %v, want projection failure", err)
		}
		if got := projectionStore.loadedTenantIDs(); len(got) != 1 || got[0] != actor.TenantID {
			t.Fatalf("projection tenant IDs = %v, want [%s]", got, actor.TenantID)
		}
		if len(ledger.bundles) != 0 {
			t.Fatalf("bundle cache changed after projection failure: %#v", ledger.bundles)
		}
		snapshot, snapshotErr := memory.Snapshot()
		if snapshotErr != nil {
			t.Fatalf("Snapshot: %v", snapshotErr)
		}
		if len(snapshot.ReleaseBundles) != 0 {
			t.Fatalf("durable bundles changed after projection failure: %#v", snapshot.ReleaseBundles)
		}
	})

	t.Run("customer package rejects a foreign tenant projection", func(t *testing.T) {
		ctx := context.Background()
		memory := NewMemoryUnitOfWorkFactory()
		ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
		product, err := ledger.CreateProduct(ctx, actor, "Package product", "package-product")
		if err != nil {
			t.Fatalf("CreateProduct: %v", err)
		}
		release, err := ledger.CreateRelease(ctx, actor, product.ID, "2.0.0")
		if err != nil {
			t.Fatalf("CreateRelease: %v", err)
		}
		profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{
			Name:         "Customer-safe projection",
			AllowedTypes: []string{"sbom"},
		})
		if err != nil {
			t.Fatalf("CreateRedactionProfile: %v", err)
		}

		projectionStore := &recordingWorkerProjectionStore{projection: WorkerProjection{SBOMs: []domain.SBOM{{
			ID: "sbom_foreign", TenantID: "ten_foreign", EvidenceID: "ev_foreign", ReleaseID: release.ID,
			Format: "cyclonedx", CreatedAt: fixedNow(),
		}}}}
		ledger.workerProjections = projectionStore

		_, _, err = ledger.WithIdempotency(ctx, actor, "POST", "/v1/customer-packages", "projection-package", []byte(`{"product_id":"`+product.ID+`"}`), func(commandCtx context.Context, commandLedger *Ledger) (int, any, error) {
			pkg, commandErr := commandLedger.CreateCustomerSecurityPackage(commandCtx, actor, CreateCustomerPackageInput{
				ProductID: product.ID, ReleaseID: release.ID, RedactionProfileID: profile.ID,
				Title: "Customer package", ExpiresAt: fixedNow().Add(time.Hour),
			})
			return 201, pkg, commandErr
		})
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("WithIdempotency error = %v, want tenant projection conflict", err)
		}
		if got := projectionStore.loadedTenantIDs(); len(got) != 1 || got[0] != actor.TenantID {
			t.Fatalf("projection tenant IDs = %v, want [%s]", got, actor.TenantID)
		}
		if len(ledger.customerPackages) != 0 {
			t.Fatalf("customer package cache changed after tenant conflict: %#v", ledger.customerPackages)
		}
		snapshot, snapshotErr := memory.Snapshot()
		if snapshotErr != nil {
			t.Fatalf("Snapshot: %v", snapshotErr)
		}
		if len(snapshot.CustomerPackages) != 0 {
			t.Fatalf("durable customer packages changed after tenant conflict: %#v", snapshot.CustomerPackages)
		}
	})
}

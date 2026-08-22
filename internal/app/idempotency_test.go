package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type idempotencyPersistenceFailureStore struct{ err error }

type idempotencyReloadStore struct {
	state PersistedState
	ok    bool
}

func (s *idempotencyReloadStore) LoadState(context.Context) (PersistedState, bool, error) {
	return s.state, s.ok, nil
}

func (*idempotencyReloadStore) SaveState(context.Context, PersistedState) error { return nil }

type failingIdempotencyCompletionRepository struct{ IdempotencyRepository }

func (failingIdempotencyCompletionRepository) Complete(context.Context, IdempotencyRecordKey, string, int, any, time.Time) error {
	return errInjectedRepositoryFailure
}

func (s idempotencyPersistenceFailureStore) LoadState(context.Context) (PersistedState, bool, error) {
	return PersistedState{}, false, nil
}

func (s idempotencyPersistenceFailureStore) SaveState(context.Context, PersistedState) error {
	return s.err
}

func (s idempotencyPersistenceFailureStore) ApplyCriticalMutation(context.Context, CriticalMutation) error {
	return s.err
}

func TestPublishCommittedIdempotencyCommandReloadsDurableCache(t *testing.T) {
	seed := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	seed.mu.Lock()
	state, err := seed.snapshotLocked()
	seed.mu.Unlock()
	if err != nil {
		t.Fatalf("snapshot seed ledger: %v", err)
	}
	store := &idempotencyReloadStore{state: state, ok: true}
	ledger, err := NewLedgerWithContext(context.Background(), Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store})
	if err != nil {
		t.Fatalf("create durable ledger: %v", err)
	}

	// Model an outbox worker appending durable state after the API process took
	// the command snapshot. The durable state, rather than the stale command
	// clone, must win when publishing after commit.
	store.state.Products["prod_worker"] = domain.Product{ID: "prod_worker", TenantID: "tenant-idempotency", Name: "Worker product", Slug: "worker-product", CreatedAt: fixedNow()}
	command := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	command.products["prod_command"] = domain.Product{ID: "prod_command", TenantID: "tenant-idempotency", Name: "Command product", Slug: "command-product", CreatedAt: fixedNow()}
	if err := ledger.publishCommittedIdempotencyCommand(context.Background(), command); err != nil {
		t.Fatalf("publish durable idempotency command: %v", err)
	}
	if _, ok := ledger.products["prod_worker"]; !ok {
		t.Fatal("durable cache refresh discarded state committed by another process")
	}
	if _, ok := ledger.products["prod_command"]; ok {
		t.Fatal("durable cache refresh applied stale command snapshot over durable state")
	}
}

func TestWithIdempotencyDoesNotExecuteConcurrentPendingRequest(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor := domain.Actor{TenantID: "tenant-idempotency", KeyID: "key-idempotency"}
	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan struct{})

	go func() {
		defer close(firstDone)
		status, _, err := ledger.WithIdempotency(context.Background(), actor, "POST", "/v1/products", "concurrent-key", []byte(`{"name":"Payments"}`), func(context.Context, *Ledger) (int, any, error) {
			close(started)
			<-release
			return 201, map[string]any{"id": "prod-first"}, nil
		})
		if err != nil || status != 201 {
			t.Errorf("first request status=%d err=%v, want 201 and no error", status, err)
		}
	}()
	<-started

	var secondRan atomic.Bool
	status, response, err := ledger.WithIdempotency(context.Background(), actor, "POST", "/v1/products", "concurrent-key", []byte(`{"name":"Payments"}`), func(context.Context, *Ledger) (int, any, error) {
		secondRan.Store(true)
		return 201, map[string]any{"id": "prod-second"}, nil
	})
	if !errors.Is(err, ErrIdempotencyInProgress) {
		t.Fatalf("concurrent request status=%d response=%#v err=%v, want idempotency in progress", status, response, err)
	}
	if secondRan.Load() {
		t.Fatal("concurrent request executed its command while the first lease was active")
	}

	close(release)
	<-firstDone

	status, response, err = ledger.WithIdempotency(context.Background(), actor, "POST", "/v1/products", "concurrent-key", []byte(`{"name":"Payments"}`), func(context.Context, *Ledger) (int, any, error) {
		t.Fatal("completed idempotency record must replay without executing the command")
		return 0, nil, nil
	})
	if err != nil || status != 201 {
		t.Fatalf("completed replay status=%d err=%v, want 201 and no error", status, err)
	}
	if got, ok := response.(map[string]any); !ok || got["id"] != "prod-first" {
		t.Fatalf("completed replay response=%#v, want original response", response)
	}
}

func TestWithIdempotencyCommitsCommandAndReplayTogether(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	var commandRuns atomic.Int32
	status, response, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/products", "atomic-product", []byte(`{"name":"Atomic","slug":"atomic"}`), func(ctx context.Context, commandLedger *Ledger) (int, any, error) {
		commandRuns.Add(1)
		product, err := commandLedger.CreateProduct(ctx, actor, "Atomic", "atomic")
		return 201, product, err
	})
	if err != nil || status != 201 {
		t.Fatalf("atomic command status=%d response=%#v err=%v", status, response, err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after atomic command: %v", err)
	}
	if len(snapshot.Products) != 1 || len(snapshot.Idempotency) != 1 {
		t.Fatalf("atomic command did not commit product and replay record together: %#v", snapshot)
	}
	for _, record := range snapshot.Idempotency {
		if record.State != IdempotencyCompleted || record.Response == nil {
			t.Fatalf("atomic command record=%#v, want completed safe replay", record)
		}
	}
	status, replay, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/products", "atomic-product", []byte(`{"name":"Atomic","slug":"atomic"}`), func(context.Context, *Ledger) (int, any, error) {
		t.Fatal("completed atomic command must replay without re-executing")
		return 0, nil, nil
	})
	if err != nil || status != 201 || commandRuns.Load() != 1 || replay == nil {
		t.Fatalf("atomic replay status=%d response=%#v runs=%d err=%v", status, replay, commandRuns.Load(), err)
	}
}

func TestWithIdempotencyRollsBackCommandWhenItFails(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	commandErr := errors.New("command rejected after staging write")
	if _, _, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/products", "atomic-rollback", []byte(`{"name":"Rollback","slug":"rollback"}`), func(ctx context.Context, commandLedger *Ledger) (int, any, error) {
		if _, err := commandLedger.CreateProduct(ctx, actor, "Rollback", "rollback"); err != nil {
			return 0, nil, err
		}
		return 500, nil, commandErr
	}); !errors.Is(err, commandErr) {
		t.Fatalf("failed command err=%v, want command error", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after rollback: %v", err)
	}
	if len(snapshot.Products) != 0 {
		t.Fatalf("failed command committed a product: %#v", snapshot.Products)
	}
	for _, record := range snapshot.Idempotency {
		if record.State != IdempotencyFailed || record.Response != nil {
			t.Fatalf("failed command replay record=%#v", record)
		}
	}
	if _, _, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/products", "atomic-rollback", []byte(`{"name":"Rollback","slug":"rollback"}`), func(context.Context, *Ledger) (int, any, error) {
		t.Fatal("failed command must not be retried with the same key")
		return 0, nil, nil
	}); !errors.Is(err, ErrIdempotencyFailed) {
		t.Fatalf("failed command replay err=%v, want idempotency failed", err)
	}
}

func TestWithIdempotencyStoresNoOneTimeSecretInReplay(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	status, first, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/api-keys", "one-time-secret", []byte(`{"name":"automation"}`), func(context.Context, *Ledger) (int, any, error) {
		return 201, map[string]any{"api_key": map[string]any{"id": "key-one-time"}, "secret": "evy_sensitive_one_time_secret"}, nil
	})
	if err != nil || status != 201 || first.(map[string]any)["secret"] != "evy_sensitive_one_time_secret" {
		t.Fatalf("first one-time response status=%d response=%#v err=%v", status, first, err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot one-time response: %v", err)
	}
	for _, record := range snapshot.Idempotency {
		if encoded, err := json.Marshal(record.Response); err != nil || strings.Contains(string(encoded), "evy_sensitive_one_time_secret") || strings.Contains(string(encoded), `"secret"`) {
			t.Fatalf("replay record retained one-time secret: response=%#v encoded=%q err=%v", record.Response, encoded, err)
		}
	}
	_, replay, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/api-keys", "one-time-secret", []byte(`{"name":"automation"}`), func(context.Context, *Ledger) (int, any, error) {
		t.Fatal("one-time secret request must replay without command execution")
		return 0, nil, nil
	})
	if err != nil || replay.(map[string]any)["secret"] != nil {
		t.Fatalf("one-time replay response=%#v err=%v", replay, err)
	}
}

func TestIdempotencyStateErrorsAreSafeConflicts(t *testing.T) {
	for _, testCase := range []struct {
		err  error
		code string
	}{
		{err: ErrIdempotencyInProgress, code: "IDEMPOTENCY_IN_PROGRESS"},
		{err: ErrIdempotencyFailed, code: "IDEMPOTENCY_REQUEST_FAILED"},
	} {
		if status := StatusCode(testCase.err); status != 409 {
			t.Fatalf("status for %v = %d, want 409", testCase.err, status)
		}
		if code := ProblemCode(testCase.err); code != testCase.code {
			t.Fatalf("problem code for %v = %q, want %q", testCase.err, code, testCase.code)
		}
	}
}

func TestMemoryIdempotencyRepositoryStateTransitions(t *testing.T) {
	ctx := context.Background()
	factory := NewMemoryUnitOfWorkFactory()
	now := fixedNow()
	tenantID := "ten_idempotency_memory"
	if err := ExecuteUnitOfWork(ctx, factory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Identity.InsertTenant(ctx, domain.Tenant{ID: tenantID, Name: "Idempotency memory", CreatedAt: now})
	}); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	reserve := func(reservation IdempotencyReservation) (IdempotencyReservationResult, error) {
		var result IdempotencyReservationResult
		err := ExecuteUnitOfWork(ctx, factory, func(ctx context.Context, repositories Repositories) error {
			var err error
			result, err = repositories.Idempotency.Reserve(ctx, reservation)
			return err
		})
		return result, err
	}
	key := IdempotencyRecordKey{TenantID: tenantID, ActorID: "api_key:key_memory", Method: "POST", Path: "/v1/products", IdempotencyKey: "completed"}
	first := IdempotencyReservation{Key: key, RequestHash: "sha256:completed", OwnerTokenHash: "sha256:owner-one", Now: now, LeaseExpiresAt: now.Add(time.Minute), ExpiresAt: now.Add(24 * time.Hour)}
	if result, err := reserve(first); err != nil || result.Outcome != IdempotencyReservationAcquired {
		t.Fatalf("first reserve result=%#v err=%v, want acquired", result, err)
	}
	if err := ExecuteUnitOfWork(ctx, factory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Idempotency.Complete(ctx, key, first.OwnerTokenHash, 201, map[string]any{"id": "prod-memory"}, now)
	}); err != nil {
		t.Fatalf("complete memory record: %v", err)
	}
	if result, err := reserve(first); err != nil || result.Outcome != IdempotencyReservationReplay || result.Record.Status != 201 {
		t.Fatalf("completed replay result=%#v err=%v, want replay", result, err)
	}
	mismatched := first
	mismatched.RequestHash = "sha256:mismatched"
	mismatched.OwnerTokenHash = "sha256:owner-mismatched"
	if _, err := reserve(mismatched); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("mismatched request err=%v, want idempotency conflict", err)
	}

	pendingKey := key
	pendingKey.IdempotencyKey = "recovered"
	pending := first
	pending.Key = pendingKey
	pending.RequestHash = "sha256:recovered"
	pending.OwnerTokenHash = "sha256:owner-pending"
	if result, err := reserve(pending); err != nil || result.Outcome != IdempotencyReservationAcquired {
		t.Fatalf("pending reserve result=%#v err=%v, want acquired", result, err)
	}
	recovery := pending
	recovery.OwnerTokenHash = "sha256:owner-recovered"
	recovery.Now = now.Add(2 * time.Minute)
	recovery.LeaseExpiresAt = recovery.Now.Add(time.Minute)
	if result, err := reserve(recovery); err != nil || result.Outcome != IdempotencyReservationRecovered {
		t.Fatalf("recovery reserve result=%#v err=%v, want recovered", result, err)
	}
	if err := ExecuteUnitOfWork(ctx, factory, func(ctx context.Context, repositories Repositories) error {
		if err := repositories.Idempotency.Complete(ctx, pendingKey, pending.OwnerTokenHash, 201, map[string]any{"id": "stale"}, recovery.Now); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale owner complete err=%v, want conflict", err)
		}
		return repositories.Idempotency.Fail(ctx, pendingKey, recovery.OwnerTokenHash, recovery.Now)
	}); err != nil {
		t.Fatalf("fail recovered record: %v", err)
	}
	if result, err := reserve(recovery); err != nil || result.Outcome != IdempotencyReservationFailure {
		t.Fatalf("failed reserve result=%#v err=%v, want failed", result, err)
	}
	if err := ExecuteUnitOfWork(ctx, factory, func(ctx context.Context, repositories Repositories) error {
		deleted, err := repositories.Idempotency.DeleteExpired(ctx, now.Add(25*time.Hour))
		if err != nil {
			return err
		}
		if deleted != 2 {
			t.Fatalf("deleted expired records=%d, want 2", deleted)
		}
		return nil
	}); err != nil {
		t.Fatalf("delete expired memory records: %v", err)
	}
	if _, err := reserve(IdempotencyReservation{Key: IdempotencyRecordKey{TenantID: "ten_missing", ActorID: "api_key:key_missing", Method: "POST", Path: "/v1/products", IdempotencyKey: "missing"}, RequestHash: "sha256:missing", OwnerTokenHash: "sha256:owner-missing", Now: now, LeaseExpiresAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing tenant reserve err=%v, want not found", err)
	}
}

func TestWithIdempotencyStoresOnlySafeFailedState(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor := domain.Actor{TenantID: "tenant-idempotency-failure", KeyID: "key-idempotency-failure"}
	runErr := errors.New("upstream secret response must not be replayed")
	if _, _, err := ledger.WithIdempotency(context.Background(), actor, "POST", "/v1/products", "failed-key", []byte(`{"name":"Payments"}`), func(context.Context, *Ledger) (int, any, error) {
		return 502, map[string]any{"token": "must-not-store"}, runErr
	}); !errors.Is(err, runErr) {
		t.Fatalf("first failed request err=%v, want original error", err)
	}
	ranAgain := false
	status, response, err := ledger.WithIdempotency(context.Background(), actor, "POST", "/v1/products", "failed-key", []byte(`{"name":"Payments"}`), func(context.Context, *Ledger) (int, any, error) {
		ranAgain = true
		return 201, map[string]any{"id": "must-not-create"}, nil
	})
	if !errors.Is(err, ErrIdempotencyFailed) || status != 0 || response != nil || ranAgain {
		t.Fatalf("failed replay status=%d response=%#v ranAgain=%t err=%v", status, response, ranAgain, err)
	}
	storeKey := NewIdempotencyRecordKey(actor.TenantID, idempotencyActorID(actor), "POST", "/v1/products", "failed-key")
	record := ledger.idempotency[storeKey]
	if record.State != IdempotencyFailed || record.Response != nil || record.OwnerTokenHash != "" || record.FailedAt == nil {
		t.Fatalf("failed record retained unsafe state: %#v", record)
	}
}

func TestWithIdempotencyAllowsRetryAfterTransientSigningFailure(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor := domain.Actor{TenantID: "tenant-idempotency-retry", KeyID: "key-idempotency-retry"}
	body := []byte(`{"provider_id":"provider"}`)
	if _, _, err := ledger.WithIdempotency(context.Background(), actor, "POST", "/v1/signing-operations", "retry-key", body, func(context.Context, *Ledger) (int, any, error) {
		return 503, nil, ErrRetryableSigning
	}); !errors.Is(err, ErrRetryableSigning) {
		t.Fatalf("first signing request err=%v, want retryable signing error", err)
	}
	ranAgain := false
	status, response, err := ledger.WithIdempotency(context.Background(), actor, "POST", "/v1/signing-operations", "retry-key", body, func(context.Context, *Ledger) (int, any, error) {
		ranAgain = true
		return 201, map[string]any{"id": "sop_1"}, nil
	})
	if err != nil || !ranAgain || status != 201 || response.(map[string]any)["id"] != "sop_1" {
		t.Fatalf("retry status=%d response=%#v ran=%t err=%v", status, response, ranAgain, err)
	}
}

func TestWithIdempotencyReplaysLegacyRecordsAndReplacesExpiredKeys(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor := domain.Actor{TenantID: "tenant-idempotency-legacy", KeyID: "key-idempotency-legacy"}
	legacyBody := []byte(`{"name":"Legacy"}`)
	key := NewIdempotencyRecordKey(actor.TenantID, idempotencyActorID(actor), "POST", "/v1/products", "legacy-key")
	ledger.idempotency[key] = IdempotencyRecord{RequestHash: hashBytes(append([]byte("POST\n/v1/products\n"), legacyBody...)), Status: 201, Response: map[string]any{"id": "prod-legacy", "secret": "legacy-one-time-secret"}, CreatedAt: fixedNow()}
	status, response, err := ledger.WithIdempotency(context.Background(), actor, "POST", "/v1/products", "legacy-key", legacyBody, func(context.Context, *Ledger) (int, any, error) {
		t.Fatal("legacy completed record must replay without execution")
		return 0, nil, nil
	})
	if err != nil || status != 201 || response.(map[string]any)["id"] != "prod-legacy" || response.(map[string]any)["secret"] != nil {
		t.Fatalf("legacy replay status=%d response=%#v err=%v", status, response, err)
	}

	expired := ledger.idempotency[key]
	expired.ExpiresAt = fixedNow().Add(-time.Second)
	ledger.idempotency[key] = expired
	runCount := 0
	status, response, err = ledger.WithIdempotency(context.Background(), actor, "POST", "/v1/products", "legacy-key", []byte(`{"name":"Replacement"}`), func(context.Context, *Ledger) (int, any, error) {
		runCount++
		return 201, map[string]any{"id": "prod-replacement"}, nil
	})
	if err != nil || status != 201 || runCount != 1 || response.(map[string]any)["id"] != "prod-replacement" {
		t.Fatalf("expired replacement status=%d response=%#v runs=%d err=%v", status, response, runCount, err)
	}
}

func TestIdempotencyHelpersRejectInvalidReservations(t *testing.T) {
	if err := ValidateIdempotencyKey(IdempotencyRecordKey{}); !errors.Is(err, ErrValidation) {
		t.Fatalf("empty idempotency key err=%v, want validation", err)
	}
	if err := ValidateIdempotencyReservation(IdempotencyReservation{}); !errors.Is(err, ErrValidation) {
		t.Fatalf("empty reservation err=%v, want validation", err)
	}
	legacy, err := NormalizeLegacyIdempotencyRecord(IdempotencyRecord{RequestHash: "sha256:legacy", Status: 201, Response: map[string]any{"id": "legacy"}, CreatedAt: fixedNow()})
	if err != nil || legacy.State != IdempotencyCompleted || legacy.CompletedAt == nil || legacy.ExpiresAt.IsZero() {
		t.Fatalf("normalize legacy record=%#v err=%v", legacy, err)
	}
	reservation := IdempotencyReservation{Key: IdempotencyRecordKey{TenantID: "tenant", ActorID: "api_key:key", Method: "POST", Path: "/v1/products", IdempotencyKey: "helper"}, RequestHash: "sha256:helper", OwnerTokenHash: "sha256:owner", Now: fixedNow(), LeaseExpiresAt: fixedNow().Add(time.Minute), ExpiresAt: fixedNow().Add(time.Hour)}
	pending := PendingIdempotencyRecord(reservation)
	if pending.State != IdempotencyPending || pending.LeaseExpiresAt == nil {
		t.Fatalf("pending helper record=%#v", pending)
	}
	recovered := RecoveredPendingIdempotencyRecord(pending, IdempotencyReservation{Key: reservation.Key, RequestHash: reservation.RequestHash, OwnerTokenHash: "sha256:recovered", Now: fixedNow().Add(2 * time.Minute), LeaseExpiresAt: fixedNow().Add(3 * time.Minute), ExpiresAt: fixedNow().Add(48 * time.Hour)})
	if recovered.CreatedAt != pending.CreatedAt || !recovered.ExpiresAt.Equal(pending.ExpiresAt) || recovered.OwnerTokenHash != "sha256:recovered" {
		t.Fatalf("recovered helper record=%#v", recovered)
	}
}

func TestWithIdempotencyDurablyMarksFailedReservations(t *testing.T) {
	ctx := context.Background()
	factory := NewMemoryUnitOfWorkFactory()
	now := fixedNow()
	actor := domain.Actor{TenantID: "tenant-idempotency-durable-failure", KeyID: "key-idempotency-durable-failure"}
	if err := ExecuteUnitOfWork(ctx, factory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Identity.InsertTenant(ctx, domain.Tenant{ID: actor.TenantID, Name: "Durable idempotency", CreatedAt: now})
	}); err != nil {
		t.Fatalf("insert durable tenant: %v", err)
	}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, UnitOfWork: factory})
	runErr := errors.New("durable command failure")
	if _, _, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/products", "durable-failed", []byte(`{"name":"Payments"}`), func(context.Context, *Ledger) (int, any, error) {
		return 503, nil, runErr
	}); !errors.Is(err, runErr) {
		t.Fatalf("durable failure err=%v, want command error", err)
	}
	snapshot, err := factory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot durable failure: %v", err)
	}
	if len(snapshot.Idempotency) != 1 {
		t.Fatalf("durable failure did not persist state: %#v", snapshot.Idempotency)
	}
	for _, record := range snapshot.Idempotency {
		if record.State != IdempotencyFailed || record.Response != nil || record.FailedAt == nil {
			t.Fatalf("durable failure record=%#v", record)
		}
	}
}

func TestWithIdempotencyReturnsDurableCompletionFailure(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	now := fixedNow()
	actor := domain.Actor{TenantID: "tenant-idempotency-completion-failure", KeyID: "key-idempotency-completion-failure"}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Identity.InsertTenant(ctx, domain.Tenant{ID: actor.TenantID, Name: "Idempotency completion failure", CreatedAt: now})
	}); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	ledger := NewLedger(Config{
		APIKeyPepper: "test-pepper",
		Now:          fixedNow,
		UnitOfWork: repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
			repositories.Idempotency = failingIdempotencyCompletionRepository{IdempotencyRepository: repositories.Idempotency}
			return repositories
		}},
	})
	if status, response, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/products", "completion-fails", []byte(`{"name":"Payments"}`), func(context.Context, *Ledger) (int, any, error) {
		return 201, map[string]any{"id": "prod-completion-failure"}, nil
	}); !errors.Is(err, errInjectedRepositoryFailure) || status != 0 || response != nil {
		t.Fatalf("durable completion failure status=%d response=%#v err=%v", status, response, err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot completion failure: %v", err)
	}
	if len(snapshot.Idempotency) != 0 {
		t.Fatalf("completion failure committed a replay record: %#v", snapshot.Idempotency)
	}
}

func TestIdempotencyInternalGuardsAndLeaseRecovery(t *testing.T) {
	ctx := context.Background()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	now := fixedNow()
	key := IdempotencyRecordKey{TenantID: "tenant-idempotency-internal", ActorID: "api_key:key-internal", Method: "POST", Path: "/v1/products", IdempotencyKey: "recover"}
	storeKey := NewIdempotencyRecordKey(key.TenantID, key.ActorID, key.Method, key.Path, key.IdempotencyKey)
	expiredLease := now.Add(-time.Second)
	ledger.idempotency[storeKey] = IdempotencyRecord{State: IdempotencyPending, RequestHash: "sha256:recover", OwnerTokenHash: "sha256:old-owner", CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour), LeaseExpiresAt: &expiredLease, ExpiresAt: now.Add(time.Hour)}
	reservation := IdempotencyReservation{Key: key, RequestHash: "sha256:recover", OwnerTokenHash: "sha256:new-owner", Now: now, LeaseExpiresAt: now.Add(time.Minute), ExpiresAt: now.Add(24 * time.Hour)}
	result, err := ledger.reserveInMemoryIdempotency(ctx, reservation)
	if err != nil || result.Outcome != IdempotencyReservationRecovered || result.Record.OwnerTokenHash != reservation.OwnerTokenHash {
		t.Fatalf("lease recovery result=%#v err=%v", result, err)
	}
	if err := ledger.completeInMemoryIdempotency(ctx, reservation, 99, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid completion status err=%v, want validation", err)
	}
	wrongOwner := reservation
	wrongOwner.OwnerTokenHash = "sha256:wrong-owner"
	if err := ledger.completeInMemoryIdempotency(ctx, wrongOwner, 201, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong completion owner err=%v, want conflict", err)
	}
	if err := ledger.failInMemoryIdempotency(ctx, wrongOwner); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong failure owner err=%v, want conflict", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := ledger.reserveInMemoryIdempotency(canceled, reservation); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reserve err=%v, want context canceled", err)
	}
	if _, err := ledger.reserveInMemoryIdempotency(ctx, IdempotencyReservation{}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid reserve err=%v, want validation", err)
	}
	if _, err := newIdempotencyReservation(IdempotencyRecordKey{}, "sha256:invalid", now); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid new reservation err=%v, want validation", err)
	}
	if _, err := normalizeLegacyIdempotencyRecord(IdempotencyRecord{State: IdempotencyFailed, RequestHash: "sha256:invalid-state", Status: 201, CreatedAt: now}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid legacy state err=%v, want validation", err)
	}
	if _, err := replayableIdempotencyRecord(IdempotencyRecord{State: IdempotencyPending, RequestHash: "sha256:pending", Status: 201, ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, ErrValidation) {
		t.Fatalf("pending replay err=%v, want validation", err)
	}

	completeErr := errors.New("completion failed")
	if _, _, err := ledger.finishIdempotencyReservation(ctx, reservation, IdempotencyReservationResult{Outcome: IdempotencyReservationAcquired}, func() (int, any, error) {
		return 201, map[string]any{"id": "completion-error"}, nil
	}, func(context.Context, int, any) error { return completeErr }, func(context.Context) error { return nil }); !errors.Is(err, completeErr) {
		t.Fatalf("completion failure err=%v, want completion error", err)
	}
	if _, _, err := ledger.finishIdempotencyReservation(ctx, reservation, IdempotencyReservationResult{Outcome: "unknown"}, func() (int, any, error) {
		return 201, nil, nil
	}, func(context.Context, int, any) error { return nil }, func(context.Context) error { return nil }); !errors.Is(err, ErrValidation) {
		t.Fatalf("unknown outcome err=%v, want validation", err)
	}
}

func TestInMemoryIdempotencyRollsBackWhenCompatibilityPersistenceFails(t *testing.T) {
	persistErr := errors.New("critical persistence failed")
	ledger, err := NewLedgerWithContext(context.Background(), Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: idempotencyPersistenceFailureStore{err: persistErr}})
	if err != nil {
		t.Fatalf("create ledger: %v", err)
	}
	now := fixedNow()
	key := IdempotencyRecordKey{TenantID: "tenant-idempotency-store", ActorID: "api_key:key-store", Method: "POST", Path: "/v1/products", IdempotencyKey: "store"}
	storeKey := NewIdempotencyRecordKey(key.TenantID, key.ActorID, key.Method, key.Path, key.IdempotencyKey)
	reservation := IdempotencyReservation{Key: key, RequestHash: "sha256:store", OwnerTokenHash: "sha256:owner-store", Now: now, LeaseExpiresAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour)}
	if _, err := ledger.reserveInMemoryIdempotency(context.Background(), reservation); !errors.Is(err, persistErr) {
		t.Fatalf("initial persistence error=%v, want injected error", err)
	}
	if _, exists := ledger.idempotency[storeKey]; exists {
		t.Fatal("failed initial reservation remained in memory")
	}

	expiredLease := now.Add(-time.Minute)
	previous := IdempotencyRecord{State: IdempotencyPending, RequestHash: reservation.RequestHash, OwnerTokenHash: "sha256:previous", CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour), LeaseExpiresAt: &expiredLease, ExpiresAt: now.Add(time.Hour)}
	ledger.idempotency[storeKey] = previous
	if _, err := ledger.reserveInMemoryIdempotency(context.Background(), reservation); !errors.Is(err, persistErr) {
		t.Fatalf("recovery persistence error=%v, want injected error", err)
	}
	if got := ledger.idempotency[storeKey]; got.OwnerTokenHash != previous.OwnerTokenHash || got.State != IdempotencyPending {
		t.Fatalf("failed recovery did not restore previous state: %#v", got)
	}

	activeLease := now.Add(time.Minute)
	ledger.idempotency[storeKey] = IdempotencyRecord{State: IdempotencyPending, RequestHash: reservation.RequestHash, OwnerTokenHash: reservation.OwnerTokenHash, CreatedAt: now, UpdatedAt: now, LeaseExpiresAt: &activeLease, ExpiresAt: now.Add(time.Hour)}
	if err := ledger.completeInMemoryIdempotency(context.Background(), reservation, 201, map[string]any{"id": "rolled-back"}); !errors.Is(err, persistErr) {
		t.Fatalf("completion persistence error=%v, want injected error", err)
	}
	if got := ledger.idempotency[storeKey]; got.State != IdempotencyPending || got.OwnerTokenHash != reservation.OwnerTokenHash {
		t.Fatalf("failed completion did not restore pending state: %#v", got)
	}
	if err := ledger.failInMemoryIdempotency(context.Background(), reservation); !errors.Is(err, persistErr) {
		t.Fatalf("failure persistence error=%v, want injected error", err)
	}
	if got := ledger.idempotency[storeKey]; got.State != IdempotencyPending || got.OwnerTokenHash != reservation.OwnerTokenHash {
		t.Fatalf("failed failure transition did not restore pending state: %#v", got)
	}

	invalidKey := key
	invalidKey.IdempotencyKey = "invalid-state"
	ledger.idempotency[NewIdempotencyRecordKey(invalidKey.TenantID, invalidKey.ActorID, invalidKey.Method, invalidKey.Path, invalidKey.IdempotencyKey)] = IdempotencyRecord{State: "invalid", RequestHash: reservation.RequestHash, ExpiresAt: now.Add(time.Hour)}
	invalidReservation := reservation
	invalidReservation.Key = invalidKey
	if _, err := ledger.reserveInMemoryIdempotency(context.Background(), invalidReservation); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid stored state err=%v, want validation", err)
	}
	invalidLegacyKey := key
	invalidLegacyKey.IdempotencyKey = "invalid-legacy"
	ledger.idempotency[NewIdempotencyRecordKey(invalidLegacyKey.TenantID, invalidLegacyKey.ActorID, invalidLegacyKey.Method, invalidLegacyKey.Path, invalidLegacyKey.IdempotencyKey)] = IdempotencyRecord{Status: 201, CreatedAt: now}
	invalidLegacyReservation := reservation
	invalidLegacyReservation.Key = invalidLegacyKey
	if _, err := ledger.reserveInMemoryIdempotency(context.Background(), invalidLegacyReservation); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid stored legacy record err=%v, want validation", err)
	}
	if _, err := replayableIdempotencyRecord(IdempotencyRecord{RequestHash: "sha256:legacy-replay", Status: 201, CreatedAt: now}); err != nil {
		t.Fatalf("legacy replay normalization err=%v", err)
	}
	if _, _, err := ledger.finishIdempotencyReservation(context.Background(), reservation, IdempotencyReservationResult{Outcome: IdempotencyReservationReplay, Record: IdempotencyRecord{State: IdempotencyCompleted, RequestHash: reservation.RequestHash, Status: 0, ExpiresAt: now.Add(time.Hour)}}, func() (int, any, error) {
		return 0, nil, nil
	}, func(context.Context, int, any) error { return nil }, func(context.Context) error { return nil }); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid replay err=%v, want validation", err)
	}
}

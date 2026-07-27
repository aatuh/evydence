package app

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type concurrentIdempotencyResult struct {
	status   int
	response any
	err      error
}

// runConcurrentIdempotency releases every caller from the same barrier. It
// deliberately uses no sleeps: each test asserts the result only after every
// request has returned, so it stays deterministic under -race and repetition.
func runConcurrentIdempotency(t *testing.T, callers int, run func(int) concurrentIdempotencyResult) []concurrentIdempotencyResult {
	t.Helper()
	if callers < 1 {
		t.Fatal("callers must be positive")
	}
	ready := make(chan struct{}, callers)
	start := make(chan struct{})
	results := make(chan concurrentIdempotencyResult, callers)
	for i := 0; i < callers; i++ {
		go func(index int) {
			ready <- struct{}{}
			<-start
			results <- run(index)
		}(i)
	}
	for i := 0; i < callers; i++ {
		<-ready
	}
	close(start)
	collected := make([]concurrentIdempotencyResult, 0, callers)
	for i := 0; i < callers; i++ {
		collected = append(collected, <-results)
	}
	return collected
}

func idempotencyResponseID(t *testing.T, response any) string {
	t.Helper()
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal idempotency response: %v", err)
	}
	var decoded struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode idempotency response: %v", err)
	}
	if decoded.ID == "" {
		t.Fatalf("idempotency response did not contain an id")
	}
	return decoded.ID
}

func TestWithIdempotencyConcurrentReleaseBundleCommitsOneEffectAndReplay(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before fan-out: %v", err)
	}

	const callers = 32
	var commandRuns atomic.Int32
	results := runConcurrentIdempotency(t, callers, func(int) concurrentIdempotencyResult {
		status, response, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/release-bundles", "concurrent-release-bundle", []byte(`{"release_id":"stable"}`), func(commandCtx context.Context, commandLedger *Ledger) (int, any, error) {
			commandRuns.Add(1)
			bundle, err := commandLedger.CreateReleaseBundle(commandCtx, actor, release.ID)
			return 201, bundle, err
		})
		return concurrentIdempotencyResult{status: status, response: response, err: err}
	})

	var responseID string
	for _, result := range results {
		if result.err != nil || result.status != 201 {
			t.Fatalf("concurrent bundle status=%d err=%v", result.status, result.err)
		}
		id := idempotencyResponseID(t, result.response)
		if responseID == "" {
			responseID = id
		} else if id != responseID {
			t.Fatalf("replayed bundle id=%q, want %q", id, responseID)
		}
	}
	if got := commandRuns.Load(); got != 1 {
		t.Fatalf("bundle command runs=%d, want 1", got)
	}

	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after fan-out: %v", err)
	}
	if got, want := len(after.ReleaseBundles)-len(before.ReleaseBundles), 1; got != want {
		t.Fatalf("release bundle delta=%d, want %d", got, want)
	}
	if got, want := len(after.Signatures)-len(before.Signatures), 1; got != want {
		t.Fatalf("signature delta=%d, want %d", got, want)
	}
	if got, want := len(after.AuditEntries[actor.TenantID])-len(before.AuditEntries[actor.TenantID]), 1; got != want {
		t.Fatalf("audit entry delta=%d, want %d", got, want)
	}
	if got, want := len(after.OutboxJobs)-len(before.OutboxJobs), 1; got != want {
		t.Fatalf("outbox job delta=%d, want %d", got, want)
	}
	if got, want := len(after.Idempotency)-len(before.Idempotency), 1; got != want {
		t.Fatalf("idempotency record delta=%d, want %d", got, want)
	}
	for _, record := range after.Idempotency {
		if record.RequestHash == "" || record.State != IdempotencyCompleted || record.OwnerTokenHash != "" || record.Status != 201 || idempotencyResponseID(t, record.Response) != responseID {
			t.Fatalf("unsafe or incomplete idempotency replay record: %#v", record)
		}
	}
}

func TestWithIdempotencyConcurrentScopesDoNotCollide(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actorA := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	_, actorBSecret, err := ledger.CreateAPIKey(ctx, actorA, "second-writer", []string{ScopeProductWrite}, nil)
	if err != nil {
		t.Fatalf("create second actor key: %v", err)
	}
	actorB, err := ledger.Authenticate(ctx, actorBSecret)
	if err != nil {
		t.Fatalf("authenticate second actor: %v", err)
	}
	_, _, tenantCSecret, err := ledger.BootstrapTenant(ctx, "Tenant C", "writer", []string{ScopeProductWrite})
	if err != nil {
		t.Fatalf("bootstrap second tenant: %v", err)
	}
	actorC, err := ledger.Authenticate(ctx, tenantCSecret)
	if err != nil {
		t.Fatalf("authenticate second tenant actor: %v", err)
	}
	const scopedCallers int32 = 3
	callers := []struct {
		actor domain.Actor
		name  string
		slug  string
	}{
		{actor: actorA, name: "Actor A", slug: "actor-a"},
		{actor: actorB, name: "Actor B", slug: "actor-b"},
		{actor: actorC, name: "Tenant C", slug: "tenant-c"},
	}
	var commandRuns atomic.Int32
	results := runConcurrentIdempotency(t, len(callers), func(index int) concurrentIdempotencyResult {
		call := callers[index]
		body := []byte(`{"name":"` + call.name + `","slug":"` + call.slug + `"}`)
		status, response, err := ledger.WithIdempotency(ctx, call.actor, "POST", "/v1/products", "shared-scope-key", body, func(commandCtx context.Context, commandLedger *Ledger) (int, any, error) {
			commandRuns.Add(1)
			product, err := commandLedger.CreateProduct(commandCtx, call.actor, call.name, call.slug)
			return 201, product, err
		})
		return concurrentIdempotencyResult{status: status, response: response, err: err}
	})
	for _, result := range results {
		if result.err != nil || result.status != 201 || idempotencyResponseID(t, result.response) == "" {
			t.Fatalf("scoped request status=%d response=%#v err=%v", result.status, result.response, result.err)
		}
	}
	if got, want := commandRuns.Load(), scopedCallers; got != want {
		t.Fatalf("scoped command runs=%d, want %d", got, want)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after scoped fan-out: %v", err)
	}
	if got, want := len(snapshot.Products), len(callers); got != want {
		t.Fatalf("products=%d, want %d", got, want)
	}
	if got, want := len(snapshot.Idempotency), len(callers); got != want {
		t.Fatalf("idempotency records=%d, want %d", got, want)
	}
	seenScopes := map[string]bool{}
	for key, record := range snapshot.Idempotency {
		if key.TenantID == "" || key.ActorID == "" || key.IdempotencyKey != "shared-scope-key" || record.State != IdempotencyCompleted {
			t.Fatalf("unexpected scoped record key=%#v record=%#v", key, record)
		}
		seenScopes[key.TenantID+"/"+key.ActorID] = true
	}
	if got, want := len(seenScopes), len(callers); got != want {
		t.Fatalf("unique idempotency scopes=%d, want %d", got, want)
	}
}

func TestWithIdempotencyConcurrentDifferentBodiesRunsOnlyOwner(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	calls := []struct {
		name string
		slug string
	}{
		{name: "First", slug: "first"},
		{name: "Second", slug: "second"},
	}
	var commandRuns atomic.Int32
	results := runConcurrentIdempotency(t, len(calls), func(index int) concurrentIdempotencyResult {
		call := calls[index]
		body := []byte(`{"name":"` + call.name + `","slug":"` + call.slug + `"}`)
		status, response, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/products", "same-key-different-body", body, func(commandCtx context.Context, commandLedger *Ledger) (int, any, error) {
			commandRuns.Add(1)
			product, err := commandLedger.CreateProduct(commandCtx, actor, call.name, call.slug)
			return 201, product, err
		})
		return concurrentIdempotencyResult{status: status, response: response, err: err}
	})
	var successes, conflicts int
	for _, result := range results {
		switch {
		case result.err == nil && result.status == 201:
			successes++
		case errors.Is(result.err, ErrIdempotencyConflict):
			conflicts++
		default:
			t.Fatalf("different-body result status=%d err=%v", result.status, result.err)
		}
	}
	if successes != 1 || conflicts != 1 || commandRuns.Load() != 1 {
		t.Fatalf("different-body successes=%d conflicts=%d command runs=%d", successes, conflicts, commandRuns.Load())
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after changed body: %v", err)
	}
	if len(snapshot.Products) != 1 || len(snapshot.Idempotency) != 1 {
		t.Fatalf("different body committed duplicate state: products=%d records=%d", len(snapshot.Products), len(snapshot.Idempotency))
	}
}

func TestWithIdempotencyCanceledWaiterDoesNotRunOrReserve(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan concurrentIdempotencyResult, 1)
	var commandRuns atomic.Int32
	go func() {
		status, response, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/products", "cancel-waiter", []byte(`{"name":"Canceled","slug":"canceled"}`), func(commandCtx context.Context, commandLedger *Ledger) (int, any, error) {
			commandRuns.Add(1)
			close(started)
			<-release
			product, err := commandLedger.CreateProduct(commandCtx, actor, "Canceled", "canceled")
			return 201, product, err
		})
		firstDone <- concurrentIdempotencyResult{status: status, response: response, err: err}
	}()
	<-started

	canceledCtx, cancel := context.WithCancel(ctx)
	secondAttempted := make(chan struct{})
	secondDone := make(chan concurrentIdempotencyResult, 1)
	go func() {
		close(secondAttempted)
		status, response, err := ledger.WithIdempotency(canceledCtx, actor, "POST", "/v1/products", "cancel-waiter", []byte(`{"name":"Canceled","slug":"canceled"}`), func(context.Context, *Ledger) (int, any, error) {
			commandRuns.Add(1)
			return 201, map[string]any{"id": "must-not-run"}, nil
		})
		secondDone <- concurrentIdempotencyResult{status: status, response: response, err: err}
	}()
	<-secondAttempted
	cancel()
	close(release)
	first := <-firstDone
	if first.err != nil || first.status != 201 {
		t.Fatalf("owner status=%d err=%v", first.status, first.err)
	}
	second := <-secondDone
	if !errors.Is(second.err, context.Canceled) || second.status != 0 || second.response != nil {
		t.Fatalf("canceled waiter status=%d response=%#v err=%v", second.status, second.response, second.err)
	}
	if got := commandRuns.Load(); got != 1 {
		t.Fatalf("canceled waiter ran command count=%d, want 1", got)
	}
	expiredCtx, cancelDeadline := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancelDeadline()
	status, response, err := ledger.WithIdempotency(expiredCtx, actor, "POST", "/v1/products", "expired-client", []byte(`{"name":"Expired","slug":"expired"}`), func(context.Context, *Ledger) (int, any, error) {
		commandRuns.Add(1)
		return 201, map[string]any{"id": "must-not-run"}, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || status != 0 || response != nil {
		t.Fatalf("expired client status=%d response=%#v err=%v", status, response, err)
	}
	if got := commandRuns.Load(); got != 1 {
		t.Fatalf("expired client ran command count=%d, want 1", got)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after cancellation: %v", err)
	}
	if len(snapshot.Products) != 1 || len(snapshot.Idempotency) != 1 {
		t.Fatalf("canceled waiter changed durable state: products=%d records=%d", len(snapshot.Products), len(snapshot.Idempotency))
	}
}

func TestWithIdempotencyRecoversExpiredPendingAfterProcessRestart(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	_, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	startedAt := fixedNow()
	key := IdempotencyRecordKey{
		TenantID:       actor.TenantID,
		ActorID:        idempotencyActorID(actor),
		Method:         "POST",
		Path:           "/v1/products",
		IdempotencyKey: "restart-recovery",
	}
	body := []byte(`{"name":"Recovered","slug":"recovered"}`)
	reservation, err := newIdempotencyReservation(key, hashBytes(append([]byte(key.Method+"\n"+key.Path+"\n"), body...)), startedAt)
	if err != nil {
		t.Fatalf("new pending reservation: %v", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		result, err := repositories.Idempotency.Reserve(ctx, reservation)
		if err != nil {
			return err
		}
		if result.Outcome != IdempotencyReservationAcquired {
			return ErrConflict
		}
		return nil
	}); err != nil {
		t.Fatalf("persist pending reservation before restart: %v", err)
	}

	// A fresh ledger models a new API process. It deliberately has no copy of
	// the original process cache; recovery relies only on the durable UOW state.
	restarted := NewLedger(Config{
		APIKeyPepper: "test-pepper",
		Now: func() time.Time {
			return startedAt.Add(defaultIdempotencyLease + time.Second)
		},
		UnitOfWork: memory,
	})
	var commandRuns atomic.Int32
	status, response, err := restarted.WithIdempotency(ctx, actor, key.Method, key.Path, key.IdempotencyKey, body, func(context.Context, *Ledger) (int, any, error) {
		commandRuns.Add(1)
		return 201, map[string]any{"id": "recovered-after-restart"}, nil
	})
	if err != nil || status != 201 || idempotencyResponseID(t, response) != "recovered-after-restart" {
		t.Fatalf("restart recovery status=%d response=%#v err=%v", status, response, err)
	}
	if commandRuns.Load() != 1 {
		t.Fatalf("recovered command runs=%d, want 1", commandRuns.Load())
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after restart recovery: %v", err)
	}
	record, ok := snapshot.Idempotency[key]
	if !ok || record.State != IdempotencyCompleted || record.OwnerTokenHash != "" || record.LeaseExpiresAt != nil || idempotencyResponseID(t, record.Response) != "recovered-after-restart" {
		t.Fatalf("recovered pending record=%#v exists=%v", record, ok)
	}
}

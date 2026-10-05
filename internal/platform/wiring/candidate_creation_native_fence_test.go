package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/domain"
)

func TestPostgresCandidateCreationNativeConcurrentReplayCreatesOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedCandidateCreationNative(t, p, store)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"release:write"}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var calls atomic.Int32
	type reply struct {
		status int
		value  any
		err    error
	}
	done := make(chan reply, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			s, v, err := o.DurableCommandExecutor.WithBody(ctx, a, "POST", "/v1/release-candidates", "concurrent", []byte(candidateCreationNativeBody()), func(ctx context.Context) error {
				return o.CandidateCommands.AuthorizeCandidateCreation(ctx, a, candidateCreationNativeInput())
			}, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := o.CandidateCommands.CreateReleaseCandidate(ctx, a, candidateCreationNativeInput())
				return 201, candidateRecord(v), err
			})
			done <- reply{s, v, err}
		}()
	}
	close(start)
	var replies [2]string
	for n := range replies {
		select {
		case r := <-done:
			if r.err != nil || r.status != 201 {
				t.Fatal("concurrent candidate failed", r.status, r.err)
			}
			b, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			replies[n] = string(b)
		case <-ctx.Done():
			t.Fatal("candidate replay leaked transaction", ctx.Err())
		}
	}
	assertRetentionHTTPReplay(t, replies[0], replies[1])
	if calls.Load() != 1 || candidateCreationNativeCounts(t, p) != [5]int{1, 1, 0, 1, 0} {
		t.Fatal("concurrent replay duplicated candidate effects", calls.Load(), candidateCreationNativeCounts(t, p))
	}
}

func TestPostgresCandidateCreationCancelledGuardReleasesFenceBeforeOwnershipLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedCandidateCreationNative(t, p, store)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"release:write"}}
	leader, err := p.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = leader.Rollback(context.WithoutCancel(t.Context())) }()
	if err := coordination.LockWorkerProjection(t.Context(), leader, "tenant"); err != nil {
		t.Fatal(err)
	}
	pid := leader.Conn().PgConn().PID()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- o.CandidateCommands.AuthorizeCandidateCreation(ctx, a, candidateCreationNativeInput()) }()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var blocked bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked)
		return blocked, err
	}, done)
	if _, err := leader.Exec(t.Context(), `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
		t.Fatal("ownership lock preceded writer fence", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("candidate lost cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("candidate cancellation leaked transaction")
	}
	if err := leader.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := o.CandidateCommands.AuthorizeCandidateCreation(t.Context(), a, candidateCreationNativeInput()); err != nil {
		t.Fatal("cancelled guard leaked fence", err)
	}
	if got := candidateCreationNativeCounts(t, p); got != [5]int{} {
		t.Fatal("cancelled guard wrote candidate effects", got)
	}
}

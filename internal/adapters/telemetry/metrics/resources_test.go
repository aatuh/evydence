package metrics

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

type runtimeResourceFixture struct {
	read func(context.Context) (telemetry.RuntimeResources, error)
}

func (f runtimeResourceFixture) ReadRuntimeResources(ctx context.Context) (telemetry.RuntimeResources, error) {
	return f.read(ctx)
}

func testRuntimeResources() telemetry.RuntimeResources {
	return telemetry.RuntimeResources{
		PrimaryPool: telemetry.PoolResources{Max: 4, Acquired: 1, Idle: 2, Constructing: 1, Acquires: 12, CanceledAcquires: 3, WaitedAcquires: 4, AcquireDuration: 2 * time.Second, AcquireWait: time.Second},
		ReadPool:    telemetry.PoolResources{Max: 2, Idle: 2, Acquires: 5},
		Queue:       telemetry.QueueResources{Queued: 1, Retrying: 2, Running: 3, Succeeded: 4, DeadLetter: 5, Attempts: 30, EligiblePending: 2, OverduePending: 1, ExpiredLeases: 1, OldestPendingAt: time.Now().Add(-time.Hour), OldestEligibleAt: time.Now().Add(-time.Minute)},
		Migrations:  telemetry.MigrationResources{Known: true, Applied: 60, Pending: 1, Unexpected: 2},
	}
}

func TestRuntimeResourceMetricsHaveOnlyFixedLabelsAndActualValues(t *testing.T) {
	r, err := New(Config{Service: "api", ResourceReader: runtimeResourceFixture{func(ctx context.Context) (telemetry.RuntimeResources, error) {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > telemetry.RuntimeResourceTimeout {
			t.Error("resource reader has no bounded context")
		}
		return testRuntimeResources(), nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := r.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []string{
		`evydence_db_pool_connections{pool="primary",service="api",state="acquired"} 1`,
		`evydence_db_pool_connections{pool="package_read",service="api",state="maximum"} 2`,
		`evydence_db_pool_acquires_total{pool="primary",service="api"} 12`,
		`evydence_db_pool_canceled_acquires_total{pool="primary",service="api"} 3`,
		`evydence_db_pool_waited_acquires_total{pool="primary",service="api"} 4`,
		`evydence_db_pool_acquire_duration_seconds_total{pool="primary",service="api"} 2`,
		`evydence_db_pool_wait_seconds_total{pool="primary",service="api"} 1`,
		`evydence_queue_jobs{service="api",state="dead_letter"} 5`,
		`evydence_queue_attempts{service="api"} 30`,
		`evydence_queue_eligible_jobs{service="api"} 2`,
		`evydence_queue_overdue_jobs{service="api"} 1`,
		`evydence_queue_expired_leases{service="api"} 1`,
		`evydence_queue_oldest_pending_age_seconds{service="api"}`,
		`evydence_queue_oldest_eligible_age_seconds{service="api"}`,
		`evydence_migration_expectations_known{service="api"} 1`,
		`evydence_migration_versions{service="api",state="applied"} 60`,
		`evydence_migration_versions{service="api",state="pending"} 1`,
		`evydence_migration_versions{service="api",state="unexpected"} 2`,
	} {
		if !strings.Contains(body, sample) {
			t.Fatal("missing actual operational sample", sample)
		}
	}
	for _, forbidden := range []string{"PRIVATE", "tenant=", "job=", "url=", "dsn=", "process_cpu"} {
		if strings.Contains(body, forbidden) {
			t.Fatal("unexpected operational label or process collector", forbidden)
		}
	}
}

func TestRuntimeResourceMetricsFailureCancellationAndRecovery(t *testing.T) {
	for _, failure := range []string{"error", "panic", "invalid", "timeout"} {
		t.Run(failure, func(t *testing.T) {
			fail := true
			reader := runtimeResourceFixture{func(ctx context.Context) (telemetry.RuntimeResources, error) {
				if !fail {
					return testRuntimeResources(), nil
				}
				switch failure {
				case "error":
					return testRuntimeResources(), errors.New("PRIVATE_CREDENTIAL_DATABASE_URL")
				case "panic":
					panic("PRIVATE_RESOURCE_ERROR")
				case "invalid":
					return telemetry.RuntimeResources{}, nil
				default:
					<-ctx.Done()
					return testRuntimeResources(), nil
				}
			}}
			r, err := New(Config{Service: "worker", ResourceReader: reader})
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			body, err := r.Snapshot(t.Context())
			if err == nil || body != "" || strings.Contains(err.Error(), "PRIVATE") || time.Since(start) > 3*time.Second {
				t.Fatal("snapshot returned partial/private data or exceeded its bound", err)
			}
			fail = false
			body, err = r.Snapshot(t.Context())
			if err != nil || !strings.Contains(body, "evydence_queue_jobs") {
				t.Fatal("resource snapshot did not recover", err)
			}
		})
	}
	reads := 0
	r, err := New(Config{Service: "api", ResourceReader: runtimeResourceFixture{func(context.Context) (telemetry.RuntimeResources, error) { reads++; return testRuntimeResources(), nil }}})
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if body, err := r.Snapshot(canceled); !errors.Is(err, context.Canceled) || body != "" || reads != 0 {
		t.Fatal("canceled resource scrape read data", err, reads)
	}
}

func TestConcurrentRuntimeResourceScrapesDoNotShareMutableGaugeState(t *testing.T) {
	type key struct{}
	r, err := New(Config{Service: "worker", ResourceReader: runtimeResourceFixture{func(ctx context.Context) (telemetry.RuntimeResources, error) {
		r := testRuntimeResources()
		r.Queue.Attempts = ctx.Value(key{}).(int64)
		return r, nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	var joined sync.WaitGroup
	for i := int64(1); i <= 32; i++ {
		joined.Go(func() {
			body, err := r.Snapshot(context.WithValue(t.Context(), key{}, i))
			if err != nil || !strings.Contains(body, fmt.Sprintf("evydence_queue_attempts{service=\"worker\"} %d\n", i)) {
				t.Error("concurrent scrape mixed resource snapshots", err)
			}
		})
	}
	joined.Wait()
}

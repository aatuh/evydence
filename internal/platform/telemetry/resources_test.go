package telemetry

import (
	"math"
	"testing"
	"time"
)

func TestRuntimeResourceValidationRejectsImpossibleOrNegativeScalars(t *testing.T) {
	valid := RuntimeResources{
		PrimaryPool: PoolResources{Max: 4, Acquired: 2, Idle: 1, Constructing: 1, Acquires: 12, WaitedAcquires: 2, AcquireDuration: time.Second},
		ReadPool:    PoolResources{Max: 1, Idle: 1},
		Queue:       QueueResources{Queued: 1, Retrying: 2, Running: 1, EligiblePending: 2, OverduePending: 1, ExpiredLeases: 1, OldestPendingAt: time.Now(), OldestEligibleAt: time.Now()},
	}
	if !valid.Valid() {
		t.Fatal("valid scalar snapshot rejected")
	}
	for _, mutate := range []func(*RuntimeResources){
		func(r *RuntimeResources) { r.PrimaryPool.Max = 0 },
		func(r *RuntimeResources) { r.ReadPool.Acquired = 2 },
		func(r *RuntimeResources) { r.PrimaryPool.Idle = -1 },
		func(r *RuntimeResources) { r.PrimaryPool.Acquires = -1 },
		func(r *RuntimeResources) { r.PrimaryPool.CanceledAcquires = -1 },
		func(r *RuntimeResources) { r.PrimaryPool.WaitedAcquires = -1 },
		func(r *RuntimeResources) { r.PrimaryPool.AcquireDuration = -1 },
		func(r *RuntimeResources) { r.PrimaryPool.AcquireWait = -1 },
		func(r *RuntimeResources) {
			r.ReadPool.Max = math.MaxInt32
			r.ReadPool.Acquired = math.MaxInt32
			r.ReadPool.Idle = math.MaxInt32
		},
		func(r *RuntimeResources) { r.Queue.Queued = -1 },
		func(r *RuntimeResources) { r.Queue.Attempts = -1 },
		func(r *RuntimeResources) { r.Queue.EligiblePending = 4 },
		func(r *RuntimeResources) { r.Queue.OverduePending = 3 },
		func(r *RuntimeResources) { r.Queue.ExpiredLeases = 2 },
		func(r *RuntimeResources) { r.Queue.OldestPendingAt = time.Time{} },
		func(r *RuntimeResources) { r.Queue.OldestEligibleAt = time.Time{} },
		func(r *RuntimeResources) { r.Migrations.Applied = -1 },
		func(r *RuntimeResources) { r.Migrations.Pending = -1 },
		func(r *RuntimeResources) { r.Migrations.Unexpected = -1 },
	} {
		invalid := valid
		mutate(&invalid)
		if invalid.Valid() {
			t.Fatal("impossible operational snapshot accepted", invalid)
		}
	}
	valid.Queue = QueueResources{Queued: math.MaxInt64, Retrying: math.MaxInt64, EligiblePending: math.MaxInt64, OldestPendingAt: time.Now(), OldestEligibleAt: time.Now()}
	if !valid.Valid() {
		t.Fatal("valid large queue counts overflowed validation")
	}
}

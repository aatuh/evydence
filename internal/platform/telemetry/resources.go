package telemetry

import (
	"context"
	"time"
)

// RuntimeResourceTimeout bounds an authorized operational snapshot, including
// waiting for a database connection. It does not extend the caller's deadline.
const RuntimeResourceTimeout = time.Second

// RuntimeResources contains scalar operational data only. Its fixed primary
// and read-pool slots cannot carry tenant names, DSNs or arbitrary labels.
type RuntimeResources struct {
	PrimaryPool PoolResources
	ReadPool    PoolResources
	Queue       QueueResources
}

type PoolResources struct {
	Acquired, Idle, Constructing, Max          int32
	Acquires, CanceledAcquires, WaitedAcquires int64
	AcquireDuration, AcquireWait               time.Duration
}

type QueueResources struct {
	Queued, Retrying, Running, Succeeded, DeadLetter         int64
	Attempts, EligiblePending, OverduePending, ExpiredLeases int64
	OldestPendingAt, OldestEligibleAt                        time.Time
}

// ResourceReader must honor cancellation, return a value copy and perform no
// writes or aggregate Ledger loading. Callers authorize instance access before
// invoking it. Implementations return no rows, IDs, payloads or credentials.
type ResourceReader interface {
	ReadRuntimeResources(context.Context) (RuntimeResources, error)
}

func validPool(p PoolResources) bool {
	return p.Max > 0 && p.Acquired >= 0 && p.Idle >= 0 && p.Constructing >= 0 &&
		int64(p.Acquired)+int64(p.Idle)+int64(p.Constructing) <= int64(p.Max) &&
		p.Acquires >= 0 && p.CanceledAcquires >= 0 && p.WaitedAcquires >= 0 &&
		p.AcquireDuration >= 0 && p.AcquireWait >= 0
}

func (r RuntimeResources) Valid() bool {
	q := r.Queue
	for _, value := range [...]int64{q.Queued, q.Retrying, q.Running, q.Succeeded,
		q.DeadLetter, q.Attempts, q.EligiblePending, q.OverduePending, q.ExpiredLeases} {
		if value < 0 {
			return false
		}
	}
	// Compare by subtraction to avoid overflowing a sum of retained job counts.
	eligibleFits := q.EligiblePending <= q.Queued || q.EligiblePending-q.Queued <= q.Retrying
	return validPool(r.PrimaryPool) && validPool(r.ReadPool) && eligibleFits &&
		q.OverduePending <= q.EligiblePending && q.ExpiredLeases <= q.Running &&
		((q.Queued == 0 && q.Retrying == 0) == q.OldestPendingAt.IsZero()) &&
		((q.EligiblePending == 0) == q.OldestEligibleAt.IsZero())
}

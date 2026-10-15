package httpapi

import (
	"sync"
	"time"
)

// failureBudget owns admission and completion, unlike the toolkit's Allow-only
// request limiter. Reserve before verification; successful work releases its
// slot and failures retain it through the current UTC minute. Fixed-size opaque
// keys contain no identity or credential text. Capacity exhaustion denies new
// keys without evicting active history. The HTTP in-flight bound also limits
// leases that can outlive their minute; old completions never affect a new one.
type failureBudget struct {
	mu          sync.Mutex
	limit       int
	capacity    int
	windowStart time.Time
	buckets     map[[32]byte]*failureBucket
}

type failureBucket struct {
	failed, pending int
}

type failureReservation struct {
	once   sync.Once
	owner  *failureBudget
	bucket *failureBucket
	key    [32]byte
	window time.Time
}

func newFailureBudget(limit, capacity int) *failureBudget {
	if limit <= 0 || capacity <= 0 {
		return nil
	}
	return &failureBudget{limit: limit, capacity: capacity, buckets: make(map[[32]byte]*failureBucket)}
}

func (b *failureBudget) reserve(key [32]byte, now time.Time) (*failureReservation, bool) {
	if b == nil || now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
		return nil, false
	}
	window := now.UTC().Truncate(time.Minute)
	b.mu.Lock()
	defer b.mu.Unlock()
	if window.Before(b.windowStart) {
		return nil, false
	}
	if window.After(b.windowStart) {
		b.windowStart = window
		b.buckets = make(map[[32]byte]*failureBucket)
	}
	bucket := b.buckets[key]
	if bucket == nil {
		if len(b.buckets) >= b.capacity {
			return nil, false
		}
		bucket = &failureBucket{}
		b.buckets[key] = bucket
	}
	if bucket.pending >= b.limit-bucket.failed {
		return nil, false
	}
	bucket.pending++
	return &failureReservation{owner: b, bucket: bucket, key: key, window: window}, true
}

func (r *failureReservation) finish(failed bool) {
	r.once.Do(func() {
		b := r.owner
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.windowStart != r.window || b.buckets[r.key] != r.bucket {
			return
		}
		r.bucket.pending--
		if failed {
			r.bucket.failed++
		}
		if r.bucket.pending == 0 && r.bucket.failed == 0 {
			delete(b.buckets, r.key)
		}
	})
}

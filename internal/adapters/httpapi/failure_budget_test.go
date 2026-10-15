package httpapi

import (
	"sync"
	"testing"
	"time"
)

func TestFailureBudgetReservesBeforeEffectsAndReleasesSuccess(t *testing.T) {
	b := newFailureBudget(2, 2)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	key := [32]byte{1}
	first, ok := b.reserve(key, now)
	if !ok {
		t.Fatal("first attempt denied")
	}
	second, ok := b.reserve(key, now)
	if !ok {
		t.Fatal("second attempt denied")
	}
	if _, ok := b.reserve(key, now); ok {
		t.Fatal("concurrent work exceeded remaining failure budget")
	}
	first.finish(false)
	third, ok := b.reserve(key, now)
	if !ok {
		t.Fatal("successful work did not release its reservation")
	}
	second.finish(true)
	third.finish(true)
	second.finish(false)
	if _, ok := b.reserve(key, now); ok {
		t.Fatal("double completion restored exhausted budget")
	}
}

func TestFailureBudgetCapacityCannotEvictActiveFailureHistory(t *testing.T) {
	b := newFailureBudget(1, 1)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	first, ok := b.reserve([32]byte{1}, now)
	if !ok {
		t.Fatal("first client denied")
	}
	first.finish(true)
	if _, ok := b.reserve([32]byte{2}, now); ok {
		t.Fatal("new client evicted active failure history")
	}
	if _, ok := b.reserve([32]byte{1}, now); ok {
		t.Fatal("saturation restored original client's budget")
	}
	if next, ok := b.reserve([32]byte{2}, now.Add(time.Minute)); !ok {
		t.Fatal("expired window did not recover capacity")
	} else {
		next.finish(false)
	}
}

func TestFailureBudgetLateCompletionCannotConsumeFreshWindow(t *testing.T) {
	b := newFailureBudget(1, 1)
	now := time.Date(2026, 10, 15, 12, 0, 59, 0, time.UTC)
	old, ok := b.reserve([32]byte{1}, now)
	if !ok {
		t.Fatal("old window denied")
	}
	fresh, ok := b.reserve([32]byte{1}, now.Add(time.Second))
	if !ok {
		t.Fatal("new window denied")
	}
	old.finish(true)
	fresh.finish(false)
	last, ok := b.reserve([32]byte{1}, now.Add(time.Second))
	if !ok {
		t.Fatal("old completion corrupted fresh window")
	}
	last.finish(true)
	if _, ok := b.reserve([32]byte{1}, now.Add(time.Second)); ok {
		t.Fatal("fresh failure did not exhaust budget")
	}
	if _, ok := b.reserve([32]byte{1}, now.Add(-time.Minute)); ok {
		t.Fatal("backward clock reset exhausted history")
	}
	if _, ok := b.reserve([32]byte{1}, time.Time{}); ok {
		t.Fatal("invalid clock granted a reservation")
	}
}

func TestFailureBudgetSuccessfulTrafficDoesNotAccumulateFailures(t *testing.T) {
	b := newFailureBudget(1, 1)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	for i := range 100 {
		lease, ok := b.reserve([32]byte{byte(i)}, now)
		if !ok {
			t.Fatal("successful traffic retained capacity", i)
		}
		lease.finish(false)
	}
}

func TestFailureBudgetConcurrentAdmissionNeverExceedsFailureCapacity(t *testing.T) {
	b := newFailureBudget(7, 2)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	leases := make(chan *failureReservation, 100)
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if lease, ok := b.reserve([32]byte{1}, now); ok {
				leases <- lease
			}
		}()
	}
	wg.Wait()
	close(leases)
	count := 0
	for lease := range leases {
		count++
		lease.finish(true)
	}
	if count != 7 {
		t.Fatal("concurrent admission count", count)
	}
	if _, ok := b.reserve([32]byte{1}, now); ok {
		t.Fatal("concurrent failures did not retain exhausted budget")
	}
}

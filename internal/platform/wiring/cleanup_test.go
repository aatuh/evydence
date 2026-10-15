package wiring

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOwnedResourcesCleanupHasOneBudgetAndRunsOnceInOrder(t *testing.T) {
	root, cancel := context.WithCancel(t.Context())
	cancel()
	var owner OwnedResources
	var order []string
	var deadline time.Time
	for _, name := range []string{"provider", "objects", "database"} {
		owner.Add(name, func(ctx context.Context) error {
			if ctx.Err() != nil {
				t.Error("cleanup inherited canceled work context")
			}
			got, ok := ctx.Deadline()
			if !ok {
				t.Error("cleanup has no deadline")
			}
			if deadline.IsZero() {
				deadline = got
			} else if !deadline.Equal(got) {
				t.Error("cleanup reset budget between resources")
			}
			order = append(order, name)
			return nil
		})
	}
	if err := owner.Close(root, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(root, time.Second); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"provider", "objects", "database"}) {
		t.Fatal("owned resources closed out of order or more than once", order)
	}
}

func TestOwnedResourcesCleanupDeadlineDoesNotAdvanceToDatabase(t *testing.T) {
	var owner OwnedResources
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var databaseCloses atomic.Int32
	defer func() {
		close(release)
		<-finished
		<-owner.done
		if databaseCloses.Load() != 0 {
			t.Error("cleanup advanced after its expired closer returned")
		}
	}()
	owner.Add("provider", func(context.Context) error { close(entered); <-release; close(finished); return nil })
	owner.Add("database", func(context.Context) error { databaseCloses.Add(1); return nil })
	done := make(chan error, 1)
	go func() { done <- owner.Close(t.Context(), 20*time.Millisecond) }()
	<-entered
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("cleanup did not fail at deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("uncooperative cleanup blocked caller")
	}
	if databaseCloses.Load() != 0 {
		t.Fatal("database closed after incomplete dependent cleanup")
	}
	if err := owner.Close(t.Context(), time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("repeat close forgot forced failure", err)
	}
}

func TestOwnedResourcesCleanupFailureIsSafeAndStopsDependentCleanup(t *testing.T) {
	var owner OwnedResources
	owner.Add("provider", func(context.Context) error { return errors.New("postgres://owner:private-credential@host/data") })
	owner.Add("database", func(context.Context) error { t.Error("database closed after provider cleanup failed"); return nil })
	err := owner.Close(t.Context(), time.Second)
	if err == nil || !strings.Contains(err.Error(), "provider") || strings.Contains(err.Error(), "private-credential") || strings.Contains(err.Error(), "postgres://") {
		t.Fatal("cleanup returned unsafe or missing error", err)
	}
}

func TestOwnedResourcesCleanupConcurrentCallerHasBoundedWait(t *testing.T) {
	var owner OwnedResources
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	owner.Add("provider", func(ctx context.Context) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	first := make(chan error, 1)
	go func() { first <- owner.Close(t.Context(), time.Second) }()
	<-entered
	started := time.Now()
	if err := owner.Close(t.Context(), 20*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("concurrent caller did not respect own bound", err)
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("concurrent close waited on another caller's budget")
	}
	if err := <-first; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("first close lost its deadline", err)
	}
	<-owner.done
}

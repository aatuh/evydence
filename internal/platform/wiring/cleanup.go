package wiring

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type ownedResource struct {
	name  string
	close func(context.Context) error
}

// OwnedResources closes only explicitly registered resources, in dependency
// order. Register every owned resource before Close; never register borrowed
// clients. A failed or timed-out close is terminal and requires process exit.
type OwnedResources struct {
	mu        sync.Mutex
	resources []ownedResource
	done      chan struct{}
	err       error
	active    string
}

func (o *OwnedResources) Add(name string, closeResource func(context.Context) error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done != nil || name == "" || closeResource == nil {
		panic("owned cleanup registration requires a name, closer and unstarted owner")
	}
	o.resources = append(o.resources, ownedResource{name: name, close: closeResource})
}

// Close survives work-context cancellation and gives all resources one budget.
// Concurrent callers have their own bounded wait; only the first starts cleanup.
// On timeout an uncooperative closer may survive until process exit, but this
// owner never advances to later resources after its budget expires.
func (o *OwnedResources) Close(root context.Context, timeout time.Duration) error {
	if root == nil || timeout <= 0 {
		return errors.New("cleanup requires context and positive timeout")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(root), timeout)
	defer cancel()
	o.mu.Lock()
	if o.err != nil {
		err := o.err
		o.mu.Unlock()
		return err
	}
	started := o.done == nil
	if started {
		o.done = make(chan struct{})
		go o.run(ctx)
	}
	done := o.done
	o.mu.Unlock()
	select {
	case <-done:
		o.mu.Lock()
		err := o.err
		o.mu.Unlock()
		return err
	case <-ctx.Done():
		if started {
			o.mu.Lock()
			if o.err == nil {
				o.err = fmt.Errorf("cleanup %s: %w", o.active, ctx.Err())
			}
			err := o.err
			o.mu.Unlock()
			return err
		}
		return ctx.Err()
	}
}

func (o *OwnedResources) run(ctx context.Context) {
	var result error
	for _, resource := range o.resources {
		if result = ctx.Err(); result != nil {
			break
		}
		o.mu.Lock()
		o.active = resource.name
		o.mu.Unlock()
		if err := resource.close(ctx); err != nil {
			// Resource labels are static composition names. Do not propagate raw
			// adapter errors, which can contain URLs, credentials or payloads.
			cause := errors.New("resource close failed")
			if errors.Is(err, context.Canceled) {
				cause = context.Canceled
			}
			if errors.Is(err, context.DeadlineExceeded) {
				cause = context.DeadlineExceeded
			}
			result = fmt.Errorf("cleanup %s: %w", resource.name, cause)
			break
		}
	}
	if result == nil {
		result = ctx.Err()
	}
	o.mu.Lock()
	if o.err == nil {
		o.err = result
	}
	close(o.done)
	o.mu.Unlock()
}

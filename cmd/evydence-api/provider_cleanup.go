package main

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/platform/wiring"
)

// Call only for a client this process just constructed, never for borrowed
// runtime ports. A port without persistent resources needs no registration.
func ownNewProvider(owner *wiring.OwnedResources, name string, provider any) {
	if closer, ok := provider.(interface{ Close() error }); ok {
		owner.Add(name, func(context.Context) error { return closer.Close() })
	}
}

func closeAPIResources(ctx context.Context, runErr error, runtime *wiring.Runtime, providers *wiring.OwnedResources, timeout time.Duration) error {
	if errors.Is(runErr, errAPIForcedDrain) {
		return runErr
	}
	if runtime != nil {
		return errors.Join(runErr, runtime.CloseContext(ctx, timeout))
	}
	return errors.Join(runErr, providers.Close(ctx, timeout))
}

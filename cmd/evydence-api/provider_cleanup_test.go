package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/platform/wiring"
)

type ownedProviderFixture struct{ closes atomic.Int32 }

func (p *ownedProviderFixture) Close() error { p.closes.Add(1); return nil }

func TestAPIPartialStartupClosesOnlyExplicitOwnedProviderOnce(t *testing.T) {
	var providers wiring.OwnedResources
	provider := &ownedProviderFixture{}
	ownNewProvider(&providers, "provider", provider)
	ownNewProvider(&providers, "optional", nil)
	root, cancel := context.WithCancel(t.Context())
	cancel()
	cause := errors.New("startup failed")
	if err := closeAPIResources(root, cause, nil, &providers, time.Second); !errors.Is(err, cause) {
		t.Fatal("startup failure lost", err)
	}
	if err := closeAPIResources(root, nil, nil, &providers, time.Second); err != nil {
		t.Fatal(err)
	}
	if provider.closes.Load() != 1 {
		t.Fatal("provider leaked or closed twice", provider.closes.Load())
	}
}

func TestAPIForcedDrainRetainsProviderResourcesUntilExit(t *testing.T) {
	var providers wiring.OwnedResources
	provider := &ownedProviderFixture{}
	ownNewProvider(&providers, "provider", provider)
	if err := closeAPIResources(t.Context(), errAPIForcedDrain, nil, &providers, time.Second); !errors.Is(err, errAPIForcedDrain) {
		t.Fatal("forced failure lost", err)
	}
	if provider.closes.Load() != 0 {
		t.Fatal("forced drain closed resources under in-flight work")
	}
}

func TestAPIInvalidCleanupBudgetFailsBeforeStorage(t *testing.T) {
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "postgres")
	t.Setenv("EVYDENCE_DATABASE_URL", "postgres://owner:private-canary@127.0.0.1:1/ledger")
	t.Setenv("EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS", "0")
	if err := runWithContext(t.Context()); err == nil || err.Error() != "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS must be an integer between 1 and 60" {
		t.Fatal("invalid cleanup budget did not fail before storage", err)
	}
}

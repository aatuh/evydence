package confighealth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func configuredWorker(t *testing.T, extra ...string) (config.Configuration, config.Environment, []string) {
	t.Helper()
	entries := append([]string{"EVYDENCE_RUNTIME_PROFILE=postgres", "EVYDENCE_DATABASE_URL=host=PRIVATE_DB"}, extra...)
	e, err := config.Capture(entries)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := config.Parse(e, config.Worker)
	if err != nil {
		t.Fatal(err)
	}
	return settings, e, entries
}

func TestConfiguredProbeUsesSharedSourceSelectionAndRecovers(t *testing.T) {
	settings, original, entries := configuredWorker(t, "PGUSER=PRIVATE_USER")
	current := original
	calls := 0
	source := func(ctx context.Context) (config.Environment, error) {
		calls++
		return current, ctx.Err()
	}
	probe, err := NewConfigured(t.Context(), settings, source)
	if err != nil || calls != 1 {
		t.Fatal("configured probe did not validate its supplied source", err)
	}
	current, err = config.Capture(append(entries, "UNRELATED=PRIVATE_CHANGE"))
	if err != nil || probe(t.Context()) != nil {
		t.Fatal("unrelated input was treated as drift", err)
	}
	current, err = config.Capture(append(entries[:2:2], "PGUSER=PRIVATE_CHANGED"))
	if err != nil {
		t.Fatal(err)
	}
	if err := probe(t.Context()); !errors.Is(err, errConfigurationUnavailable) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("native source drift was accepted or disclosed", err)
	}
	current = original
	if err := probe(t.Context()); err != nil {
		t.Fatal("source restoration did not recover", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := calls
	if err := probe(ctx); !errors.Is(err, context.Canceled) || calls != before {
		t.Fatal("cancelled refresh called the source", err)
	}
}

func TestConfiguredProbePreservesRevisionDriftAndRecovery(t *testing.T) {
	file := filepath.Join(t.TempDir(), "PRIVATE_REVISION")
	revision := strings.Repeat("a", 64)
	if err := os.WriteFile(file, []byte(revision), 0600); err != nil {
		t.Fatal(err)
	}
	settings, snapshot, _ := configuredWorker(t, "EVYDENCE_CONFIGURATION_REVISION="+revision, "EVYDENCE_CONFIGURATION_REVISION_FILE="+file)
	probe, err := NewConfigured(t.Context(), settings, func(context.Context) (config.Environment, error) { return snapshot, nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{strings.Repeat("b", 64), revision} {
		if err := os.WriteFile(file, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		err := probe(t.Context())
		if (err != nil) != (value != revision) || (err != nil && strings.Contains(err.Error(), "PRIVATE")) {
			t.Fatal("configured probe changed revision freshness semantics", err)
		}
	}
}

func TestConfiguredProbeRejectsInvalidStateAndRedactsSourceErrors(t *testing.T) {
	settings, snapshot, _ := configuredWorker(t)
	good := func(context.Context) (config.Environment, error) { return snapshot, nil }
	bad := func(context.Context) (config.Environment, error) {
		return config.Environment{}, errors.New("PRIVATE_SOURCE_ERROR")
	}
	for _, tc := range []struct {
		settings config.Configuration
		source   func(context.Context) (config.Environment, error)
	}{{config.Configuration{}, good}, {settings, nil}, {settings, bad}} {
		probe, err := NewConfigured(t.Context(), tc.settings, tc.source)
		if probe != nil || !errors.Is(err, errConfigurationUnavailable) || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid configured probe returned a reader or sensitive error", err)
		}
	}
}

func TestConfiguredProbeAcceptsOnlyDaemonRoles(t *testing.T) {
	_, snapshot, _ := configuredWorker(t)
	for _, role := range []config.Role{config.API, config.Worker, config.Migrate, config.CLI} {
		settings, err := config.Parse(snapshot, role)
		if err != nil {
			t.Fatal(err)
		}
		called := false
		probe, err := NewConfigured(t.Context(), settings, func(context.Context) (config.Environment, error) { called = true; return snapshot, nil })
		allowed := role == config.API || role == config.Worker
		if allowed {
			if err != nil || probe == nil || !called {
				t.Fatal("daemon role rejected", err)
			}
		} else if !errors.Is(err, errConfigurationUnavailable) || probe != nil || called {
			t.Fatal("non-daemon role entered health source observation", err)
		}
	}
}

func TestConfiguredProbePreservesCancellationWithoutSourceCauses(t *testing.T) {
	settings, _, _ := configuredWorker(t, "EVYDENCE_CONFIGURATION_REVISION="+strings.Repeat("a", 64), "EVYDENCE_CONFIGURATION_REVISION_FILE="+filepath.Join(t.TempDir(), "PRIVATE_MISSING"))
	for _, want := range []error{context.Canceled, context.DeadlineExceeded} {
		probe, err := NewConfigured(t.Context(), settings, func(context.Context) (config.Environment, error) {
			return config.Environment{}, errors.Join(want, errors.New("PRIVATE_SOURCE_CAUSE"))
		})
		if probe != nil || !errors.Is(err, want) || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("source cancellation lost its class or exposed its cause", err)
		}
	}
	settings, snapshot, _ := configuredWorker(t, "EVYDENCE_CONFIGURATION_REVISION="+strings.Repeat("a", 64), "EVYDENCE_CONFIGURATION_REVISION_FILE="+filepath.Join(t.TempDir(), "PRIVATE_MISSING"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	probe, err := NewConfigured(ctx, settings, func(context.Context) (config.Environment, error) {
		cancel()
		return snapshot, nil
	})
	if probe != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation during observation reached missing revision I/O", err)
	}
}

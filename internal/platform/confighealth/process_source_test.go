package confighealth

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestProcessSourceUsesCanonicalCaptureAndSafeFailures(t *testing.T) {
	t.Setenv("EVYDENCE_PRIVATE_SOURCE", "PRIVATE_VALUE")
	want, err := config.Capture(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProcessSource(t.Context())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("process health source diverged from canonical capture", err)
	}
	t.Setenv("EVYDENCE_PRIVATE_SOURCE", "\xff")
	got, err = ProcessSource(t.Context())
	if !errors.Is(err, config.ErrInvalidEnvironment) || !reflect.DeepEqual(got, config.Environment{}) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("invalid process source returned partial input or unsafe diagnostics", err)
	}
}

func TestProcessSourceRejectsCancelledOrMissingContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		ctx  context.Context
		want error
	}{{ctx, context.Canceled}, {nil, errConfigurationUnavailable}} {
		got, err := ProcessSource(tc.ctx)
		if !errors.Is(err, tc.want) || !reflect.DeepEqual(got, config.Environment{}) {
			t.Fatal("unavailable context captured process input", err)
		}
	}
}

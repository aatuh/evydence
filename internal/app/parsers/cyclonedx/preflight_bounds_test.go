package cyclonedx

import (
	"errors"
	"testing"
)

func TestParseBoundedRejectsDuplicateObjectKeys(t *testing.T) {
	for name, raw := range map[string]string{
		"root":            `{"bomFormat":"SPDX","bomFormat":"CycloneDX","specVersion":"1.6"}`,
		"component":       `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"first","name":"second"}]}`,
		"nested metadata": `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"2026-08-09T00:00:00Z","timestamp":"2026-08-09T00:00:01Z"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBounded([]byte(raw), DefaultLimits(1<<20)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v, want invalid", err)
			}
		})
	}
}

func TestStreamingPreflightMatchesValueAndStringBounds(t *testing.T) {
	limits := DefaultLimits(1 << 20)
	limits.MaxValues = 3
	if _, err := ParseBounded([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`), limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("value bound err=%v, want invalid", err)
	}

	limits = DefaultLimits(1 << 20)
	limits.MaxStringBytes = 8
	if _, err := ParseBounded([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`), limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("key/string bound err=%v, want invalid", err)
	}
}

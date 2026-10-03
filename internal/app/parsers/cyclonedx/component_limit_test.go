package cyclonedx

import (
	"errors"
	"testing"
)

func TestParseBoundedCountsNestedComponentsAgainstLimit(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"application","name":"parent","components":[{"type":"library","name":"child"}]}]}`)
	limits := DefaultLimits(1 << 20)
	limits.MaxComponents = 1
	if _, err := ParseBounded(raw, limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v, want invalid", err)
	}
}

func TestParseBoundedCountsMetadataComponentAgainstLimit(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"root"}},"components":[{"type":"library","name":"child"}]}`)
	limits := DefaultLimits(1 << 20)
	limits.MaxComponents = 1
	if _, err := ParseBounded(raw, limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v, want invalid", err)
	}
}

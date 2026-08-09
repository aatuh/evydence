package cyclonedx

import (
	"errors"
	"testing"
)

func TestParseBoundedRejectsMalformedNestedComponents(t *testing.T) {
	tests := []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"application","name":"root","components":[{"name":"missing-type"}]}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application"}}}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"tools":{"components":[{"type":"application"}]}}}`,
	}
	for _, raw := range tests {
		if _, err := ParseBounded([]byte(raw), DefaultLimits(1<<20)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("malformed nested component accepted: raw=%s err=%v", raw, err)
		}
	}
}

package cyclonedx

import "testing"

func TestDepthPreflightPreservesUseNumberAcceptance(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1e1000}`)
	if _, err := ParseBounded(raw, DefaultLimits(1<<20)); err != nil {
		t.Fatalf("large JSON number rejected by depth preflight: %v", err)
	}
}

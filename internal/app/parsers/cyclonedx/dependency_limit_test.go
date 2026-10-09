package cyclonedx

import (
	"errors"
	"testing"
)

func TestParseBoundedCountsAggregateDependencyEdgesAgainstLimit(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","dependencies":[{"ref":"a","dependsOn":["b","c"]},{"ref":"b","dependsOn":["c"]}]}`)
	limits := DefaultLimits(1 << 20)
	limits.MaxDependencies = 2
	if _, err := ParseBounded(raw, limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v, want invalid", err)
	}
}

func TestParseBoundedCountsAggregateProvidesEdgesAgainstLimit(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","dependencies":[{"ref":"a","provides":["x","y"]},{"ref":"b","provides":["z"]}]}`)
	limits := DefaultLimits(1 << 20)
	limits.MaxDependencies = 2
	if _, err := ParseBounded(raw, limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v, want invalid", err)
	}
}

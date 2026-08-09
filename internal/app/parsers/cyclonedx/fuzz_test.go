package cyclonedx

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func FuzzCycloneDX(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"bom-ref":"pkg:generic/api@1.0.0","type":"library","name":"api","version":"1.0.0","purl":"pkg:generic/api@1.0.0"}],"dependencies":[{"ref":"pkg:generic/api@1.0.0","dependsOn":[]}]}`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"2026-08-09T00:00:00Z"},"components":[{"type":"library","name":"api","hashes":[{"alg":"SHA-256","content":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}],"licenses":[{"license":{"id":"MIT"}}],"properties":[{"name":"evydence:test","value":"true"}]}],"services":[{"name":"backend"}],"properties":[{"name":"build","value":"42"}],"compositions":[{"aggregate":"complete"}]}`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"a"}],"dependencies":[{"ref":"a","dependsOn":["b"],"provides":["c"]}]} trailing`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":{"type":"library","name":"not-an-array"}}`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"missing-type"}]}`),
		[]byte(strings.Repeat(`{"nested":`, 40) + `null` + strings.Repeat(`}`, 40)),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","properties":[{"name":"oversized","value":"` + strings.Repeat("x", 70<<10) + `"}]}`),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	limits := Limits{
		MaxBytes:        64 << 10,
		MaxDepth:        32,
		MaxComponents:   256,
		MaxDependencies: 512,
		MaxStringBytes:  4 << 10,
		MaxValues:       8 << 10,
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		first, firstErr := ParseBounded(raw, limits)
		second, secondErr := ParseBounded(raw, limits)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("same input produced inconsistent success: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			if !errors.Is(firstErr, ErrInvalid) || !errors.Is(secondErr, ErrInvalid) {
				t.Fatalf("invalid input returned unexpected errors: first=%v second=%v", firstErr, secondErr)
			}
			return
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("same input normalized nondeterministically:\nfirst=%#v\nsecond=%#v", first, second)
		}
		if first.SpecVersion != SupportedSpecVersion {
			t.Fatalf("accepted unsupported spec version %q", first.SpecVersion)
		}
		if len(first.Components) > limits.MaxComponents || len(first.Dependencies) > limits.MaxDependencies {
			t.Fatalf("accepted result exceeds structural limits: components=%d dependencies=%d", len(first.Components), len(first.Dependencies))
		}
		edges := 0
		for _, dependency := range first.Dependencies {
			edges += len(dependency.DependsOn)
		}
		if edges > limits.MaxDependencies {
			t.Fatalf("accepted result exceeds dependency-edge limit: %d", edges)
		}
		for _, component := range first.Components {
			if component.Identity == "" || component.Type == "" || component.Name == "" {
				t.Fatalf("accepted component lacks normalized identity fields: %#v", component)
			}
		}
	})
}

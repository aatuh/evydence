package cyclonedx

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestComponentAndDependencyHelpersRejectMalformedShapes(t *testing.T) {
	limits := DefaultLimits(1024)

	componentCases := []struct {
		name  string
		value any
		limit Limits
	}{
		{name: "non-array", value: map[string]any{}},
		{name: "too-many", value: []any{map[string]any{"type": "library", "name": "one"}}, limit: Limits{MaxComponents: -1}},
		{name: "non-object", value: []any{"component"}},
		{name: "missing-type", value: []any{map[string]any{"name": "component"}}},
		{name: "missing-name", value: []any{map[string]any{"type": "library"}}},
	}
	for _, tc := range componentCases {
		t.Run("component/"+tc.name, func(t *testing.T) {
			configured := limits
			if tc.limit.MaxComponents != 0 {
				configured = tc.limit
			}
			if _, err := parseComponents(tc.value, configured); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v, want invalid", err)
			}
		})
	}

	dependencyCases := []struct {
		name  string
		value any
		limit Limits
	}{
		{name: "non-array", value: map[string]any{}},
		{name: "too-many", value: []any{map[string]any{"ref": "a"}}, limit: Limits{MaxDependencies: -1}},
		{name: "non-object", value: []any{"dependency"}},
		{name: "missing-ref", value: []any{map[string]any{}}},
		{name: "invalid-depends-on", value: []any{map[string]any{"ref": "a", "dependsOn": []any{1}}}},
		{name: "invalid-provides", value: []any{map[string]any{"ref": "a", "provides": []any{" "}}}},
	}
	for _, tc := range dependencyCases {
		t.Run("dependency/"+tc.name, func(t *testing.T) {
			configured := limits
			if tc.limit.MaxDependencies != 0 {
				configured = tc.limit
			}
			if _, err := parseDependencies(tc.value, configured); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v, want invalid", err)
			}
		})
	}
}

func TestParserHelperOrderingAndLimits(t *testing.T) {
	for _, tc := range []struct {
		name        string
		left, right []string
		want        int
	}{
		{name: "equal", left: []string{"a"}, right: []string{"a"}, want: 0},
		{name: "less-element", left: []string{"a"}, right: []string{"b"}, want: -1},
		{name: "greater-element", left: []string{"b"}, right: []string{"a"}, want: 1},
		{name: "shorter-prefix", left: []string{"a"}, right: []string{"a", "b"}, want: -1},
		{name: "longer-prefix", left: []string{"a", "b"}, right: []string{"a"}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := compareStringSlices(tc.left, tc.right); got != tc.want {
				t.Fatalf("compareStringSlices(%v, %v)=%d want=%d", tc.left, tc.right, got, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name  string
		value any
		limit int
	}{
		{name: "non-array", value: "a", limit: 2},
		{name: "too-many", value: []any{"a", "b"}, limit: 1},
		{name: "non-string", value: []any{1}, limit: 2},
		{name: "blank", value: []any{" "}, limit: 2},
	} {
		t.Run("string-array/"+tc.name, func(t *testing.T) {
			if _, err := stringArray(tc.value, tc.limit); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v, want invalid", err)
			}
		})
	}
}

func TestComponentOrderingRemainsDeterministicForSharedPURLs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		left      map[string]any
		right     map[string]any
		wantFirst string
	}{
		{
			name: "bom-ref", left: map[string]any{"bom-ref": "z", "type": "library", "name": "name", "version": "1", "purl": "pkg:generic/shared@1"},
			right: map[string]any{"bom-ref": "a", "type": "library", "name": "name", "version": "1", "purl": "pkg:generic/shared@1"}, wantFirst: "a",
		},
		{
			name: "type", left: map[string]any{"bom-ref": "ref", "type": "z", "name": "name", "version": "1", "purl": "pkg:generic/shared@1"},
			right: map[string]any{"bom-ref": "ref", "type": "a", "name": "name", "version": "1", "purl": "pkg:generic/shared@1"}, wantFirst: "a",
		},
		{
			name: "name", left: map[string]any{"bom-ref": "ref", "type": "library", "name": "z", "version": "1", "purl": "pkg:generic/shared@1"},
			right: map[string]any{"bom-ref": "ref", "type": "library", "name": "a", "version": "1", "purl": "pkg:generic/shared@1"}, wantFirst: "a",
		},
		{
			name: "version", left: map[string]any{"bom-ref": "ref", "type": "library", "name": "name", "version": "z", "purl": "pkg:generic/shared@1"},
			right: map[string]any{"bom-ref": "ref", "type": "library", "name": "name", "version": "a", "purl": "pkg:generic/shared@1"}, wantFirst: "a",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			components, err := parseComponents([]any{tc.left, tc.right}, DefaultLimits(1024))
			if err != nil {
				t.Fatal(err)
			}
			switch tc.name {
			case "bom-ref":
				if components[0].BOMRef != tc.wantFirst {
					t.Fatalf("first bom-ref=%q want=%q", components[0].BOMRef, tc.wantFirst)
				}
			case "type":
				if components[0].Type != tc.wantFirst {
					t.Fatalf("first type=%q want=%q", components[0].Type, tc.wantFirst)
				}
			case "name":
				if components[0].Name != tc.wantFirst {
					t.Fatalf("first name=%q want=%q", components[0].Name, tc.wantFirst)
				}
			case "version":
				if components[0].Version != tc.wantFirst {
					t.Fatalf("first version=%q want=%q", components[0].Version, tc.wantFirst)
				}
			}
		})
	}
}

func TestParserValidationHelpersFailClosedAtLimits(t *testing.T) {
	if err := validateLimits(Limits{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v, want invalid", err)
	}
	if err := requireEOF(json.NewDecoder(strings.NewReader(`null`))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v, want invalid", err)
	}

	limits := DefaultLimits(1024)
	for _, tc := range []struct {
		name   string
		value  any
		depth  int
		limits Limits
		count  int
	}{
		{name: "value-count", value: "value", depth: 1, limits: Limits{MaxDepth: 2, MaxValues: 1, MaxStringBytes: 8}, count: 1},
		{name: "string-length", value: "too-long", depth: 1, limits: Limits{MaxDepth: 2, MaxValues: 2, MaxStringBytes: 1}},
		{name: "array-child", value: []any{"too-long"}, depth: 1, limits: Limits{MaxDepth: 2, MaxValues: 3, MaxStringBytes: 1}},
		{name: "map-key", value: map[string]any{"too-long": "ok"}, depth: 1, limits: Limits{MaxDepth: 2, MaxValues: 3, MaxStringBytes: 1}},
		{name: "map-child", value: map[string]any{"ok": "too-long"}, depth: 1, limits: Limits{MaxDepth: 2, MaxValues: 3, MaxStringBytes: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count := tc.count
			if err := checkValueBounds(tc.value, tc.depth, tc.limits, &count); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v, want invalid", err)
			}
		})
	}
	if err := checkComponentCount(map[string]any{"components": "not-an-array"}, limits.MaxComponents); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v, want invalid", err)
	}
}

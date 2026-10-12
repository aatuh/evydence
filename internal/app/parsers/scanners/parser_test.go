package scanners

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseFixtures(t *testing.T) {
	for _, name := range []string{"generic", "grype", "trivy", "osv-scanner", "dependency-track"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := preflight(bytes.NewReader(raw), DefaultLimits(1<<20)); err != nil {
				t.Fatalf("preflight: %v", err)
			}
			got, err := ParseBounded(raw, DefaultLimits(1<<20))
			if err != nil {
				t.Fatalf("ParseBounded: %v", err)
			}
			if len(got.Findings) != 1 || got.Findings[0].Vulnerability == "" || got.Findings[0].Identity.PURL == "" {
				t.Fatalf("unexpected normalized result: %#v", got)
			}
			golden, err := os.ReadFile(filepath.Join("testdata", name+".golden.json"))
			if err != nil {
				t.Fatal(err)
			}
			var want Result
			if err := json.Unmarshal(golden, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("normalized result = %#v, want %#v", got, want)
			}
		})
	}
}

func TestParseRejectsAmbiguousAndUnknown(t *testing.T) {
	for _, raw := range []string{
		`{"scanner":"generic","target_ref":"pkg:oci/x","release_id":"r","findings":[{"vulnerability":"CVE-1","severity":"high","identity":{"cve":"CVE-1","unexpected":"x"}]}`,
		`{"scanner":"grype","target_ref":"pkg:oci/x","release_id":"r","source_schema":"grype-json.v99","payload":{"matches":[]}}`,
		`{"scanner":"grype","target_ref":"pkg:oci/x","release_id":"r","source_schema":"grype-json.v1","payload":{"matches":[{"vulnerability":{"id":"CVE-1","aliases":["CVE-2"],"severity":"high"},"artifact":{"purl":"pkg:apk/a@1"}}]}}`,
	} {
		if _, err := ParseBounded([]byte(raw), DefaultLimits(1<<20)); err == nil {
			t.Fatalf("accepted unsafe input %s", raw)
		}
	}
}

func TestProbeReleaseIDBoundedReaderPreservesTopLevelFieldOrder(t *testing.T) {
	raw := []byte(`{"scanner":"generic","findings":[{"vulnerability":"CVE-2026-0001","severity":"high"}],"target_ref":"pkg:oci/example","release_id":" rel_late "}`)

	got, err := ProbeReleaseIDBoundedReader(bytes.NewReader(raw), DefaultLimits(1<<20))
	if err != nil {
		t.Fatalf("ProbeReleaseIDBoundedReader: %v", err)
	}
	if got != "rel_late" {
		t.Fatalf("release id = %q, want rel_late", got)
	}
}

func TestProbeReleaseIDBoundedReaderRejectsMissingAmbiguousAndUnboundedInput(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		limits Limits
	}{
		{name: "missing", raw: `{"scanner":"generic","findings":[]}`, limits: DefaultLimits(1 << 20)},
		{name: "empty", raw: `{"release_id":"   ","findings":[]}`, limits: DefaultLimits(1 << 20)},
		{name: "wrong type", raw: `{"release_id":42,"findings":[]}`, limits: DefaultLimits(1 << 20)},
		{name: "duplicate", raw: `{"release_id":"rel_a","release_id":"rel_b","findings":[]}`, limits: DefaultLimits(1 << 20)},
		{name: "byte limit", raw: `{"findings":[{"component":"` + strings.Repeat("x", 256) + `"}],"release_id":"rel_late"}`, limits: DefaultLimits(128)},
		{name: "depth limit", raw: `{"findings":[[[[]]]],"release_id":"rel_late"}`, limits: Limits{MaxBytes: 1 << 20, MaxDepth: 3, MaxFindings: 10, MaxStringBytes: 100, MaxValues: 100}},
		{name: "value limit", raw: `{"findings":[1,2,3,4],"release_id":"rel_late"}`, limits: Limits{MaxBytes: 1 << 20, MaxDepth: 10, MaxFindings: 10, MaxStringBytes: 100, MaxValues: 4}},
		{name: "string limit", raw: `{"findings":[],"release_id":"release-too-long"}`, limits: Limits{MaxBytes: 1 << 20, MaxDepth: 10, MaxFindings: 10, MaxStringBytes: 5, MaxValues: 100}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, err := ProbeReleaseIDBoundedReader(strings.NewReader(test.raw), test.limits); err == nil {
				t.Fatalf("ProbeReleaseIDBoundedReader accepted input with release id %q", got)
			}
		})
	}
}

func TestProbeReleaseIDBoundedReaderEnforcesSelectedAdapterFindingLimit(t *testing.T) {
	limits := DefaultLimits(1 << 20)
	limits.MaxFindings = 1
	tests := []struct {
		name string
		raw  string
	}{
		{name: "generic", raw: `{"findings":[{},{}],"release_id":"rel_1","scanner":"generic","target_ref":"target"}`},
		{name: "grype", raw: `{"payload":{"matches":[{},{}]},"release_id":"rel_1","scanner":"grype","source_schema":"grype-json.v1","target_ref":"target"}`},
		{name: "trivy", raw: `{"payload":{"Results":[{"Vulnerabilities":[{},{}]}]},"release_id":"rel_1","scanner":"trivy","source_schema":"trivy-json.v1","target_ref":"target"}`},
		{name: "osv scanner", raw: `{"payload":{"results":[{"packages":[{"vulnerabilities":[{},{}]}]}]},"release_id":"rel_1","scanner":"osv-scanner","source_schema":"osv-scanner-json.v1","target_ref":"target"}`},
		{name: "dependency track", raw: `{"payload":{"findings":[{},{}]},"release_id":"rel_1","scanner":"dependency-track","source_schema":"dependency-track-json.v1","target_ref":"target"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, err := ProbeReleaseIDBoundedReader(strings.NewReader(test.raw), limits); err == nil {
				t.Fatalf("ProbeReleaseIDBoundedReader accepted %s over finding limit with release %q", test.name, got)
			}
		})
	}
}

func TestProbeReleaseIDBoundedReaderIgnoresInactiveAdapterArrays(t *testing.T) {
	limits := DefaultLimits(1 << 20)
	limits.MaxFindings = 1
	raw := []byte(`{"payload":{"matches":[],"Results":[{},{}]},"release_id":"rel_1","scanner":"grype","source_schema":"grype-json.v1","target_ref":"target"}`)

	if _, err := ParseBounded(raw, limits); err != nil {
		t.Fatalf("ParseBounded compatibility fixture: %v", err)
	}
	if got, err := ProbeReleaseIDBoundedReader(bytes.NewReader(raw), limits); err != nil || got != "rel_1" {
		t.Fatalf("ProbeReleaseIDBoundedReader release=%q error=%v", got, err)
	}
}

func TestNormalizationGuardsAndFallbacks(t *testing.T) {
	if got := component(Identity{CPE: "cpe:2.3:a:example:demo:*"}); got != "cpe:2.3:a:example:demo:*" {
		t.Fatalf("CPE component = %q", got)
	}
	if got := primary(Identity{VendorAdvisory: "RHSA-2026:1"}); got != "RHSA-2026:1" {
		t.Fatalf("vendor primary = %q", got)
	}
	if got := nonEmpty("", "open"); got != "open" {
		t.Fatalf("fallback = %q", got)
	}
	if got := osvSeverity([]any{map[string]any{"score": "CVSS:3.1/AV:N"}}); got != "unknown" {
		t.Fatalf("OSV score severity = %q", got)
	}
	if got := osvSeverity([]any{map[string]any{"score": ""}}); got != "unknown" {
		t.Fatalf("invalid OSV score severity = %q", got)
	}
	if _, err := parseIdentity(map[string]any{"cve": "CVE-2026-1", "purl": "pkg:npm/demo@1"}, []string{"CVE-2026-1"}, ""); err != nil {
		t.Fatalf("valid explicit identity: %v", err)
	}
	for _, value := range []any{map[string]any{"unknown": "x"}, "identity", map[string]any{"cve": "CVE-1"}} {
		_, err := parseIdentity(value, []string{"CVE-2"}, "")
		if err == nil {
			t.Fatalf("accepted conflicting/invalid identity %#v", value)
		}
	}
	for _, value := range []any{[]any{"a", "b"}, []any{""}, "not-array"} {
		_, err := stringsList(value)
		if (value == "not-array" || reflect.DeepEqual(value, []any{""})) && err == nil {
			t.Fatalf("accepted invalid string list %#v", value)
		}
	}
}

func FuzzParseBounded(f *testing.F) {
	f.Add([]byte(`{"scanner":"generic","target_ref":"pkg:oci/x","release_id":"r","findings":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = ParseBounded(raw, DefaultLimits(1<<20)) })
}

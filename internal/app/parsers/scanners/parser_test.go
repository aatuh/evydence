package scanners

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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

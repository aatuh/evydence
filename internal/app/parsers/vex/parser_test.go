package vex

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseOfficialFixturesAndExtensions(t *testing.T) {
	tests := []struct {
		name, fixture string
		parse         func([]byte, Limits) (Document, error)
		wantFormat    string
	}{
		{"openvex", "openvex/openvex-spec-minimal.json", ParseOpenVEX, "openvex"},
		{"cyclonedx", "cyclonedx-vex/official-vex-1.4.json", ParseCycloneDX, "cyclonedx"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", tt.fixture))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := tt.parse(raw, DefaultLimits(20<<20))
			if err != nil || doc.Format != tt.wantFormat || len(doc.Statements) == 0 {
				t.Fatalf("document=%#v err=%v", doc, err)
			}
		})
	}

	doc, err := ParseOpenVEX([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"urn:test","author":"test","timestamp":"2026-01-01T00:00:00Z","version":1,"x-vendor":{"preserved":true},"statements":[{"vulnerability":{"name":"CVE-2026-0001","aliases":["GHSA-test"]},"products":[{"@id":"pkg:apk/example@1.0.0","identifiers":{"purl":"pkg:apk/example@1.0.0"}}],"status":"fixed","x-statement":true}]}`), DefaultLimits(20<<20))
	if err != nil || !strings.Contains(strings.Join(doc.Warnings, "\n"), "$.x-vendor") {
		t.Fatalf("extension document=%#v err=%v", doc, err)
	}
}

func TestParseRejectsDuplicateKeysAndBounds(t *testing.T) {
	limits := DefaultLimits(1024)
	for _, raw := range [][]byte{
		[]byte(`{"author":"a","author":"b"}`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[]}`),
		[]byte(`{"@context":"x","author":"a","timestamp":"not-a-time","statements":[]}`),
	} {
		if _, err := ParseOpenVEX(raw, limits); !errors.Is(err, ErrInvalid) {
			t.Fatalf("openvex err=%v, want invalid", err)
		}
	}
	if _, err := ParseCycloneDX([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"resolved"}},{"id":"CVE-1","analysis":{"state":"resolved"}}]}`), Limits{MaxBytes: 1024, MaxStringBytes: 128, MaxDepth: 8, MaxStatements: 1, MaxValues: 100}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("statement bound err=%v", err)
	}
}

func TestNormalizationHelpersAndMalformedStatementShapes(t *testing.T) {
	if scalar(" value ") != "value" || scalar(json.Number("2")) != "2" || scalar(true) != "" {
		t.Fatalf("scalar normalization failed")
	}
	for source, want := range map[string]string{
		"resolved": "fixed", "resolved_with_pedigree": "fixed", "not_affected": "not_affected",
		"false_positive": "not_affected", "exploitable": "affected", "in_triage": "under_investigation", "unknown": "",
	} {
		if got := cycloneDXStatus(source); got != want {
			t.Fatalf("cycloneDXStatus(%q)=%q want %q", source, got, want)
		}
	}
	for _, version := range []string{"1.4", "1.5", "1.6", "1.7"} {
		if !supportedCycloneDXVersion(version) {
			t.Fatalf("version %s not supported", version)
		}
	}
	if supportedCycloneDXVersion("1.3") || openVEXStatus("invalid") {
		t.Fatal("unsupported value accepted")
	}

	limits := DefaultLimits(1024)
	for _, raw := range [][]byte{
		[]byte(`{"@context":"x","author":"a","timestamp":"2026-01-01T00:00:00Z","statements":[{"vulnerability":{"name":"CVE-1"},"products":"not-an-array","status":"fixed"}]}`),
		[]byte(`{"@context":"x","author":"a","timestamp":"2026-01-01T00:00:00Z","statements":[{"vulnerability":"not-an-object","products":[{"@id":"pkg:a"}],"status":"fixed"}]}`),
	} {
		if _, err := ParseOpenVEX(raw, limits); !errors.Is(err, ErrInvalid) {
			t.Fatalf("openvex shape err=%v", err)
		}
	}
	for _, raw := range [][]byte{
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":["not-an-object"]}`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-1","affects":"not-an-array","analysis":{"state":"resolved"}}]}`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"resolved","response":[1]}}]}`),
	} {
		if _, err := ParseCycloneDX(raw, limits); !errors.Is(err, ErrInvalid) {
			t.Fatalf("cyclonedx shape err=%v", err)
		}
	}
}

func FuzzVEX(f *testing.F) {
	limits := DefaultLimits(64 << 10)
	limits.MaxDepth, limits.MaxStringBytes, limits.MaxValues, limits.MaxStatements = 32, 4096, 8192, 128
	rows := strings.TrimSuffix(strings.Repeat(`{"id":"`+strings.Repeat("<", 4000)+`","analysis":{"state":"resolved"}},`, 15), ",")
	escaped := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[` + rows + `]}`)
	if _, err := ParseCycloneDX(escaped, limits); err != nil {
		f.Fatalf("positive escaping seed rejected: %v", err)
	}
	f.Add(escaped)
	f.Add([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","author":"test","timestamp":"2026-01-01T00:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:apk/a@1"}],"status":"fixed"}]}`))
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"resolved"}}]}`))
	for _, path := range []string{"openvex/openvex-spec-minimal.json", "cyclonedx-vex/official-vex-1.4.json"} {
		raw, err := os.ReadFile(filepath.Join("testdata", path))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	for _, version := range []string{"1.4", "1.5", "1.6", "1.7"} {
		f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"` + version + `","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"resolved"}},{"id":"CVE-2","analysis":{"state":"in_triage"}}]}`))
	}
	f.Add([]byte(`{"author":"first","\u0061uthor":"second"}`))
	f.Add([]byte(`{} null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		for _, parse := range []func([]byte, Limits) (Document, error){ParseOpenVEX, ParseCycloneDX} {
			first, err := parse(raw, limits)
			if err != nil {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("unexpected parser error: %v", err)
				}
				continue
			}
			again, err := parse(raw, limits)
			if err != nil || !reflect.DeepEqual(first, again) {
				t.Fatalf("successful parse not repeatable: %v", err)
			}
			if len(first.Statements) == 0 || len(first.Statements) > limits.MaxStatements || (first.Format != "openvex" && first.Format != "cyclonedx") {
				t.Fatal("invalid normalized document")
			}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			var value any
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			encodedLimits := limits
			if int64(len(encoded)) > limits.MaxBytes {
				if _, err := parse(encoded, limits); !errors.Is(err, ErrInvalid) {
					t.Fatal("expanded serialization escaped the original byte budget")
				}
				encodedLimits.MaxBytes = int64(len(encoded))
			}
			roundTrip, err := parse(encoded, encodedLimits)
			if err != nil || !reflect.DeepEqual(first, roundTrip) {
				t.Fatalf("JSON serialization changed projection: %v", err)
			}
			key := "author"
			if first.Format == "cyclonedx" {
				key = "bomFormat"
			}
			duplicate := append([]byte(`{"`+key+`":null,`), bytes.TrimSpace(raw)[1:]...)
			if _, err := parse(duplicate, limits); !errors.Is(err, ErrInvalid) {
				t.Fatal("duplicate decoded key accepted")
			}
			for _, constrained := range []Limits{
				func() Limits { v := limits; v.MaxBytes = int64(len(raw) - 1); return v }(),
				func() Limits { v := limits; v.MaxDepth = 1; return v }(),
				func() Limits { v := limits; v.MaxStringBytes = 1; return v }(),
				func() Limits { v := limits; v.MaxValues = 1; return v }(),
			} {
				if _, err := parse(raw, constrained); !errors.Is(err, ErrInvalid) {
					t.Fatal("structural budget ignored")
				}
			}
			if len(first.Statements) > 1 {
				constrained := limits
				constrained.MaxStatements = len(first.Statements) - 1
				if _, err := parse(raw, constrained); !errors.Is(err, ErrInvalid) {
					t.Fatal("statement budget ignored")
				}
			}
		}
	})
}

package spdx

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
)

func FuzzSPDX(f *testing.F) {
	limits := DefaultLimits(64 << 10)
	limits.MaxDepth, limits.MaxStringBytes, limits.MaxValues = 32, 4096, 8192
	limits.MaxPackages, limits.MaxRelationships = 128, 256
	limits.MaxChecksums, limits.MaxExternalRefs = 256, 256
	rows := strings.TrimSuffix(strings.Repeat(`{"name":"`+strings.Repeat("<", 4000)+`"},`, 15), ",")
	escaped := []byte(`{"spdxVersion":"SPDX-2.3","packages":[` + rows + `]}`)
	if _, err := ParseBounded(escaped, limits); err != nil {
		f.Fatalf("positive escaping seed rejected: %v", err)
	}
	f.Add(escaped)
	// SOURCE.md distinguishes the upstream 2.2 example, project-authored 2.3
	// example and sanitized generator fixtures. Do not relabel their origins.
	for _, path := range []string{"spdx-2.3-example.json", "spdx-spec-v2.2-example.json", "syft-1.46.0-spdx-2.3.json", "trivy-0.58.1-spdx-2.3.json"} {
		raw, err := os.ReadFile("testdata/" + path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte(`{"spdxVersion":"SPDX-2.3","spdxVersion":"SPDX-2.2"}`))
	f.Add([]byte(`{"spdxVersion":"SPDX-2.1"}`))
	f.Add([]byte(`{} null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		first, err := ParseBounded(raw, limits)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		again, err := ParseBoundedReader(iotest.HalfReader(bytes.NewReader(raw)), limits)
		if err != nil || !reflect.DeepEqual(first, again) {
			t.Fatalf("partial-reader parse is not repeatable: %v", err)
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
			if _, err := ParseBounded(encoded, limits); !errors.Is(err, ErrInvalid) {
				t.Fatal("expanded serialization escaped the original byte budget")
			}
			encodedLimits.MaxBytes = int64(len(encoded))
		}
		roundTrip, err := ParseBounded(encoded, encodedLimits)
		if err != nil || !reflect.DeepEqual(first, roundTrip) {
			t.Fatalf("JSON serialization changed projection: %v", err)
		}
		if first.SpecVersion != "SPDX-2.2" && first.SpecVersion != "SPDX-2.3" {
			t.Fatal("unsupported version accepted")
		}
		// Checksums and external references are bounded per package by the
		// current parser; MaxValues bounds aggregate document work. Preserve
		// that contract rather than imposing a new global interpretation.
		maxChecksums, maxReferences := 0, 0
		for _, row := range value.(map[string]any)["packages"].([]any) {
			pkg := row.(map[string]any)
			checksums, _ := pkg["checksums"].([]any)
			references, _ := pkg["externalRefs"].([]any)
			maxChecksums = max(maxChecksums, len(checksums))
			maxReferences = max(maxReferences, len(references))
		}
		if len(first.Packages) > limits.MaxPackages || len(first.Relationships) > limits.MaxRelationships || maxChecksums > limits.MaxChecksums || maxReferences > limits.MaxExternalRefs || len(first.Warnings) != len(first.UnsupportedPaths) || !slices.IsSorted(first.UnsupportedPaths) {
			t.Fatal("normalized counts or warning order violated")
		}
		for index, pkg := range first.Packages {
			if pkg.Identity == "" || (index > 0 && first.Packages[index-1].Identity > pkg.Identity) {
				t.Fatal("package identity or ordering violated")
			}
		}
		duplicate := append([]byte(`{"spdxVersion":null,`), bytes.TrimSpace(raw)[1:]...)
		if _, err := ParseBounded(duplicate, limits); !errors.Is(err, ErrInvalid) {
			t.Fatal("duplicate decoded key accepted")
		}
		for _, constrained := range []Limits{
			func() Limits { v := limits; v.MaxBytes = int64(len(raw) - 1); return v }(),
			func() Limits { v := limits; v.MaxDepth = 1; return v }(),
			func() Limits { v := limits; v.MaxStringBytes = 1; return v }(),
			func() Limits { v := limits; v.MaxValues = 1; return v }(),
		} {
			if _, err := ParseBounded(raw, constrained); !errors.Is(err, ErrInvalid) {
				t.Fatal("structural budget ignored")
			}
		}
		for name, count := range map[string]int{"packages": len(first.Packages), "relationships": len(first.Relationships), "checksums": maxChecksums, "references": maxReferences} {
			if count <= 1 {
				continue
			}
			constrained := limits
			switch name {
			case "packages":
				constrained.MaxPackages = count - 1
			case "relationships":
				constrained.MaxRelationships = count - 1
			case "checksums":
				constrained.MaxChecksums = count - 1
			case "references":
				constrained.MaxExternalRefs = count - 1
			}
			if _, err := ParseBounded(raw, constrained); !errors.Is(err, ErrInvalid) {
				t.Fatalf("%s budget ignored", name)
			}
		}
	})
}

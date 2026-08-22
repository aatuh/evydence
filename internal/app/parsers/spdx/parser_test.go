package spdx

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestParseBoundedReaderNormalizesSPDX23Deterministically(t *testing.T) {
	raw, err := os.ReadFile("testdata/spdx-2.3-example.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBounded(raw, DefaultLimits(int64(len(raw))))
	if err != nil {
		t.Fatal(err)
	}
	if got.SpecVersion != "SPDX-2.3" || len(got.Packages) != 2 || len(got.Relationships) != 2 {
		t.Fatalf("unexpected result: %#v", got)
	}
	if got.Packages[0].SPDXID != "SPDXRef-App" || got.Packages[0].PURL != "pkg:golang/example/app@1.0.0" || got.Packages[0].Identity != "purl:pkg:golang/example/app@1.0.0" {
		t.Fatalf("unexpected first package: %#v", got.Packages[0])
	}
	if got.Packages[1].Identity != "spdx:SPDXRef-Library" || got.ChecksumCount != 2 || got.LicenseCount != 4 || got.ExternalReferenceCount != 1 {
		t.Fatalf("unexpected normalized counts: %#v", got)
	}
}

func TestParseBoundedReaderAcceptsReferenceAndGeneratorFixtures(t *testing.T) {
	for _, fixture := range []struct {
		name, version string
	}{
		{"spdx-spec-v2.2-example.json", "SPDX-2.2"},
		{"syft-1.46.0-spdx-2.3.json", "SPDX-2.3"},
		{"trivy-0.58.1-spdx-2.3.json", "SPDX-2.3"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/" + fixture.name)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseBounded(raw, DefaultLimits(int64(len(raw))))
			if err != nil {
				t.Fatal(err)
			}
			if got.SpecVersion != fixture.version || len(got.Packages) == 0 {
				t.Fatalf("result=%#v", got)
			}
		})
	}
}

func TestParseBoundedReaderPreservesUnknownFieldsAsWarnings(t *testing.T) {
	raw := []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"example","documentNamespace":"https://example.test/spdx","dataLicense":"CC0-1.0","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: test"]},"x-legal-extension":{"retention":"seven-years"},"packages":[{"SPDXID":"SPDXRef-Package","name":"pkg","x-legal-extension":"preserve-raw"}]}`)
	got, err := ParseBounded(raw, DefaultLimits(int64(len(raw))))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Warnings) != 2 || got.UnsupportedPaths[0] != "$.packages[0].x-legal-extension" || got.UnsupportedPaths[1] != "$.x-legal-extension" {
		t.Fatalf("unexpected warnings: %#v %#v", got.Warnings, got.UnsupportedPaths)
	}
}

func TestParseBoundedReaderRejectsUnsupportedVersionDuplicateKeysAndBounds(t *testing.T) {
	base := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"example","documentNamespace":"https://example.test/spdx","dataLicense":"CC0-1.0","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: test"]},"packages":[]}`
	for name, raw := range map[string]string{
		"unsupported version": strings.Replace(base, "SPDX-2.3", "SPDX-2.1", 1),
		"duplicate key":       strings.Replace(base, `"name":"example"`, `"name":"example","name":"duplicate"`, 1),
		"relationship limit":  strings.Replace(base, `"packages":[]`, `"relationships":[{"spdxElementId":"SPDXRef-A","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-B"},{"spdxElementId":"SPDXRef-B","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-A"}]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			limits := DefaultLimits(int64(len(raw)))
			if name == "relationship limit" {
				limits.MaxRelationships = 1
			}
			if _, err := ParseBounded([]byte(raw), limits); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestParseBoundedReaderRejectsInvalidCreationTimestamp(t *testing.T) {
	raw := []byte(`{"spdxVersion":"SPDX-2.3","creationInfo":{"created":"not-a-time","creators":["Tool: test"]},"packages":[]}`)
	if _, err := ParseBounded(raw, DefaultLimits(int64(len(raw)))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

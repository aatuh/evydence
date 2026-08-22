package cyclonedx

import (
	"bytes"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseBoundedAcceptsStandardFieldsWithoutNormalizingThem(t *testing.T) {
	raw := []byte(`{
		"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
		"metadata":{"timestamp":"2026-08-08T12:00:00Z"},
		"components":[{
			"bom-ref":"pkg:oci/api@1.0.0","type":"container","name":"api","version":"1.0.0","purl":"pkg:oci/api@1.0.0",
			"hashes":[{"alg":"SHA-256","content":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
			"licenses":[{"license":{"id":"Apache-2.0"}}],
			"properties":[{"name":"syft:package:foundBy","value":"go-module-cataloger"}]
		}],
		"dependencies":[{"ref":"pkg:oci/api@1.0.0","dependsOn":["pkg:golang/example.org/lib@1.2.3"]}],
		"services":[{"bom-ref":"service:api","name":"API"}],
		"compositions":[{"aggregate":"complete","assemblies":["pkg:oci/api@1.0.0"]}]
	}`)
	got, err := ParseBounded(raw, DefaultLimits(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if got.SpecVersion != "1.6" || len(got.Components) != 1 || len(got.Dependencies) != 1 {
		t.Fatalf("result=%#v", got)
	}
	component := got.Components[0]
	if component.Identity != "purl:pkg:oci/api@1.0.0" || component.BOMRef != "pkg:oci/api@1.0.0" || component.Name != "api" {
		t.Fatalf("component=%#v", component)
	}
	if strings.Join(got.Dependencies[0].DependsOn, ",") != "pkg:golang/example.org/lib@1.2.3" {
		t.Fatalf("dependency=%#v", got.Dependencies[0])
	}
	warnings := strings.Join(got.Warnings, "\n")
	for _, want := range []string{"components[].hashes", "components[].licenses", "components[].properties", "services", "compositions"} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("warnings=%q missing %q", warnings, want)
		}
	}
}

func TestParseBoundedNormalizesDependencyOrdering(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"lib"}],"dependencies":[{"ref":"z","dependsOn":["b","a"]},{"ref":"a"}]}`)
	got, err := ParseBounded(raw, DefaultLimits(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if got.Components[0].Identity != "component:library:lib@" {
		t.Fatalf("identity=%q", got.Components[0].Identity)
	}
	if got.Dependencies[0].Ref != "a" || got.Dependencies[1].Ref != "z" || strings.Join(got.Dependencies[1].DependsOn, ",") != "a,b" {
		t.Fatalf("dependencies=%#v", got.Dependencies)
	}
}

func TestOfficialCycloneDX16FixturesAreAccepted(t *testing.T) {
	tests := []struct {
		name             string
		components       int
		dependencies     int
		warningSubstring string
	}{
		{name: "valid-dependency-1.6.json", components: 3, dependencies: 2},
		{name: "valid-properties-1.6.json", components: 1, warningSubstring: "components[].properties"},
		{name: "valid-standard-1.6.json", warningSubstring: "definitions"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/official/" + test.name)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseBounded(raw, DefaultLimits(1<<20))
			if err != nil {
				t.Fatalf("official fixture rejected: %v", err)
			}
			if len(got.Components) != test.components || len(got.Dependencies) != test.dependencies {
				t.Fatalf("components/dependencies=%d/%d want=%d/%d", len(got.Components), len(got.Dependencies), test.components, test.dependencies)
			}
			if test.warningSubstring != "" && !strings.Contains(strings.Join(got.Warnings, "\n"), test.warningSubstring) {
				t.Fatalf("warnings=%#v missing %q", got.Warnings, test.warningSubstring)
			}
		})
	}
}

func TestParseBoundedReaderStreamsWithinHardByteLimit(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"reader"}]}`)
	limits := DefaultLimits(int64(len(raw)))
	got, err := ParseBoundedReader(bytes.NewReader(raw), limits)
	if err != nil || len(got.Components) != 1 || got.Components[0].Name != "reader" {
		t.Fatalf("reader result=%#v err=%v", got, err)
	}

	oversized := append(append([]byte(nil), raw...), ' ')
	if _, err := ParseBoundedReader(bytes.NewReader(oversized), limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized reader err=%v, want invalid", err)
	}
	if _, err := ParseBoundedReader(nil, limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil reader err=%v, want invalid", err)
	}
}

func TestParseBoundedReaderFailsClosedOnSourceError(t *testing.T) {
	limits := DefaultLimits(1 << 20)
	reader := io.MultiReader(
		strings.NewReader(`{"bomFormat":"CycloneDX","specVersion":"1.6",`),
		errReader{err: errors.New("source failed")},
	)
	if _, err := ParseBoundedReader(reader, limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("source error=%v, want invalid", err)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestParseBoundedRejectsUnsupportedVersionAndMalformedCore(t *testing.T) {
	for name, raw := range map[string]string{
		"wrong format":   `{"bomFormat":"SPDX","specVersion":"1.6"}`,
		"wrong version":  `{"bomFormat":"CycloneDX","specVersion":"1.5"}`,
		"missing type":   `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"x"}]}`,
		"missing name":   `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library"}]}`,
		"bad dependency": `{"bomFormat":"CycloneDX","specVersion":"1.6","dependencies":[{"ref":""}]}`,
		"trailing json":  `{"bomFormat":"CycloneDX","specVersion":"1.6"}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBounded([]byte(raw), DefaultLimits(1<<20)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v, want invalid", err)
			}
		})
	}
}

func TestParseBoundedEnforcesResourceLimits(t *testing.T) {
	base := DefaultLimits(1 << 20)
	tests := []struct {
		name   string
		raw    string
		limits Limits
	}{
		{name: "bytes", raw: `{"bomFormat":"CycloneDX","specVersion":"1.6"}`, limits: DefaultLimits(8)},
		{name: "depth", raw: `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"a":{"b":{"c":1}}}}`, limits: func() Limits { v := base; v.MaxDepth = 3; return v }()},
		{name: "components", raw: `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"a"},{"type":"library","name":"b"}]}`, limits: func() Limits { v := base; v.MaxComponents = 1; return v }()},
		{name: "dependencies", raw: `{"bomFormat":"CycloneDX","specVersion":"1.6","dependencies":[{"ref":"a"},{"ref":"b"}]}`, limits: func() Limits { v := base; v.MaxDependencies = 1; return v }()},
		{name: "string", raw: `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"123456789"}]}`, limits: func() Limits { v := base; v.MaxStringBytes = 8; return v }()},
		{name: "values", raw: `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"a"}]}`, limits: func() Limits { v := base; v.MaxValues = 4; return v }()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseBounded([]byte(test.raw), test.limits); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v, want invalid", err)
			}
		})
	}
}

func FuzzCycloneDX(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"x"}]}`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"2026-08-09T00:00:00Z"},"components":[{"type":"application","name":"root","components":[{"type":"library","name":"nested"}]}],"dependencies":[{"ref":"root","dependsOn":["nested"]}],"properties":[{"name":"source","value":"fuzz-seed"}]}`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","dependencies":[{"ref":"root","provides":["virtual"]}]}`),
		[]byte(`{}`),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}{}`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		limits := DefaultLimits(256 << 10)
		limits.MaxComponents = 1024
		limits.MaxDependencies = 2048
		limits.MaxValues = 8192
		first, err := ParseBounded(raw, limits)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("unexpected parser error: %v", err)
			}
			return
		}
		second, err := ParseBounded(raw, limits)
		if err != nil {
			t.Fatalf("successful parse was not repeatable: %v", err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("non-deterministic parse:\nfirst=%#v\nsecond=%#v", first, second)
		}
		if first.SpecVersion != SupportedSpecVersion {
			t.Fatalf("specVersion=%q", first.SpecVersion)
		}
		if len(first.Warnings) != len(first.UnsupportedPaths) {
			t.Fatalf("warnings=%d unsupportedPaths=%d", len(first.Warnings), len(first.UnsupportedPaths))
		}
		for _, component := range first.Components {
			if component.Identity == "" || component.Identity != componentIdentity(component) {
				t.Fatalf("unstable component identity: %#v", component)
			}
		}
		for i, dependency := range first.Dependencies {
			if dependency.Ref == "" {
				t.Fatalf("empty dependency ref")
			}
			if i > 0 && first.Dependencies[i-1].Ref > dependency.Ref {
				t.Fatalf("dependency order is not canonical: %#v", first.Dependencies)
			}
			for j := 1; j < len(dependency.DependsOn); j++ {
				if dependency.DependsOn[j-1] > dependency.DependsOn[j] {
					t.Fatalf("dependsOn order is not canonical: %#v", dependency.DependsOn)
				}
			}
		}
	})
}

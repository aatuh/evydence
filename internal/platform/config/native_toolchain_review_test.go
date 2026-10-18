package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

var nativeGoBoundaries = []string{
	"tls_roots", "http_transport", "unix_executable", "windows_executable",
	"user_home", "http_proxy", "unix_path_list", "windows_path_list",
}

// This is a source-review guard, not a replacement native loader. The schema
// describes current Go; the review must also cover the supported minimum.
func validateNativeGoReview(sources []nativeBoundarySource, versions []string, definitions []NativeDefinition, running string, readGo func(string) ([]byte, error)) error {
	if len(versions) == 0 || !slices.Contains(versions, running) {
		return errors.New("running Go has no declared native boundary review")
	}
	covered := map[string]map[string]bool{}
	for _, version := range versions {
		if version == "" || covered[version] != nil {
			return errors.New("invalid declared Go review versions")
		}
		covered[version] = map[string]bool{}
	}
	for _, entry := range sources {
		if !strings.HasPrefix(entry.Source, "go@") {
			if entry.GoBoundary != "" {
				return errors.New("non-Go source has a Go boundary")
			}
			continue
		}
		version, path, ok := strings.Cut(strings.TrimPrefix(entry.Source, "go@"), "/")
		if !ok || covered[version] == nil || !strings.HasPrefix(path, "src/") || !fs.ValidPath(path) || !slices.Contains(nativeGoBoundaries, entry.GoBoundary) || covered[version][entry.GoBoundary] {
			return fmt.Errorf("unbound, invalid or duplicate Go boundary source: %s", entry.Source)
		}
		covered[version][entry.GoBoundary] = true
		if version == running {
			data, err := readGo(path)
			if err != nil {
				return fmt.Errorf("cannot read running toolchain boundary source: %s", entry.Source)
			}
			actual := sha256.Sum256(data)
			if hex.EncodeToString(actual[:]) != entry.SHA256 {
				return fmt.Errorf("running toolchain source differs from committed review: %s", entry.Source)
			}
		}
	}
	for _, version := range versions {
		if len(covered[version]) != len(nativeGoBoundaries) {
			return fmt.Errorf("supported Go lacks a complete native boundary review: %s", version)
		}
	}
	current := versions[len(versions)-1]
	for _, d := range definitions {
		if strings.HasPrefix(d.Source, "go@") && !strings.HasPrefix(d.Source, "go@"+current+"/") {
			return fmt.Errorf("native catalogue is stale against current Go: %s", d.Name)
		}
	}
	return nil
}

func nativeGoPolicy(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("../../../release/support-matrix.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Go struct{ Minimum, Current string }
	}
	if err := json.Unmarshal(data, &policy); err != nil || policy.Go.Minimum == "" || policy.Go.Current == "" {
		t.Fatal("missing declared Go support policy", err)
	}
	data, err = os.ReadFile("../../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	module, err := modfile.Parse("go.mod", data, nil)
	if err != nil || module.Go == nil || module.Go.Version != policy.Go.Minimum {
		t.Fatal("module minimum differs from declared support policy", err)
	}
	if module.Toolchain != nil && module.Toolchain.Name != "go"+policy.Go.Current {
		t.Fatal("preferred module toolchain differs from declared current Go")
	}
	if policy.Go.Minimum == policy.Go.Current {
		return []string{policy.Go.Current}
	}
	return []string{policy.Go.Minimum, policy.Go.Current}
}

func TestNativeBoundaryCatalogueUsesCurrentGo(t *testing.T) {
	versions := nativeGoPolicy(t)
	current := versions[len(versions)-1]
	for _, d := range NativeDefinitions() {
		if strings.HasPrefix(d.Source, "go@") && !strings.HasPrefix(d.Source, "go@"+current+"/") {
			t.Error("native catalogue does not describe the declared current Go", d.Name)
		}
	}
}

func TestNativeBoundaryReviewCoversSupportedToolchains(t *testing.T) {
	data, err := os.ReadFile("testdata/native-boundary-review.json")
	if err != nil {
		t.Fatal(err)
	}
	var review struct {
		Version int `json:"schema_version"`
		Sources []struct {
			Source   string `json:"source"`
			Boundary string `json:"go_boundary"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(data, &review); err != nil || review.Version != 2 {
		t.Fatal("dual-toolchain native review schema is missing", err)
	}
	versions := nativeGoPolicy(t)
	boundaries := map[string][]string{}
	for _, entry := range review.Sources {
		if !strings.HasPrefix(entry.Source, "go@") {
			continue
		}
		version, _, _ := strings.Cut(strings.TrimPrefix(entry.Source, "go@"), "/")
		if !slices.Contains(versions, version) || entry.Boundary == "" || slices.Contains(boundaries[version], entry.Boundary) {
			t.Fatal("unbound or duplicate standard-library source review", entry.Source)
		}
		boundaries[version] = append(boundaries[version], entry.Boundary)
	}
	for _, version := range versions {
		slices.Sort(boundaries[version])
		if len(boundaries[version]) == 0 || !slices.Equal(boundaries[version], boundaries[versions[0]]) {
			t.Fatal("a supported Go version lacks equivalent boundary review", version)
		}
	}
}

func TestNativeBoundaryGoReviewRejectsDrift(t *testing.T) {
	type input struct {
		sources     []nativeBoundarySource
		versions    []string
		definitions []NativeDefinition
		running     string
		readFailure bool
	}
	files := map[string][]byte{}
	fixture := func() input {
		v := input{versions: []string{"1.26.9", "1.27.2"}, running: "1.27.2"}
		for _, version := range v.versions {
			for _, boundary := range nativeGoBoundaries {
				path := "src/" + boundary + ".go"
				data := []byte("reviewed fixture for " + boundary)
				files[path] = data
				hash := sha256.Sum256(data)
				v.sources = append(v.sources, nativeBoundarySource{Source: "go@" + version + "/" + path, SHA256: hex.EncodeToString(hash[:]), GoBoundary: boundary, Finding: "synthetic guard fixture"})
			}
		}
		v.definitions = []NativeDefinition{{Definition: Definition{Name: "SSL_CERT_FILE"}, Source: "go@1.27.2/src/tls_roots.go:loadSystemRoots"}}
		return v
	}
	check := func(v input) error {
		return validateNativeGoReview(v.sources, v.versions, v.definitions, v.running, func(path string) ([]byte, error) {
			if v.readFailure {
				return nil, fs.ErrNotExist
			}
			return files[path], nil
		})
	}
	for _, version := range []string{"1.26.9", "1.27.2"} {
		v := fixture()
		v.running = version
		if err := check(v); err != nil {
			t.Fatal("complete synthetic review rejected", err)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*input)
	}{
		{"minimum-boundary-removed", func(v *input) { v.sources = v.sources[1:] }},
		{"current-boundary-removed", func(v *input) { v.sources = v.sources[:len(v.sources)-1] }},
		{"duplicate-boundary", func(v *input) { v.sources = append(v.sources, v.sources[0]) }},
		{"missing-boundary-name", func(v *input) { v.sources[0].GoBoundary = "" }},
		{"unknown-boundary", func(v *input) { v.sources[0].GoBoundary = "unreviewed" }},
		{"unreviewed-source-version", func(v *input) { v.sources[0].Source = "go@1.28.0/src/tls_roots.go" }},
		{"path-escape", func(v *input) { v.sources[0].Source = "go@1.26.9/src/../tls_roots.go" }},
		{"non-source-path", func(v *input) { v.sources[0].Source = "go@1.26.9/tls_roots.go" }},
		{"current-source-bytes", func(v *input) { v.sources[len(nativeGoBoundaries)].SHA256 = strings.Repeat("0", 64) }},
		{"minimum-source-bytes", func(v *input) { v.running = "1.26.9"; v.sources[0].SHA256 = strings.Repeat("0", 64) }},
		{"source-unreadable", func(v *input) { v.readFailure = true }},
		{"stale-catalogue", func(v *input) { v.definitions[0].Source = "go@1.26.9/src/tls_roots.go:loadSystemRoots" }},
		{"unsupported-compiler", func(v *input) { v.running = "1.28.0" }},
		{"unreviewed-current-policy", func(v *input) { v.versions[1] = "1.28.0"; v.running = "1.28.0" }},
		{"unreviewed-minimum-policy", func(v *input) { v.versions[0] = "1.26.10" }},
		{"no-policy", func(v *input) { v.versions = nil }},
		{"duplicate-policy-version", func(v *input) { v.versions = []string{"1.27.2", "1.27.2"} }},
		{"non-go-boundary", func(v *input) {
			v.sources = append(v.sources, nativeBoundarySource{Source: "internal/not-go.go", GoBoundary: "tls_roots"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := fixture()
			tc.mutate(&v)
			if err := check(v); err == nil {
				t.Fatal("native source drift was accepted")
			}
		})
	}
}

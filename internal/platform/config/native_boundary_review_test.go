package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/modfile"
)

type nativeBoundarySource struct {
	Source     string `json:"source"`
	SHA256     string `json:"sha256"`
	Finding    string `json:"finding"`
	GoBoundary string `json:"go_boundary,omitempty"`
}

func TestNativeBoundaryReviewMatchesPinnedSources(t *testing.T) {
	data, err := os.ReadFile("testdata/native-boundary-review.json")
	if err != nil {
		t.Fatal(err)
	}
	var review struct {
		Version int                    `json:"schema_version"`
		Scope   string                 `json:"scope"`
		Sources []nativeBoundarySource `json:"sources"`
	}
	if err := json.Unmarshal(data, &review); err != nil || review.Version != 2 || review.Scope == "" || len(review.Sources) == 0 {
		t.Fatal("native boundary review is missing or malformed", err)
	}
	data, err = os.ReadFile("../../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	module, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]string{}
	for _, requirement := range module.Require {
		pins[requirement.Mod.Path] = requirement.Mod.Version
	}
	reviewed := map[string]bool{}
	sourceRoot, err := os.OpenRoot("../../..")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sourceRoot.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, entry := range review.Sources {
		hash, err := hex.DecodeString(entry.SHA256)
		if err != nil || len(hash) != sha256.Size || entry.Finding == "" || reviewed[entry.Source] {
			t.Fatal("native source review has invalid or duplicate evidence", entry.Source)
		}
		reviewed[entry.Source] = true
		dependency, rest, external := strings.Cut(entry.Source, "@")
		if external {
			version, _, hasPath := strings.Cut(rest, "/")
			if !hasPath || (dependency != "go" && pins[dependency] != version) {
				t.Fatal("reviewed native boundary dependency changed; review its environment inputs", entry.Source)
			}
			continue
		}
		if !strings.HasPrefix(entry.Source, "internal/") && !strings.HasPrefix(entry.Source, "scripts/") {
			t.Fatal("unexpected repository boundary source", entry.Source)
		}
		data, err := sourceRoot.ReadFile(entry.Source)
		if err != nil {
			t.Fatal(err)
		}
		actual := sha256.Sum256(data)
		if hex.EncodeToString(actual[:]) != entry.SHA256 {
			t.Fatal("repository boundary source changed; refresh the scoped source review", entry.Source)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	data, err = exec.CommandContext(ctx, "go", "env", "-json", "GOROOT", "GOVERSION").Output()
	if err != nil {
		t.Fatal("cannot locate the selected Go source tree", err)
	}
	var toolchain struct{ GOROOT, GOVERSION string }
	if err := json.Unmarshal(data, &toolchain); err != nil || toolchain.GOROOT == "" || toolchain.GOVERSION != runtime.Version() {
		t.Fatal("selected Go command differs from the test compiler", err)
	}
	goRoot, err := os.OpenRoot(toolchain.GOROOT)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := goRoot.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := validateNativeGoReview(review.Sources, nativeGoPolicy(t), NativeDefinitions(), strings.TrimPrefix(runtime.Version(), "go"), func(path string) ([]byte, error) {
		return goRoot.ReadFile(filepath.FromSlash(path))
	}); err != nil {
		t.Fatal(err)
	}
	for _, definition := range NativeDefinitions() {
		source, _, _ := strings.Cut(definition.Source, ":")
		if !reviewed[source] {
			t.Fatal("native schema source has no committed review record", definition.Name, source)
		}
	}
}

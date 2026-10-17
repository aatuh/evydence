package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

func TestNativeBoundaryReviewMatchesPinnedSources(t *testing.T) {
	data, err := os.ReadFile("testdata/native-boundary-review.json")
	if err != nil {
		t.Fatal(err)
	}
	var review struct {
		Version int    `json:"schema_version"`
		Scope   string `json:"scope"`
		Sources []struct {
			Source  string `json:"source"`
			SHA256  string `json:"sha256"`
			Finding string `json:"finding"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(data, &review); err != nil || review.Version != 1 || review.Scope == "" || len(review.Sources) == 0 {
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
	pins := map[string]string{"go": module.Go.Version}
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
			if !hasPath || pins[dependency] != version {
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
	for _, definition := range NativeDefinitions() {
		source, _, _ := strings.Cut(definition.Source, ":")
		if !reviewed[source] {
			t.Fatal("native schema source has no committed review record", definition.Name, source)
		}
	}
}

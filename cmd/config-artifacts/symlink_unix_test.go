//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/aatuh/evydence/internal/platform/configartifact"
)

func TestWriteRejectsSymlinkTargetsAndAncestors(t *testing.T) {
	for _, tc := range []struct{ ancestor, inside bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		directory, originals := artifactFixture(t)
		outside := t.TempDir()
		if tc.inside {
			outside = filepath.Join(directory, "alternate")
			if err := os.Mkdir(outside, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		canary := originals[configartifact.ConfigurationReferencePath]
		outsideFile := filepath.Join(outside, "configuration.md")
		if err := os.WriteFile(outsideFile, canary, 0o600); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(directory, filepath.FromSlash(configartifact.ConfigurationReferencePath))
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if tc.ancestor {
			target = filepath.Dir(target)
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			link := outside
			if tc.inside {
				link = "../alternate"
			}
			if err := os.Symlink(link, target); err != nil {
				t.Fatal(err)
			}
		} else {
			link := outsideFile
			if tc.inside {
				link = "../../alternate/configuration.md"
			}
			if err := os.Symlink(link, target); err != nil {
				t.Fatal(err)
			}
		}
		if code, _, _ := invokeArtifacts(t, directory, "--write"); code != 1 {
			t.Fatal("symlink artifact boundary was accepted")
		}
		for name, before := range originals {
			after, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(name)))
			if err != nil || !bytes.Equal(after, before) {
				t.Fatal("symlink rejection changed an operator artifact")
			}
		}
		after, err := os.ReadFile(outsideFile)
		if err != nil || !bytes.Equal(after, canary) {
			t.Fatal("generator changed data outside the repository")
		}
	}
}

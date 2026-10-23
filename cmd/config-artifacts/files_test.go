package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/aatuh/evydence/internal/platform/configartifact"
)

func TestStagedArtifactDetectsOperatorChangesAndCleansUp(t *testing.T) {
	for _, kind := range []string{"contents", "replacement", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			directory, originals := artifactFixture(t)
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := root.Close(); err != nil {
					t.Error(err)
				}
			})
			artifact, err := openArtifact(root, configartifact.ProductionEnvironmentPath)
			if err != nil {
				t.Fatal(err)
			}
			artifact.after = []byte("replacement generated content\n")
			if err := artifact.stage(); err != nil {
				_ = artifact.close()
				t.Fatal(err)
			}
			temporary := artifact.temporary
			before := originals[configartifact.ProductionEnvironmentPath]
			current := bytes.Clone(before)
			switch kind {
			case "contents":
				current = append(current, []byte("# PRIVATE_CONCURRENT_EDIT\n")...)
				if err := root.WriteFile(configartifact.ProductionEnvironmentPath, current, 0o600); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				if err := root.WriteFile("replacement", current, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := root.Rename("replacement", configartifact.ProductionEnvironmentPath); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				file, err := root.Open(configartifact.ProductionEnvironmentPath)
				if err != nil {
					t.Fatal(err)
				}
				chmodErr := file.Chmod(0o640)
				closeErr := file.Close()
				if chmodErr != nil || closeErr != nil {
					t.Fatal("cannot update fixture permissions")
				}
			}
			if artifact.unchanged() {
				t.Error("concurrent operator change was accepted")
			}
			if err := artifact.close(); err != nil {
				t.Fatal(err)
			}
			if _, err := root.Lstat(temporary); !os.IsNotExist(err) {
				t.Fatal("staged replacement was not cleaned up")
			}
			after, err := root.ReadFile(configartifact.ProductionEnvironmentPath)
			if err != nil || !bytes.Equal(current, after) {
				t.Fatal("cleanup changed the concurrent operator edit")
			}
		})
	}
}

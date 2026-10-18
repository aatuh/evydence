package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/configartifact"
)

var testArtifactPaths = []string{
	configartifact.ProductionEnvironmentPath,
	configartifact.ConfigurationReferencePath,
	configartifact.HelmReferencePath,
}

func artifactFixture(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	directory := t.TempDir()
	originals := make(map[string][]byte)
	for _, name := range testArtifactPaths {
		file := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		start, end := "<!-- BEGIN EVYDENCE GENERATED CONFIGURATION -->", "<!-- END EVYDENCE GENERATED CONFIGURATION -->"
		if name == configartifact.ProductionEnvironmentPath {
			start, end = "# BEGIN EVYDENCE GENERATED CONFIGURATION", "# END EVYDENCE GENERATED CONFIGURATION"
		}
		body := []byte("# Operator instructions: PRIVATE_OPERATOR_CANARY  preserve spacing.\n" + start + "\nPRIVATE_OLD_GENERATED_CANARY\n" + end + "\n# Keep these operator instructions too.\n")
		if err := os.WriteFile(file, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if name != configartifact.ProductionEnvironmentPath {
			if err := os.Chmod(file, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		originals[name] = body
	}
	return directory, originals
}

func invokeArtifacts(t *testing.T, directory string, args ...string) (int, string, string) {
	t.Helper()
	var out, diagnostics bytes.Buffer
	var opened *os.Root
	code := run(args, &out, &diagnostics, func() (*os.Root, error) {
		root, err := os.OpenRoot(directory)
		opened = root
		return root, err
	})
	if opened != nil {
		if _, err := opened.Stat("."); err == nil {
			_ = opened.Close()
			t.Fatal("command did not close its owned repository root")
		}
	}
	if strings.Contains(out.String()+diagnostics.String(), "PRIVATE_") {
		t.Fatal("command exposed operator content or sensitive input")
	}
	return code, out.String(), diagnostics.String()
}

func TestCheckIsReadOnlyAndExplicitWriteConverges(t *testing.T) {
	t.Setenv("ENV", "PRIVATE_INVALID_ENVIRONMENT")
	t.Setenv("EVYDENCE_DATABASE_URL", "PRIVATE_DATABASE_CANARY")
	directory, originals := artifactFixture(t)
	modes := make(map[string]os.FileMode)
	for name := range originals {
		info, err := os.Stat(filepath.Join(directory, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		modes[name] = info.Mode().Perm()
	}
	code, _, _ := invokeArtifacts(t, directory)
	if code != 1 {
		t.Fatal("default check did not report drift")
	}
	for name, before := range originals {
		after, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("default check changed an operator artifact")
		}
	}
	if code, _, _ := invokeArtifacts(t, directory, "--write"); code != 0 {
		t.Fatal("explicit generation failed")
	}
	for name, before := range originals {
		after, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(name)))
		prefix := bytes.SplitN(before, []byte("\n"), 2)[0]
		if err != nil || bytes.Equal(before, after) || !bytes.HasPrefix(after, prefix) || !bytes.HasSuffix(after, []byte("# Keep these operator instructions too.\n")) {
			t.Fatal("generation lost operator instructions or did not update settings")
		}
		info, err := os.Stat(filepath.Join(directory, filepath.FromSlash(name)))
		if err != nil || info.Mode().Perm() != modes[name] {
			t.Fatal("generation changed existing artifact permissions")
		}
	}
	if code, _, _ := invokeArtifacts(t, directory, "--check"); code != 0 {
		t.Fatal("generated artifacts still report drift")
	}
	file := filepath.Join(directory, configartifact.ProductionEnvironmentPath)
	generated, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("# BEGIN EVYDENCE GENERATED CONFIGURATION\n")
	modified := bytes.Replace(generated, marker, append(bytes.Clone(marker), []byte("# PRIVATE_MANUAL_DRIFT_CANARY\n")...), 1)
	if bytes.Equal(modified, generated) {
		t.Fatal("fixture did not modify the generated section")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(configartifact.ProductionEnvironmentPath, modified, 0o600); err != nil {
		_ = root.Close()
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := invokeArtifacts(t, directory, "--check"); code != 1 {
		t.Fatal("manual drift inside the generated section was accepted")
	}
	afterCheck, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(afterCheck, modified) {
		t.Fatal("drift check repaired the artifact without write authorization")
	}
	if code, _, _ := invokeArtifacts(t, directory, "--write"); code != 0 {
		t.Fatal("explicit generation did not repair drift")
	}
	identities := make(map[string]os.FileInfo)
	for _, name := range testArtifactPaths {
		info, err := os.Stat(filepath.Join(directory, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		identities[name] = info
	}
	if code, _, _ := invokeArtifacts(t, directory, "--write"); code != 0 {
		t.Fatal("idempotent generation failed")
	}
	for name, before := range identities {
		after, err := os.Stat(filepath.Join(directory, filepath.FromSlash(name)))
		if err != nil || !os.SameFile(before, after) {
			t.Fatal("generation rewrote an already-current artifact")
		}
	}
	if err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(entry.Name(), "evydence-config-") {
			t.Error("generation left a temporary file")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHelpAndInvalidFlagsDoNotOpenRepositoryOrExposeArguments(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"--help"}, 0},
		{[]string{"-h"}, 0},
		{[]string{"--check", "--write"}, 2},
		{[]string{"--PRIVATE_ARGUMENT=value"}, 2},
		{[]string{"--write=PRIVATE_ARGUMENT"}, 2},
		{[]string{"PRIVATE_ARGUMENT"}, 2},
	} {
		var out, diagnostics bytes.Buffer
		opened := false
		code := run(tc.args, &out, &diagnostics, func() (*os.Root, error) {
			opened = true
			return nil, errors.New("PRIVATE_ROOT_ERROR")
		})
		if code != tc.code || opened || strings.Contains(out.String()+diagnostics.String(), "PRIVATE_") {
			t.Fatal("help/flag validation opened a repository or exposed input")
		}
	}
}

func TestWriteValidatesEveryArtifactBeforeChangingAny(t *testing.T) {
	for _, invalid := range testArtifactPaths {
		t.Run(invalid, func(t *testing.T) {
			directory, originals := artifactFixture(t)
			bad := []byte("PRIVATE_OPERATOR_CANARY without owned markers\n")
			if err := os.WriteFile(filepath.Join(directory, filepath.FromSlash(invalid)), bad, 0o600); err != nil {
				t.Fatal(err)
			}
			originals[invalid] = bad
			if code, _, _ := invokeArtifacts(t, directory, "--write"); code != 1 {
				t.Fatal("invalid marker ownership was accepted")
			}
			for name, before := range originals {
				after, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(name)))
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("late preflight failure changed an operator artifact")
				}
			}
		})
	}
}

func TestArtifactReadFailuresUseFixedDiagnostics(t *testing.T) {
	for _, kind := range []string{"oversized", "directory", "missing"} {
		t.Run(kind, func(t *testing.T) {
			directory, _ := artifactFixture(t)
			file := filepath.Join(directory, configartifact.ProductionEnvironmentPath)
			if err := os.Remove(file); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "oversized":
				f, err := os.Create(file)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate(configartifact.MaxArtifactBytes + 1); err != nil {
					_ = f.Close()
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(file, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if code, _, _ := invokeArtifacts(t, directory, "--write"); code != 1 {
				t.Fatal("invalid artifact input was accepted")
			}
		})
	}
}

func TestRootOpenFailureDoesNotExposeUnderlyingCause(t *testing.T) {
	var out, diagnostics bytes.Buffer
	code := run(nil, &out, &diagnostics, func() (*os.Root, error) {
		return nil, errors.New("PRIVATE_ROOT_PATH_AND_CAUSE")
	})
	if code != 1 || strings.Contains(out.String()+diagnostics.String(), "PRIVATE_") {
		t.Fatal("repository-open failure exposed its underlying cause")
	}
}

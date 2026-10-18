//go:build deployment

// Package deploymentcheck supplies fake operator inputs to tagged startup tests.
// It renders repository assets without starting containers or opening providers.
package deploymentcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/platform/config"
)

const maxFixtureBytes = 1 << 20

var ServerSources = []struct{ Name, Mode string }{{"helm", "env"}, {"helm", "files"}, {"compose", "env"}}

type projection struct {
	Guest string            `json:"guest"`
	Mode  os.FileMode       `json:"mode"`
	Files map[string]string `json:"files"`
}

type Fixture struct {
	Environment map[string]string `json:"environment"`
	Mounts      []projection      `json:"mounts"`
	Expected    map[string]string `json:"expected"`
	ownedFiles  map[string]string
}

func Load(t *testing.T, source, process, mode string) *Fixture {
	t.Helper()
	repo, err := repositoryRoot()
	if err != nil {
		t.Fatal("cannot locate deployment fixture renderer")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	command, err := fixtureCommand(ctx, source, process, mode)
	if err != nil {
		t.Fatal("unsupported deployment fixture selection")
	}
	command.Dir = repo
	var output boundedOutput
	command.Stdout, command.Stderr = &output, io.Discard
	if command.Run() != nil {
		t.Fatal("deployment fixture rendering failed; output withheld")
	}
	var fixture Fixture
	decoder := json.NewDecoder(bytes.NewReader(output.body.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&fixture) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) || fixture.Environment == nil || fixture.Expected == nil {
		t.Fatal("invalid deployment fixture output; contents withheld")
	}
	// The native driver resolves process PG* defaults separately. Keep those
	// test inputs empty so a developer's service/password/TLS files are unused.
	for _, definition := range config.NativeDefinitions() {
		if definition.Boundary == config.NativePostgres {
			t.Setenv(definition.Name, "")
			for _, fallback := range definition.Fallbacks {
				t.Setenv(fallback, "")
			}
		}
	}
	fixture.materialize(t)
	return &fixture
}

// Keep the executable and every argument literal. Unknown selectors cannot
// become subprocess arguments, even if a future test passes operator input.
func fixtureCommand(ctx context.Context, source, process, mode string) (*exec.Cmd, error) {
	switch source + "/" + process + "/" + mode {
	case "helm/api/env":
		return exec.CommandContext(ctx, "python3", "scripts/render_deployment_fixture.py", "--source=helm", "--process=api", "--secret-source=env"), nil
	case "helm/api/files":
		return exec.CommandContext(ctx, "python3", "scripts/render_deployment_fixture.py", "--source=helm", "--process=api", "--secret-source=files"), nil
	case "helm/worker/env":
		return exec.CommandContext(ctx, "python3", "scripts/render_deployment_fixture.py", "--source=helm", "--process=worker", "--secret-source=env"), nil
	case "helm/worker/files":
		return exec.CommandContext(ctx, "python3", "scripts/render_deployment_fixture.py", "--source=helm", "--process=worker", "--secret-source=files"), nil
	case "compose/api/env":
		return exec.CommandContext(ctx, "python3", "scripts/render_deployment_fixture.py", "--source=compose", "--process=api", "--secret-source=env"), nil
	case "compose/worker/env":
		return exec.CommandContext(ctx, "python3", "scripts/render_deployment_fixture.py", "--source=compose", "--process=worker", "--secret-source=env"), nil
	case "compose/migrate/env":
		return exec.CommandContext(ctx, "python3", "scripts/render_deployment_fixture.py", "--source=compose", "--process=migrate", "--secret-source=env"), nil
	case "compose/migrate/files":
		return exec.CommandContext(ctx, "python3", "scripts/render_deployment_fixture.py", "--source=compose", "--process=migrate", "--secret-source=files"), nil
	case "operator/cli/env":
		return exec.CommandContext(ctx, "python3", "scripts/render_deployment_fixture.py", "--source=operator", "--process=cli", "--secret-source=env"), nil
	case "operator/cli/files":
		return exec.CommandContext(ctx, "python3", "scripts/render_deployment_fixture.py", "--source=operator", "--process=cli", "--secret-source=files"), nil
	default:
		return nil, errors.New("unsupported fixture selection")
	}
}

func (fixture *Fixture) Input(t *testing.T, overrides map[string]string) config.Environment {
	t.Helper()
	values := maps.Clone(fixture.Environment)
	maps.Copy(values, overrides)
	entries := make([]string, 0, len(values))
	for name, value := range values {
		entries = append(entries, name+"="+value)
	}
	environment, err := config.Capture(entries)
	if err != nil {
		t.Fatal("cannot capture rendered input; values withheld")
	}
	return environment
}

func (fixture *Fixture) CheckDiagnostics(t *testing.T, diagnostics string, err error) {
	t.Helper()
	if strings.Contains(diagnostics, "PRIVATE_") || (err != nil && strings.Contains(err.Error(), "PRIVATE_")) {
		t.Fatal("startup diagnostic exposed fixture content or paths")
	}
}

// Install isolates real command capture from the developer/CI process settings.
// HOME, PATH and other platform-owned inputs are left intact.
func (fixture *Fixture) Install(t *testing.T, overrides map[string]string) {
	t.Helper()
	for _, definition := range config.NativeDefinitions() {
		if definition.Boundary != config.NativeHost {
			for _, name := range append([]string{definition.Name}, definition.Fallbacks...) {
				t.Setenv(name, "")
				if os.Unsetenv(name) != nil {
					t.Fatal("cannot isolate native command inputs")
				}
			}
		}
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name == "ENV" || name == "CI" || strings.HasPrefix(name, "EVYDENCE_") || strings.HasPrefix(name, "GITHUB_") {
			t.Setenv(name, "")
			if os.Unsetenv(name) != nil {
				t.Fatal("cannot isolate command environment")
			}
		}
	}
	values := maps.Clone(fixture.Environment)
	maps.Copy(values, overrides)
	for name, value := range values {
		t.Setenv(name, value)
	}
}

func (fixture *Fixture) materialize(t *testing.T) {
	t.Helper()
	paths := make(map[string]bool)
	references := make(map[string]bool)
	fixture.ownedFiles = make(map[string]string)
	for _, definition := range config.Definitions() {
		if definition.Kind == config.Path {
			paths[definition.Name] = true
		}
		if definition.FileOption != "" {
			paths[definition.FileOption] = true
			references[definition.FileOption] = true
		}
		if definition.Kind == config.Path && strings.HasSuffix(definition.Name, "_FILE") {
			references[definition.Name] = true
		}
	}
	if len(fixture.Mounts) > 16 {
		t.Fatal("too many fixture projections")
	}
	for _, mount := range fixture.Mounts {
		if !filepath.IsAbs(mount.Guest) || filepath.Clean(mount.Guest) != mount.Guest || mount.Mode&^os.FileMode(0o777) != 0 || len(mount.Files) > 32 {
			t.Fatal("invalid fixture mount")
		}
		directory := t.TempDir()
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal("cannot open private fixture root")
		}
		if err := root.Mkdir("PRIVATE_projection", 0o700); err != nil {
			_ = root.Close()
			t.Fatal("cannot create fixture projection")
		}
		private, err := root.OpenRoot("PRIVATE_projection")
		closeErr := root.Close()
		if err != nil || closeErr != nil {
			if private != nil {
				_ = private.Close()
			}
			t.Fatal("cannot open fixture projection")
		}
		func() {
			defer func() { _ = private.Close() }()
			if private.Mkdir("PRIVATE_revision", 0o700) != nil || private.Symlink("PRIVATE_revision", "..data") != nil {
				t.Fatal("cannot create fixture version")
			}
			for name, value := range mount.Files {
				if !validFilename(name) {
					t.Fatal("invalid fixture filename")
				}
				if private.WriteFile("PRIVATE_revision/"+name, []byte(value), 0o600) != nil || private.Symlink("..data/"+name, name) != nil {
					t.Fatal("cannot materialize fixture file")
				}
				if changeMode(private, name, mount.Mode) != nil {
					t.Fatal("cannot set fixture file mode")
				}
				for option, input := range fixture.Environment {
					if paths[option] && input == mount.Guest+"/"+name {
						fixture.Environment[option] = filepath.Join(directory, "PRIVATE_projection", name)
						fixture.ownedFiles[option] = fixture.Environment[option]
					}
				}
			}
		}()
	}
	for option := range references {
		if fixture.Environment[option] != "" && fixture.ownedFiles[option] == "" {
			t.Fatal("fixture file reference is not in an owned projection")
		}
	}
}

func (fixture *Fixture) SetFileMode(t *testing.T, option string, mode os.FileMode) {
	t.Helper()
	name := fixture.ownedFiles[option]
	if name == "" {
		t.Fatal("fixture file is not owned")
	}
	root, err := os.OpenRoot(filepath.Dir(name))
	if err != nil {
		t.Fatal("cannot open owned fixture file directory")
	}
	defer func() { _ = root.Close() }()
	info, err := root.Stat(filepath.Base(name))
	if err != nil || changeMode(root, filepath.Base(name), mode) != nil {
		t.Fatal("cannot update owned fixture file mode")
	}
	t.Cleanup(func() {
		root, err := os.OpenRoot(filepath.Dir(name))
		if err != nil {
			t.Error("cannot reopen fixture directory for cleanup")
			return
		}
		defer func() { _ = root.Close() }()
		if changeMode(root, filepath.Base(name), info.Mode().Perm()) != nil {
			t.Error("cannot restore fixture file mode")
		}
	})
}

func (fixture *Fixture) SetFileContents(t *testing.T, option, contents string) {
	t.Helper()
	name := fixture.ownedFiles[option]
	if name == "" {
		t.Fatal("fixture file is not owned")
	}
	root, err := os.OpenRoot(filepath.Dir(name))
	if err != nil {
		t.Fatal("cannot open owned fixture directory")
	}
	defer func() { _ = root.Close() }()
	base := filepath.Base(name)
	original, err := root.ReadFile(base)
	info, statErr := root.Stat(base)
	if err != nil || statErr != nil {
		t.Fatal("cannot snapshot owned fixture file")
	}
	replace := func(root *os.Root, body []byte) error {
		if changeMode(root, base, 0o600) != nil {
			return errors.New("cannot make fixture writable")
		}
		return errors.Join(root.WriteFile(base, body, 0o600), changeMode(root, base, info.Mode().Perm()))
	}
	if replace(root, []byte(contents)) != nil {
		t.Fatal("cannot replace fixture file")
	}
	t.Cleanup(func() {
		root, err := os.OpenRoot(filepath.Dir(name))
		if err != nil {
			t.Error("cannot reopen fixture directory for restoration")
			return
		}
		defer func() { _ = root.Close() }()
		if replace(root, original) != nil {
			t.Error("cannot restore fixture file")
		}
	})
}

func changeMode(root *os.Root, name string, mode os.FileMode) error {
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	return errors.Join(file.Chmod(mode), file.Close())
}

func validFilename(name string) bool {
	return name != "." && name != ".." && name != "" && filepath.Base(name) == name && !strings.ContainsAny(name, "\\\x00")
}

func repositoryRoot() (string, error) {
	directory, err := os.Getwd()
	for err == nil {
		if info, statErr := os.Stat(filepath.Join(directory, "scripts/render_deployment_fixture.py")); statErr == nil && info.Mode().IsRegular() {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	return "", errors.New("deployment fixture root unavailable")
}

type boundedOutput struct{ body bytes.Buffer }

func (output *boundedOutput) Write(body []byte) (int, error) {
	if len(body) > maxFixtureBytes-output.body.Len() {
		return 0, errors.New("deployment fixture output exceeds limit")
	}
	return output.body.Write(body)
}

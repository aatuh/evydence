package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestEnvironmentReadGuardResolvesFiniteSources(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		want         []string
	}{
		{"literal-and-import-alias", `package sample; import system "os"; func run() { system.Getenv("ENV"); system.LookupEnv("CI") }`, []string{"CI", "ENV"}},
		{"computed-name", `package sample; import "os"; const prefix = "EVYDENCE_"; func run() { const suffix = "LOG_LEVEL"; os.Getenv(prefix + suffix) }`, []string{"EVYDENCE_LOG_LEVEL"}},
		{"forwarded-wrapper", `package sample; import "os"; func read(name string) string { return os.Getenv(name) }; func forward(key string) string { return read(key) }; func run() { forward("EVYDENCE_LOG_LEVEL"); forward("EVYDENCE_LOG_FORMAT") }`, []string{"EVYDENCE_LOG_FORMAT", "EVYDENCE_LOG_LEVEL"}},
		{"finite-loop", `package sample; import "os"; var names = []string{"EVYDENCE_FIRST", "EVYDENCE_SECOND"}; func read(key string) string { return os.Getenv(key) }; func run() { for _, key := range names { read(key) } }`, []string{"EVYDENCE_FIRST", "EVYDENCE_SECOND"}},
		{"injected-reader", `package sample; func config(read func(string) string) { read("EVYDENCE_LOG_LEVEL") }`, []string{"EVYDENCE_LOG_LEVEL"}},
		{"package-separated-files", `package sample; import "os"; func read(name string) string { return os.Getenv(name) }`, []string{"EVYDENCE_LOG_LEVEL"}},
		{"constant-lexical-scope", `package sample; import "os"; const prefix = "EVYDENCE_"; const name = prefix + "LOG_LEVEL"; func run() { prefix := "WRONG_"; _ = prefix; os.Getenv(name) }`, []string{"EVYDENCE_LOG_LEVEL"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"source.go": tc.source}
			if tc.name == "package-separated-files" {
				files["caller.go"] = `package sample; func run() { read("EVYDENCE_LOG_LEVEL") }`
			}
			got, err := environmentReadNames(files)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatal("finite environment read sources were not resolved", got, err)
			}
		})
	}
}

func TestEnvironmentReadGuardRejectsUnresolvedSources(t *testing.T) {
	for _, source := range []string{
		`package sample; import "os"; func run() { os.Getenv(os.Args[1]) }`,
		`package sample; import "os"; func read(name string) string { return os.Getenv(name) }; func run() { read(os.Args[1]) }`,
		`package sample; import "os"; func read(name string) string { return os.Getenv(name) }; func run() { alias := read; alias("EVYDENCE_LOG_LEVEL") }`,
		`package sample; import "os"; func read(name string) string { return os.Getenv(name) }; func run() { read("ENV"); alias := read; alias(os.Args[1]) }`,
		`package sample; import "os"; func run() { alias := os.Getenv; alias(os.Args[1]) }`,
		`package sample; import "os"; func read(name string) string { return os.Getenv(name) }; func forward(name string) string { return read(name) }; func run(name string) { forward(name) }`,
		`package sample; import "os"; func config(read func(string) string, name string) { read(name) }`,
		`package sample; func config(read func(string) string) { alias := read; alias("EVYDENCE_LOG_LEVEL") }`,
		`package sample; import "os"; var names = []string{"ENV"}; func init() { alias := names; alias[0] = os.Args[1] }; func run() { for _, name := range names { os.Getenv(name) } }`,
	} {
		if names, err := environmentReadNames(map[string]string{"source.go": source}); err == nil || len(names) != 0 {
			t.Fatal("unresolved environment read bypassed the coverage guard")
		}
	}
}

func TestSchemaCoversComputedEnvironmentReads(t *testing.T) {
	known := map[string]bool{}
	for _, d := range Definitions() {
		known[d.Name] = true
		for _, alias := range d.Aliases {
			known[alias] = true
		}
	}
	for _, d := range NativeDefinitions() {
		known[d.Name] = true
		for _, alias := range d.Fallbacks {
			known[alias] = true
		}
	}
	packages := map[string]map[string]string{}
	root := filepath.Clean("../../..")
	sourceRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sourceRoot.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, base := range []string{"cmd", "internal"} {
		err := fs.WalkDir(sourceRoot.FS(), base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path == "internal/platform/config" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := sourceRoot.ReadFile(path)
			if err != nil {
				return err
			}
			directory := filepath.Dir(path)
			if packages[directory] == nil {
				packages[directory] = map[string]string{}
			}
			packages[directory][path] = string(data)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for directory, files := range packages {
		names, err := environmentReadNames(files)
		if err != nil {
			t.Error("unresolved source environment read:", directory, err)
			continue
		}
		for _, name := range names {
			if !known[name] {
				t.Error("computed source environment name is absent from schema:", directory, name)
			}
		}
	}
}

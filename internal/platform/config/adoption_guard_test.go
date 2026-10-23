package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A finite getenv wrapper is still an ambient read. After command adoption,
// only the reviewed startup/cold-freshness Capture calls may read process input.
// SDK/platform boundaries live in their pinned external packages, not a local
// forwarding parser whose validation could be bypassed by a future caller.
func TestRuntimeConfigurationOwnsAllProcessEnvironmentReads(t *testing.T) {
	packages := make(map[string]map[string]string)
	root, err := os.OpenRoot("../../..")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, base := range []string{"cmd", "internal"} {
		err := fs.WalkDir(root.FS(), base, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if path == "internal/platform/config" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, err := root.ReadFile(path)
			if err != nil {
				return err
			}
			dir := filepath.ToSlash(filepath.Dir(path))
			if packages[dir] == nil {
				packages[dir] = make(map[string]string)
			}
			packages[dir][path] = string(body)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	retired := map[string]map[string]bool{
		"internal/platform/wiring":       {"CleanupTimeoutFromEnv": true, "ObjectStoreConfigFromEnv": true},
		"internal/platform/logging":      {"Run": true, "ConfigFromEnv": true},
		"internal/platform/confighealth": {"New": true, "configurationEnvironment": true, "validConfigurationRevision": true},
	}

	owners := map[string]string{
		"cmd/evydence-api/main.go":                         "run",
		"cmd/evydence-worker/main.go":                      "runWorkerWithContext",
		"cmd/evydence-migrate/main.go":                     "run",
		"cmd/evydence/main.go":                             "run",
		"internal/platform/confighealth/process_source.go": "ProcessSource",
	}
	for dir, files := range packages {
		names, err := environmentReadNames(files)
		if err != nil || len(names) != 0 {
			t.Error("runtime configuration escaped explicit startup/freshness capture", dir, names, err)
		}
		for path, body := range files {
			file, err := parser.ParseFile(token.NewFileSet(), path, body, 0)
			if err != nil {
				t.Fatal(err)
			}

			osName := ""
			for _, spec := range file.Imports {
				imported, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if imported == "os" {
					osName = "os"
					if spec.Name != nil {
						osName = spec.Name.Name
					}
				}
			}
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok {
					continue
				}
				if function.Recv == nil && retired[dir][function.Name.Name] {
					t.Error("obsolete environment parser remains in production", dir, function.Name.Name)
				}
				ast.Inspect(function.Body, func(node ast.Node) bool {
					selector, ok := node.(*ast.SelectorExpr)
					if !ok || selector.Sel.Name != "Environ" {
						return true
					}
					identifier, ok := selector.X.(*ast.Ident)
					if ok && identifier.Name == osName && (function.Recv != nil || owners[path] != function.Name.Name) {
						t.Error("process snapshot has no reviewed owner", path, function.Name.Name)
					}
					return true
				})
			}
		}
	}
}

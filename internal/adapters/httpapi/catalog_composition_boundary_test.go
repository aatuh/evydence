package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestCatalogCreationTransportUsesFocusedCommandsOnly(t *testing.T) {
	for _, tc := range []struct {
		filename string
		handlers []string
	}{
		{"catalog_creation_commands.go", []string{"createProduct", "createProject", "createRelease"}},
		{"artifact_image_registration.go", []string{"registerArtifact", "registerContainerImage"}},
		{"build_commands.go", []string{"createBuild"}},
		{"candidate_creation.go", []string{"createReleaseCandidate"}},
		{"state_transitions.go", []string{"transitionRelease", "transitionReleaseCandidate"}},
		{"build_attestation_commands.go", []string{"uploadBuildAttestation"}},
	} {
		t.Run(tc.filename, func(t *testing.T) {
			assertCatalogWriteComposition(t, tc.filename, tc.handlers)
		})
	}
}

func assertCatalogWriteComposition(t *testing.T, filename string, expected []string) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filename, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	handlers := make(map[string]bool, len(expected))
	for _, name := range expected {
		handlers[name] = false
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, ok := handlers[function.Name.Name]; !ok {
			continue
		}
		handlers[function.Name.Name] = true
		durableCalls := 0
		ast.Inspect(function.Body, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			owner, ok := selector.X.(*ast.Ident)
			if !ok || owner.Name != "s" {
				return true
			}
			switch selector.Sel.Name {
			case "ledger", "releaseCatalog", "idempotency", "createWithActorFingerprint", "create":
				t.Errorf("%s retains legacy dependency %s", function.Name.Name, selector.Sel.Name)
			case "createDurable", "createDurableWithFingerprint", "createDurableWithLimit":
				durableCalls++
			}
			return true
		})
		if durableCalls != 1 {
			t.Errorf("%s has %d focused replay calls, want exactly one", function.Name.Name, durableCalls)
		}
	}
	for name, found := range handlers {
		if !found {
			t.Errorf("catalog handler %s was not inspected", name)
		}
	}
}

func TestReleaseCatalogTransportDependencyIsRetired(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.TypeSpec:
				if value.Name.Name == "releaseCatalogService" {
					t.Errorf("%s retains the broad release-catalog interface", name)
				}
			case *ast.Field:
				for _, field := range value.Names {
					if field.Name == "releaseCatalog" {
						t.Errorf("%s retains the broad release-catalog binding", name)
					}
				}
			case *ast.SelectorExpr:
				if value.Sel.Name == "releaseCatalog" {
					t.Errorf("%s accesses the retired release-catalog binding", name)
				}
			}
			return true
		})
	}
}

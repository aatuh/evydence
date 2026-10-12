package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestPackageAggregateTransportDependencyIsRetired(t *testing.T) {
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
				if value.Name.Name == "packageService" {
					t.Errorf("%s retains the broad Package interface", name)
				}
			case *ast.Field:
				for _, field := range value.Names {
					if field.Name == "packages" {
						t.Errorf("%s retains the broad Package binding", name)
					}
				}
			case *ast.SelectorExpr:
				if value.Sel.Name == "packages" {
					t.Errorf("%s accesses the broad Package binding", name)
				}
			}
			return true
		})
	}
	for _, tc := range []struct {
		file     string
		handlers []string
	}{
		{"release_bundle_creation.go", []string{"createReleaseBundleCommand"}},
		{"customer_package_creation_commands.go", []string{"createCustomerPackage"}},
		{"router.go", []string{"createRedactionProfile", "getCustomerPackage", "securityReviewPackageReport", "craReadinessHTMLPackage", "releaseReadinessReport"}},
		{"customer_package_access_commands.go", []string{"customerPackageArchive"}},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), tc.file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range tc.handlers {
			found := false
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Name.Name != name {
					continue
				}
				found = true
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
					case "ledger", "packages", "idempotency", "create", "createWithActorFingerprint":
						t.Errorf("%s retains aggregate dependency %s", name, selector.Sel.Name)
					}
					return true
				})
			}
			if !found {
				t.Errorf("Package handler %s was not inspected", name)
			}
		}
	}
}

func TestReleaseBundleDescriptionDoesNotPromiseRetiredRuntime(t *testing.T) {
	description, ok := releaseBundleCreationSchema()["description"].(string)
	if !ok || strings.Contains(description, "Both profiles") || strings.Contains(description, "Local memory retains") {
		t.Fatal("release-bundle contract promises a retired API runtime")
	}
}

package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestIngestionFixturesRetireCacheGuardsAndBackendSwitch(t *testing.T) {
	retired := map[string]bool{"ingestionFixtureAuthority": true, "ingestionFixtureGuardEffects": true, "ingestionFixtureReadAuthority": true, "ingestionFixtureGuardTransaction": true, "ingestionFixtureGuardRunner": true, "ingestionFixtureGuardClock": true, "ingestionFixtureGuardID": true, "fixtureOwnerReader": true, "readFixtureSource": true, "bindRepositoryIngestionFixtureScope": true}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	inspected := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		inspected++
		ast.Inspect(file, func(node ast.Node) bool {
			switch v := node.(type) {
			case *ast.TypeSpec:
				if retired[v.Name.Name] {
					t.Errorf("%s retains retired cache-guard type %s", name, v.Name.Name)
				}
			case *ast.FuncDecl:
				if retired[v.Name.Name] {
					t.Errorf("%s retains retired cache-guard function %s", name, v.Name.Name)
				}
			case *ast.Field:
				for _, field := range v.Names {
					if field.Name == "repositoryScope" {
						t.Errorf("%s retains obsolete backend switch", name)
					}
				}
			}
			return true
		})
	}
	if inspected == 0 {
		t.Fatal("no fixture sources inspected")
	}
}
